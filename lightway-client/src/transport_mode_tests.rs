use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use super::*;
use lightway_core::mock::{Inbox, MockFactory, MockTransport, NullOutsideIo};
use lightway_core::{
    ClientTransportArgs, InsideIOSendCallback, InsideIpConfig, LightwayFeature,
    OutsideIOSendCallback, OutsideIOSendCallbackArg, ServerAuth, ServerAuthHandle,
    ServerAuthResult, ServerContextBuilder, ServerIpPool, TickType, Transport, TransportArgs,
    TransportCaps, TransportError,
};

const CAPS: TransportCaps = TransportCaps {
    lossy: true,
    reliable_control: false,
    wire_header: false,
    supports_roaming: true,
};

const PEER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
    443,
);

const SERVER_DN: &str = "server.example";

/// Checks that the client passes its peer checks to the factory.
struct CheckArgs(MockFactory);

impl ClientTransportFactory for CheckArgs {
    fn connect(
        &self,
        args: TransportArgs,
        client: ClientTransportArgs,
    ) -> Result<Box<dyn Transport>, TransportError> {
        assert_eq!(client.domain_name.as_deref(), Some(SERVER_DN));
        self.0.connect(args, client)
    }
}

/// Hands the client the packets that the server transport wrote.
struct InboxIo(Inbox);

impl OutsideIOSendCallback for InboxIo {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        IOCallbackResult::Ok(buf.len())
    }

    fn send_gso(&self, _bufs: &[std::io::IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    fn peer_addr(&self) -> SocketAddr {
        PEER
    }
}

#[async_trait::async_trait]
impl io::outside::OutsideIO for InboxIo {
    fn set_send_buffer_size(&self, _size: usize) -> Result<()> {
        Ok(())
    }

    fn set_recv_buffer_size(&self, _size: usize) -> Result<()> {
        Ok(())
    }

    fn send_buffer_size(&self) -> Result<usize> {
        Ok(0)
    }

    fn recv_buffer_size(&self) -> Result<usize> {
        Ok(0)
    }

    async fn poll(&self, _interest: tokio::io::Interest) -> Result<tokio::io::Ready> {
        while self.0.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(tokio::io::Ready::READABLE)
    }

    fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize> {
        match self.0.lock().unwrap().pop_front() {
            Some(pkt) => {
                buf.clear();
                buf.extend_from_slice(&pkt);
                IOCallbackResult::Ok(pkt.len())
            }
            None => IOCallbackResult::WouldBlock,
        }
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg {
        self
    }

    fn peer_addr(&self) -> SocketAddr {
        PEER
    }

    fn socket(&self) -> Option<io::outside::OutsideSocket> {
        None
    }
}

struct Tun;

#[async_trait::async_trait]
impl io::inside::InsideIORecv<()> for Tun {
    async fn recv_buf(&self, _buf: &mut BytesMut) -> IOCallbackResult<usize> {
        std::future::pending().await
    }

    fn try_send(&self, pkt: BytesMut, _ip_config: Option<InsideIpConfig>) -> Result<usize> {
        Ok(pkt.len())
    }

    fn mtu(&self) -> usize {
        1350
    }

    fn into_io_send_callback(self: Arc<Self>) -> InsideIOSendCallbackArg<ConnectionState<()>> {
        self
    }
}

impl<S> InsideIOSendCallback<S> for Tun {
    fn send(&self, buf: BytesMut, _state: &mut S) -> IOCallbackResult<usize> {
        IOCallbackResult::Ok(buf.len())
    }

    fn mtu(&self) -> usize {
        1350
    }

    fn if_index(&self) -> std::io::Result<u32> {
        Err(std::io::Error::other("none"))
    }

    fn name(&self) -> std::io::Result<String> {
        Err(std::io::Error::other("none"))
    }
}

struct Auth;

impl ServerAuth<()> for Auth {
    fn authorize(&self, _method: &AuthMethod, _state: &mut ()) -> ServerAuthResult {
        ServerAuthResult::Granted {
            handle: Some(Box::new(Handle)),
            tunnel_protocol_version: None,
        }
    }
}

#[derive(Debug)]
struct Handle;

impl ServerAuthHandle for Handle {
    fn expired(&self) -> bool {
        false
    }

    fn features(&self) -> HashSet<LightwayFeature> {
        HashSet::new()
    }
}

struct Pool;

impl ServerIpPool<()> for Pool {
    fn alloc(&self, _state: &mut ()) -> Option<InsideIpConfig> {
        Some(InsideIpConfig {
            client_ip: "10.125.0.2".parse().unwrap(),
            server_ip: "10.125.0.1".parse().unwrap(),
            dns_ip: "10.125.0.1".parse().unwrap(),
            mtu: None,
        })
    }

    fn free(&self, _state: &mut ()) {}
}

fn tick(_d: Duration, _state: &mut (), _t: TickType) {}

#[tokio::test]
async fn caller_supplied_transport_reaches_online() {
    let (client_transport, server_transport) = MockTransport::pair(CAPS);
    let client_inbox = client_transport.inbox();
    let server_inbox = server_transport.inbox();

    let server_ctx = ServerContextBuilder::new(Arc::new(Auth), Arc::new(Pool), Arc::new(Tun), tick)
        .build()
        .unwrap();
    let mut server = server_ctx
        .start_accept(Version::MAXIMUM, Arc::new(NullOutsideIo))
        .unwrap()
        .accept((), Box::new(|_| Ok(Box::new(server_transport))))
        .unwrap();
    let server_task = tokio::spawn(async move {
        loop {
            let pkt = server_inbox.lock().unwrap().pop_front();
            match pkt {
                Some(mut pkt) => {
                    server
                        .outside_data_received(OutsidePacket::Wire(&mut pkt))
                        .unwrap();
                }
                None => tokio::time::sleep(Duration::from_millis(1)).await,
            }
        }
    });

    let config: ClientConfig<()> =
        ClientConfig::try_from_reload_sig_and_config(None, config::Config::default()).unwrap();
    let factory: Arc<dyn ClientTransportFactory> =
        Arc::new(CheckArgs(MockFactory::new(client_transport)));
    let io: Arc<dyn io::outside::OutsideIO> = Arc::new(InboxIo(client_inbox));
    let server_config = ClientConnectionConfig::<EventStreamCallback> {
        mode: ClientConnectionMode::Transport {
            factory,
            connector: Box::new(move || async move { Ok(io) }.boxed()),
        },
        cipher: Cipher::default(),
        server_dn: Some(SERVER_DN.to_string()),
        server: PEER,
        auth: AuthMethod::Token {
            token: "token".to_string(),
        },
        cert_content: String::new(),
        inside_plugins: Default::default(),
        outside_plugins: Default::default(),
        inside_pkt_codec: None,
        event_handler: None,
    };

    let mut client = connect(&config, server_config, Arc::new(Tun))
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        client.connected_signal.take().unwrap(),
    )
    .await
    .expect("client did not reach Online")
    .unwrap();
    assert_eq!(client.conn.lock().unwrap().state(), State::Online);

    server_task.abort();
}
