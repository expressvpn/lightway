use self::channel::Channel;

use lightway_app_utils::IOUring;

use anyhow::Result;
use async_channel::{Receiver, Sender, bounded};
use bytes::BytesMut;
use clap::Parser;
use lightway_core::IOCallbackResult;
use pnet::packet::ipv4::MutableIpv4Packet;

use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tun::{AsyncDevice as Tun, Configuration as TunConfig};

const PORT: u16 = 40890;
const CHANNEL_SIZE: usize = 32 * 1024;

// Set it lower than MAX_OUTSIDE_MTU so outside UDP packet does not have to IP fragment
const TUN_MTU: usize = 1460;
const MAX_OUTSIDE_MTU: usize = 1500;

use clap::ValueEnum;

#[derive(Copy, Clone, ValueEnum, Debug)]
enum TunBackend {
    Direct,
    Channel,
    IoRing,
}

#[derive(Parser, Debug)]
struct Arguments {
    #[clap(short, long, default_value_t = PORT)]
    port: u16,
    #[clap(short, long)]
    remote: SocketAddr,
    #[clap(short, long)]
    tun_backend: TunBackend,
    #[clap(long, default_value = "udprelay")]
    tun_name: String,
    // Any value more than 1024 negatively impact the throughput
    #[clap(long, default_value_t = 1024)]
    ring_size: usize,
    #[clap(long, default_value_t = CHANNEL_SIZE)]
    channel_size: usize,
}

fn tun_local_addr() -> Ipv4Addr {
    Ipv4Addr::new(169, 254, 1, 1)
}

fn tun_peer_addr() -> Ipv4Addr {
    Ipv4Addr::new(169, 254, 1, 2)
}

async fn build_tun(name: String) -> Result<Tun> {
    let mut tun_config = TunConfig::default();
    tun_config
        .tun_name(&name[..])
        .mtu(TUN_MTU as _)
        .address(tun_local_addr())
        .destination(tun_peer_addr())
        .up();
    let tun = tun::create_as_async(&tun_config)?;
    Ok(tun)
}

async fn build_udp(port: u16, _peer: SocketAddr) -> Result<UdpSocket> {
    let sockaddr = format!("0.0.0.0:{}", port);
    let sockaddr = sockaddr.parse::<SocketAddr>()?;
    let sock = UdpSocket::bind(sockaddr).await?;
    // Connected UDP socket makes app not receiving udp messages in some cases
    // sock.connect(peer).await?;
    Ok(sock)
}

async fn tun_task(sock: Arc<UdpSocket>, peer: SocketAddr, tun: Arc<dyn TunAdapter>) -> Result<()> {
    loop {
        let mut buf = tun.recv_from_tun().await?;
        let len = buf.len();

        // Reverse source and dest ip so that we can use same tunnel ip in both ends
        // No need to update checksum since we swapeed the values and not changed
        if let Some(mut pkt) = MutableIpv4Packet::new(&mut buf[..len]) {
            let source = pkt.get_source();
            pkt.set_source(pkt.get_destination());
            pkt.set_destination(source);
        } else {
            continue;
        }

        let _ = sock.send_to(&buf[..len], peer).await?;
    }
}

async fn udp_task(sock: Arc<UdpSocket>, tun: Arc<dyn TunAdapter>) -> Result<()> {
    let mut first_packet_seen = false;

    loop {
        let mut buf = BytesMut::zeroed(MAX_OUTSIDE_MTU);
        let (len, _) = sock.recv_from(&mut buf).await?;
        let _ = buf.split_off(len);
        if !first_packet_seen {
            println!("Tunnel connected");
            first_packet_seen = !first_packet_seen;
        }

        tun.send_to_tun(buf).await?;
    }
}

#[async_trait::async_trait]
trait TunAdapter: Sync + Send {
    async fn send_to_tun(&self, buf: BytesMut) -> Result<()>;
    async fn recv_from_tun(&self) -> Result<BytesMut>;
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Arguments::parse();

    println!("Starting with {:?}", args);

    let sock = build_udp(args.port, args.remote).await?;
    let tun = build_tun(args.tun_name).await?;

    let sock = Arc::new(sock);
    let tun: Arc<dyn TunAdapter> = match args.tun_backend {
        TunBackend::Direct => Arc::new(tun),
        TunBackend::Channel => Arc::new(TunChannel::new(tun, args.channel_size)?),
        TunBackend::IoRing => {
            Arc::new(TunIOUring::new(tun, args.ring_size, args.channel_size).await?)
        }
    };

    let a = tokio::spawn(udp_task(sock.clone(), tun.clone()));
    let b = tokio::spawn(tun_task(sock, args.remote, tun));

    let _ = tokio::join!(a, b);
    Ok(())
}

#[async_trait::async_trait]
impl TunAdapter for Tun {
    async fn send_to_tun(&self, buf: BytesMut) -> Result<()> {
        let _ = self.send(&buf[..]).await;
        Ok(())
    }

    async fn recv_from_tun(&self) -> Result<BytesMut> {
        let mut buf = BytesMut::zeroed(TUN_MTU);
        let len = self.recv(&mut buf[..]).await?;
        let _ = buf.split_off(len);
        Ok(buf)
    }
}

#[allow(dead_code)]
struct TunChannel {
    recv_q_rx: Receiver<BytesMut>,
    send_q_tx: Sender<BytesMut>,
    tun_channel: Channel<Tun>,
}

impl TunChannel {
    fn new(tun: Tun, channel_size: usize) -> Result<Self> {
        let (recv_q_tx, recv_q_rx) = bounded(channel_size);
        let (send_q_tx, send_q_rx) = bounded(channel_size);
        let tun_channel = Channel::new(Arc::new(tun), recv_q_tx, send_q_rx)?;

        Ok(Self {
            recv_q_rx,
            send_q_tx,
            tun_channel,
        })
    }
}

#[async_trait::async_trait]
impl TunAdapter for TunChannel {
    async fn send_to_tun(&self, buf: BytesMut) -> Result<()> {
        // TODO Check async version of send
        self.send_q_tx.try_send(buf).map_err(anyhow::Error::msg)
    }

    async fn recv_from_tun(&self) -> Result<BytesMut> {
        self.recv_q_rx.recv().await.map_err(anyhow::Error::msg)
    }
}

struct WrappedTun(Tun);
impl AsRawFd for WrappedTun {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.0.as_raw_fd()
    }
}

#[allow(dead_code)]
struct TunIOUring {
    tun_iouring: IOUring<WrappedTun>,
}

impl TunIOUring {
    async fn new(tun: Tun, ring_size: usize, channel_size: usize) -> Result<Self> {
        let tun_iouring = match IOUring::new(
            Arc::new(WrappedTun(tun)),
            ring_size,
            channel_size,
            TUN_MTU,
            Duration::from_millis(100),
        )
        .await
        {
            Ok(it) => it,
            Err(err) => return Err(err),
        };

        Ok(Self { tun_iouring })
    }
}

#[async_trait::async_trait]
impl TunAdapter for TunIOUring {
    async fn send_to_tun(&self, buf: BytesMut) -> Result<()> {
        // TODO Check async version of send
        match self.tun_iouring.try_send(buf) {
            IOCallbackResult::Ok(_) => Ok(()),
            IOCallbackResult::WouldBlock => Ok(()),
            IOCallbackResult::Err(err) => Err(err.into()),
        }
    }

    async fn recv_from_tun(&self) -> Result<BytesMut> {
        match self.tun_iouring.recv().await {
            IOCallbackResult::Ok(pkt) => Ok(pkt),
            IOCallbackResult::WouldBlock => {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock).into())
            }
            IOCallbackResult::Err(err) => Err(err.into()),
        }
    }
}

mod channel {
    use anyhow::Result;
    use async_channel::{Receiver, Sender};
    use bytes::BytesMut;
    use tun::AsyncDevice as Tun;

    use super::TUN_MTU;
    use std::sync::Arc;
    use std::thread;
    use std::thread::JoinHandle;

    #[allow(missing_docs, dead_code)]
    pub struct Channel<T> {
        owned_fd: Arc<T>,
        io_uring_thread_handle: JoinHandle<Result<()>>,
    }

    #[allow(missing_docs)]
    impl Channel<Tun> {
        pub fn new(
            tun: Arc<Tun>,
            recv_q_tx: Sender<BytesMut>,
            send_q_rx: Receiver<BytesMut>,
        ) -> Result<Self> {
            let tun_clone = tun.clone();
            let io_uring_thread_handle = thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed building Tokio Runtime")
                    .block_on(main_task(tun_clone, recv_q_tx, send_q_rx))
            });

            Ok(Self {
                owned_fd: tun,
                io_uring_thread_handle,
            })
        }
    }

    async fn send_task(tun: Arc<Tun>, send_q_rx: Receiver<BytesMut>) -> Result<()> {
        while let Ok(buf) = send_q_rx.recv().await {
            let _ = tun.send(&buf[..]).await;
        }
        Ok(())
    }

    async fn recv_task(tun: Arc<Tun>, recv_q_tx: Sender<BytesMut>) -> Result<()> {
        loop {
            let mut buf = BytesMut::zeroed(TUN_MTU);
            let len = tun.recv(&mut buf[..]).await?;
            let _ = buf.split_off(len);
            let _ = recv_q_tx.send(buf).await;
        }
    }

    async fn main_task(
        tun: Arc<Tun>,
        recv_q_tx: Sender<BytesMut>,
        send_q_rx: Receiver<BytesMut>,
    ) -> Result<()> {
        let _ = tokio::join!(send_task(tun.clone(), send_q_rx), recv_task(tun, recv_q_tx),);

        Ok(())
    }
}
