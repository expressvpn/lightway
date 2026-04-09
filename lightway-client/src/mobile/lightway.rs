use crate::event_handlers::EventHandlers;
use crate::io::outside::OutsideIO;
use crate::keepalive::{Keepalive, KeepaliveResult};
use crate::state::ExpresslaneState;
use crate::{
    ClientConnectionConfig, ClientConnectionMode, ClientIpConfigCb, ConnectionState, io,
    keepalive::Config as KeepaliveConfig, outside_io_task,
};
use futures::future::{FutureExt, OptionFuture, select_all};
use lightway_app_utils::{
    ConnectionTicker, DplpmtudTimer, EventStreamCallback, TunConfig, connection_ticker_cb,
};
use lightway_core::{
    BuilderPredicates, ClientContextBuilder, Connection, ConnectionType, IOCallbackResult,
    InsideIOSendCallback, PluginFactoryList,
};
use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::Receiver as MpscReceiver;
use tokio::sync::mpsc::Sender as MpscSender;
use tokio::sync::{Notify, oneshot};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tracing::{Instrument, debug, error, info, info_span};
use uniffi::deps::anyhow::{Context, anyhow, bail};
use uniffi::deps::bytes::BytesMut;

const INTERNAL_MTU: u16 = 1350;
#[cfg(apple)]
const MAX_SOCKET_BUFFER_LEN: usize = 1024000;
const ENABLE_PMTUD: bool = false;

/// Builder for creating OutsideIO connections with optional obfuscation and proxy
///
/// Handles both initial connections (which may need obfuscation and proxy) and network
/// changes (which don't need obfuscation or proxy).
struct OutsideIOBuilder {
    socket: crate::OutsideSocket,
    server_sockaddr: SocketAddr,
}

impl<'a> OutsideIOBuilder {
    fn new(socket: crate::OutsideSocket, server_sockaddr: SocketAddr) -> Self {
        Self {
            socket,
            server_sockaddr,
        }
    }

    async fn build(
        self,
        _plugins: &mut PluginFactoryList,
    ) -> uniffi::Result<(ConnectionType, Arc<dyn OutsideIO>)> {
        let result: Result<(ConnectionType, Arc<dyn OutsideIO>), _> = match self.socket {
            crate::OutsideSocket::Tcp(s) => {
                let stream = s.connect(self.server_sockaddr).await?;
                let sock = io::outside::Tcp::new(self.server_sockaddr, Some(stream))
                    .await
                    .context("Outside IO TCP")?;
                Ok((ConnectionType::Stream, Arc::new(sock)))
            }
            crate::OutsideSocket::Udp(s) => {
                let sock = io::outside::Udp::new(self.server_sockaddr, Some(s))
                    .await
                    .context("Outside IO UDP")?;
                // TODO: Skip setting send/recv buffer size on Android for now
                #[cfg(apple)]
                {
                    sock.set_send_buffer_size(MAX_SOCKET_BUFFER_LEN)?;
                    sock.set_recv_buffer_size(MAX_SOCKET_BUFFER_LEN)?;
                }
                Ok((ConnectionType::Datagram, Arc::new(sock)))
            }
        };

        result
    }
}

pub type TunnelState = Option<Arc<io::inside::Tun>>;

/// Inside IO which can be cloned by multiple parallel connections
///
/// The actual tunnel `InsideIO` is stored inside `ConnectionState::extended`
/// After a connection becomes active, it updates the connection state with tunnel `InsideIO`
#[derive(Clone)]
struct MobileInsideIo {
    mtu: usize,
}

impl InsideIOSendCallback<ConnectionState<TunnelState>> for MobileInsideIo {
    fn send(
        &self,
        buf: BytesMut,
        state: &mut ConnectionState<TunnelState>,
    ) -> IOCallbackResult<usize> {
        if let Some(tun) = state.extended.clone() {
            tun.send(buf, state)
        } else {
            // Fake it, but all tunnel traffic is dropped/blocked
            IOCallbackResult::Ok(buf.len())
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn if_index(&self) -> uniffi::Result<u32, std::io::Error> {
        Err(std::io::Error::other("unimplemented!"))
    }

    fn name(&self) -> uniffi::Result<String, std::io::Error> {
        Err(std::io::Error::other("unimplemented!"))
    }
}

pub(crate) async fn setup_tunnel_interface(
    tun_fd: RawFd,
    local_ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
) -> uniffi::Result<Arc<io::inside::Tun>> {
    let mut tun_config = TunConfig::default();

    // Tun device should not be closed on client exit, since the same tunnel will be
    // used by further connection
    tun_config.raw_fd(tun_fd).close_fd_on_drop(false);

    Ok(Arc::new(
        io::inside::Tun::new(&tun_config, local_ip, dns_ip)
            .await
            .context("Tun creation")?,
    ))
}

struct OutsideIOConfig {
    mtu: usize,
    connection_type: ConnectionType,
    outside_io: Arc<dyn OutsideIO>,
}

/// This function is responsible for running `outside_io_task` to handle outside packet.
/// It can restart the task with an updated ` outside_io ` upon receiving a new outside IO callback.
async fn restartable_outside_io_task(
    conn: Arc<Mutex<Connection<ConnectionState<TunnelState>>>>,
    outside_io_config: OutsideIOConfig,
    keepalive: Keepalive,
    notify_keepalive_reply: Arc<Notify>,
    mut new_outside_io_receiver: MpscReceiver<()>,
    external_event_handler: Arc<dyn EventHandlers>,
) -> uniffi::Result<()> {
    let mut current_outside_io = outside_io_config.outside_io;
    let mut first_run = true;

    loop {
        // For the first run, we don't need to send a new keepalive because the outside IO used here
        // should be the same as the one we're using while setting up and connecting to the servers.
        let ready_tx = if first_run {
            first_run = false;
            None
        } else {
            let (tx, rx) = oneshot::channel();
            let keepalive = keepalive.clone();
            let keepalive_reply = notify_keepalive_reply.clone();
            let handler = external_event_handler.clone();
            tokio::spawn(async move {
                match rx.await {
                    Ok(_) => keepalive.network_changed().await,
                    Err(e) => {
                        error!("outside_io_task ready signal failed: {e:?}");
                        return;
                    }
                }
                keepalive_reply.notified().await;
                handler.connection_has_floated();
            });
            Some(tx)
        };

        tokio::select! {
            result = outside_io_task(conn.clone(), outside_io_config.mtu, outside_io_config.connection_type, current_outside_io.clone(), keepalive.clone(), ready_tx) => return result,

            new_outside_io_result = new_outside_io_receiver.recv() => {
                match new_outside_io_result {
                    Some(_) => {
                        info!("Restarting outside_io_task with new socket");
                        let peer_addr = conn.lock().unwrap().peer_addr();
                        let socket = crate::OutsideSocket::new(false, None)?;
                        let mut outside_plugins = PluginFactoryList::new();
                        let (_, new_socket) = OutsideIOBuilder::new(socket, peer_addr)
                            .build(&mut outside_plugins)
                            .await?;
                        let mut conn = conn.lock().unwrap();
                        current_outside_io = new_socket.clone();
                        conn.set_outside_io(new_socket.into_io_send_callback());
                        // Continue the loop to restart with a new socket
                    },
                    None => {
                        bail!("Reset receiver closed")
                    }
                }
            }
        }
    }
}

pub(crate) fn first_outside_io_exit(
    connections: &mut HashMap<usize, LightwayConnection>,
) -> impl Future<Output = (usize, Result<uniffi::Result<()>, tokio::task::JoinError>)> + '_ {
    if connections.is_empty() {
        return futures::future::Either::Left(std::future::pending());
    }
    futures::future::Either::Right(
        select_all(
            connections
                .values_mut()
                .map(|c| Box::pin(async move { (c.instance_id, (&mut c.outside_io_task).await) })),
        )
        .map(|((id, result), _, _)| (id, result)),
    )
}

pub(crate) async fn cleanup_connections(
    in_progress_connections_abort_handle: Vec<AbortHandle>,
    completed_connections: Vec<LightwayConnection>,
) {
    for conn in in_progress_connections_abort_handle {
        if !conn.is_finished() {
            conn.abort();
        }
    }
    for mut c in completed_connections.into_iter() {
        let span = info_span!("CleanupConnection", instance_id = ?c.instance_id);
        span.in_scope(|| {
            debug!("Disconnecting completed connection");
            let _ = c.conn.lock().unwrap().disconnect();
            c.outside_io_task.abort();
            c.join_set.abort_all();
        });
        drop(c.keepalive);
        c.keepalive_task.await;
    }
    info!("Cleaned up unused connections");
}

pub(crate) struct LightwayConnection {
    pub(crate) conn: Arc<Mutex<Connection<ConnectionState<TunnelState>>>>,
    pub(crate) outside_io_task: JoinHandle<uniffi::Result<()>>,
    pub(crate) new_outside_io_sender: MpscSender<()>,
    pub(crate) keepalive: Keepalive,
    pub(crate) keepalive_task: OptionFuture<JoinHandle<KeepaliveResult>>,
    pub(crate) keepalive_config: KeepaliveConfig,
    pub(crate) join_set: JoinSet<()>,
    pub(crate) instance_id: usize,
    pub(crate) expresslane_event_rx: Option<MpscReceiver<ExpresslaneState>>,
}

/// Individual connection to a lightway server
pub(crate) async fn lightway_client_connect(
    ClientConnectionConfig {
        instance_id,
        mode,
        cipher,
        outside_mtu,
        server_dn,
        auth,
        ca_content,
        server,
        sni_header,
        socket,
        enable_keepalive,
        enable_expresslane,
        online_signal_sender,
        event_stream_handler,
        external_event_handler,
    }: ClientConnectionConfig,
) -> uniffi::Result<LightwayConnection> {
    let mut join_set = JoinSet::new();

    // TODO: Should be strong type error
    let socket = socket.ok_or(anyhow!("socket not provided"))?;

    let inside_plugins = PluginFactoryList::new();

    let mut outside_plugins = PluginFactoryList::new();

    let (connection_type, outside_io): (ConnectionType, Arc<dyn OutsideIO>) = {
        let builder = OutsideIOBuilder::new(socket, server);
        builder.build(&mut outside_plugins).await?
    };

    let inside_io = MobileInsideIo {
        mtu: INTERNAL_MTU as usize,
    };
    let inside_io: Arc<dyn InsideIOSendCallback<ConnectionState<TunnelState>> + Send + Sync> =
        Arc::new(inside_io);

    let (event_cb, event_stream) = EventStreamCallback::new();

    let (ticker, ticker_task) = ConnectionTicker::new();
    let state: ConnectionState<TunnelState> = ConnectionState {
        ticker,
        ip_config: None,
        extended: None,
    };
    let (pmtud_timer, pmtud_timer_task) = DplpmtudTimer::new();

    let conn_builder = ClientContextBuilder::new(
        connection_type,
        lightway_core::wolfssl::RootCertificate::PemBuffer(ca_content.as_bytes()),
        Some(inside_io),
        Arc::new(ClientIpConfigCb),
        connection_ticker_cb,
    )?
    // TODO: Do we really need wrapper and a core::Cipher instance to call as_cipher_list?
    .with_cipher(cipher.into())?
    .with_inside_plugins(inside_plugins)
    .with_outside_plugins(outside_plugins)
    .when(connection_type.is_datagram() && enable_expresslane, |b| {
        b.with_expresslane()
    })
    .build()
    .start_connect(outside_io.clone().into_io_send_callback(), outside_mtu)?
    .with_auth(auth)
    .with_event_cb(Box::new(event_cb))
    .when(server_dn.is_some(), |b| {
        b.with_server_domain_name_validation(
            server_dn.as_ref().expect("checked in builder pattern"),
        )
    })
    .when(!sni_header.is_empty(), |b| b.with_sni_header(&sni_header))
    .when(connection_type.is_datagram() && ENABLE_PMTUD, |b| {
        b.with_pmtud_timer(pmtud_timer)
    });

    #[cfg(feature = "postquantum")]
    let conn_builder = conn_builder.when(true, |b| b.with_pq_crypto());

    let conn = Arc::new(Mutex::new(conn_builder.connect(state)?));

    let keepalive_config = KeepaliveConfig {
        interval: Duration::new(2, 0),
        timeout: Duration::new(6, 0),
        continuous: enable_keepalive,
        tracer_trigger_timeout: Some(Duration::from_secs(10)),
    };
    let (keepalive, keepalive_task) =
        Keepalive::new(keepalive_config.clone(), Arc::downgrade(&conn));

    let notify_keepalive_reply = Arc::new(Notify::new());
    let (expresslane_event_tx, expresslane_event_rx) =
        if enable_expresslane && matches!(mode, ClientConnectionMode::Datagram(_)) {
            Some(tokio::sync::mpsc::channel(5))
        } else {
            None
        }
        .unzip();

    join_set.spawn(crate::event_handlers::handle_events(
        event_stream,
        keepalive.clone(),
        notify_keepalive_reply.clone(),
        Arc::downgrade(&conn),
        event_stream_handler,
        online_signal_sender.clone(),
        instance_id,
        expresslane_event_tx,
    ));

    ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);
    pmtud_timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

    let (new_outside_io_sender, new_outside_io_receiver) = tokio::sync::mpsc::channel(1);
    let outside_io_task: JoinHandle<uniffi::Result<()>> = tokio::spawn(
        restartable_outside_io_task(
            conn.clone(),
            OutsideIOConfig {
                mtu: outside_mtu,
                connection_type,
                outside_io,
            },
            keepalive.clone(),
            notify_keepalive_reply,
            new_outside_io_receiver,
            external_event_handler,
        )
        .in_current_span(),
    );

    Ok(LightwayConnection {
        conn,
        outside_io_task,
        new_outside_io_sender,
        keepalive,
        keepalive_task,
        keepalive_config,
        join_set,
        instance_id,
        expresslane_event_rx,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::event_handlers::MockEventHandlers;
    use mockall::Sequence;
    use mockall::predicate::eq;

    #[tokio::test]
    async fn test_outside_socket_new_calls_created_outside_fd() {
        // Test TCP socket creation
        let mut mock_event_handler = MockEventHandlers::new();

        mock_event_handler
            .expect_created_outside_fd()
            .times(1)
            .return_const(());

        let tcp_result = OutsideSocket::new(true, Some(Arc::new(mock_event_handler)));
        assert!(tcp_result.is_ok());

        // Test UDP socket creation
        let mut mock_event_handler = MockEventHandlers::new();

        mock_event_handler
            .expect_created_outside_fd()
            .times(1)
            .return_const(());

        let udp_result = OutsideSocket::new(false, Some(Arc::new(mock_event_handler)));
        assert!(udp_result.is_ok());
    }
}
