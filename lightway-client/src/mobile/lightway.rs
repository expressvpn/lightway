use crate::endpoint::RustEndpointConfig;
use crate::io::outside::OutsideIO;
use crate::keepalive::{Keepalive, KeepaliveResult};
use crate::mobile::RustEventHandlers;
use crate::mobile::{DeviceNetworkState, ExpresslaneState, LightwayUserSettings};
use crate::{
    ClientIpConfigCb, ClientResult, ConnectionState, inside_io_task, io,
    keepalive::Config as KeepaliveConfig, outside_io_task,
};
use futures::StreamExt;
use futures::future::{FutureExt, OptionFuture, select_all};
use futures::stream::{FusedStream, FuturesUnordered};
use lightway_app_utils::{
    ConnectionTicker, DplpmtudTimer, EventStream, EventStreamCallback, TunConfig,
    connection_ticker_cb,
};
use lightway_core::{
    BuilderPredicates, Cipher, ClientContextBuilder, Connection, ConnectionError, ConnectionType,
    Event, EventCallback, IOCallbackResult, InsideIOSendCallback, PluginFactoryList,
    RootCertificate, State,
};
use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::mpsc::Receiver as MpscReceiver;
use tokio::sync::mpsc::Sender as MpscSender;
use tokio::sync::{Notify, oneshot};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tokio::time::Instant;
use tracing::{Instrument, debug, error, info, info_span, warn};
use uniffi::deps::anyhow::{Context, anyhow, bail};
use uniffi::deps::bytes::BytesMut;

const INTERNAL_MTU: u16 = 1350;
#[cfg(apple)]
const MAX_SOCKET_BUFFER_LEN: usize = 1024000;
const ENABLE_PMTUD: bool = false;

enum OutsideSocket {
    Tcp(TcpSocket),
    Udp(UdpSocket),
}

impl OutsideSocket {
    fn new(
        use_tcp: bool,
        event_handler: Option<Arc<dyn RustEventHandlers>>,
    ) -> uniffi::Result<Self> {
        if use_tcp {
            let socket = TcpSocket::new_v4()?;
            let fd = socket.as_raw_fd();

            debug!("Created OutsideIO TCP FD: {}", fd);
            if let Some(e) = event_handler {
                e.created_outside_fd(fd)
            }
            Ok(OutsideSocket::Tcp(socket))
        } else {
            let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
            let fd = socket.as_raw_fd();

            debug!("Created OutsideIO UDP FD: {}", fd);
            if let Some(e) = event_handler {
                e.created_outside_fd(fd)
            }
            socket.set_nonblocking(true)?;
            Ok(OutsideSocket::Udp(UdpSocket::from_std(socket)?))
        }
    }
}

/// Builder for creating OutsideIO connections with optional obfuscation and proxy
///
/// Handles both initial connections (which may need obfuscation and proxy) and network
/// changes (which don't need obfuscation or proxy).
struct OutsideIOBuilder {
    socket: OutsideSocket,
    server_sockaddr: SocketAddr,
}

impl<'a> OutsideIOBuilder {
    fn new(socket: OutsideSocket, server_sockaddr: SocketAddr) -> Self {
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
            OutsideSocket::Tcp(s) => {
                let stream = s.connect(self.server_sockaddr).await?;
                let sock = io::outside::Tcp::new(self.server_sockaddr, Some(stream))
                    .await
                    .context("Outside IO TCP")?;
                Ok((ConnectionType::Stream, Arc::new(sock)))
            }
            OutsideSocket::Udp(s) => {
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

type TunnelState = Option<Arc<io::inside::Tun>>;

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

async fn setup_tunnel_interface(
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

pub(crate) async fn async_lightway_start(
    endpoints: Vec<RustEndpointConfig>,
    tun_fd: RawFd,
    external_event_handler: Arc<dyn RustEventHandlers>,
    user_settings: LightwayUserSettings,
    connected_index: Arc<OnceLock<usize>>,
) -> uniffi::Result<ClientResult> {
    let mut outside_sockets = endpoints
        .iter()
        .map(|e| OutsideSocket::new(e.use_tcp, Some(external_event_handler.clone())).ok())
        .collect::<Vec<Option<OutsideSocket>>>();

    let inside_io =
        setup_tunnel_interface(tun_fd, user_settings.local_ip(), user_settings.dns_ip()).await?;

    let (_network_change_sender, mut network_change_receiver) = tokio::sync::mpsc::channel(1);

    let (online_signal_sender, mut online_signal) = tokio::sync::mpsc::channel(endpoints.len());
    let (event_handler, stream) = EventStreamCallback::new();
    let connection_start = Instant::now();
    tokio::spawn(handle_global_events(
        stream,
        connection_start,
        external_event_handler.clone(),
    ));

    let (mut in_progress_connection_abort_handles, mut in_progress_connections): (
        Vec<_>,
        FuturesUnordered<_>,
    ) = endpoints
        .iter()
        .enumerate()
        .map(|(instance_id, endpoint)| {
            let task = tokio::spawn(
                lightway_client_connect(LightwayClientConnectArgs {
                    instance_id,
                    endpoint: endpoint.clone(),
                    sni_header: user_settings.sni_header.clone(),
                    socket: outside_sockets[instance_id].take(),
                    enable_keepalive: user_settings.enable_heart_beat,
                    enable_expresslane: user_settings.enable_expresslane,
                    online_signal_sender: online_signal_sender.clone(),
                    event_stream_handler: event_handler.clone(),
                    external_event_handler: external_event_handler.clone(),
                })
                .instrument(info_span!("LightwayConnection", instance_id = instance_id)),
            );
            (task.abort_handle(), task)
        })
        .unzip();

    let defer_duration = user_settings.get_defer_timeout_duration();
    let mut wait_timer_task = tokio::spawn(tokio::time::sleep(defer_duration));

    debug!(
        "Creating {} parallel connections",
        in_progress_connections.len()
    );

    drop(outside_sockets);
    drop(event_handler);

    // Drop the last sender
    drop(online_signal_sender);

    let mut non_preferred_connections: Vec<(usize, LightwayConnection)> = Vec::new();
    let mut pending_online_connections: HashMap<usize, LightwayConnection> =
        HashMap::with_capacity(endpoints.len());
    let mut failed_connections = 0usize;
    let mut connection_error_to_return = None;

    debug!("Waiting for online signal");
    let tcp_connections_only = endpoints.iter().all(|e| e.use_tcp);
    let active_connection = loop {
        tokio::select! {
            // Prioritise management commands over other branches, also make sure we add
            // LightwayConnection to HashMap first to make sure when it goes online,
            // we can remove it from the HashMap and break the loop.
            biased;
            _ = futures::future::ready(()), if failed_connections == endpoints.len() => {
                error!("All connections failed, exiting...");
                return Err(connection_error_to_return.unwrap_or(anyhow!("All connections failed")));
            }

            // On iOS specifically:
            // If the library is called during a network change, it is possible all the TCP sockets
            // created during this moment are "offline", and they cannot reach the servers.

            // We early return and end connections attempt earlier for both Android and iOS as
            // the connected endpoints are going to get reset by the network change later anyway.
            Some(DeviceNetworkState::Online | DeviceNetworkState::RouteUpdated | DeviceNetworkState::InterfaceChanged) = network_change_receiver.recv(), if tcp_connections_only => {
                info!("client shutting down due to network change while connecting for Lightway - TCP");
                return Ok(ClientResult::NetworkChange)
            },

            Some(connection_result) = in_progress_connections.next(), if !in_progress_connections.is_terminated() => {
                match connection_result {
                    Ok(Ok(connection)) => {
                        debug!("Adding connections to hash map");
                        let _ = pending_online_connections.insert(connection.instance_id, connection);
                        continue;
                    },
                    Ok(Err(e)) => error!("Error while waiting for connection to set up: {:?}", e),
                    Err(e) => error!("Join Error while waiting for connection to set up: {:?}", e)
                };
                failed_connections += 1;
            },

            _ = &mut wait_timer_task, if !wait_timer_task.is_finished() => {
                if !non_preferred_connections.is_empty() {
                    non_preferred_connections.sort_by_key(|(instance_id, _)| *instance_id);
                    let (instance_id, connection) = non_preferred_connections.swap_remove(0);
                    info!(?instance_id, "Defer timeout, choosing best connection");
                    break connection;
                }
            },

            Some(instance_id) = online_signal.recv() => {
                debug!(?instance_id, "Online received for");
                if let Some(connection) = pending_online_connections.remove(&instance_id) {
                    if wait_timer_task.is_finished() {
                        info!(?instance_id, "Defer timeout, using current connection");
                        break connection;
                    }
                    // We don't defer connection if it's the first endpoint from the pecking order
                    if instance_id == 0 {
                        info!("Using best connection");
                        break connection;
                    }
                    info!("Deferring connection {}", instance_id);
                    non_preferred_connections.push((instance_id, connection));
                } else {
                    warn!(?instance_id, "Cannot find LightwayConnection");
                }
            },

            (instance_id, outside_io_result) = first_outside_io_exit(&mut pending_online_connections) => {
                // outside_io_task should not early return here, we're not going to use this connection anyway, removing it for clean-up
                let connection = pending_online_connections.remove(&instance_id);
                if let Some(connection) = connection {
                    let _ = connection.conn.lock().unwrap().disconnect();
                    drop(connection);
                }
                match outside_io_result {
                    Ok(Err(e)) if matches!(e.downcast_ref::<ConnectionError>(), Some(ConnectionError::Unauthorized)) => {
                        error!(?instance_id, "Unauthorized connection");
                        connection_error_to_return = Some(ConnectionError::Unauthorized.into());
                    }
                    _ => error!(?instance_id, "Unexpected outside_io_task early exit: {:?}", outside_io_result),
                }
                failed_connections += 1;
            }
        }
    };

    // Drop the receiver so that no more connections can be active
    drop(online_signal);

    debug!(?active_connection.instance_id, "Using connection");
    if let Err(e) = connected_index.set(active_connection.instance_id) {
        warn!(
            "Connection index has been set already, should only be called once: {}",
            e
        );
    }

    external_event_handler.handle_status_change(State::Online as u8);

    non_preferred_connections.extend(pending_online_connections.drain());
    drop(pending_online_connections);

    let _ = in_progress_connection_abort_handles.swap_remove(active_connection.instance_id);
    tokio::spawn(cleanup_connections(
        in_progress_connection_abort_handles,
        non_preferred_connections
            .into_iter()
            .map(|(_, connection)| connection)
            .collect(),
    ));

    let LightwayConnection {
        conn,
        outside_io_task,
        new_outside_io_sender,
        keepalive,
        keepalive_task,
        keepalive_config,
        expresslane_event_rx,
        ..
    } = active_connection;

    // We are online listen for network changes
    let network_change_task = tokio::spawn(handle_network_change(
        keepalive.clone(),
        network_change_receiver,
        Arc::downgrade(&conn),
        new_outside_io_sender,
    ));

    if let Some(mut expresslane_event_rx) = expresslane_event_rx {
        // We only process Expresslane state changes after we selected the best connection
        tokio::spawn(async move {
            while let Some(state) = expresslane_event_rx.recv().await {
                debug!(?state, "Expresslane State Change");
                external_event_handler.handle_expresslane_state_change(state);
            }
        });
    }

    conn.lock().unwrap().app_state_mut().extended = Some(inside_io.clone());
    let inside_io_loop: JoinHandle<uniffi::Result<()>> = tokio::spawn(inside_io_task(
        conn.clone(),
        inside_io,
        user_settings.dns_ip(),
        keepalive,
        keepalive_config,
    ));

    tokio::select! {
        // Use biased selection to prioritize management commands and prevent race conditions
        // where network_change_task exits early due to network change, dropping its mpsc sender and
        // causing outside_io_task to throw channel errors and return wrong result to the app.
        biased;
        result = network_change_task => {
            match result {
                Ok(Ok(client_result)) => {
                    info!("network change task result: {client_result:?}");
                    Ok(client_result.into())
                },
                Ok(Err(e)) => {
                    Err(anyhow!("error during network change: {e:?}"))
                }
                Err(e) => {
                    Err(anyhow!("network change task error: {e:?}"))
                }
            }
        }
        Some(_) = keepalive_task => Err(anyhow!("Keepalive timeout")),
        io = outside_io_task => match io {
                Ok(Err(e)) if matches!(e.downcast_ref::<ConnectionError>(), Some(ConnectionError::Goodbye)) => {
                    info!("Received server goodbye, returning result...");
                    Ok(ClientResult::ServerGoodbye)
                }
                _ => Err(anyhow!("Outside IO loop exited: {io:?}"))
        },
        io = inside_io_loop => Err(anyhow!("Inside IO loop exited: {io:?}")),
    }
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
    external_event_handler: Arc<dyn RustEventHandlers>,
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
                        let socket = OutsideSocket::new(false, None)?;
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

fn first_outside_io_exit(
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

async fn cleanup_connections(
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

struct LightwayConnection {
    conn: Arc<Mutex<Connection<ConnectionState<TunnelState>>>>,
    outside_io_task: JoinHandle<uniffi::Result<()>>,
    new_outside_io_sender: MpscSender<()>,
    keepalive: Keepalive,
    keepalive_task: OptionFuture<JoinHandle<KeepaliveResult>>,
    keepalive_config: KeepaliveConfig,
    join_set: JoinSet<()>,
    instance_id: usize,
    expresslane_event_rx: Option<MpscReceiver<ExpresslaneState>>,
}

struct LightwayClientConnectArgs {
    instance_id: usize,
    endpoint: RustEndpointConfig,
    sni_header: String,
    socket: Option<OutsideSocket>,
    enable_keepalive: bool,
    enable_expresslane: bool,
    online_signal_sender: tokio::sync::mpsc::Sender<usize>,
    event_stream_handler: EventStreamCallback,
    external_event_handler: Arc<dyn RustEventHandlers>,
}

/// Individual connection to a lightway server
async fn lightway_client_connect(
    args: LightwayClientConnectArgs,
) -> uniffi::Result<LightwayConnection> {
    let mut join_set = JoinSet::new();

    // TODO: Should be strong type error
    let socket = args.socket.ok_or(anyhow!("socket not provided"))?;

    let auth = match (
        args.endpoint.auth_token,
        args.endpoint.username,
        args.endpoint.password,
    ) {
        (Some(token), _, _) => lightway_core::AuthMethod::Token { token },
        (None, Some(user), Some(password)) => {
            lightway_core::AuthMethod::UserPass { user, password }
        }
        // TODO: Should be strong type error
        _ => return Err(anyhow!("Insufficient Authentication for config")),
    };

    let inside_plugins = PluginFactoryList::new();

    let mut outside_plugins = PluginFactoryList::new();

    let server_sockaddr = SocketAddr::from((args.endpoint.server_ip.clone(), args.endpoint.port));

    let (connection_type, outside_io): (ConnectionType, Arc<dyn OutsideIO>) = {
        let builder = OutsideIOBuilder::new(socket, server_sockaddr);
        builder.build(&mut outside_plugins).await?
    };

    let root_ca_cert = RootCertificate::PemBuffer(args.endpoint.ca_cert.as_bytes());

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
    let cipher = match args.endpoint.use_cha_cha_20 {
        true => Cipher::Chacha20,
        false => Cipher::Aes256,
    };

    let conn_builder = ClientContextBuilder::new(
        connection_type,
        root_ca_cert,
        Some(inside_io),
        Arc::new(ClientIpConfigCb),
        connection_ticker_cb,
    )?
    .with_cipher(cipher)?
    .with_inside_plugins(inside_plugins)
    .with_outside_plugins(outside_plugins)
    .when(
        connection_type.is_datagram() && args.enable_expresslane,
        |b| b.with_expresslane(),
    )
    .build()
    .start_connect(
        outside_io.clone().into_io_send_callback(),
        args.endpoint.outside_mtu as usize,
    )?
    .with_auth(auth)
    .with_event_cb(Box::new(event_cb))
    .when(!args.endpoint.server_dn.is_empty(), |b| {
        b.with_server_domain_name_validation(args.endpoint.server_dn.clone())
    })
    .when(!args.sni_header.is_empty(), |b| {
        b.with_sni_header(&args.sni_header)
    })
    .when(connection_type.is_datagram() && ENABLE_PMTUD, |b| {
        b.with_pmtud_timer(pmtud_timer)
    });

    #[cfg(feature = "postquantum")]
    let conn_builder = conn_builder.when(true, |b| {
        b.with_pq_crypto(lightway_app_utils::args::KeyShare::default().into())
    });

    let conn = Arc::new(Mutex::new(conn_builder.connect(state)?));

    let keepalive_config = KeepaliveConfig {
        interval: Duration::new(2, 0),
        timeout: Duration::new(6, 0),
        continuous: args.enable_keepalive,
        tracer_trigger_timeout: Some(Duration::from_secs(10)),
    };
    let (keepalive, keepalive_task) =
        Keepalive::new(keepalive_config.clone(), Arc::downgrade(&conn));

    let notify_keepalive_reply = Arc::new(Notify::new());
    let (expresslane_event_tx, expresslane_event_rx) =
        if args.enable_expresslane && !args.endpoint.use_tcp {
            Some(tokio::sync::mpsc::channel(5))
        } else {
            None
        }
        .unzip();

    join_set.spawn(handle_events(
        event_stream,
        keepalive.clone(),
        notify_keepalive_reply.clone(),
        Arc::downgrade(&conn),
        args.event_stream_handler,
        args.online_signal_sender.clone(),
        args.instance_id,
        expresslane_event_tx,
    ));

    ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);
    pmtud_timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

    let (new_outside_io_sender, new_outside_io_receiver) = tokio::sync::mpsc::channel(1);
    let outside_io_task: JoinHandle<uniffi::Result<()>> = tokio::spawn(
        restartable_outside_io_task(
            conn.clone(),
            OutsideIOConfig {
                mtu: args.endpoint.outside_mtu as usize,
                connection_type,
                outside_io,
            },
            keepalive.clone(),
            notify_keepalive_reply,
            new_outside_io_receiver,
            args.external_event_handler,
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
        instance_id: args.instance_id,
        expresslane_event_rx,
    })
}

/// This event handler is used to advertise State changes and First Packet Received event to mobile application
///
/// Only `Connecting`, `LinkUp`, and `Authenticating` are advertised from this handler. The mobile
/// app can ignore the status if it wasn't supported. Plus, we will return the disconnection result to the client now
/// so once the client has disconnected from the server, the mobile app would instantly know it has disconnected.
/// `Online` state is advertised from `async_lightway_start` since we are waiting for parallel connect to finish.
/// Only the first FirstPacketReceived event is advertised to mobile application
/// since only the first one makes sense.
async fn handle_global_events(
    mut stream: EventStream,
    connection_start_time: Instant,
    event_handler: Arc<dyn RustEventHandlers>,
) {
    let mut current_state = State::Connecting;
    let mut is_first_packet_received = false;

    while let Some(event) = stream.next().await {
        match event {
            Event::StateChanged(state) => {
                let allowed_states: &[State] = match current_state {
                    State::Connecting => &[State::LinkUp, State::Authenticating, State::Online],
                    State::LinkUp => &[State::Authenticating, State::Online],
                    State::Authenticating => &[],
                    State::Online => &[],
                    State::Disconnecting => &[],
                    State::Disconnected => &[],
                };

                if allowed_states.contains(&state) {
                    if !matches!(state, State::Online) {
                        event_handler.handle_status_change(state as u8);
                    }
                    current_state = state;
                }
            }
            Event::FirstPacketReceived if !is_first_packet_received => {
                info!("First packet received");
                let elapsed_ms = connection_start_time.elapsed().as_millis();
                // UniFFI does not support u128 types in its interface bindings.
                // In the unlikely event that connection time exceeds u64::MAX ms,
                // we clamp to u64::MAX rather than panic.
                let time_to_receive_first_packet_in_ms =
                    u64::try_from(elapsed_ms).unwrap_or(u64::MAX);
                event_handler.received_first_packet(time_to_receive_first_packet_in_ms);
                is_first_packet_received = true;
            }
            Event::EncodingStateChanged { enabled } => {
                info!("Encoding state changed to {enabled}");
                event_handler.handle_inside_pkt_codec_status_change(enabled);
            }
            _ => (),
        }
    }
}

/// Event handler for individual parallel connections
#[allow(clippy::too_many_arguments)]
async fn handle_events<A: 'static + Send + EventCallback>(
    mut stream: EventStream,
    keepalive: Keepalive,
    notify_keepalive_reply: Arc<Notify>,
    weak: Weak<Mutex<Connection<ConnectionState<TunnelState>>>>,
    mut event_handler: A,
    online_signal: tokio::sync::mpsc::Sender<usize>,
    instance_id: usize,
    expresslane_event_tx: Option<MpscSender<ExpresslaneState>>,
) {
    while let Some(event) = stream.next().await {
        match &event {
            Event::StateChanged(state) => {
                if matches!(state, State::Online) {
                    let _ = online_signal.send(instance_id).await;
                    keepalive.online().await;

                    let Some(_conn) = weak.upgrade() else {
                        break; // Connection disconnected.
                    };
                }
            }
            Event::KeepaliveReply => {
                notify_keepalive_reply.notify_waiters();
                keepalive.reply_received().await
            }
            Event::ExpresslaneStateChanged(state) => {
                if let Some(tx) = expresslane_event_tx.as_ref()
                    && let Ok(state) = (*state).try_into()
                {
                    if let Err(e) = tx.try_send(state) {
                        warn!("Unable to send Expresslane state change event: {:?}", e);
                    }
                }
                continue;
            }
            Event::FirstPacketReceived | Event::EncodingStateChanged { .. } => (), // will be handled by handle_global_events

            // Server-only events
            Event::SessionIdRotationAcknowledged { .. }
            | Event::TlsKeysUpdateStart
            | Event::TlsKeysUpdateCompleted
            | Event::SessionIdRotationStarted { .. } => {
                unreachable!("server only event received");
            }
        }
        event_handler.event(event);
    }
}

/// Handle all the network changes on the device.
async fn handle_network_change(
    keepalive: Keepalive,
    mut network_change_receiver: MpscReceiver<DeviceNetworkState>,
    weak: Weak<Mutex<Connection<ConnectionState<TunnelState>>>>,
    #[cfg_attr(not(apple), allow(unused_variables))] reset_outside_io_tx: MpscSender<()>,
) -> uniffi::Result<ClientResult> {
    while let Some(network_state) = network_change_receiver.recv().await {
        let Some(conn) = weak.upgrade() else {
            return Ok(ClientResult::UserDisconnect);
        };
        let conn_type = conn.lock().unwrap().connection_type();
        info!("Device network state change to {network_state:?}");
        match network_state {
            DeviceNetworkState::Online | DeviceNetworkState::InterfaceChanged => {
                match conn_type {
                    ConnectionType::Datagram => {
                        // We only need to use reset new socket on iOS but not on Android
                        #[cfg(apple)]
                        {
                            // Reset UDP transport when the network changes. This will ensure the udp traffic is routed
                            // via the new network path and avoid using mobile data unnecessarily.
                            info!("resetting udp transport due to network change ..");
                            reset_outside_io_tx.send(()).await?;
                        }
                        #[cfg(not(apple))]
                        // Trigger a new keepalive on the new socket (keepalive will
                        // be triggered after the socket has been updated on iOS)
                        keepalive.network_changed().await;
                    }
                    ConnectionType::Stream => {
                        info!("client shutting down due to network change ..");
                        let _ = conn.lock().unwrap().disconnect();
                        return Ok(ClientResult::NetworkChange);
                    }
                }
            }
            DeviceNetworkState::RouteUpdated => {
                match conn_type {
                    ConnectionType::Datagram => {
                        // UDP survives updating the network, but to ensure that the new network
                        // with the current endpoint works reliably, we trigger keep-alives
                        // e.g swapping from an unrestricted network to one that blocks UDP
                        info!("sending keepalives due to network change ..");
                        keepalive.network_changed().await;
                    }
                    ConnectionType::Stream => {
                        info!("client shutting down due to network change ..");
                        let _ = conn.lock().unwrap().disconnect();
                        return Ok(ClientResult::NetworkChange);
                    }
                }
            }
            DeviceNetworkState::Offline => {
                // Suspend keepalive timers as we're guaranteed
                // to fail and disconnect after all failed attempts
                info!("suspending keepalive...");
                keepalive.suspend().await;
            }
        }
    }
    Ok(ClientResult::UserDisconnect)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mobile::MockRustEventHandlers;
    use mockall::Sequence;
    use mockall::predicate::eq;

    #[tokio::test]
    async fn test_handle_global_events() {
        let (mut sender, receiver) = EventStreamCallback::new();
        let instant = Instant::now();
        tokio::spawn(async move {
            sender.event(Event::StateChanged(State::Connecting));
            sender.event(Event::StateChanged(State::LinkUp));
            sender.event(Event::StateChanged(State::Authenticating));
            sender.event(Event::StateChanged(State::Online));
        });

        // Make sure we don't advertise Online state in this function
        let mut seq = Sequence::new();
        let mut mock_event_handler = MockRustEventHandlers::new();
        mock_event_handler
            .expect_handle_status_change()
            .times(1)
            .in_sequence(&mut seq)
            .with(eq(State::LinkUp as u8))
            .return_const(());
        mock_event_handler
            .expect_handle_status_change()
            .times(1)
            .in_sequence(&mut seq)
            .with(eq(State::Authenticating as u8))
            .return_const(());
        mock_event_handler
            .expect_handle_status_change()
            .times(0)
            .with(eq(State::Online as u8))
            .return_const(());
        handle_global_events(receiver, instant, Arc::new(mock_event_handler)).await;
    }

    #[tokio::test]
    async fn test_handle_global_events_invalid_state_sequence() {
        let (mut sender, receiver) = EventStreamCallback::new();
        let instant = Instant::now();

        tokio::spawn(async move {
            sender.event(Event::StateChanged(State::Online));
            sender.event(Event::StateChanged(State::LinkUp));
            sender.event(Event::StateChanged(State::Authenticating));
            sender.event(Event::StateChanged(State::Disconnecting));
            sender.event(Event::StateChanged(State::Disconnected));
        });

        let mut mock_event_handler = MockRustEventHandlers::new();
        mock_event_handler
            .expect_handle_status_change()
            .times(0)
            .return_const(());
        handle_global_events(receiver, instant, Arc::new(mock_event_handler)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_handle_global_events_first_packet_received_only_send_once() {
        let (mut sender, receiver) = EventStreamCallback::new();
        let instant = Instant::now();

        tokio::spawn(async move {
            tokio::time::advance(Duration::from_millis(174)).await;
            sender.event(Event::FirstPacketReceived);
            sender.event(Event::FirstPacketReceived);
            sender.event(Event::FirstPacketReceived);
        });

        let mut mock_event_handler = MockRustEventHandlers::new();
        mock_event_handler
            .expect_received_first_packet()
            .with(eq(174u64))
            .times(1)
            .return_const(());
        handle_global_events(receiver, instant, Arc::new(mock_event_handler)).await;
    }

    #[tokio::test]
    async fn test_outside_socket_new_calls_created_outside_fd() {
        // Test TCP socket creation
        let mut mock_event_handler = MockRustEventHandlers::new();

        mock_event_handler
            .expect_created_outside_fd()
            .times(1)
            .return_const(());

        let tcp_result = OutsideSocket::new(true, Some(Arc::new(mock_event_handler)));
        assert!(tcp_result.is_ok());

        // Test UDP socket creation
        let mut mock_event_handler = MockRustEventHandlers::new();

        mock_event_handler
            .expect_created_outside_fd()
            .times(1)
            .return_const(());

        let udp_result = OutsideSocket::new(false, Some(Arc::new(mock_event_handler)));
        assert!(udp_result.is_ok());
    }
}
