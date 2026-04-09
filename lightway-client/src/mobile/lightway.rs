use crate::event_handlers::EventHandlers;
use crate::io::outside::OutsideIO;
use crate::keepalive::{Keepalive, KeepaliveResult};
use crate::state::ExpresslaneState;
use crate::{ConnectionState, io, keepalive::Config as KeepaliveConfig, outside_io_task};
use futures::future::{FutureExt, OptionFuture, select_all};
use lightway_app_utils::TunConfig;
use lightway_core::{
    Connection, ConnectionType, IOCallbackResult, InsideIOSendCallback, PluginFactoryList,
};
use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::Receiver as MpscReceiver;
use tokio::sync::mpsc::Sender as MpscSender;
use tokio::sync::{Notify, oneshot};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tracing::{debug, error, info, info_span};
use uniffi::deps::anyhow::{Context, bail};
use uniffi::deps::bytes::BytesMut;

/// Builder for creating OutsideIO connections with optional obfuscation and proxy
///
/// Handles both initial connections (which may need obfuscation and proxy) and network
/// changes (which don't need obfuscation or proxy).
pub struct OutsideIOBuilder {
    socket: crate::OutsideSocket,
    server_sockaddr: SocketAddr,
}

impl<'a> OutsideIOBuilder {
    pub fn new(socket: crate::OutsideSocket, server_sockaddr: SocketAddr) -> Self {
        Self {
            socket,
            server_sockaddr,
        }
    }

    pub async fn build(
        self,
        #[cfg_attr(not(apple), allow(unused_variables))] buffer_size: usize,
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
                    sock.set_send_buffer_size(buffer_size)?;
                    sock.set_recv_buffer_size(buffer_size)?;
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
pub(crate) struct MobileInsideIo {
    pub(crate) mtu: usize,
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

pub(crate) struct OutsideIOConfig {
    pub(crate) mtu: usize,
    pub(crate) connection_type: ConnectionType,
    pub(crate) outside_io: Arc<dyn OutsideIO>,
}

/// This function is responsible for running `outside_io_task` to handle outside packet.
/// It can restart the task with an updated ` outside_io ` upon receiving a new outside IO callback.
pub(crate) async fn restartable_outside_io_task(
    conn: Arc<Mutex<Connection<ConnectionState<TunnelState>>>>,
    outside_io_config: OutsideIOConfig,
    keepalive: Keepalive,
    notify_keepalive_reply: Arc<Notify>,
    mut new_outside_io_receiver: MpscReceiver<()>,
    external_event_handler: Arc<dyn EventHandlers>,
    max_socket_buffer_len: usize,
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
                            .build(max_socket_buffer_len, &mut outside_plugins)
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
