#[cfg(feature = "mobile")]
pub mod mobile;
pub mod tcp;
pub mod udp;
#[cfg(batch_receive)]
mod udp_batch_receiver;

#[cfg(feature = "mobile")]
pub use mobile::OutsideSocket;
pub use tcp::Tcp;
pub use udp::Udp;

use anyhow::{Context, Result};
use async_trait::async_trait;
#[cfg(feature = "mobile")]
use lightway_core::Connection;
use lightway_core::{ConnectionType, IOCallbackResult, OutsideIOSendCallbackArg};
#[cfg(feature = "mobile")]
use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc};
#[cfg(not(feature = "mobile"))]
use tracing::error;

/// Maximum number of packets to receive in a single batch syscall.
#[cfg(batch_receive)]
pub const BATCH_RECV_SIZE: usize = 32;

#[async_trait]
pub trait OutsideIO: Sync + Send {
    fn set_send_buffer_size(&self, size: usize) -> Result<()>;
    fn set_recv_buffer_size(&self, size: usize) -> Result<()>;

    async fn poll(&self, interest: tokio::io::Interest) -> Result<tokio::io::Ready>;

    /// Receive a single packet into `buf`. Returns how many bytes were read.
    fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize>;

    /// Receive packets into `bufs`, filling up to `bufs.len()` entries.
    /// Returns how many buffers were actually written (always `>= 1` on `Ok`).
    ///
    /// The default implementation reads a single packet into `bufs[0]` and is
    /// appropriate for stream transports (e.g. TCP) or UDP without batch support.
    /// Transports with a native batch-receive syscall should override this.
    #[cfg(batch_receive)]
    fn recv_bufs(&self, bufs: &mut [bytes::BytesMut; BATCH_RECV_SIZE]) -> IOCallbackResult<usize> {
        match self.recv_buf(&mut bufs[0]) {
            IOCallbackResult::Ok(_size) => IOCallbackResult::Ok(1),
            others => others,
        }
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg;

    fn peer_addr(&self) -> SocketAddr;
}

#[cfg(not(feature = "mobile"))]
pub async fn build<EventHandler: 'static + Send + lightway_core::EventCallback>(
    server_config: &mut crate::ClientConnectionConfig<EventHandler>,
) -> Result<(ConnectionType, Arc<dyn OutsideIO>)> {
    match server_config.mode {
        crate::ClientConnectionMode::Datagram(ref mut maybe_sock) => {
            let sock = Udp::new(server_config.server, maybe_sock.take())
                .await
                .inspect_err(|e| error!("Failed to create outside IO UDP socket: {e}"))
                .context("Outside IO UDP")?;

            Ok((ConnectionType::Datagram, Arc::new(sock)))
        }
        crate::ClientConnectionMode::Stream(ref mut maybe_sock) => {
            let sock = Tcp::new(server_config.server, maybe_sock.take())
                .await
                .inspect_err(|e| error!("Failed to create outside IO TCP socket: {e}"))
                .context("Outside IO TCP")?;
            Ok((ConnectionType::Stream, Arc::new(sock)))
        }
    }
}

#[cfg(feature = "mobile")]
pub async fn build(
    socket: OutsideSocket,
    server_sockaddr: SocketAddr,
    #[cfg_attr(not(apple), allow(unused_variables))] buffer_size: usize,
    _plugins: &mut lightway_core::PluginFactoryList,
) -> Result<(ConnectionType, Arc<dyn OutsideIO>)> {
    match socket {
        OutsideSocket::Tcp(s) => {
            let stream = s.connect(server_sockaddr).await?;
            let sock = Tcp::new(server_sockaddr, Some(stream))
                .await
                .context("Outside IO TCP")?;
            Ok((ConnectionType::Stream, Arc::new(sock)))
        }
        OutsideSocket::Udp(s) => {
            let sock = Udp::new(server_sockaddr, Some(s))
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
    }
}

/// This function is responsible for running `outside_io_task` to handle outside packet.
/// It can restart the task with an updated ` outside_io` upon receiving a new outside IO callback.
#[cfg(feature = "mobile")]
pub async fn restartable_outside_io_task(
    conn: Arc<Mutex<Connection<crate::ConnectionState<crate::TunnelState>>>>,
    outside_mtu: usize,
    connection_type: ConnectionType,
    mut outside_io: Arc<dyn OutsideIO>,
    keepalive: crate::keepalive::Keepalive,
    notify_keepalive_reply: Arc<tokio::sync::Notify>,
    mut new_outside_io_receiver: tokio::sync::mpsc::Receiver<()>,
    external_event_handler: Arc<dyn crate::event_handlers::EventHandlers>,
    max_socket_buffer_len: usize,
) -> uniffi::Result<()> {
    let mut first_run = true;

    loop {
        let ready_tx = if first_run {
            first_run = false;
            None
        } else {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let keepalive = keepalive.clone();
            let keepalive_reply = notify_keepalive_reply.clone();
            let handler = external_event_handler.clone();
            tokio::spawn(async move {
                match rx.await {
                    Ok(_) => keepalive.network_changed().await,
                    Err(e) => {
                        tracing::error!("outside_io_task ready signal failed: {e:?}");
                        return;
                    }
                }
                keepalive_reply.notified().await;
                handler.connection_has_floated();
            });
            Some(tx)
        };

        tokio::select! {
            result = outside_io_task(conn.clone(), outside_mtu, connection_type, outside_io.clone(), keepalive.clone(), ready_tx) => return result,

            new_outside_io_result = new_outside_io_receiver.recv() => {
                match new_outside_io_result {
                    Some(_) => {
                        tracing::info!("Restarting outside_io_task with new socket");
                        let peer_addr = conn.lock().unwrap().peer_addr();
                        let socket = crate::io::outside::OutsideSocket::new(false, None)?;
                        let mut outside_plugins = lightway_core::PluginFactoryList::new();
                        let (_, new_socket) = crate::io::outside::build(socket, peer_addr, max_socket_buffer_len, &mut outside_plugins).await?;
                        let mut conn = conn.lock().unwrap();
                        outside_io = new_socket.clone();
                        conn.set_outside_io(new_socket.into_io_send_callback());
                        // Continue the loop to restart with a new socket
                    },
                    None => {
                        anyhow::bail!("Reset receiver closed")
                    }
                }
            }
        }
    }
}

/// An async function to handle all the outside traffic
/// You can pass in an optional oneshot channel to listen to when the socket is ready to read.
#[cfg(feature = "mobile")]
pub async fn outside_io_task<ExtAppState: Send + Sync>(
    conn: Arc<Mutex<Connection<crate::ConnectionState<ExtAppState>>>>,
    mtu: usize,
    connection_type: ConnectionType,
    outside_io: Arc<dyn OutsideIO>,
    keepalive: crate::Keepalive,
    mut ready_signal: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<()> {
    let mut buf = bytes::BytesMut::with_capacity(mtu);
    loop {
        // Recover full capacity
        buf.clear();
        buf.reserve(mtu);

        // Unrecoverable errors: https://github.com/tokio-rs/tokio/discussions/5552
        outside_io.poll(tokio::io::Interest::READABLE).await?;

        // Send ready signal after first successful poll
        if let Some(tx) = ready_signal.take() {
            let _ = tx.send(());
        }

        match outside_io.recv_buf(&mut buf) {
            IOCallbackResult::Ok(_nr) => {}
            IOCallbackResult::WouldBlock => continue, // Spuriously failed to read, keep waiting
            IOCallbackResult::Err(err) => {
                // Fatal error
                return Err(err.into());
            }
        };

        let pkt = lightway_core::OutsidePacket::Wire(&mut buf, connection_type);
        if let Err(err) = conn.lock().unwrap().outside_data_received(pkt) {
            if err.is_fatal(connection_type) {
                return Err(err.into());
            }
            tracing::error!("Failed to process outside data: {err}");
        }

        keepalive.outside_activity().await
    }
}
