//! Mobile mod of outside with external event handler

use std::sync::Arc;
use tracing::debug;

pub enum OutsideSocket {
    Tcp(tokio::net::TcpSocket),
    Udp(tokio::net::UdpSocket),
}

/// A warpper for outside scokets with hooks
impl OutsideSocket {
    pub fn new(
        use_tcp: bool,
        event_handler: Option<Arc<dyn crate::event_handlers::EventHandlers>>,
    ) -> uniffi::Result<Self> {
        use std::os::fd::AsRawFd;

        if use_tcp {
            let socket = tokio::net::TcpSocket::new_v4()?;
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
            Ok(OutsideSocket::Udp(tokio::net::UdpSocket::from_std(socket)?))
        }
    }
}
