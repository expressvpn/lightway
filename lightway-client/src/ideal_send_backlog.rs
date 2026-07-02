//! Windows TCP Ideal Send Backlog (ISB) monitoring.
//!
//! The Windows TCP stack continuously estimates the connection's
//! bandwidth-delay product and exposes it as the "ideal send backlog":
//! the amount of data an application should keep outstanding to
//! saturate the connection. We poll it periodically and use it as the
//! byte capacity of the connection's pending send queue, giving frames
//! headroom to queue above the socket send buffer without bufferbloat.

use std::os::windows::io::RawSocket;
use std::sync::{Mutex, Weak};
use std::time::Duration;

use lightway_core::Connection;
use tracing::{debug, warn};

use crate::ConnectionState;
use crate::io::outside::OutsideIO;

const ISB_POLL_INTERVAL: Duration = Duration::from_secs(5);

// Not exported by windows-sys. ws2tcpip.h defines it as
// _IOR('t', 123, ULONG) which expands to this value.
const SIO_IDEAL_SEND_BACKLOG_QUERY: u32 = 0x4004747B;

fn query_ideal_send_backlog(socket: RawSocket) -> std::io::Result<u32> {
    use windows_sys::Win32::Networking::WinSock::{SOCKET_ERROR, WSAIoctl};

    let mut isb: u32 = 0;
    let mut bytes_returned: u32 = 0;
    // SAFETY: `isb` and `bytes_returned` are live for the duration of the
    // call; no input buffer and no overlapped I/O are used.
    let ret = unsafe {
        WSAIoctl(
            socket as usize,
            SIO_IDEAL_SEND_BACKLOG_QUERY,
            std::ptr::null(),
            0,
            &mut isb as *mut u32 as *mut _,
            std::mem::size_of::<u32>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if ret == SOCKET_ERROR {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(isb)
    }
}

/// Periodically query the kernel's ideal send backlog for the outside
/// TCP socket and apply it as the connection's pending send queue
/// capacity. Exits when the connection is dropped or the query fails.
pub(crate) async fn monitor_task<ExtAppState: 'static + Send + Sync>(
    weak: Weak<Mutex<Connection<ConnectionState<ExtAppState>>>>,
    outside_io: std::sync::Arc<dyn OutsideIO>,
) {
    let mut interval = tokio::time::interval(ISB_POLL_INTERVAL);
    let mut last_isb = 0u32;
    loop {
        interval.tick().await;
        let Some(conn) = weak.upgrade() else {
            return;
        };
        match query_ideal_send_backlog(outside_io.socket().raw_handle()) {
            Ok(isb) => {
                if isb != last_isb {
                    debug!(isb, "ideal send backlog changed");
                    last_isb = isb;
                }
                conn.lock()
                    .unwrap()
                    .set_pending_send_queue_capacity(isb as usize);
            }
            Err(err) => {
                warn!(%err, "Failed to query ideal send backlog, stopping ISB monitor");
                return;
            }
        }
    }
}
