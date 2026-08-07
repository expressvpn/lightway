//! Dissolve a UDP socket's peer association (Apple platforms).
#![allow(unsafe_code)]

use std::io;
use std::os::fd::AsRawFd;

/// Dissolve the peer association of a `connect()`-ed UDP socket.
///
/// After this call the socket can be used with `send_to` again (`send_to` on a
/// connected socket fails with `EISCONN`), and the implicitly bound local
/// address is cleared, so the kernel re-selects the route and source address
/// per packet. The local port is retained.
///
/// Dissolving an already-unconnected socket reports `ENOTCONN`.
pub fn udp_disconnect(sock: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: `disconnectx` performs no memory access through its arguments;
    // the fd is valid for the lifetime of `sock` and the wildcard association /
    // connection ids are documented constants.
    let rc = unsafe {
        libc::disconnectx(
            sock.as_raw_fd(),
            libc::SAE_ASSOCID_ANY,
            libc::SAE_CONNID_ANY,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
