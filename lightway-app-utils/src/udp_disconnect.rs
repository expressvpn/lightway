//! Dissolve a UDP socket's peer association.
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
/// Dissolving an already-unconnected socket reports `ENOTCONN` (Apple).
/// On Linux, `connect(AF_UNSPEC)` is idempotent and always succeeds for UDP.
pub fn udp_disconnect(sock: &impl AsRawFd) -> io::Result<()> {
    #[cfg(apple)]
    {
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
    #[cfg(linux)]
    {
        use std::mem::size_of;
        // On Linux, connecting a UDP socket to AF_UNSPEC dissolves the peer
        // association — the kernel special-cases it in __udp_disconnect.
        // This is idempotent: calling it on an already-unconnected socket
        // also succeeds.
        let addr = libc::sockaddr {
            sa_family: libc::AF_UNSPEC as libc::sa_family_t,
            sa_data: [0; 14],
        };
        // SAFETY: `addr` is a fully initialised `sockaddr` with sa_family set
        // to AF_UNSPEC and all remaining bytes zeroed; `addrlen` matches its
        // size. The kernel's UDP layer recognises AF_UNSPEC and clears the
        // socket's peer association without dereferencing `addr` further.
        let rc = unsafe {
            libc::connect(
                sock.as_raw_fd(),
                (&raw const addr).cast(),
                size_of::<libc::sockaddr>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}
