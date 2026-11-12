#![allow(unsafe_code)]

use std::os::fd::AsRawFd;

/// Enable the `UDP_GRO` sockopt (Linux 5.0+).
///
/// The kernel then coalesces trains of equal-size datagrams from the
/// same flow into a single buffer per `recvmsg(2)`, reporting the
/// per-segment size via a `UDP_GRO` control message. Callers that
/// enable this MUST receive with control-message space and split on
/// the reported boundary — a plain `recv(2)` would silently merge
/// separate datagrams.
pub fn socket_enable_udp_gro(sock: &impl AsRawFd) -> std::io::Result<()> {
    // SAFETY: `setsockopt` requires a valid fd and a valid buffer of `c_int` size
    let res = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_GRO,
            &1 as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if res == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
