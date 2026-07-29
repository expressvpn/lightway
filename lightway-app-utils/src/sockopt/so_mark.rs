//! `SO_MARK` support (Linux only).
//!
//! Packets sent from a marked socket carry a firewall mark, which lets policy
//! routing rules (`ip rule ... fwmark`) steer them independently of the routing
//! table used by ordinary traffic.
//!
//! This is what keeps a VPN client's *own* encrypted packets out of its own
//! tunnel. Without it, correctness depends on a host route to the server being
//! present at every instant; if that route is ever briefly missing -- for
//! example while the default route is being replaced after a network change --
//! the tunnel's outbound packets match the tunnel's own default route, get read
//! back off the tun device, re-encapsulated, and sent again. Each lap adds one
//! encapsulation header, so the packet grows until it exceeds the inside MTU and
//! the cycle restarts, saturating the link.
//!
//! A firewall mark removes the race entirely: the routing decision for the
//! tunnel's own traffic no longer depends on a route that can transiently
//! disappear.

use super::AsGenericHandle;

/// Set `SO_MARK` on a socket.
///
/// Requires `CAP_NET_ADMIN`.
///
/// Must be called before the socket sends anything, otherwise an early packet
/// can escape unmarked.
pub fn set_so_mark(sock: &impl AsGenericHandle, mark: u32) -> std::io::Result<()> {
    let value = mark as libc::c_uint;
    // SAFETY: `value` outlives the call and `optlen` matches its size.
    let ret = unsafe {
        libc::setsockopt(
            sock.as_generic_handle(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &value as *const libc::c_uint as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read back `SO_MARK`, for verifying the mark actually landed.
pub fn get_so_mark(sock: &impl AsGenericHandle) -> std::io::Result<u32> {
    let mut value: libc::c_uint = 0;
    let mut len = std::mem::size_of::<libc::c_uint>() as libc::socklen_t;
    // SAFETY: `value`/`len` are correctly sized for SO_MARK.
    let ret = unsafe {
        libc::getsockopt(
            sock.as_generic_handle(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mut value as *mut libc::c_uint as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(value as u32)
}
