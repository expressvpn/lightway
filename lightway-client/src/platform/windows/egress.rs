//! Pin the outside socket to the physical egress interface.
//!
//! Windows use `IP_UNICAST_IF` / `IPV6_UNICAST_IF` to constrain the
//! route lookup for a socket to a single interface.
//!
//! Pinning makes egress selection independent of the routing table, so a
//! missing or stale host route can no longer divert outside traffic into the
//! tunnel. The interface index does not change when an adapter roams between
//! access points, so the pin survives exactly the event that breaks the route.

use std::io;
use std::os::windows::io::RawSocket;

use windows_sys::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, SOCKET_ERROR, setsockopt,
};

/// Constrain `socket`'s egress to interface `if_index`.
pub fn set_unicast_if(socket: RawSocket, if_index: u32, ipv6: bool) -> io::Result<()> {
    let (level, optname, value) = if ipv6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, if_index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, if_index.to_be())
    };

    #[allow(unsafe_code)]
    // SAFETY: `value` is a live `u32` and `optlen` matches its size, so
    // `setsockopt` reads exactly the bytes it is told about. The socket handle
    // is owned by the caller and valid for the duration of the call.
    let result = unsafe {
        setsockopt(
            socket as SOCKET,
            level,
            optname,
            (&raw const value).cast::<u8>(),
            size_of::<u32>() as i32,
        )
    };

    if result == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
