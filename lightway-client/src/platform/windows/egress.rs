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
use std::net::{IpAddr, SocketAddr};
use std::os::windows::io::RawSocket;

use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterfaceEx;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IP_UNICAST_IF, IPPROTO_IP,
    IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKET,
    SOCKET_ERROR, setsockopt,
};

/// The interface index Windows would currently use to reach `dst`.
pub fn best_interface_index(dst: IpAddr) -> io::Result<u32> {
    // Storage for whichever sockaddr flavour is needed; declared here so it
    // outlives the call the raw pointer is handed to.
    let v4_addr;
    let v6_addr;

    let addr: *const SOCKADDR = match dst {
        IpAddr::V4(ip) => {
            v4_addr = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    // `S_addr` holds the address in network byte order, which
                    // is the in-memory order of `octets()`.
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                sin_zero: [0; 8],
            };
            (&raw const v4_addr).cast()
        }
        IpAddr::V6(ip) => {
            v6_addr = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: ip.octets() },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            };
            (&raw const v6_addr).cast()
        }
    };

    let mut if_index: u32 = 0;

    #[allow(unsafe_code)]
    // SAFETY: `addr` points at a fully initialised sockaddr of the family
    // named in its `sa_family` field, owned by this frame and live for the
    // whole call. `GetBestInterfaceEx` only reads through it, and writes the
    // result through the exclusive `&mut if_index` borrow.
    let result = unsafe { GetBestInterfaceEx(addr, &mut if_index) };

    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(if_index)
}

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

/// Pin `socket` to the interface currently used to reach `peer`.
///
/// Returns the interface index that was pinned.
pub fn pin_to_peer_interface(socket: RawSocket, peer: SocketAddr) -> io::Result<u32> {
    let if_index = best_interface_index(peer.ip())?;
    set_unicast_if(socket, if_index, peer.is_ipv6())?;
    Ok(if_index)
}
