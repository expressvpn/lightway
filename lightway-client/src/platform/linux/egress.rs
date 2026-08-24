//! Pin the outside socket to the physical egress interface.
//!
//! Linux supports `IP_UNICAST_IF` / `IPV6_UNICAST_IF` to constrain a socket's
//! egress to a single interface, preventing the tunnel's own routes from
//! capturing outside traffic after they are installed.

use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;

/// Constrain `socket`'s egress to interface `if_index`.
pub fn set_unicast_if(fd: RawFd, if_index: u32, ipv6: bool) -> io::Result<()> {
    // IP_UNICAST_IF on Linux applies ntohl() to the value internally, so the
    // index must be supplied in network byte order (big-endian). IPV6_UNICAST_IF
    // stores the value directly and therefore uses host byte order.
    let idx = if ipv6 {
        if_index as libc::c_uint
    } else {
        (if_index as libc::c_uint).to_be()
    };
    let result = if ipv6 {
        #[allow(unsafe_code)]
        // SAFETY: `idx` is a live `c_uint` and `optlen` matches its size, so
        // `setsockopt` reads exactly the bytes it is told about. The file
        // descriptor is valid for the duration of the call.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_IF,
                (&raw const idx).cast::<libc::c_void>(),
                size_of::<libc::c_uint>() as libc::socklen_t,
            )
        }
    } else {
        #[allow(unsafe_code)]
        // SAFETY: same as above; `idx` is already in network byte order (see
        // above) and `optlen` matches its size.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_UNICAST_IF,
                (&raw const idx).cast::<libc::c_void>(),
                size_of::<libc::c_uint>() as libc::socklen_t,
            )
        }
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Pin `socket` to the interface currently used to reach `peer`.
///
/// Returns the interface index that was pinned.
pub fn pin_to_peer_interface(fd: RawFd, peer: SocketAddr) -> io::Result<u32> {
    let if_index = best_interface_index(peer.ip())?;
    set_unicast_if(fd, if_index, peer.is_ipv6())?;
    Ok(if_index)
}

/// The interface index the kernel would currently use to reach `dst`.
///
/// Connects a throw-away `SOCK_DGRAM` socket to `dst`, which forces the
/// kernel to do a route lookup and assign a source address. Reading back the
/// source address identifies the interface, which is then mapped to an index
/// via `getifaddrs` + `if_nametoindex`.
fn best_interface_index(dst: IpAddr) -> io::Result<u32> {
    let family = match dst {
        IpAddr::V4(_) => libc::AF_INET,
        IpAddr::V6(_) => libc::AF_INET6,
    };

    #[allow(unsafe_code)]
    // SAFETY: All three arguments are valid constants; the returned fd is
    // either -1 (checked below) or a valid open socket descriptor.
    let sock = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    struct Guard(libc::c_int);
    impl Drop for Guard {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            // SAFETY: `self.0` is a valid open socket descriptor created
            // above; it has not been closed yet.
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let _guard = Guard(sock);

    match dst {
        IpAddr::V4(ip) => {
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 1u16.to_be(),
                sin_addr: libc::in_addr {
                    // `s_addr` is in network byte order; `from_ne_bytes` on the
                    // IP octets gives exactly that representation.
                    s_addr: u32::from_ne_bytes(ip.octets()),
                },
                sin_zero: [0; 8],
            };
            #[allow(unsafe_code)]
            // SAFETY: `addr` is a fully initialised `sockaddr_in` whose
            // `sin_family` matches the socket's address family; `addrlen`
            // matches its size. `connect` on a SOCK_DGRAM socket does not
            // establish a connection — it only records the peer address for
            // later sends and triggers a route lookup.
            let ret = unsafe {
                libc::connect(
                    sock,
                    (&raw const addr).cast(),
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        IpAddr::V6(ip) => {
            let addr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 1u16.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: ip.octets(),
                },
                sin6_scope_id: 0,
            };
            #[allow(unsafe_code)]
            // SAFETY: `addr` is a fully initialised `sockaddr_in6` matching
            // the socket's AF_INET6 family; `addrlen` matches its size.
            let ret = unsafe {
                libc::connect(
                    sock,
                    (&raw const addr).cast(),
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    #[allow(unsafe_code)]
    // SAFETY: `local` is stack-allocated storage large enough for any
    // sockaddr; `len` starts as its exact size and `getsockname` may reduce
    // it to the actual address length. The socket is open and valid.
    let mut local: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    #[allow(unsafe_code)]
    // SAFETY: `local` is a zeroed `sockaddr_storage` and `len` reflects its
    // true size; `getsockname` writes at most `*len` bytes through the pointer.
    let ret = unsafe { libc::getsockname(sock, (&raw mut local).cast(), &mut len) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let local_ip = sockaddr_storage_to_ip(&local)?;
    if_index_for_addr(local_ip)
}

fn sockaddr_storage_to_ip(addr: &libc::sockaddr_storage) -> io::Result<IpAddr> {
    match addr.ss_family as libc::c_int {
        libc::AF_INET => {
            #[allow(unsafe_code)]
            // SAFETY: `ss_family` is `AF_INET`, so the storage holds a valid
            // `sockaddr_in`. `transmute_copy` reads the first
            // `size_of::<sockaddr_in>()` bytes, which are always present since
            // `sockaddr_storage` is larger than `sockaddr_in`.
            let a: libc::sockaddr_in = unsafe { std::mem::transmute_copy(addr) };
            // `sin_addr.s_addr` is in network byte order; `from_be` converts
            // it to host order so `Ipv4Addr::from(u32)` works correctly.
            Ok(IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            #[allow(unsafe_code)]
            // SAFETY: `ss_family` is `AF_INET6`, so the storage holds a valid
            // `sockaddr_in6`. Same size argument as the AF_INET branch.
            let a: libc::sockaddr_in6 = unsafe { std::mem::transmute_copy(addr) };
            Ok(IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)))
        }
        f => Err(io::Error::other(format!("unexpected address family {f}"))),
    }
}

fn if_index_for_addr(addr: IpAddr) -> io::Result<u32> {
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
    #[allow(unsafe_code)]
    // SAFETY: `ifaddrs` is a valid out-pointer; `getifaddrs` allocates the
    // list and writes the head through it. The list must be freed with
    // `freeifaddrs`, handled by the `Guard` below.
    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return Err(io::Error::last_os_error());
    }

    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            // SAFETY: `self.0` is the head of a list returned by
            // `getifaddrs`; it is non-null and has not been freed yet.
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
    let _guard = Guard(ifaddrs);

    let mut cur = ifaddrs;
    while !cur.is_null() {
        #[allow(unsafe_code)]
        // SAFETY: `cur` is a non-null pointer into the linked list returned
        // by `getifaddrs`; the list is live for the duration of this function.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            #[allow(unsafe_code)]
            // SAFETY: `ifa_addr` is non-null and points at a valid sockaddr
            // whose first two bytes are the `sa_family` field.
            let family = unsafe { (*ifa.ifa_addr).sa_family } as libc::c_int;
            let matches = match (family, &addr) {
                (libc::AF_INET, IpAddr::V4(target)) => {
                    #[allow(unsafe_code)]
                    // SAFETY: `ifa_addr` is non-null (checked above) and
                    // valid for the lifetime of the `getifaddrs` list.
                    let ifa_addr_ref = unsafe { &*ifa.ifa_addr };
                    #[allow(unsafe_code)]
                    // SAFETY: `sa_family` is `AF_INET`, so `ifa_addr` points
                    // at a valid `sockaddr_in` whose size fits inside the
                    // allocation that `ifa_addr_ref` describes.
                    let sa: libc::sockaddr_in = unsafe { std::mem::transmute_copy(ifa_addr_ref) };
                    Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)) == *target
                }
                (libc::AF_INET6, IpAddr::V6(target)) => {
                    #[allow(unsafe_code)]
                    // SAFETY: `ifa_addr` is non-null (checked above) and
                    // valid for the lifetime of the `getifaddrs` list.
                    let ifa_addr_ref = unsafe { &*ifa.ifa_addr };
                    #[allow(unsafe_code)]
                    // SAFETY: `sa_family` is `AF_INET6`, so `ifa_addr` points
                    // at a valid `sockaddr_in6` whose size fits inside the
                    // allocation that `ifa_addr_ref` describes.
                    let sa: libc::sockaddr_in6 = unsafe { std::mem::transmute_copy(ifa_addr_ref) };
                    Ipv6Addr::from(sa.sin6_addr.s6_addr) == *target
                }
                _ => false,
            };
            if matches {
                #[allow(unsafe_code)]
                // SAFETY: `ifa_name` is a non-null NUL-terminated C string
                // whose lifetime is tied to the `getifaddrs` list.
                let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
                #[allow(unsafe_code)]
                // SAFETY: `name` is a valid NUL-terminated C string pointing
                // into the `getifaddrs` list which is still live.
                let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
                if idx != 0 {
                    return Ok(idx);
                }
            }
        }
        cur = ifa.ifa_next;
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no interface found for address {addr}"),
    ))
}
