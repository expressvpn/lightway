use std::{io, net::SocketAddr};

/// Convert from `libc::sockaddr_storage` to `std::net::SocketAddr`
#[allow(unsafe_code)]
pub fn socket_addr_from_sockaddr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid argument (inet len)",
                ));
            }

            // SAFETY: Casting from sockaddr_storage to sockaddr_in is safe since we have validated the len.
            let addr =
                unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };

            let ip = u32::from_be(addr.sin_addr.s_addr);
            let ip = std::net::Ipv4Addr::from_bits(ip);
            let port = u16::from_be(addr.sin_port);

            Ok((ip, port).into())
        }
        libc::AF_INET6 => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid argument (inet6 len)",
                ));
            }
            // SAFETY: Casting from sockaddr_storage to sockaddr_in6 is safe since we have validated the len.
            let addr = unsafe {
                &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6)
            };

            let ip = u128::from_be_bytes(addr.sin6_addr.s6_addr);
            let ip = std::net::Ipv6Addr::from_bits(ip);
            let port = u16::from_be(addr.sin6_port);

            Ok((ip, port).into())
        }
        _ => Err(io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid argument (ss_family)",
        )),
    }
}

/// Convert from `std::net::SocketAddr` to `libc::sockaddr_storage`+`libc::socklen_t`
#[allow(unsafe_code)]
pub fn sockaddr_from_socket_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: All zeroes is a valid sockaddr_storage
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    let len = match addr {
        SocketAddr::V4(v4) => {
            let p = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in;
            // SAFETY: sockaddr_storage is defined to be big enough for any sockaddr_*.
            unsafe {
                p.write(libc::sockaddr_in {
                    sin_family: libc::AF_INET as _,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: v4.ip().to_bits().to_be(),
                    },
                    sin_zero: Default::default(),
                })
            };
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let p = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6;
            // SAFETY: sockaddr_storage is defined to be big enough for any sockaddr_*.
            unsafe {
                p.write(libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as _,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo().to_be(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.ip().to_bits().to_be_bytes(),
                    },
                    sin6_scope_id: v6.scope_id().to_be(),
                })
            };
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };

    (storage, len)
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code, clippy::undocumented_unsafe_blocks)]

    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr as _,
    };

    use super::*;

    use test_case::test_case;

    #[test]
    fn socket_addr_from_sockaddr_unknown_af() {
        // Test assumes these don't match the zero initialized
        // libc::sockaddr_storage::ss_family.
        assert_ne!(libc::AF_INET, 0);
        assert_ne!(libc::AF_INET6, 0);

        let storage = unsafe { std::mem::zeroed() };
        let err =
            socket_addr_from_sockaddr(&storage, std::mem::size_of::<libc::sockaddr_storage>() as _)
                .unwrap_err();

        assert!(matches!(err.kind(), std::io::ErrorKind::InvalidInput));
        assert!(err.to_string().contains("invalid argument (ss_family)"));
    }

    #[test]
    fn socket_addr_from_sockaddr_unknown_af_inet_short() {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        storage.ss_family = libc::AF_INET as libc::sa_family_t;

        let err = socket_addr_from_sockaddr(
            &storage,
            (std::mem::size_of::<libc::sockaddr_in>() - 1) as _,
        )
        .unwrap_err();

        assert!(matches!(err.kind(), std::io::ErrorKind::InvalidInput));
        assert!(err.to_string().contains("invalid argument (inet len)"));
    }

    #[test]
    fn socket_addr_from_sockaddr_unknown_af_inet6_short() {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        storage.ss_family = libc::AF_INET6 as libc::sa_family_t;

        let err = socket_addr_from_sockaddr(
            &storage,
            (std::mem::size_of::<libc::sockaddr_in6>() - 1) as _,
        )
        .unwrap_err();

        assert!(matches!(err.kind(), std::io::ErrorKind::InvalidInput));
        assert!(err.to_string().contains("invalid argument (inet6 len)"));
    }

    #[test]
    fn sockaddr_from_socket_addr_inet() {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let (storage, len) = sockaddr_from_socket_addr(socket_addr);
        assert_eq!(storage.ss_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(len as usize, std::mem::size_of::<libc::sockaddr_in>());
    }

    #[test]
    fn sockaddr_from_socket_addr_inet6() {
        let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080);
        let (storage, len) = sockaddr_from_socket_addr(socket_addr);
        assert_eq!(storage.ss_family, libc::AF_INET6 as libc::sa_family_t);
        assert_eq!(len as usize, std::mem::size_of::<libc::sockaddr_in6>());
    }

    #[test_case("127.0.0.1:443")]
    #[test_case("[::1]:8888")]
    fn round_trip(addr: &str) {
        let orig = SocketAddr::from_str(addr).unwrap();
        let (storage, len) = sockaddr_from_socket_addr(orig);
        let round_tripped = socket_addr_from_sockaddr(&storage, len).unwrap();
        assert_eq!(orig, round_tripped)
    }
}
