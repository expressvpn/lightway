//! Support for IP_MTU_DISCOVER sockopt
//!
//! In the absence of something like
//! <https://github.com/rust-lang/socket2/issues/487> we have to reach
//! for libc and unsafety.

use std::mem::MaybeUninit;

#[cfg(unix)]
use libc::socklen_t;

#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

// All Unix other than apple devices
#[cfg(all(not(apple), unix))]
mod internal {
    use libc::{IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_PMTUDISC_PROBE, IP_PMTUDISC_WANT};
    #[cfg(target_os = "linux")]
    use libc::{IP_PMTUDISC_INTERFACE, IP_PMTUDISC_OMIT};

    // IPV6_MTU_DISCOVER takes the same values as IP_MTU_DISCOVER, so one
    // conversion serves both options.
    const _: () = assert!(
        IP_PMTUDISC_DONT == libc::IPV6_PMTUDISC_DONT
            && IP_PMTUDISC_WANT == libc::IPV6_PMTUDISC_WANT
            && IP_PMTUDISC_DO == libc::IPV6_PMTUDISC_DO
            && IP_PMTUDISC_PROBE == libc::IPV6_PMTUDISC_PROBE
    );
    #[cfg(target_os = "linux")]
    const _: () = assert!(
        IP_PMTUDISC_INTERFACE == libc::IPV6_PMTUDISC_INTERFACE
            && IP_PMTUDISC_OMIT == libc::IPV6_PMTUDISC_OMIT
    );

    /// Enum to represent PMTUd values
    #[derive(Copy, Clone)]
    pub enum IpPmtudisc {
        /// Never send DF frames
        Dont,
        /// Use per route hints
        Want,
        /// Always DF
        Do,
        /// Ignore dst pmtu
        Probe,
        /// Ignore ICMP PMTU updates, does not support local fragmentation
        #[cfg(target_os = "linux")]
        Interface,
        /// Ignore ICMP PMTU updates, supports local fragmentation
        #[cfg(target_os = "linux")]
        Omit,
    }

    impl From<IpPmtudisc> for libc::c_int {
        fn from(value: IpPmtudisc) -> Self {
            match value {
                IpPmtudisc::Dont => IP_PMTUDISC_DONT,
                IpPmtudisc::Want => IP_PMTUDISC_WANT,
                IpPmtudisc::Do => IP_PMTUDISC_DO,
                IpPmtudisc::Probe => IP_PMTUDISC_PROBE,
                #[cfg(target_os = "linux")]
                IpPmtudisc::Interface => IP_PMTUDISC_INTERFACE,
                #[cfg(target_os = "linux")]
                IpPmtudisc::Omit => IP_PMTUDISC_OMIT,
            }
        }
    }

    impl TryFrom<libc::c_int> for IpPmtudisc {
        type Error = std::io::Error;

        fn try_from(value: libc::c_int) -> Result<Self, Self::Error> {
            match value {
                IP_PMTUDISC_DONT => Ok(IpPmtudisc::Dont),
                IP_PMTUDISC_WANT => Ok(IpPmtudisc::Want),
                IP_PMTUDISC_DO => Ok(IpPmtudisc::Do),
                IP_PMTUDISC_PROBE => Ok(IpPmtudisc::Probe),
                #[cfg(target_os = "linux")]
                IP_PMTUDISC_INTERFACE => Ok(IpPmtudisc::Interface),
                #[cfg(target_os = "linux")]
                IP_PMTUDISC_OMIT => Ok(IpPmtudisc::Omit),
                v => Err(std::io::Error::other(format!(
                    "unexpected value for IP_PMTUDISC: {:?}",
                    v
                ))),
            }
        }
    }
}

#[cfg(windows)]
mod internal {
    use windows_sys::Win32::Networking::WinSock::{
        IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_PMTUDISC_NOT_SET, IP_PMTUDISC_PROBE,
    };
    #[derive(Copy, Clone)]
    /// Enum to represent PMTUd values
    pub enum IpPmtudisc {
        /// Never send DF frames
        Dont,
        /// Always DF
        Do,
        /// Ignore dst pmtu
        Probe,
        /// No explicit setting
        NotSet,
    }

    impl From<IpPmtudisc> for libc::c_int {
        fn from(value: IpPmtudisc) -> Self {
            match value {
                IpPmtudisc::Dont => IP_PMTUDISC_DONT,
                IpPmtudisc::Do => IP_PMTUDISC_DO,
                IpPmtudisc::Probe => IP_PMTUDISC_PROBE,
                IpPmtudisc::NotSet => IP_PMTUDISC_NOT_SET,
            }
        }
    }

    impl TryFrom<libc::c_int> for IpPmtudisc {
        type Error = std::io::Error;

        fn try_from(value: libc::c_int) -> Result<Self, Self::Error> {
            match value {
                IP_PMTUDISC_DONT => Ok(IpPmtudisc::Dont),
                IP_PMTUDISC_DO => Ok(IpPmtudisc::Do),
                IP_PMTUDISC_PROBE => Ok(IpPmtudisc::Probe),
                IP_PMTUDISC_NOT_SET => Ok(IpPmtudisc::NotSet),
                v => Err(std::io::Error::other(format!(
                    "unexpected value for IP_PMTUDISC: {:?}",
                    v
                ))),
            }
        }
    }
}

#[cfg(apple)]
mod internal {
    const IP_ALLOW_FRAG: i32 = 0;
    const IP_DONT_FRAG: i32 = 1;

    /// Enum to represent PMTUd values
    #[derive(Copy, Clone)]
    pub enum IpPmtudisc {
        /// Never send DF frames
        Dont,
        /// Ignore dst pmtu
        Probe,
    }

    impl From<IpPmtudisc> for libc::c_int {
        fn from(value: IpPmtudisc) -> Self {
            match value {
                IpPmtudisc::Dont => IP_ALLOW_FRAG,
                IpPmtudisc::Probe => IP_DONT_FRAG,
            }
        }
    }

    impl TryFrom<libc::c_int> for IpPmtudisc {
        type Error = std::io::Error;

        fn try_from(value: libc::c_int) -> Result<Self, Self::Error> {
            match value {
                IP_ALLOW_FRAG => Ok(IpPmtudisc::Dont),
                IP_DONT_FRAG => Ok(IpPmtudisc::Probe),
                v => Err(std::io::Error::other(format!(
                    "unexpected value for IP_PMTUDISC: {:?}",
                    v
                ))),
            }
        }
    }
}

cfg_select! {
    apple => {
        const LEVEL_AND_OPTNAME_V4: (i32, i32) = (libc::IPPROTO_IP, libc::IP_DONTFRAG);
        const LEVEL_AND_OPTNAME_V6: (i32, i32) = (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG);
    }
    unix => {
        const LEVEL_AND_OPTNAME_V4: (i32, i32) = (libc::SOL_IP, libc::IP_MTU_DISCOVER);
        const LEVEL_AND_OPTNAME_V6: (i32, i32) = (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER);
    }
    windows => {
        const LEVEL_AND_OPTNAME_V4: (i32, i32) = (
            windows_sys::Win32::Networking::WinSock::IPPROTO_IP,
            windows_sys::Win32::Networking::WinSock::IP_MTU_DISCOVER,
        );
        const LEVEL_AND_OPTNAME_V6: (i32, i32) = (
            windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6,
            windows_sys::Win32::Networking::WinSock::IPV6_MTU_DISCOVER,
        );
    }
}

/// Whether `sock` is an IPv6 (`AF_INET6`) socket.
#[cfg(unix)]
fn is_ipv6(sock: &impl AsGenericHandle) -> std::io::Result<bool> {
    let addr = socket2::SockRef::from(sock).local_addr()?;

    if addr.is_ipv4() {
        Ok(false)
    } else if addr.is_ipv6() {
        Ok(true)
    } else {
        Err(std::io::Error::other(format!(
            "unexpected address family: {:?}",
            addr.family()
        )))
    }
}

/// Whether `sock` is an IPv6 (`AF_INET6`) socket.
#[cfg(windows)]
fn is_ipv6(sock: &impl AsGenericHandle) -> std::io::Result<bool> {
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR_STORAGE, SOCKET_ERROR, getsockname,
    };

    let mut addr: MaybeUninit<SOCKADDR_STORAGE> = MaybeUninit::zeroed();
    let mut len = std::mem::size_of::<SOCKADDR_STORAGE>() as i32;

    // SAFETY: `getsockname` requires a socket and a buffer of `len` bytes
    let res = unsafe { getsockname(sock.as_generic_handle(), addr.as_mut_ptr().cast(), &mut len) };
    if res == SOCKET_ERROR {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: the buffer was zeroed, and all zeroes is a valid `SOCKADDR_STORAGE`
    let family = unsafe { addr.assume_init() }.ss_family;
    match family {
        AF_INET => Ok(false),
        AF_INET6 => Ok(true),
        family => Err(std::io::Error::other(format!(
            "unexpected address family: {family:?}"
        ))),
    }
}

/// The option lives at a different level/name for IPv4 and IPv6
/// sockets, so inspect the socket's address family to pick the right
/// pair.
fn get_level_and_optname(sock: &impl AsGenericHandle) -> std::io::Result<(i32, i32)> {
    if is_ipv6(sock)? {
        Ok(LEVEL_AND_OPTNAME_V6)
    } else {
        Ok(LEVEL_AND_OPTNAME_V4)
    }
}

#[allow(non_camel_case_types)]
#[cfg(windows)]
type socklen_t = libc::c_int;

#[cfg(windows)]
type GenericHandle = usize;

#[cfg(windows)]
impl<T: AsRawSocket> AsGenericHandle for T {
    fn as_generic_handle(&self) -> GenericHandle {
        self.as_raw_socket() as usize
    }
}

#[cfg(windows)]
type SetOptValType = libc::c_char;

#[cfg(unix)]
type SetOptValType = libc::c_void;

#[cfg(unix)]
type GenericHandle = RawFd;

#[cfg(unix)]
impl<T: AsFd> AsGenericHandle for T {
    fn as_generic_handle(&self) -> GenericHandle {
        self.as_fd().as_raw_fd()
    }
}

pub use internal::*;

#[cfg(unix)]
/// Generic handle to use in sockopt
pub trait AsGenericHandle: AsFd {
    /// Generic handle to use in sockopt
    fn as_generic_handle(&self) -> GenericHandle;
}

#[cfg(windows)]
/// Generic handle to use in sockopt
pub trait AsGenericHandle {
    /// Generic handle to use in sockopt
    fn as_generic_handle(&self) -> GenericHandle;
}

/// Get IP_MTU_DISCOVER sockopt
///
/// An IPv6 socket reports the IPv6 option.
pub fn get_ip_mtu_discover(sock: &impl AsGenericHandle) -> std::io::Result<IpPmtudisc> {
    getsockopt(sock, get_level_and_optname(sock)?)
}

/// Get the IPv4 IP_MTU_DISCOVER sockopt only, whatever the socket's
/// address family. On an IPv6 socket this is the setting for
/// IPv4-mapped traffic.
#[cfg(all(not(apple), unix))]
pub fn get_ipv4_mtu_discover(sock: &impl AsGenericHandle) -> std::io::Result<IpPmtudisc> {
    getsockopt(sock, LEVEL_AND_OPTNAME_V4)
}

fn getsockopt(
    sock: &impl AsGenericHandle,
    (level, optname): (i32, i32),
) -> std::io::Result<IpPmtudisc> {
    let mut value: MaybeUninit<libc::c_int> = MaybeUninit::uninit();
    let mut len = std::mem::size_of::<libc::c_int>() as socklen_t;

    // SAFETY: `getsockopt` requires a socket/fd and a valid buffer of `c_int` size
    let res = unsafe {
        libc::getsockopt(
            sock.as_generic_handle(),
            level,
            optname,
            value.as_mut_ptr().cast(),
            &mut len,
        )
    };

    if res == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::c_int>() {
        return Err(std::io::Error::other(
            "unexpected len for IP_MTU_DISCOVER result",
        ));
    }

    // SAFETY: `getsockopt` initialised `value` for us.
    let value = unsafe { value.assume_init() };

    value.try_into()
}

/// Set IP_MTU_DISCOVER sockopt
///
/// An IPv6 socket takes the IPv6 option. Where it can also carry
/// IPv4-mapped traffic, which only obeys the IPv4 option, that is set
/// as well.
pub fn set_ip_mtu_discover(
    sock: &impl AsGenericHandle,
    pmtudisc: IpPmtudisc,
) -> std::io::Result<()> {
    let level_and_optname = get_level_and_optname(sock)?;
    setsockopt(sock, level_and_optname, pmtudisc)?;

    #[cfg(all(not(apple), unix))]
    if level_and_optname == LEVEL_AND_OPTNAME_V6 {
        setsockopt(sock, LEVEL_AND_OPTNAME_V4, pmtudisc)?;
    }

    Ok(())
}

/// Set the IPv4 IP_MTU_DISCOVER sockopt only, whatever the socket's
/// address family. On an IPv6 socket this covers IPv4-mapped traffic
/// and leaves IPv6 traffic alone.
#[cfg(all(not(apple), unix))]
pub fn set_ipv4_mtu_discover(
    sock: &impl AsGenericHandle,
    pmtudisc: IpPmtudisc,
) -> std::io::Result<()> {
    setsockopt(sock, LEVEL_AND_OPTNAME_V4, pmtudisc)
}

fn setsockopt(
    sock: &impl AsGenericHandle,
    (level, optname): (i32, i32),
    pmtudisc: IpPmtudisc,
) -> std::io::Result<()> {
    let pmtudisc: libc::c_int = pmtudisc.into();
    let len = std::mem::size_of::<libc::c_int>() as socklen_t;

    // SAFETY: `setsockopt` requires a socket and a valid buffer of `c_int` size
    let res = unsafe {
        libc::setsockopt(
            sock.as_generic_handle(),
            level,
            optname,
            &pmtudisc as *const libc::c_int as *const SetOptValType,
            len,
        )
    };

    if res == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(test, unix, not(miri)))]
mod tests {
    use super::*;

    fn roundtrip(sock: &std::net::UdpSocket) {
        set_ip_mtu_discover(sock, IpPmtudisc::Probe).unwrap();
        assert!(matches!(
            get_ip_mtu_discover(sock).unwrap(),
            IpPmtudisc::Probe
        ));

        set_ip_mtu_discover(sock, IpPmtudisc::Dont).unwrap();
        assert!(matches!(
            get_ip_mtu_discover(sock).unwrap(),
            IpPmtudisc::Dont
        ));
    }

    #[test]
    fn ipv4_socket() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        roundtrip(&sock);
    }

    #[test]
    fn ipv6_socket() {
        let sock = std::net::UdpSocket::bind("[::1]:0").unwrap();
        roundtrip(&sock);
    }

    /// Read an option directly, bypassing `get_ip_mtu_discover`.
    #[cfg(not(apple))]
    fn raw_getsockopt(sock: &std::net::UdpSocket, level: i32, optname: i32) -> libc::c_int {
        let mut value: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as socklen_t;
        // SAFETY: `getsockopt` requires a socket/fd and a valid buffer of `c_int` size
        let res = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                level,
                optname,
                (&raw mut value).cast(),
                &mut len,
            )
        };
        assert_eq!(res, 0, "{}", std::io::Error::last_os_error());
        value
    }

    #[cfg(not(apple))]
    fn raw_ipv4_option(sock: &std::net::UdpSocket) -> libc::c_int {
        raw_getsockopt(sock, libc::SOL_IP, libc::IP_MTU_DISCOVER)
    }

    #[cfg(not(apple))]
    fn raw_ipv6_option(sock: &std::net::UdpSocket) -> libc::c_int {
        raw_getsockopt(sock, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER)
    }

    // The IPv4 option is accepted on an AF_INET6 socket but only
    // applies to IPv4-mapped traffic, so check the IPv6 option itself.
    #[cfg(not(apple))]
    #[test]
    fn ipv6_socket_sets_ipv6_option() {
        let sock = std::net::UdpSocket::bind("[::1]:0").unwrap();
        assert_eq!(raw_ipv6_option(&sock), libc::IPV6_PMTUDISC_WANT);

        set_ip_mtu_discover(&sock, IpPmtudisc::Probe).unwrap();
        assert_eq!(raw_ipv6_option(&sock), libc::IPV6_PMTUDISC_PROBE);
        // IPv4-mapped traffic follows the IPv4 option.
        assert_eq!(raw_ipv4_option(&sock), libc::IP_PMTUDISC_PROBE);

        set_ip_mtu_discover(&sock, IpPmtudisc::Dont).unwrap();
        assert_eq!(raw_ipv6_option(&sock), libc::IPV6_PMTUDISC_DONT);
        assert_eq!(raw_ipv4_option(&sock), libc::IP_PMTUDISC_DONT);
    }

    #[cfg(not(apple))]
    #[test]
    fn ipv6_socket_ipv4_only_leaves_ipv6_option() {
        let sock = std::net::UdpSocket::bind("[::1]:0").unwrap();

        set_ipv4_mtu_discover(&sock, IpPmtudisc::Probe).unwrap();
        assert_eq!(raw_ipv4_option(&sock), libc::IP_PMTUDISC_PROBE);
        assert_eq!(raw_ipv6_option(&sock), libc::IPV6_PMTUDISC_WANT);

        // Each getter reads its own option.
        assert!(matches!(
            get_ipv4_mtu_discover(&sock).unwrap(),
            IpPmtudisc::Probe
        ));
        assert!(matches!(
            get_ip_mtu_discover(&sock).unwrap(),
            IpPmtudisc::Want
        ));
    }
}
