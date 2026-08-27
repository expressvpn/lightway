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

#[cfg(apple)]
const LEVEL_AND_OPTNAME_V4: (i32, i32) = (libc::IPPROTO_IP, libc::IP_DONTFRAG);
#[cfg(apple)]
const LEVEL_AND_OPTNAME_V6: (i32, i32) = (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG);

#[cfg(all(not(apple), unix))]
const LEVEL_AND_OPTNAME: (i32, i32) = (libc::SOL_IP, libc::IP_MTU_DISCOVER);

#[cfg(windows)]
const LEVEL_AND_OPTNAME: (i32, i32) = (
    windows_sys::Win32::Networking::WinSock::IPPROTO_IP,
    windows_sys::Win32::Networking::WinSock::IP_MTU_DISCOVER,
);

/// On Apple platforms the don't-fragment option lives at a different
/// level/name for IPv4 and IPv6 sockets, so inspect the socket's
/// address family to pick the right pair.
#[cfg(apple)]
fn get_level_and_optname(sock: &impl AsGenericHandle) -> std::io::Result<(i32, i32)> {
    let addr = socket2::SockRef::from(sock).local_addr()?;

    if addr.is_ipv4() {
        Ok(LEVEL_AND_OPTNAME_V4)
    } else if addr.is_ipv6() {
        Ok(LEVEL_AND_OPTNAME_V6)
    } else {
        Err(std::io::Error::other(format!(
            "unexpected address family: {:?}",
            addr.family()
        )))
    }
}

#[cfg(not(apple))]
fn get_level_and_optname(_sock: &impl AsGenericHandle) -> std::io::Result<(i32, i32)> {
    Ok(LEVEL_AND_OPTNAME)
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
pub fn get_ip_mtu_discover(sock: &impl AsGenericHandle) -> std::io::Result<IpPmtudisc> {
    let mut value: MaybeUninit<libc::c_int> = MaybeUninit::uninit();
    let mut len = std::mem::size_of::<libc::c_int>() as socklen_t;

    let (level, optname) = get_level_and_optname(sock)?;

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
pub fn set_ip_mtu_discover(
    sock: &impl AsGenericHandle,
    pmtudisc: IpPmtudisc,
) -> std::io::Result<()> {
    let pmtudisc: libc::c_int = pmtudisc.into();
    let len = std::mem::size_of::<libc::c_int>() as socklen_t;

    let (level, optname) = get_level_and_optname(sock)?;

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

    // On non-apple platforms an AF_INET6 socket takes the
    // don't-fragment option via a different level/optname which we
    // don't support (yet).
    #[cfg(apple)]
    #[test]
    fn ipv6_socket() {
        let sock = std::net::UdpSocket::bind("[::1]:0").unwrap();
        roundtrip(&sock);
    }
}
