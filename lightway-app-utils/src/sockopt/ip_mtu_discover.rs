//! Support for IP_MTU_DISCOVER sockopt
//!
//! In the absence of something like
//! <https://github.com/rust-lang/socket2/issues/487> we have to reach
//! for libc and unsafety.

#[cfg(all(not(target_vendor = "apple"), target_family = "unix"))]
use libc::{IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_PMTUDISC_PROBE, IP_PMTUDISC_WANT};

#[cfg(unix)]
use libc::socklen_t;

use std::mem::MaybeUninit;
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    IP_MTU_DISCOVER, IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_PMTUDISC_NOT_SET, IP_PMTUDISC_PROBE,
    IPPROTO_IP,
};

#[cfg(target_vendor = "apple")]
const IP_PMTUDISC_DONT: i32 = 0;
#[cfg(target_vendor = "apple")]
const IP_PMTUDISC_DO: i32 = 1;

/// Enum to represent PMTUd values
#[derive(Copy, Clone)]
pub enum IpPmtudisc {
    /// Never send DF frames
    Dont,
    /// Use per route hints
    #[cfg(all(not(target_vendor = "apple"), target_family = "unix"))]
    Want,
    /// Always DF
    Do,
    #[cfg(all(not(target_vendor = "apple"), target_family = "unix"))]
    /// Ignore dst pmtu
    Probe,
    /// No explicit setting
    #[cfg(windows)]
    NotSet,
}

impl From<IpPmtudisc> for libc::c_int {
    fn from(value: IpPmtudisc) -> Self {
        match value {
            IpPmtudisc::Dont => IP_PMTUDISC_DONT,
            #[cfg(not(target_vendor = "apple"))]
            IpPmtudisc::Want => IP_PMTUDISC_WANT,
            IpPmtudisc::Do => IP_PMTUDISC_DO,
            #[cfg(not(target_vendor = "apple"))]
            IpPmtudisc::Probe => IP_PMTUDISC_PROBE,
            #[cfg(windows)]
            IpPmtudisc::NotSet => IP_PMTUDISC_NOT_SET,
        }
    }
}

impl TryFrom<libc::c_int> for IpPmtudisc {
    type Error = std::io::Error;

    fn try_from(value: libc::c_int) -> Result<Self, Self::Error> {
        match value {
            IP_PMTUDISC_DONT => Ok(IpPmtudisc::Dont),
            #[cfg(not(target_vendor = "apple"))]
            IP_PMTUDISC_WANT => Ok(IpPmtudisc::Want),
            IP_PMTUDISC_DO => Ok(IpPmtudisc::Do),
            #[cfg(not(target_vendor = "apple"))]
            IP_PMTUDISC_PROBE => Ok(IpPmtudisc::Probe),
            #[cfg(windows)]
            IP_PMTUDISC_NOT_SET => Ok(IpPmtudisc::NotSet),
            v => Err(std::io::Error::other(format!(
                "unexpected value for IP_PMTUDISC: {:?}",
                v
            ))),
        }
    }
}

fn get_level_and_optname() -> (i32, i32) {
    let level: i32;
    let optname: i32;

    #[cfg(all(target_vendor = "apple", target_family = "unix"))]
    {
        level = libc::IPPROTO_IP;
        optname = libc::IP_DONTFRAG;
    }

    #[cfg(all(not(target_vendor = "apple"), target_family = "unix"))]
    {
        level = libc::SOL_IP;
        optname = libc::IP_MTU_DISCOVER;
    }

    #[cfg(windows)]
    {
        level = IPPROTO_IP;
        optname = IP_MTU_DISCOVER;
    }

    (level, optname)
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
impl<T: AsRawFd> AsGenericHandle for T {
    fn as_generic_handle(&self) -> GenericHandle {
        self.as_raw_fd()
    }
}

/// Generic handle to use in sockopt
pub trait AsGenericHandle {
    /// Generic handle to use in sockopt
    fn as_generic_handle(&self) -> GenericHandle;
}

/// Get IP_MTU_DISCOVER sockopt
pub fn get_ip_mtu_discover(sock: &impl AsGenericHandle) -> std::io::Result<IpPmtudisc> {
    let mut value: MaybeUninit<libc::c_int> = MaybeUninit::uninit();
    let mut len = std::mem::size_of::<libc::c_int>() as socklen_t;

    let (level, optname) = get_level_and_optname();

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

    let (level, optname) = get_level_and_optname();

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
