//! Support for IP_MTU_DISCOVER sockopt
//!
//! In the absence of something like
//! <https://github.com/rust-lang/socket2/issues/487> we have to reach
//! for libc and unsafety.

use libc::{IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_PMTUDISC_PROBE, IP_PMTUDISC_WANT};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;

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
}

impl From<IpPmtudisc> for libc::c_int {
    fn from(value: IpPmtudisc) -> Self {
        match value {
            IpPmtudisc::Dont => IP_PMTUDISC_DONT,
            IpPmtudisc::Want => IP_PMTUDISC_WANT,
            IpPmtudisc::Do => IP_PMTUDISC_DO,
            IpPmtudisc::Probe => IP_PMTUDISC_PROBE,
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
            v => Err(std::io::Error::other(format!(
                "unexpected value for IP_PMTUDISC: {:?}",
                v
            ))),
        }
    }
}

/// Get IP_MTU_DISCOVER sockopt
pub fn get_ip_mtu_discover(sock: &impl AsRawFd) -> std::io::Result<IpPmtudisc> {
    let mut value: MaybeUninit<libc::c_int> = MaybeUninit::uninit();
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let level: i32;
    let optname: i32;

    #[cfg(target_vendor = "apple")]
    {
        level = libc::IPPROTO_IP;
        optname = libc::IP_DONTFRAG;
    }

    #[cfg(not(target_vendor = "apple"))]
    {
        level = libc::SOL_IP;
        optname = libc::IP_MTU_DISCOVER;
    }

    // SAFETY: `getsockopt` requires an fd and a valid buffer of `c_int` size
    let res = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
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
            "unexpect len for IP_MTU_DISCOVER result",
        ));
    }

    // SAFETY: `getsockopt` initialised `value` for us.
    let value = unsafe { value.assume_init() };

    value.try_into()
}

/// Set IP_MTU_DISCOVER sockopt
pub fn set_ip_mtu_discover(sock: &impl AsRawFd, pmtudisc: IpPmtudisc) -> std::io::Result<()> {
    let pmtudisc: libc::c_int = pmtudisc.into();
    let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let level: i32;
    let optname: i32;

    #[cfg(target_vendor = "apple")]
    {
        level = libc::IPPROTO_IP;
        optname = libc::IP_DONTFRAG;
    }

    #[cfg(not(target_vendor = "apple"))]
    {
        level = libc::SOL_IP;
        optname = libc::IP_MTU_DISCOVER;
    }

    // SAFETY: `setsockopt` requires an fd and a valid buffer of `c_int` size
    let res = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            optname,
            &pmtudisc as *const libc::c_int as *const libc::c_void,
            len,
        )
    };

    if res == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
