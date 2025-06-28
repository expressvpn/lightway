#![allow(unsafe_code)]

use std::os::fd::AsRawFd;

/// Enable IP_PKTINFO sockopt.
pub fn socket_enable_pktinfo(sock: &impl AsRawFd) -> std::io::Result<()> {
    let level: i32;
    let optname: i32;

    #[cfg(target_vendor = "apple")]
    {
        level = libc::IPPROTO_IP;
        optname = libc::IP_PKTINFO;
    }

    #[cfg(not(target_vendor = "apple"))]
    {
        level = libc::SOL_IP;
        optname = libc::IP_PKTINFO;
    }

    // SAFETY: `setsockopt` requires a valid fd and a valid buffer of `c_int` size
    let res = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            optname,
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
