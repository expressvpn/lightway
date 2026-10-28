#![allow(unsafe_code)]

use std::os::fd::AsRawFd;

/// Enable IP_PKTINFO sockopt.
pub fn socket_enable_pktinfo(sock: &impl AsRawFd) -> std::io::Result<()> {
    let level = cfg_select! {
        apple => libc::IPPROTO_IP,
        _ => libc::SOL_IP,
    };
    let optname = libc::IP_PKTINFO;

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
