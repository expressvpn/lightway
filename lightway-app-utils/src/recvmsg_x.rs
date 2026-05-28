//! Apple-only `recvmsg_x` syscall bindings shared between client and server.
//!
//! `recvmsg_x` is a private Apple syscall (see XNU [`socket.h`]) that lets
//! callers receive multiple UDP datagrams in a single syscall, analogous to
//! Linux's `recvmmsg`. Because it's a private symbol that may not be present
//! on every macOS/iOS version we ship to, callers should consult
//! [`is_batch_receive_available`] before using it.
//!
//! [`socket.h`]: https://github.com/apple-oss-distributions/xnu/blob/rel/xnu-10063/bsd/sys/socket.h
#![cfg(apple)]
#![allow(non_camel_case_types)]

use std::sync::LazyLock;

/// Whether the `recvmsg_x` syscall is available on the running OS.
///
/// The symbol is a private Apple API that may not exist on all macOS/iOS
/// versions, so we probe for it with `dlsym(RTLD_DEFAULT, …)` once.
static RECVMSG_X_AVAILABLE: LazyLock<bool> = LazyLock::new(|| symbol_exists(c"recvmsg_x"));

/// Probe whether a C symbol is available in the current process via `dlsym`.
///
/// Returns `true` if `dlsym(RTLD_DEFAULT, name)` finds the symbol.
#[allow(unsafe_code)]
fn symbol_exists(name: &std::ffi::CStr) -> bool {
    // SAFETY: `dlsym` with `RTLD_DEFAULT` searches all loaded libraries for
    // the symbol. Passing a valid C string is safe; the returned pointer is
    // only used for a null check and never dereferenced.
    // Ref: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dlsym.3.html
    unsafe { !libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()).is_null() }
}

/// Check whether the platform supports batch receiving via `recvmsg_x`.
///
/// On Apple platforms `recvmsg_x` is a private syscall that may not be present
/// on every OS version, so callers should consult this probe before relying on
/// the syscall.
pub fn is_batch_receive_available() -> bool {
    *RECVMSG_X_AVAILABLE
}

/// Extended version for sendmsg_x() and recvmsg_x() calls
///
/// Layout matches Apple's `struct msghdr_x` in
/// <https://github.com/apple-oss-distributions/xnu/blob/rel/xnu-10063/bsd/sys/socket.h>.
#[repr(C)]
pub struct msghdr_x {
    /// optional address
    pub msg_name: *mut libc::c_void,
    /// size of address
    pub msg_namelen: libc::socklen_t,
    /// scatter/gather array
    pub msg_iov: *mut libc::iovec,
    /// elements in `msg_iov`.
    pub msg_iovlen: libc::c_int,
    /// ancillary data
    pub msg_control: *mut libc::c_void,
    /// ancillary data buffer len
    pub msg_controllen: libc::socklen_t,
    /// flags on received message
    pub msg_flags: libc::c_int,
    /// byte length of buffer in msg_iov
    pub msg_datalen: usize,
}

#[allow(unsafe_code)]
unsafe extern "C" {
    /// Receive up to `cnt` datagrams in a single syscall.
    ///
    /// Returns the number of messages received, or `-1` on error (with
    /// `errno` set as usual).
    pub fn recvmsg_x(
        s: libc::c_int,
        msgp: *const msghdr_x,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> isize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlsym_finds_known_symbol() {
        // `recvmsg` is a standard POSIX symbol that must exist on any Apple platform.
        assert!(symbol_exists(c"recvmsg"));
    }

    #[test]
    fn dlsym_returns_false_for_nonexistent_symbol() {
        assert!(!symbol_exists(c"definitely_should_not_exist_bruh"));
    }

    #[test]
    fn recvmsg_x_available_is_true() {
        // On macOS, recvmsg_x should be available as it ships with the OS kernel.
        assert!(*RECVMSG_X_AVAILABLE);
    }
}
