#![allow(unsafe_code)]
#![allow(non_camel_case_types, reason = "Using POSIX/libc naming")]

/// Marker for types which are usable with syscalls
///
/// # Safety
///
/// Implement only for types containing raw pointers which are
/// passed to syscalls where the concept of Sync/Send is orthogonal to
/// Rust's model.
pub(super) unsafe trait IsSyscallSafe {}

// SAFETY: iovec is used with syscalls
unsafe impl IsSyscallSafe for libc::iovec {}
// SAFETY: msghdr is used with syscalls
unsafe impl IsSyscallSafe for libc::msghdr {}

pub(super) struct SyscallSafe<T: IsSyscallSafe>(T);

impl<T: IsSyscallSafe> SyscallSafe<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        &mut self.0 as *mut T
    }
}

impl<T: IsSyscallSafe> std::ops::Deref for SyscallSafe<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: IsSyscallSafe> std::ops::DerefMut for SyscallSafe<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// SAFETY: T must be e.g. a libc type which contains raw pointers for syscall use.
// The `pub` aliases below all satisfy this.
unsafe impl<T: IsSyscallSafe> Send for SyscallSafe<T> {}

// SAFETY: T must be e.g. a libc type which contains raw pointers for syscall use.
// The `pub` aliases below all satisfy this.
unsafe impl<T: IsSyscallSafe> Sync for SyscallSafe<T> {}

pub type iovec = SyscallSafe<libc::iovec>;
pub type msghdr = SyscallSafe<libc::msghdr>;
