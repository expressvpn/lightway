//! The bits both splits share: classifying a libbpf load failure, and reading
//! a counter array back out of the kernel.

use std::io;

use libbpf_rs::{MapCore, MapFlags};

/// The errno a libbpf error renders, if it renders one.
///
/// `libbpf_rs::Error` keeps its `io::Error` private and its `kind()` folds
/// `EPERM` and `EACCES` into one variant - which is the single distinction
/// that matters here. The alternate `Display` walks the whole context chain,
/// and the innermost link of an OS error always ends in `(os error <n>)`.
fn errno_of(e: &libbpf_rs::Error) -> Option<i32> {
    let rendered = format!("{e:#}");
    let (_, tail) = rendered.rsplit_once("(os error ")?;
    let (code, _) = tail.split_once(')')?;
    code.trim().parse().ok()
}

/// Classify a BPF load failure.
///
/// Only `EPERM` becomes `PermissionDenied`, because that is what the kernel
/// answers a process that may not use `bpf(2)`. A rejected program comes back
/// as `EACCES` - the verifier's answer - and a malformed object as something
/// else again; neither may masquerade as a missing capability, or the tests
/// that skip when unprivileged would skip on a program that does not work.
pub(crate) fn load_error(e: libbpf_rs::Error) -> io::Error {
    if errno_of(&e) == Some(libc::EPERM) {
        io::Error::new(io::ErrorKind::PermissionDenied, e)
    } else {
        io::Error::other(e)
    }
}

/// Read `N` consecutive `__u64` counters out of a `BPF_MAP_TYPE_ARRAY`.
///
/// A key the kernel has never written back reads as absent rather than zero,
/// which is the same thing here: nothing has been counted yet.
pub(crate) fn read_counters<const N: usize>(map: &impl MapCore) -> io::Result<[u64; N]> {
    let mut out = [0u64; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let v = map
            .lookup(&(i as u32).to_ne_bytes(), MapFlags::ANY)
            .map_err(io::Error::other)?
            .unwrap_or_else(|| vec![0; 8]);
        let bytes: [u8; 8] = v
            .get(..8)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| io::Error::other("counter is not 8 bytes wide"))?;
        *slot = u64::from_ne_bytes(bytes);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libbpf_rs::ErrorExt as _;

    #[test]
    fn a_load_without_the_capability_is_a_permission_error() {
        let e = load_error(libbpf_rs::Error::from_raw_os_error(libc::EPERM));
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    /// libbpf layers context onto its errors; the errno is at the far end.
    #[test]
    fn the_errno_is_found_under_libbpf_context() {
        let e = libbpf_rs::Error::from_raw_os_error(libc::EPERM)
            .context("failed to load BPF object")
            .context("outside");
        assert_eq!(errno_of(&e), Some(libc::EPERM));
        assert_eq!(load_error(e).kind(), io::ErrorKind::PermissionDenied);
    }

    /// The verifier rejects a program with EACCES. Calling that a permission
    /// problem would make the privileged tests skip on a broken program
    /// instead of failing.
    #[test]
    fn a_rejected_program_is_not_a_permission_error() {
        let e = load_error(libbpf_rs::Error::from_raw_os_error(libc::EACCES));
        assert_eq!(e.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn an_error_without_an_errno_is_not_a_permission_error() {
        let e = libbpf_rs::Error::from(io::Error::new(io::ErrorKind::InvalidData, "bad ELF"));
        assert_eq!(errno_of(&e), None);
        assert_eq!(load_error(e).kind(), io::ErrorKind::Other);
    }
}
