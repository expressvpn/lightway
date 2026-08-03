//! The offload engine process.
//!
//! Started by the VPN process with one inherited unix socket on fd 3, over
//! which it receives its TUN queue and UDP socket, then a stream of control
//! messages. Packets never arrive here - the kernel's BPF steering delivers
//! them straight to the descriptors handed over.
//!
//! There is deliberately no packet loop: which descriptors this process reads,
//! and on how many threads, is the VPN process's decision to make, and it does
//! not exist yet. Everything below is what that decision cannot change.

/// The descriptor the parent leaves the control socket on.
#[cfg(target_os = "linux")]
const CONTROL_FD: std::os::fd::RawFd = 3;

/// Read one `SOL_SOCKET` integer option, or say why the descriptor cannot.
#[cfg(target_os = "linux")]
fn sock_opt(fd: std::os::fd::RawFd, name: libc::c_int) -> std::io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the kernel writes at most `len` bytes - one c_int - into
    // `value`, and both locals outlive the call. A bad `fd` is EBADF or
    // ENOTSOCK, not undefined behaviour.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(value)
}

/// Read the descriptor's file status flags.
#[cfg(target_os = "linux")]
fn status_flags(fd: std::os::fd::RawFd) -> std::io::Result<libc::c_int> {
    // SAFETY: F_GETFL takes no third argument and writes no memory; a bad
    // `fd` is EBADF, not undefined behaviour.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(flags)
}

/// Fail early if fd 3 is not the blocking unix stream socket the contract
/// calls for.
///
/// Taking ownership of a descriptor that is closed aborts the runtime later
/// with an IO-safety violation, and taking ownership of one this process does
/// not own would close a file belonging to something else. Both are the parent
/// breaking the startup contract, and saying so beats either.
///
/// The domain matters as much as the type: `UnixStream::from(OwnedFd)` is
/// infallible, so a TCP socket left on fd 3 would be adopted as a unix one and
/// only fail later, on `SCM_RIGHTS`, as something that reads like a descriptor
/// bug rather than a wrong descriptor.
///
/// `O_NONBLOCK` matters for the same reason: `run_engine` blocks in `recvmsg`,
/// so a socket pair built by an async runtime - which sets it as a matter of
/// course - would make the engine exit with `EAGAIN` the instant it started,
/// long before the parent had sent anything to blame it on.
#[cfg(target_os = "linux")]
fn check_control_fd(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    if sock_opt(fd, libc::SO_DOMAIN)? != libc::AF_UNIX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control descriptor is not a unix socket",
        ));
    }
    if sock_opt(fd, libc::SO_TYPE)? != libc::SOCK_STREAM {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control descriptor is not a stream socket",
        ));
    }
    if status_flags(fd)? & libc::O_NONBLOCK != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control descriptor is non-blocking; the engine blocks on it",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    use lightway_offload_engine::control::run_engine;
    use lightway_offload_engine::engine::Engine;

    // Without a subscriber the crate's warnings - a key that would not install,
    // a version that arrived too late - go nowhere, and the engine's only way
    // of saying so is silence.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    check_control_fd(CONTROL_FD).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("fd {CONTROL_FD} is not the control socket the parent must pass: {e}"),
        )
    })?;

    // SAFETY: fd 3 is an open socket, checked just above, and the parent
    // guarantees it does not retain it; taking ownership here is the
    // documented startup contract.
    let control = unsafe { UnixStream::from(OwnedFd::from_raw_fd(CONTROL_FD)) };

    // Shared, never owned by the loop: the same reference is what a packet
    // path would take, and versions and keys arrive per session over the
    // control socket.
    let engine = Engine::new();

    // Held for the life of the process: these are the TUN queue and the UDP
    // socket the kernel steers to, and closing either one ends the offload.
    // Process A's packet loop moves them out of this callback instead.
    let mut fds: Vec<OwnedFd> = Vec::new();
    let result = run_engine(&control, &engine, |handed_over| fds = handed_over);
    tracing::info!(descriptors = fds.len(), "engine stopped");
    result
}

/// The library is empty off Linux and a binary still needs an entry point.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the offload engine is Linux-only");
    std::process::exit(1);
}
