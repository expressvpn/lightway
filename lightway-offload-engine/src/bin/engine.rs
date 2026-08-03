//! The offload engine process.
//!
//! Started by the VPN process with one inherited unix socket on fd 3, over
//! which it receives its TUN queue and UDP socket, then a stream of control
//! messages. No packet ever crosses that socket - the kernel's BPF steering
//! delivers offloaded traffic straight to the descriptors handed over, and
//! `PacketLoops` carries it from there.
//!
//! The loops start in the attach callback, before any keys exist. They need
//! none: the session and the peer come from the engine per packet, and until
//! the first key push there is nothing to encrypt for - which is also when the
//! VPN process sets the steering flag, so nothing is being steered here yet
//! either. Starting them here is what keeps the control loop free of them:
//! nothing borrows the engine or holds a lock across its blocking read.

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
    use std::sync::Arc;

    use lightway_offload_engine::control::run_engine;
    use lightway_offload_engine::engine::Engine;
    use lightway_offload_engine::packet::PacketLoops;

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

    // Shared, never owned by the control loop: the packet loops hold the same
    // engine while it is blocked in `recvmsg`, and keys and versions arrive
    // per session over the control socket.
    let engine = Arc::new(Engine::new());

    // The loops own the descriptors from here. That also makes a failure to
    // start them safe rather than silent: the descriptors close with the
    // attempt, the device's `numqueues` drops back to 1, and the kernel puts
    // the inside path back on queue 0 - the VPN process - instead of steering
    // it at an engine that would never read it.
    let mut loops: Option<PacketLoops> = None;
    let result = run_engine(&control, &engine, |handed_over| {
        loops = start(engine.clone(), handed_over)
            .inspect_err(
                |e| tracing::error!(error = %e, "packet loops did not start, offload is off"),
            )
            .ok();
    });
    // Before the return value is reported, so the threads are gone while the
    // process still exists to say so.
    drop(loops);
    tracing::info!("engine stopped");
    result
}

/// Take the two descriptors in the order the protocol passes them - TUN queue,
/// then UDP socket - and start the loops on them.
#[cfg(target_os = "linux")]
fn start(
    engine: std::sync::Arc<lightway_offload_engine::engine::Engine>,
    handed_over: Vec<std::os::fd::OwnedFd>,
) -> std::io::Result<lightway_offload_engine::packet::PacketLoops> {
    use lightway_offload_engine::control::EXPECTED_FDS;
    use lightway_offload_engine::packet::PacketLoops;
    use std::os::fd::OwnedFd;

    let [tun, sock]: [OwnedFd; EXPECTED_FDS] = handed_over.try_into().map_err(|v: Vec<_>| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("attach delivered {} descriptors", v.len()),
        )
    })?;
    PacketLoops::spawn(
        engine,
        std::fs::File::from(tun),
        std::net::UdpSocket::from(sock),
    )
}

/// The library is empty off Linux and a binary still needs an entry point.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the offload engine is Linux-only");
    std::process::exit(1);
}
