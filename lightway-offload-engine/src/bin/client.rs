//! The control-plane process of the offloaded ExpressLane client.
//!
//! It owns the handshake and keeps lightway-core, but never sees an offloaded
//! packet: it creates both eBPF splits, keeps queue 0 and the control socket
//! for itself, and hands queue 1 and the engine socket to a child process.
//!
//! Not `#![cfg(target_os = "linux")]` at the file level, unlike the library:
//! a binary target still needs a `main` on every platform cargo builds it
//! for (this workspace's clippy job runs on macOS too), so the real
//! implementation is gated item by item and a stub `main` stands in off
//! Linux - the same split `bin/engine.rs` already uses.

/// Descriptor the child finds its control socket on.
#[cfg(target_os = "linux")]
const ENGINE_CONTROL_FD: std::os::fd::RawFd = 3;
/// Handoff order, which is a protocol between the two binaries.
#[cfg(target_os = "linux")]
const FD_TUN_INDEX: usize = 0;
#[cfg(target_os = "linux")]
const FD_SOCK_INDEX: usize = 1;
#[cfg(target_os = "linux")]
const FD_COUNT: usize = 2;

#[cfg(target_os = "linux")]
use lightway_bpf_steering::{InsideSplit, OutsideSplit};

/// Bring up both splits and start the engine holding the far ends.
///
/// Returns the spawned child and this side's control socket, over which
/// `Attach` and its two descriptors have already gone out.
#[cfg(target_os = "linux")]
fn start_engine(
    inside: &InsideSplit,
    outside: &OutsideSplit,
    engine_path: &str,
) -> std::io::Result<(std::process::Child, std::os::unix::net::UnixStream)> {
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use lightway_offload_engine::fdpass::send_with_fds;
    use lightway_offload_engine::ipc::ControlMsg;

    let (ours, theirs) = UnixStream::pair()?;

    let child_fd = theirs.as_raw_fd();
    let mut cmd = Command::new(engine_path);
    // Placing the control socket on fd 3 is the one thing this closure does,
    // and it runs in the fork()'d child, after fork and before exec, so dup2
    // - async-signal-safe, touching only the child's own descriptor table -
    // is all it needs. `UnixStream::pair` sets FD_CLOEXEC on both ends on
    // Linux, but dup2(2) never carries FD_CLOEXEC onto its target: fd 3 comes
    // out of dup2 without it and survives the exec that follows, even though
    // `child_fd`'s own number would not have.
    let place_control_socket_on_fd_3 = move || {
        // SAFETY: `child_fd` is a descriptor this process owns, valid for as
        // long as the child's copy of the table it was forked with; dup2
        // only rewires the child's own table entry at ENGINE_CONTROL_FD.
        if unsafe { libc::dup2(child_fd, ENGINE_CONTROL_FD) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: see `place_control_socket_on_fd_3` above for what the closure
    // itself relies on.
    unsafe {
        cmd.pre_exec(place_control_socket_on_fd_3);
    }
    let child = cmd.spawn()?;
    // Fork already gave the child its own reference to the peer this holds;
    // keeping it open here past this point would mean this process is also
    // holding `theirs`'s peer open, and `ours` would never see EOF once the
    // child exits, because a peer this process still holds keeps it live.
    drop(theirs);

    // Order is the protocol: the engine reads [tun queue, udp socket].
    let mut fds = [0; FD_COUNT];
    fds[FD_TUN_INDEX] = inside.engine_queue.as_raw_fd();
    fds[FD_SOCK_INDEX] = outside.engine.as_raw_fd();

    let mut payload = Vec::new();
    ControlMsg::Attach.encode(&mut payload);
    send_with_fds(&ours, &payload, &fds)?;

    Ok((child, ours))
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let engine_path =
        std::env::var("LW_ENGINE_BIN").unwrap_or_else(|_| "lightway-offload-engine".to_string());

    let inside = InsideSplit::create("lwoffload0")?;
    let outside = OutsideSplit::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;

    let (mut child, control) = start_engine(&inside, &outside, &engine_path)?;
    tracing::info!(
        tun = %inside.if_index()?,
        addr = %outside.local_addr()?,
        "engine attached"
    );

    // Task 3 replaces this with the real client; for now prove the handoff
    // survives and exit cleanly. Closing `control` is what lets the engine's
    // control loop see EOF and return, so it must happen before the wait
    // below, not after: waiting first would deadlock against an engine that
    // is still blocked reading a socket this process never let go of.
    drop(control);
    let status = child.wait()?;
    if !status.success() {
        // A bad fd 3, or a descriptor count the protocol refuses, both
        // surface as a non-zero exit from the engine - propagate it rather
        // than reporting success for a handoff that did not land.
        return Err(io::Error::other(format!(
            "engine exited with {status}; the handoff did not complete"
        )));
    }
    Ok(())
}

/// The real implementation is Linux-only and a binary still needs an entry
/// point on every platform cargo builds it for.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the offload client is Linux-only");
    std::process::exit(1);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// The descriptor order is a protocol between the two binaries: the engine
    /// reads `[tun queue, udp socket]`. Nothing in the type system pins it, so
    /// pin it here.
    #[test]
    fn descriptor_order_matches_what_the_engine_expects() {
        assert_eq!(FD_TUN_INDEX, 0);
        assert_eq!(FD_SOCK_INDEX, 1);
        assert_eq!(
            FD_COUNT,
            lightway_offload_engine::control::EXPECTED_FDS,
            "handoff count disagrees with the engine"
        );
    }

    #[test]
    fn the_engine_is_spawned_with_the_control_socket_on_fd_three() {
        assert_eq!(ENGINE_CONTROL_FD, 3);
    }
}
