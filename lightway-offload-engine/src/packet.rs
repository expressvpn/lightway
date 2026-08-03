//! The engine's two packet loops.
//!
//! Threads, not async: this process does exactly two things and both are one
//! descriptor's worth of I/O. A runtime would buy nothing and would drag a
//! scheduler into a process whose whole point is to stay small.
//!
//! Neither loop is handed a session, and neither looks one up in advance.
//! TX calls [`Engine::encrypt_current`], which picks the newest session any key
//! push named and encrypts under it in one locked step; RX takes the session id
//! out of the datagram in hand, because what arrives is whatever the peer is
//! still sending, not whatever this side rotated to last. A loop that captured
//! a session at spawn would go on encrypting for one the table no longer holds,
//! and the tunnel would go quiet with nothing to point at. It also means the
//! loops can start at descriptor hand-over, before any keys have arrived - with
//! no session there is nothing to send, which is the state the engine should be
//! in anyway until the steering flag is set.
//!
//! TX is gated on [`Engine::active`] and RX is not, which is not an oversight:
//! see `rx_loop`. Every packet either loop fails to move is counted: outbound
//! through [`Engine::count_tx_drop`], inbound through [`Engine::count_rx_drop`].
//! A data plane that goes quiet without moving a counter is the failure nobody
//! can diagnose.
//!
//! Both loops park in `poll` on their descriptor *and* on a pipe that
//! [`PacketLoops::shutdown`] writes. That pipe is the only reason shutdown
//! terminates: a thread blocked on a descriptor cannot see a flag, and neither
//! descriptor can be closed underneath it without racing an fd number the
//! kernel may already have handed to something else.

use std::fs::File;
use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::thread::JoinHandle;

use bytes::BytesMut;
use rand::RngExt;

use crate::engine::{Engine, TxDrop};

/// Largest inside packet or datagram the loops will handle.
pub const MAX_PACKET: usize = 65535;

/// The two running loops.
pub struct PacketLoops {
    /// Writing to it - or dropping it - wakes both loops out of `poll`.
    wake: PipeWriter,
    tx: Option<JoinHandle<()>>,
    rx: Option<JoinHandle<()>>,
}

/// Put `fd` in non-blocking mode.
///
/// `UdpSocket` has `set_nonblocking`; a `File` holding a TUN queue has no
/// equivalent, so this is the same call by hand.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL takes no third argument and writes no memory through the
    // descriptor; a bad `fd` is EBADF, not undefined behaviour.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL takes the flags by value and writes no memory; `fd` is
    // owned by the caller and open across the call.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wait until `fd` is worth reading, or until `wake` fires.
///
/// `Ok(false)` means shut down. `Ok(true)` means try the read, which may still
/// come back `WouldBlock` - a datagram can be discarded between the poll and
/// the receive - and that is just another trip round the loop.
fn wait_readable(fd: RawFd, wake: RawFd) -> io::Result<bool> {
    let mut fds = [
        libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: `fds` is a live array of exactly the two entries `poll` is told
    // to read, and both descriptors are owned by this loop for its whole life.
    // A negative timeout is "wait forever", which the wake pipe is what ends.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        // A signal is not a reason to stop; go round again.
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(true);
        }
        return Err(e);
    }
    // Readable, or the writing end gone: either way, stop.
    Ok(fds[1].revents == 0)
}

impl PacketLoops {
    /// Start both loops on `tun` and `sock`, taking ownership of each.
    ///
    /// No session id and no peer address: TX gets both from
    /// [`Engine::encrypt_current`] per packet, so a key push - or a rotation -
    /// takes effect on the next packet with nothing to restart.
    ///
    /// Both descriptors are put in non-blocking mode. `InsideSplit` already
    /// opens its queues that way, but the TUN arrives over a process boundary
    /// and nothing on this side can check how it was opened; a blocking one
    /// would park a loop in `read` where the wake pipe cannot reach it. The
    /// mode is per open file description, so a duplicate the caller kept sees
    /// it too.
    pub fn spawn(engine: Arc<Engine>, tun: File, sock: UdpSocket) -> io::Result<Self> {
        let (wake_rx, wake) = io::pipe()?;
        sock.set_nonblocking(true)?;
        set_nonblocking(tun.as_raw_fd())?;

        let tx = {
            let engine = engine.clone();
            let mut tun = tun.try_clone()?;
            let sock = sock.try_clone()?;
            let wake_rx = wake_rx.try_clone()?;
            std::thread::Builder::new()
                .name("lw-offload-tx".into())
                .spawn(move || tx_loop(&engine, &mut tun, &sock, &wake_rx))?
        };

        let rx = {
            let mut tun = tun;
            std::thread::Builder::new()
                .name("lw-offload-rx".into())
                .spawn(move || rx_loop(&engine, &mut tun, &sock, &wake_rx))?
        };

        Ok(Self {
            wake,
            tx: Some(tx),
            rx: Some(rx),
        })
    }

    /// Stop both loops and wait for them.
    ///
    /// The write is what both `poll`s are waiting for, so this returns as soon
    /// as each loop finishes the packet it was on. Nothing ever drains the
    /// pipe, so one byte latches both threads out for good.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        let _ = (&self.wake).write(&[1]);
        if let Some(h) = self.tx.take() {
            let _ = h.join();
        }
        if let Some(h) = self.rx.take() {
            let _ = h.join();
        }
    }
}

impl Drop for PacketLoops {
    /// One that is dropped rather than shut down stops just the same, so a
    /// panic on the way to `shutdown` cannot leave two threads running on
    /// descriptors nobody owns any more.
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// TUN -> encrypt -> socket.
fn tx_loop(engine: &Engine, tun: &mut File, sock: &UdpSocket, wake: &PipeReader) {
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        match wait_readable(tun.as_raw_fd(), wake.as_raw_fd()) {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                tracing::error!(error = %e, "tx loop stopping");
                return;
            }
        }
        let n = match tun.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "tun read failed, tx loop stopping");
                return;
            }
        };
        // A hard gate, not advice. The kernel's steering flag is what really
        // moves the inside path back to the VPN process, so by the time this is
        // false the queue should already be going quiet - but a packet read
        // just before the flip is still in hand here, and an engine that has
        // been told to stand down must not put it on the wire under a session
        // the other side may have torn down.
        if !engine.active() {
            engine.count_tx_drop(TxDrop::Inactive);
            continue;
        }
        // A fresh IV per packet; uniqueness under the current key is what the
        // AEAD's security rests on.
        let iv: [u8; 12] = rand::rng().random();
        // Both `None` paths - no session, or a session that would not encrypt
        // it - are counted inside the engine.
        let Some(out) = engine.encrypt_current(&buf[..n], iv) else {
            continue;
        };
        // Counted as sent only once the socket has taken it. A datagram the
        // peer never saw must not be weighed against what the peer says it
        // received, or a working tunnel degrades itself.
        match sock.send_to(&out.datagram, out.peer) {
            Ok(_) => engine.count_sent(&out),
            Err(e) => {
                tracing::debug!(error = %e, "outbound datagram not sent");
                engine.count_tx_drop(TxDrop::Send);
            }
        }
    }
}

/// Socket -> decrypt -> TUN.
///
/// Deliberately not gated on [`Engine::active`], where TX is. The flag says the
/// VPN process has taken the *inside* path back; it says nothing about what is
/// still arriving from the server. A datagram that reaches here has been
/// steered by the kernel, authenticated and replay-checked, and no one else is
/// going to read it - so dropping one because the engine has been told to stand
/// down is guaranteed data loss on a path that still works, which is the shape
/// of the ExpressLane degrade this project has already chased down once. It is
/// delivered and said out loud instead.
fn rx_loop(engine: &Engine, tun: &mut File, sock: &UdpSocket, wake: &PipeReader) {
    let mut buf = vec![0u8; MAX_PACKET];
    // Thread-local, so saying it once costs no shared state.
    let mut said_inactive = false;
    loop {
        match wait_readable(sock.as_raw_fd(), wake.as_raw_fd()) {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                tracing::error!(error = %e, "rx loop stopping");
                return;
            }
        }
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            // A datagram that drew an ICMP error leaves it on the socket, and
            // reading it is what clears it. The next receive is the one that
            // matters, so this is not a reason to stop.
            Err(e) => {
                tracing::debug!(error = %e, "socket receive failed");
                continue;
            }
        };
        let mut datagram = BytesMut::from(&buf[..n]);
        // A datagram the engine refuses is already counted by `decrypt`;
        // dropping it here is correct, because the kernel steered it to us and
        // no one else will read it.
        if let Some(inside) = engine.decrypt(&mut datagram) {
            if !engine.active() && !said_inactive {
                said_inactive = true;
                tracing::warn!(
                    "the server is still sending offloaded traffic after the engine stood down; \
                     delivering it rather than dropping it"
                );
            }
            // A TUN write takes one whole packet or nothing, so a short write
            // cannot happen, and a device that will not take it is a dropped
            // packet rather than a reason to stop carrying the rest.
            if let Err(e) = tun.write(&inside) {
                tracing::debug!(error = %e, "inside packet dropped");
                engine.count_rx_drop();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::os::fd::OwnedFd;
    use std::time::{Duration, Instant};

    /// Shutdown has to return with both loops idle on descriptors that will
    /// never produce a byte, which is the state a real engine spends most of
    /// its life in. A flag the loops could only notice after their next packet
    /// would hang here for ever.
    #[test]
    fn shutdown_returns_with_both_loops_parked() {
        let (tun, _writer) = io::pipe().unwrap();
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let loops = PacketLoops::spawn(
            Arc::new(Engine::new()),
            File::from(OwnedFd::from(tun)),
            sock,
        )
        .unwrap();

        // Long enough that both threads are certainly inside `poll` rather than
        // still starting, which is the case a flag-only shutdown gets wrong.
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        loops.shutdown();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "shutdown did not stop the loops"
        );
    }

    /// Dropping without shutting down must stop them too, or a panic between
    /// spawn and shutdown leaks two threads.
    #[test]
    fn dropping_stops_the_loops_as_well() {
        let (tun, _writer) = io::pipe().unwrap();
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let loops = PacketLoops::spawn(
            Arc::new(Engine::new()),
            File::from(OwnedFd::from(tun)),
            sock,
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        drop(loops);
        assert!(started.elapsed() < Duration::from_secs(5), "drop hung");
    }
}
