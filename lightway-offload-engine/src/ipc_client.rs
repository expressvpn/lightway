//! Process A's end of the control socket.
//!
//! One thread owns the socket. Everything else talks to it through channels,
//! which is what makes the two callers safe to mix: `ExpresslaneCb::update`
//! fires key pushes from wherever lightway-core happens to be, while
//! `ExpresslaneMetrics::get_stats` needs a reply **and is called synchronously
//! while core holds the connection lock**. Sharing the socket directly would
//! let a push be read as a reply, and would block the tunnel on IPC.
//!
//! Every bound here is on the *caller*, not on the engine. An engine that
//! stops answering costs a poll's worth of counters; it must never cost the
//! tunnel, because the thread asking is holding the lock every packet needs.

use std::io;
use std::net::{Shutdown, SocketAddr};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lightway_expresslane::ExpresslaneKey;

use crate::fdpass::{recv_with_fds, send_with_fds};
use crate::ipc::{ControlMsg, IpcError, MAX_CONTROL_MSG_LEN};

/// The two shapes a caller can have, because the two callers have two shapes.
///
/// The channel carrying these is unbounded, which is a decision and not an
/// oversight. `Fire` is rare - a key rotation, a state change - and dropping
/// one loses the very key the engine needs, so it must never be refused.
/// `Ask` is frequent but *self-expiring*: it carries the moment its caller
/// stops caring, and the worker skips one that has passed rather than writing
/// it. So a worker parked on an engine that has gone quiet cannot build a
/// backlog it then has to work through: on recovery it discards the stale asks
/// without a round trip and reaches the fresh one at once.
enum Request {
    /// Write it and move on; nothing comes back.
    Fire(ControlMsg),
    /// Write it and read the one message that answers it, unless the caller
    /// has already stopped waiting by the time this is reached.
    Ask {
        /// The request to write.
        msg: ControlMsg,
        /// Where the reply goes.
        reply_to: SyncSender<ControlMsg>,
        /// When the caller gives up. Past this, writing the request would only
        /// buy a reply nobody reads.
        give_up_at: Instant,
    },
    /// Stop serving.
    Stop,
}

/// The worker that owns the control socket has stopped, so nothing queued
/// behind this will ever reach the engine.
///
/// It is returned rather than logged and swallowed because the caller can
/// still act on it: an arm that cannot reach the engine must not go on to
/// point the kernel's steering at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineGone;

impl std::fmt::Display for EngineGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the engine control worker has stopped")
    }
}

impl std::error::Error for EngineGone {}

/// A handle onto the engine's control socket.
///
/// Cheap to clone behind an [`std::sync::Arc`] and safe to call from any
/// thread: nothing here touches the socket, it only queues work for the thread
/// that does.
pub struct IpcClient {
    tx: Sender<Request>,
    /// A second reference to the same socket, held only so a handle going away
    /// can break the worker out of a blocking read. Closing `tx` cannot: that
    /// is seen between exchanges, and a worker waiting on an engine that has
    /// stopped answering never reaches one.
    sock: UnixStream,
    /// Set before that socket is shut down, so the worker can tell a teardown
    /// this process asked for from an engine that died under it. Without it
    /// every clean exit would report itself as a failure, and a log that cries
    /// wolf is how the real one gets missed.
    closing: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl IpcClient {
    /// Take ownership of `sock` and start the thread that owns it.
    pub fn new(sock: UnixStream) -> io::Result<Self> {
        let ours = sock.try_clone()?;
        let (tx, rx) = channel::<Request>();
        let closing = Arc::new(AtomicBool::new(false));
        let theirs = closing.clone();
        let worker = std::thread::Builder::new()
            .name("lw-offload-ipc".into())
            .spawn(move || worker_loop(sock, rx, &theirs))?;
        Ok(Self {
            tx,
            sock: ours,
            closing,
            worker: Some(worker),
        })
    }

    /// Install keys for a session, and say where its datagrams go.
    ///
    /// Fire and forget by design: `ExpresslaneCb::update` has nowhere to
    /// report a failure to, and core republishes on every rotation and every
    /// roam anyway. A worker that has stopped is still said out loud, because
    /// a tunnel whose keys stopped reaching the engine goes quiet with nothing
    /// else to point at. Rotations are minutes apart, so this cannot flood.
    pub fn push_keys(
        &self,
        session_id: [u8; 8],
        version: u8,
        lightway_version: [u8; 2],
        self_key: ExpresslaneKey,
        peer_key: ExpresslaneKey,
        peer: SocketAddr,
    ) {
        if self
            .tx
            .send(Request::Fire(ControlMsg::PushKeys {
                session_id,
                version,
                lightway_version,
                self_key,
                peer_key,
                peer,
            }))
            .is_err()
        {
            tracing::error!(?session_id, "{EngineGone}; keys not installed");
        }
    }

    /// Tell the engine to carry the inside path, or to stand down.
    ///
    /// This is the engine's *own* gate, not the kernel's: its TX loop drops
    /// every packet while this is false. The kernel's steering flag is a
    /// separate switch on `InsideSplit`, and both have to agree.
    ///
    /// `Err` means the message was not even queued, so the engine's gate is
    /// whatever it already was. The caller has to treat that as a switch that
    /// did not move - see `OffloadEvents::set` in the client binary, which
    /// refuses to arm the kernel behind an engine it could not reach.
    ///
    /// A queued message is not an acknowledged one: `Ok` says the worker took
    /// it, not that the engine applied it. That window is the same one the
    /// arm/disarm ordering already exists to keep harmless.
    pub fn set_active(&self, active: bool) -> Result<(), EngineGone> {
        self.tx
            .send(Request::Fire(ControlMsg::SetActive { active }))
            .map_err(|_| EngineGone)
    }

    /// Ask for one session's counters, giving up after `timeout`.
    ///
    /// Bounded on purpose, and bounded here rather than on the socket: core
    /// calls this while it holds the connection lock, so an engine that stops
    /// answering must cost a poll and not the tunnel. `None` means no answer
    /// arrived in time, or the socket is gone - it never means zero traffic.
    pub fn stats(&self, session_id: [u8; 8], timeout: Duration) -> Option<ControlMsg> {
        let (reply_tx, reply_rx) = sync_channel(1);
        self.tx
            .send(Request::Ask {
                msg: ControlMsg::StatsRequest { session_id },
                reply_to: reply_tx,
                give_up_at: Instant::now() + timeout,
            })
            .ok()?;
        reply_rx.recv_timeout(timeout).ok()
    }

    /// Stop the worker and wait for it.
    ///
    /// Bounded even against an engine that has stopped answering: the socket
    /// is closed under the worker, which turns its read into end of file at
    /// once. Anything still queued is discarded - this is a shutdown.
    pub fn shutdown(mut self) {
        self.closing.store(true, Ordering::Relaxed);
        let _ = self.tx.send(Request::Stop);
        let _ = self.sock.shutdown(Shutdown::Both);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

impl Drop for IpcClient {
    /// The last handle going away has to end the worker, and dropping `tx`
    /// alone would not: a worker parked in a read never gets back to the
    /// channel to see it closed.
    fn drop(&mut self) {
        self.closing.store(true, Ordering::Relaxed);
        let _ = self.sock.shutdown(Shutdown::Both);
    }
}

/// Serve requests until the channel closes or the socket fails.
///
/// # Why a key push cannot be read as a stats reply
///
/// This is the hazard the whole module exists for, and it rests on four facts:
///
/// 1. One thread writes. Every message onto the socket is written here, in the
///    order this loop takes requests off the channel; no caller ever holds the
///    socket.
/// 2. The engine never speaks unprompted. `Engine::apply` returns a message
///    for `StatsRequest` and for nothing else, so every byte travelling the
///    other way is part of a reply.
/// 3. At most one request is outstanding. A `Fire` writes and moves on without
///    reading; an `Ask` does not return until it has decoded exactly one whole
///    message. So requests and replies are one for one and in order, and the
///    message decoded after a `StatsRequest` is that request's reply.
/// 4. A caller that gave up changes none of this. Either the request was never
///    written - an `Ask` past its deadline is skipped whole - or it was, and
///    its reply is still consumed here, `try_send` failing being ignored on
///    purpose. Both leave the next exchange level rather than one reply behind.
///
/// `pending` therefore carries a *part* of a message between reads and never a
/// whole one, and its size is bounded by [`MAX_CONTROL_MSG_LEN`]: `decode`
/// refuses a declared length no variant can have as soon as the prefix lands.
fn worker_loop(sock: UnixStream, rx: Receiver<Request>, closing: &AtomicBool) {
    // Everything below reports why this thread stopped, except when the answer
    // is "because it was asked to".
    let unexpected = || !closing.load(Ordering::Relaxed);
    // Comfortably past the longest message, which is also what keeps
    // `recv_with_fds` from ever refusing a buffer-filling read.
    let mut buf = [0u8; MAX_CONTROL_MSG_LEN * 4];
    let mut pending: Vec<u8> = Vec::with_capacity(MAX_CONTROL_MSG_LEN);
    let mut out: Vec<u8> = Vec::with_capacity(MAX_CONTROL_MSG_LEN);

    while let Ok(req) = rx.recv() {
        let (msg, reply_to) = match req {
            Request::Stop => return,
            Request::Fire(m) => (m, None),
            // Skipped before it is written, so no reply is ever owed for it
            // and fact 3 above still holds.
            Request::Ask { give_up_at, .. } if Instant::now() >= give_up_at => continue,
            Request::Ask { msg, reply_to, .. } => (msg, Some(reply_to)),
        };

        out.clear();
        msg.encode(&mut out);
        if let Err(e) = send_with_fds(&sock, &out, &[]) {
            // The engine is gone. Returning drops every queued reply channel
            // with it, so a caller waiting on one fails at once instead of
            // serving out its timeout, and every later call fails at the
            // channel. That is the intended signal, not an error to propagate
            // - but it is the last thing this thread does, so if it says
            // nothing the tunnel simply stops being offloaded and no line
            // anywhere says why.
            if unexpected() {
                tracing::warn!(error = %e, "engine control socket write failed; the engine is gone");
            }
            return;
        }

        let Some(reply_to) = reply_to else { continue };

        loop {
            match ControlMsg::decode(&pending) {
                Ok((reply, used)) => {
                    pending.drain(..used);
                    // Ignored deliberately: see fact 4 above.
                    let _ = reply_to.try_send(reply);
                    break;
                }
                Err(IpcError::Incomplete) => {}
                // Not a slow engine and not a dead one: the two binaries
                // disagree about the protocol. Nothing on this socket can be
                // trusted afterwards, and read as "no stats" it looks exactly
                // like an engine under load - which is why it is an error and
                // names the byte that caused it.
                Err(e) => {
                    tracing::error!(
                        error = ?e,
                        "engine control protocol desync; the two binaries disagree"
                    );
                    return;
                }
            }
            // Always empty: the engine passes no descriptors. Anything that
            // did arrive is closed with it rather than leaked.
            let mut fds = Vec::new();
            match recv_with_fds(&sock, &mut buf, &mut fds) {
                Ok(0) => {
                    if unexpected() {
                        tracing::warn!("engine closed the control socket");
                    }
                    return;
                }
                Err(e) => {
                    if unexpected() {
                        tracing::warn!(error = %e, "engine control socket read failed");
                    }
                    return;
                }
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};
    use std::net::Ipv4Addr;

    const SID: [u8; 8] = [0x11; 8];
    const OTHER: [u8; 8] = [0x22; 8];
    const PEER: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 4500);

    /// Stand in for the engine process: run the real control loop on the far
    /// end of a socketpair.
    fn engine_on(sock: UnixStream) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let engine = Engine::new();
            let _ = crate::control::run_engine(&sock, &engine, |_fds| {});
        })
    }

    fn known(reply: ControlMsg) -> ([u8; 8], bool) {
        let ControlMsg::StatsReply {
            session_id,
            known_session,
            ..
        } = reply
        else {
            panic!("wrong reply: {reply:?}")
        };
        (session_id, known_session)
    }

    /// Every caller lives behind an `Arc` shared across threads, so the handle
    /// has to be both.
    #[test]
    fn the_handle_can_be_shared_across_threads() {
        fn require<T: Send + Sync>() {}
        require::<IpcClient>();
    }

    #[test]
    fn a_key_push_reaches_the_engine_and_stats_come_back() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let engine = engine_on(theirs);
        let client = IpcClient::new(ours).unwrap();

        let k = ExpresslaneKey([9; EXPRESSLANE_KEY_SIZE]);
        client.push_keys(SID, 2, [1, 3], k, k, PEER);

        let reply = client
            .stats(SID, Duration::from_secs(2))
            .expect("no reply from the engine");
        let (session_id, known_session) = known(reply);
        assert_eq!(session_id, SID);
        assert!(known_session, "the engine did not take the key push");

        client.shutdown();
        let _ = engine.join();
    }

    /// A session the engine never had must answer `known_session: false`, not
    /// zeros - that distinction is the whole reason the field exists.
    #[test]
    fn stats_for_an_unknown_session_say_so() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let engine = engine_on(theirs);
        let client = IpcClient::new(ours).unwrap();

        let (session_id, known_session) =
            known(client.stats(OTHER, Duration::from_secs(2)).unwrap());
        assert_eq!(session_id, OTHER);
        assert!(!known_session);

        client.shutdown();
        let _ = engine.join();
    }

    /// The engine dying must not hang the caller - core holds the connection
    /// lock across this call.
    #[test]
    fn stats_time_out_rather_than_hanging_when_the_engine_is_gone() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        drop(theirs);
        let client = IpcClient::new(ours).unwrap();

        let started = Instant::now();
        let reply = client.stats(SID, Duration::from_millis(200));
        assert!(reply.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "stats blocked far past its timeout"
        );
        client.shutdown();
    }

    /// The case a closed socket does not cover, and the one core actually
    /// depends on: an engine that takes the request and never answers. Nothing
    /// on the socket ends this - only the caller's own bound does.
    #[test]
    fn stats_stay_bounded_when_the_engine_takes_the_request_and_goes_quiet() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let client = IpcClient::new(ours).unwrap();

        let started = Instant::now();
        assert!(client.stats(SID, Duration::from_millis(200)).is_none());
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(150),
            "gave up before its own bound, so the bound is not what returned: {waited:?}"
        );
        assert!(
            waited < Duration::from_secs(2),
            "blocked past its bound with the connection lock held: {waited:?}"
        );

        // And tearing down must not wait on that read either.
        let closing = Instant::now();
        client.shutdown();
        assert!(
            closing.elapsed() < Duration::from_secs(2),
            "shutdown waited on a read that never ends"
        );
        drop(theirs);
    }

    /// Key pushes and stats share one stream; a push must never be mistaken
    /// for a reply. A one-message desync shows up as a reply naming the
    /// previous request's session, which is why the second ask uses a
    /// different one.
    #[test]
    fn interleaved_pushes_do_not_corrupt_a_stats_reply() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let engine = engine_on(theirs);
        let client = IpcClient::new(ours).unwrap();

        let k = ExpresslaneKey([3; EXPRESSLANE_KEY_SIZE]);
        for _ in 0..50 {
            client.push_keys(SID, 2, [1, 3], k, k, PEER);
        }
        let (session_id, known_session) = known(client.stats(SID, Duration::from_secs(2)).unwrap());
        assert_eq!(session_id, SID, "reply is for the wrong session");
        assert!(known_session);

        for _ in 0..50 {
            client.push_keys(SID, 2, [1, 3], k, k, PEER);
        }
        let (session_id, known_session) =
            known(client.stats(OTHER, Duration::from_secs(2)).unwrap());
        assert_eq!(
            session_id, OTHER,
            "the stream is one reply behind, so a reply is being read for the wrong request"
        );
        assert!(!known_session);

        client.shutdown();
        let _ = engine.join();
    }

    /// A hand-rolled engine that answers the first request only after the
    /// caller has given up on it. Every reply carries its ordinal in `sent`.
    fn late_answering_engine(sock: UnixStream, delay: Duration) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut pending: Vec<u8> = Vec::new();
            let mut answered = 0u64;
            loop {
                let mut fds = Vec::new();
                let n = match recv_with_fds(&sock, &mut buf, &mut fds) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                pending.extend_from_slice(&buf[..n]);
                while let Ok((msg, used)) = ControlMsg::decode(&pending) {
                    pending.drain(..used);
                    let ControlMsg::StatsRequest { session_id } = msg else {
                        continue;
                    };
                    if answered == 0 {
                        std::thread::sleep(delay);
                    }
                    answered += 1;
                    let mut out = Vec::new();
                    ControlMsg::StatsReply {
                        session_id,
                        sent: answered,
                        received: 0,
                        sent_bytes: 0,
                        received_bytes: 0,
                        decrypt_failures: 0,
                        refused: 0,
                        tx_dropped: 0,
                        rx_dropped: 0,
                        known_session: true,
                    }
                    .encode(&mut out);
                    if send_with_fds(&sock, &out, &[]).is_err() {
                        return;
                    }
                }
            }
        })
    }

    /// The corruption the timeout could otherwise introduce: a reply that
    /// arrives after its caller gave up must be consumed here, not handed to
    /// whoever asks next. Without that the stream runs permanently one reply
    /// behind and every later poll reports a stale session's counters.
    #[test]
    fn a_reply_its_caller_gave_up_on_is_not_handed_to_the_next_one() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let engine = late_answering_engine(theirs, Duration::from_millis(300));
        let client = IpcClient::new(ours).unwrap();

        assert!(
            client.stats(SID, Duration::from_millis(50)).is_none(),
            "the first reply is deliberately late; the caller must not wait for it"
        );

        let reply = client
            .stats(OTHER, Duration::from_secs(3))
            .expect("no second reply");
        let ControlMsg::StatsReply {
            session_id, sent, ..
        } = reply
        else {
            panic!("wrong reply: {reply:?}")
        };
        assert_eq!(
            session_id, OTHER,
            "the abandoned reply was handed to the next caller"
        );
        assert_eq!(sent, 2, "the second caller was given the first reply");

        client.shutdown();
        let _ = engine.join();
    }

    /// An engine that goes quiet parks the worker while callers keep queueing.
    /// If those stale asks were written on recovery, the first fresh poll would
    /// wait behind all of them; skipping them makes recovery cost one round
    /// trip regardless of how long the engine was gone.
    #[test]
    fn a_backlog_built_up_while_the_engine_was_quiet_is_not_replayed() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        // Long enough that everything below is queued while the worker is
        // parked on the first reply.
        let engine = late_answering_engine(theirs, Duration::from_millis(500));
        let client = IpcClient::new(ours).unwrap();

        assert!(client.stats(SID, Duration::from_millis(50)).is_none());
        // Queued behind that parked read, and expired long before it ends.
        for _ in 0..20 {
            assert!(client.stats(SID, Duration::from_millis(1)).is_none());
        }

        let reply = client
            .stats(OTHER, Duration::from_secs(3))
            .expect("no reply after the backlog");
        let ControlMsg::StatsReply {
            session_id, sent, ..
        } = reply
        else {
            panic!("wrong reply: {reply:?}")
        };
        assert_eq!(session_id, OTHER);
        assert_eq!(
            sent, 2,
            "the engine was asked {} times, so the expired backlog was replayed",
            sent
        );

        client.shutdown();
        let _ = engine.join();
    }
}
