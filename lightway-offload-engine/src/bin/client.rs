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

/// Translating lightway-core's expresslane callbacks into control messages.
///
/// One `#[cfg]` on the module rather than one per item: everything in here
/// needs the Linux-only library. `dead_code` is allowed for the same reason
/// the module exists ahead of its caller - Task 4 hands these to
/// `lightway_client::ClientConfig`; until then only the tests below reach them.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod offload {
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use lightway_bpf_steering::InsideSplit;
    use lightway_core::{
        Event, EventCallback, ExpresslaneCb, ExpresslaneCbData, ExpresslaneMetrics,
        ExpresslanePacketStats, ExpresslaneState, ExpresslaneStatsError, SessionId, Version,
    };
    use lightway_offload_engine::ipc::ControlMsg;
    use lightway_offload_engine::ipc_client::IpcClient;

    /// How long `get_stats` waits for the engine.
    ///
    /// Small on purpose: lightway-core calls it synchronously while holding
    /// the connection lock, so an engine that stops answering has to cost one
    /// keepalive's counters rather than the tunnel.
    const STATS_BUDGET: Duration = Duration::from_millis(50);

    /// Least time between two "no usable engine stats" lines.
    ///
    /// core asks twice per keepalive for as long as the tunnel lives, so an
    /// engine that has stopped answering is a log loop unless this exists.
    const COMPLAIN_EVERY: Duration = Duration::from_secs(30);

    /// The Lightway protocol version this process's datagrams carry.
    ///
    /// Not negotiated and not a guess: `ClientConnectionBuilder::connect` pins
    /// a client's `tunnel_protocol_version` to `Version::MAXIMUM`, and
    /// `set_tunnel_protocol_version` refuses on a client, so that is what it
    /// stays for the whole connection - and the peer drops any datagram whose
    /// header says otherwise. Read from the constant rather than written out,
    /// so a core that raises its maximum takes the engine with it.
    fn client_lightway_version() -> [u8; 2] {
        [Version::MAXIMUM.major(), Version::MAXIMUM.minor()]
    }

    /// Forwards key rotations to the engine.
    pub struct OffloadCb {
        ipc: Arc<IpcClient>,
        lightway_version: [u8; 2],
    }

    impl OffloadCb {
        /// Build one that pushes over `ipc`.
        pub fn new(ipc: Arc<IpcClient>) -> Self {
            Self {
                ipc,
                lightway_version: client_lightway_version(),
            }
        }
    }

    impl<T> ExpresslaneCb<T> for OffloadCb {
        fn update(&self, session_id: SessionId, data: ExpresslaneCbData, _state: &T) {
            // The callback fires whenever EITHER key changes, so a half key can
            // arrive; the engine skips those, but not sending them is cheaper.
            if data.self_key.is_invalid() || data.peer_key.is_invalid() {
                return;
            }
            self.ipc.push_keys(
                *session_id.as_bytes(),
                data.version.into(),
                self.lightway_version,
                data.self_key,
                data.peer_key,
                data.peer_sockaddr,
            );
        }
    }

    /// How often the zeros have been reported, and how often they have not.
    #[derive(Default)]
    struct Complaints {
        last: Option<Instant>,
        suppressed: u64,
    }

    /// Answers lightway-core's counter reads out of the engine.
    pub struct OffloadMetrics {
        ipc: Arc<IpcClient>,
        complaints: Mutex<Complaints>,
    }

    impl OffloadMetrics {
        /// Build one reading over `ipc`.
        pub fn new(ipc: Arc<IpcClient>) -> Self {
            Self {
                ipc,
                complaints: Mutex::default(),
            }
        }

        /// `Some(suppressed_since_the_last_line)` when it is time to complain.
        ///
        /// A lock rather than atomics: core reaches this twice per keepalive,
        /// from one place, under one lock of its own.
        fn may_complain(&self) -> Option<u64> {
            let mut c = self.complaints.lock().expect("complaint state poisoned");
            if c.last.is_some_and(|at| at.elapsed() < COMPLAIN_EVERY) {
                c.suppressed += 1;
                return None;
            }
            c.last = Some(Instant::now());
            Some(std::mem::take(&mut c.suppressed))
        }
    }

    impl ExpresslaneMetrics for OffloadMetrics {
        fn get_stats(
            &self,
            session_id: SessionId,
        ) -> Result<ExpresslanePacketStats, ExpresslaneStatsError> {
            match self.ipc.stats(*session_id.as_bytes(), STATS_BUDGET) {
                Some(ControlMsg::StatsReply {
                    sent,
                    received,
                    sent_bytes,
                    received_bytes,
                    known_session: true,
                    ..
                }) => Ok(ExpresslanePacketStats {
                    sent_packets: sent,
                    received_packets: received,
                    sent_bytes,
                    received_bytes,
                }),
                Some(ControlMsg::StatsReply {
                    known_session: false,
                    ..
                }) => Err(ExpresslaneStatsError::UnknownSession),
                // No usable reply at all: core skips the health window on an
                // error, but an engine that has stopped answering is still
                // worth a line - core asks twice per keepalive for the life
                // of the connection, so logging every one is a loop.
                other => {
                    if let Some(suppressed) = self.may_complain() {
                        tracing::warn!(
                            ?session_id,
                            answered = other.is_some(),
                            suppressed,
                            "no usable engine stats"
                        );
                    }
                    Err(ExpresslaneStatsError::Temporary)
                }
            }
        }
    }

    /// The kernel steering flag, as the event handler needs it.
    ///
    /// A trait rather than the split itself so the handler can be driven
    /// without CAP_BPF: this flag is the only thing it touches.
    pub trait SteeringFlag: Send + Sync {
        /// Route the inside path at the engine, or back at this process.
        fn set_offload_active(&self, active: bool) -> io::Result<()>;
    }

    impl SteeringFlag for InsideSplit {
        fn set_offload_active(&self, active: bool) -> io::Result<()> {
            InsideSplit::set_offload_active(self, active)
        }
    }

    /// Drives both offload switches off the connection's own state changes.
    ///
    /// There are two of them and they are not the same switch: the engine's TX
    /// loop hard-gates on `SetActive`, and the kernel's BPF steering gates on
    /// the split's own flag. An engine told to go active that the kernel never
    /// steers to sees no packets at all; a kernel steering at an engine that
    /// was never told to go active drops every one of them and moves nothing
    /// but `tx_dropped`. Both read as a tunnel that went quiet, so both are set
    /// from one place.
    pub struct OffloadEvents {
        ipc: Arc<IpcClient>,
        steering: Arc<dyn SteeringFlag>,
        active: bool,
    }

    impl OffloadEvents {
        /// Build one driving `ipc` and `steering`. Both start disarmed, which
        /// is how the engine and the BPF map start too.
        pub fn new(ipc: Arc<IpcClient>, steering: Arc<dyn SteeringFlag>) -> Self {
            Self {
                ipc,
                steering,
                active: false,
            }
        }

        /// Set both switches, in the order that leaves no window where the
        /// kernel is steering at an engine that will not send.
        ///
        /// Arming: the engine first. Disarming: the kernel first. The engine's
        /// half is a queued message rather than an acknowledged one, so a short
        /// window remains either way; it costs packets that `tx_dropped`
        /// counts, not correctness.
        ///
        /// Neither half of a failed flip is latched, so the next transition
        /// tries again rather than acting on a state that was never reached.
        /// Which half is left standing is chosen so that packets keep moving:
        /// whichever switch the failure leaves in force is the one that still
        /// has a path for them.
        ///
        /// Both halves are error-checked, and for the same reason: a kernel
        /// steering inside packets at an engine that was never armed drops
        /// every one of them, and that is true whether the engine refused the
        /// message or was never there to take it.
        fn set(&mut self, active: bool) {
            if active == self.active {
                return;
            }
            if active {
                if let Err(e) = self.ipc.set_active(true) {
                    // Nothing armed the engine, so arming the kernel would
                    // point the inside path at a process that will not carry
                    // it. Stay on D/TLS and do not latch.
                    tracing::error!(error = %e, "engine not armed; staying on D/TLS");
                    return;
                }
                if let Err(e) = self.steering.set_offload_active(true) {
                    // Nothing is being steered at the engine, so it has nothing
                    // to carry; stand it back down and stay as we were. The
                    // inside path is still on queue 0 and this process carries
                    // it over D/TLS.
                    tracing::error!(error = %e, "kernel steering not armed; staying on D/TLS");
                    // Already reported by the arm above if the engine is gone,
                    // and an engine left armed with nothing steered at it is
                    // harmless either way.
                    let _ = self.ipc.set_active(false);
                    return;
                }
            } else {
                if let Err(e) = self.steering.set_offload_active(false) {
                    // The kernel is still steering the inside path at the
                    // engine, which makes the engine the only thing that can
                    // move those packets - they never reach this process at
                    // all. Standing it down here would drop every one of them
                    // and leave a dead tunnel with nothing but `tx_dropped` to
                    // show for it, so leave it armed and try again next time.
                    tracing::error!(error = %e, "kernel steering not disarmed; leaving the engine armed");
                    return;
                }
                // The kernel is already turned away, so the inside path is back
                // on queue 0 whatever the engine does or does not hear. Latch.
                if let Err(e) = self.ipc.set_active(false) {
                    tracing::error!(error = %e, "engine not stood down; the kernel already is");
                }
            }
            self.active = active;
        }
    }

    impl EventCallback for OffloadEvents {
        fn event(&mut self, event: Event) {
            if let Event::ExpresslaneStateChanged(state) = event {
                // Active is the only state in which offloaded traffic is real:
                // Degraded is the D/TLS fallback and the rest are before it.
                self.set(matches!(state, ExpresslaneState::Active));
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey, ExpresslaneVersion};
        use lightway_offload_engine::control::run_engine;
        use lightway_offload_engine::engine::Engine;
        use std::net::{Ipv4Addr, SocketAddr};
        use std::os::unix::net::UnixStream;
        use std::sync::Mutex;

        const SID: [u8; 8] = [0x33; 8];
        const PEER: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 4500);

        /// A socketpair with the real engine on the far end, and the same
        /// engine borrowed back so a test can look at what arrived.
        fn engine_pair() -> (Arc<IpcClient>, Arc<Engine>, std::thread::JoinHandle<()>) {
            let (ours, theirs) = UnixStream::pair().unwrap();
            let engine = Arc::new(Engine::new());
            let far = engine.clone();
            let served = std::thread::spawn(move || {
                let _ = run_engine(&theirs, &far, |_fds| {});
            });
            (Arc::new(IpcClient::new(ours).unwrap()), engine, served)
        }

        fn cb_data(self_key: ExpresslaneKey, peer_key: ExpresslaneKey) -> ExpresslaneCbData {
            ExpresslaneCbData {
                self_key,
                peer_key,
                peer_sockaddr: PEER,
                version: ExpresslaneVersion::Version2,
            }
        }

        fn known(ipc: &IpcClient, session_id: [u8; 8]) -> bool {
            let reply = ipc
                .stats(session_id, Duration::from_secs(2))
                .expect("the engine did not answer");
            let ControlMsg::StatsReply { known_session, .. } = reply else {
                panic!("wrong reply: {reply:?}")
            };
            known_session
        }

        /// A version the peer did not negotiate is dropped by its header check,
        /// with nothing to point at but a dead tunnel. Pin that what goes out
        /// is what a client connection actually speaks, and that core would
        /// still accept it.
        #[test]
        fn the_pushed_lightway_version_is_the_one_a_client_connection_speaks() {
            let v = client_lightway_version();
            assert_eq!(
                Version::try_new(v[0], v[1]),
                Some(Version::MAXIMUM),
                "a client pins tunnel_protocol_version to Version::MAXIMUM"
            );
        }

        /// The whole point of the callback: what core publishes has to arrive
        /// as a session the engine can encrypt for.
        #[test]
        fn a_key_update_reaches_the_engine_as_a_usable_session() {
            let (ipc, engine, served) = engine_pair();
            let cb = OffloadCb::new(ipc.clone());

            let k = ExpresslaneKey([7; EXPRESSLANE_KEY_SIZE]);
            cb.update(SessionId::from_const(SID), cb_data(k, k), &());

            assert!(known(&ipc, SID), "the engine did not take the key push");
            assert_eq!(
                engine.current_session(),
                Some((SID, PEER)),
                "the peer address did not ride with the keys"
            );
            assert!(
                engine.encrypt(SID, b"inside packet", [1; 12]).is_some(),
                "the engine holds the session but cannot encrypt for it"
            );

            drop(cb);
            Arc::into_inner(ipc).expect("one holder left").shutdown();
            let _ = served.join();
        }

        /// The callback fires whenever either key changes, so a half key is a
        /// normal event, not a fault. Sending it would only be skipped later.
        #[test]
        fn a_half_key_is_not_pushed_at_all() {
            let (ipc, _engine, served) = engine_pair();
            let cb = OffloadCb::new(ipc.clone());
            let k = ExpresslaneKey([8; EXPRESSLANE_KEY_SIZE]);

            cb.update(
                SessionId::from_const(SID),
                cb_data(ExpresslaneKey::INVALID, k),
                &(),
            );
            cb.update(
                SessionId::from_const(SID),
                cb_data(k, ExpresslaneKey::INVALID),
                &(),
            );
            assert!(!known(&ipc, SID), "a half key created a session");

            drop(cb);
            Arc::into_inner(ipc).expect("one holder left").shutdown();
            let _ = served.join();
        }

        #[derive(Default)]
        struct RecordingFlag(Mutex<Vec<bool>>);

        impl RecordingFlag {
            fn taken(&self) -> Vec<bool> {
                std::mem::take(&mut *self.0.lock().unwrap())
            }
        }

        impl SteeringFlag for RecordingFlag {
            fn set_offload_active(&self, active: bool) -> io::Result<()> {
                self.0.lock().unwrap().push(active);
                Ok(())
            }
        }

        /// The failure Task 1 left waiting: the engine's TX loop hard-gates on
        /// `SetActive`, so an offload that never sends it is a silent tunnel
        /// with `tx_dropped` climbing. Both switches have to move, and they are
        /// two different mechanisms.
        #[test]
        fn reaching_active_arms_both_switches_and_leaving_it_disarms_them() {
            let (ipc, engine, served) = engine_pair();
            let flag = Arc::new(RecordingFlag::default());
            let mut events = OffloadEvents::new(ipc.clone(), flag.clone());

            assert!(!engine.active(), "the engine must start stood down");

            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Active));
            // One socket, one worker, so a reply proves the SetActive queued
            // ahead of it has already been applied.
            known(&ipc, SID);
            assert!(engine.active(), "the engine was never told to go active");
            assert_eq!(flag.taken(), vec![true], "the kernel was never steered");

            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Degraded));
            known(&ipc, SID);
            assert!(!engine.active(), "degrade left the engine armed");
            assert_eq!(
                flag.taken(),
                vec![false],
                "degrade left the kernel steering"
            );

            // A repeat of the state in force must not churn either switch.
            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Inactive));
            assert!(flag.taken().is_empty(), "an unchanged state moved the flag");

            drop(events);
            Arc::into_inner(ipc).expect("one holder left").shutdown();
            let _ = served.join();
        }

        /// A flag that also records what the *engine's* own gate said at the
        /// moment the kernel flag moved. That is the only way the order of the
        /// two is observable: the engine's half is a queued message, so this
        /// forces it through with a round trip on the same socket - one worker,
        /// so a reply proves everything queued ahead of it has been applied -
        /// and then looks.
        struct OrderingFlag {
            ipc: Arc<IpcClient>,
            engine: Arc<Engine>,
            seen: Mutex<Vec<(bool, bool)>>,
        }

        impl SteeringFlag for OrderingFlag {
            fn set_offload_active(&self, active: bool) -> io::Result<()> {
                let _ = self.ipc.stats([0u8; 8], Duration::from_secs(2));
                self.seen
                    .lock()
                    .unwrap()
                    .push((active, self.engine.active()));
                Ok(())
            }
        }

        /// The ordering the module claims, pinned rather than stated: arming
        /// reaches the engine before the kernel steers at it, and disarming
        /// turns the kernel away before the engine stands down. Either way
        /// round the wrong way leaves a window where the kernel is steering
        /// inside packets at an engine that drops them.
        #[test]
        fn the_engine_is_armed_before_the_kernel_and_stood_down_after_it() {
            let (ipc, engine, served) = engine_pair();
            let flag = Arc::new(OrderingFlag {
                ipc: ipc.clone(),
                engine: engine.clone(),
                seen: Mutex::default(),
            });
            let mut events = OffloadEvents::new(ipc.clone(), flag.clone());

            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Active));
            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Degraded));

            assert_eq!(
                *flag.seen.lock().unwrap(),
                vec![(true, true), (false, true)],
                "the engine must already be armed when the kernel starts \
                 steering, and still armed when it stops"
            );

            drop(events);
            drop(flag);
            Arc::into_inner(ipc).expect("one holder left").shutdown();
            let _ = served.join();
        }

        /// The mirror of `a_kernel_arm_that_fails_stands_the_engine_back_down`,
        /// on the half that used to have no way to fail at all: `set_active`
        /// returned `()`, so an engine that had died took the kernel steering
        /// with it and latched `active`. Every inside packet then goes to a
        /// process that is not there, and the counters say the offload is on.
        #[test]
        fn an_engine_that_is_gone_is_never_steered_at() {
            let (ours, theirs) = UnixStream::pair().unwrap();
            // No peer, so the worker's first write fails and it stops.
            drop(theirs);
            let ipc = Arc::new(IpcClient::new(ours).unwrap());

            let deadline = Instant::now() + Duration::from_secs(5);
            while ipc.set_active(false).is_ok() {
                assert!(Instant::now() < deadline, "the worker never noticed");
                std::thread::sleep(Duration::from_millis(5));
            }

            let flag = Arc::new(RecordingFlag::default());
            let mut events = OffloadEvents::new(ipc.clone(), flag.clone());
            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Active));
            assert!(
                flag.taken().is_empty(),
                "the kernel was steered at an engine that cannot be reached"
            );

            // And it is not latched: a later transition tries again rather than
            // believing an arm that never happened.
            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Degraded));
            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Active));
            assert!(flag.taken().is_empty());
        }

        /// A flag that refuses one direction, to stand in for a BPF map update
        /// that fails.
        struct FlakyFlag {
            fails_on: bool,
            asked: Mutex<Vec<bool>>,
        }

        impl SteeringFlag for FlakyFlag {
            fn set_offload_active(&self, active: bool) -> io::Result<()> {
                self.asked.lock().unwrap().push(active);
                if active == self.fails_on {
                    return Err(io::Error::other("map update refused"));
                }
                Ok(())
            }
        }

        /// The worst state these two switches can reach: the kernel still
        /// steering inside packets at an engine that has been told to stand
        /// down. Those packets never reach this process, so the engine is the
        /// only thing that can move them - standing it down drops every one and
        /// leaves a dead tunnel with nothing but `tx_dropped` to show for it.
        #[test]
        fn a_kernel_disarm_that_fails_leaves_the_engine_carrying_traffic() {
            let (ipc, engine, served) = engine_pair();
            let flag = Arc::new(FlakyFlag {
                fails_on: false,
                asked: Mutex::default(),
            });
            let mut events = OffloadEvents::new(ipc.clone(), flag.clone());

            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Active));
            known(&ipc, SID);
            assert!(engine.active());

            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Degraded));
            known(&ipc, SID);
            assert!(
                engine.active(),
                "the kernel is still steering at the engine, so standing it \
                 down drops every inside packet"
            );

            // And the failure must not latch: the next transition tries again
            // rather than believing a disarm that never happened.
            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Inactive));
            assert_eq!(
                *flag.asked.lock().unwrap(),
                vec![true, false, false],
                "a failed disarm was never retried"
            );

            drop(events);
            Arc::into_inner(ipc).expect("one holder left").shutdown();
            let _ = served.join();
        }

        /// The mirror case, where the safe direction is the other one: nothing
        /// is being steered at the engine, so it has nothing to carry and the
        /// inside path is still this process's over D/TLS. Leaving the engine
        /// armed would only disagree with the kernel for no gain.
        #[test]
        fn a_kernel_arm_that_fails_stands_the_engine_back_down() {
            let (ipc, engine, served) = engine_pair();
            let flag = Arc::new(FlakyFlag {
                fails_on: true,
                asked: Mutex::default(),
            });
            let mut events = OffloadEvents::new(ipc.clone(), flag.clone());

            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Active));
            known(&ipc, SID);
            assert!(
                !engine.active(),
                "the kernel steers nothing here, so an armed engine is a \
                 disagreement with no upside"
            );

            // Not latched either, so the state can still be reached later.
            events.event(Event::ExpresslaneStateChanged(ExpresslaneState::Active));
            assert_eq!(
                *flag.asked.lock().unwrap(),
                vec![true, true],
                "a failed arm was never retried"
            );

            drop(events);
            Arc::into_inner(ipc).expect("one holder left").shutdown();
            let _ = served.join();
        }

        /// A missing reply from an engine that cannot answer is reported as a
        /// transient failure, never as zeros - and core asks twice per
        /// keepalive for the life of the connection, so logging every one of
        /// them is a loop that buries everything else.
        #[test]
        fn an_engine_that_cannot_answer_does_not_become_a_log_loop() {
            let (ours, theirs) = UnixStream::pair().unwrap();
            drop(theirs);
            let metrics = OffloadMetrics::new(Arc::new(IpcClient::new(ours).unwrap()));

            for _ in 0..100 {
                assert!(matches!(
                    metrics.get_stats(SessionId::from_const(SID)),
                    Err(ExpresslaneStatsError::Temporary)
                ));
            }

            let c = metrics.complaints.lock().unwrap();
            assert!(
                c.last.is_some(),
                "the first failure must always be reported"
            );
            assert_eq!(
                c.suppressed, 99,
                "every failure after the first must be folded into the next line"
            );
        }

        /// A session the engine does not hold is a different fault from an
        /// engine that cannot answer, and never the engine's totals or zeros.
        #[test]
        fn an_unknown_session_reports_unknown_rather_than_the_engines_totals() {
            let (ipc, _engine, served) = engine_pair();
            let metrics = OffloadMetrics::new(ipc.clone());

            assert!(matches!(
                metrics.get_stats(SessionId::from_const(SID)),
                Err(ExpresslaneStatsError::UnknownSession)
            ));
            assert!(
                metrics.complaints.lock().unwrap().last.is_none(),
                "an unknown session is not a missing-reply complaint"
            );

            drop(metrics);
            Arc::into_inner(ipc).expect("one holder left").shutdown();
            let _ = served.join();
        }

        /// lightway-client takes these behind `Arc<dyn ... + Send + Sync>` and
        /// an owned `EventCallback`; a type that does not fit only fails where
        /// it is handed over, which is Task 4.
        #[test]
        fn the_callbacks_fit_the_bounds_lightway_client_asks_for() {
            let (ipc, _engine, served) = engine_pair();

            let _cb: Arc<dyn ExpresslaneCb<()> + Send + Sync> =
                Arc::new(OffloadCb::new(ipc.clone()));
            let _metrics: Arc<dyn ExpresslaneMetrics + Send + Sync> =
                Arc::new(OffloadMetrics::new(ipc.clone()));
            let events: Box<dyn EventCallback + Send + Sync> = Box::new(OffloadEvents::new(
                ipc.clone(),
                Arc::new(RecordingFlag::default()),
            ));

            drop((_cb, _metrics, events));
            Arc::into_inner(ipc).expect("one holder left").shutdown();
            let _ = served.join();
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use lightway_offload_engine::ipc_client::IpcClient;

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

    // Task 4 replaces this with the real client. What it proves today is the
    // piece Task 3 adds: a request and the reply to it crossing the socket
    // between the two processes, over the descriptor the child inherited.
    let ipc = IpcClient::new(control)?;
    let Some(reply) = ipc.stats([0u8; 8], Duration::from_secs(2)) else {
        return Err(io::Error::other(
            "the engine did not answer a stats request; the control channel is one-way",
        ));
    };
    tracing::info!(?reply, "engine answered over the control socket");

    // Shutting the socket is what lets the engine's control loop see EOF and
    // return, so it must happen before the wait below, not after: waiting
    // first would deadlock against an engine still blocked reading a socket
    // this process never let go of.
    ipc.shutdown();
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
