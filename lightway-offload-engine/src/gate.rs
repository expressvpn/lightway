//! Whether traffic actually took the offloaded path.
//!
//! **This proves STEERING, never DELIVERY.** Every input below is a count of
//! where the kernel *sent* a packet. Nothing here asks whether anything at the
//! other end of that path did something useful with it, and the gate passes
//! sessions where nothing did: give the client a `--tun-local-ip` the server
//! did not assign it and the engine encrypts and steers every packet exactly
//! as it should, `offloaded` comes back true, the process exits 0 - and 100%
//! of the traffic is dropped at the far end for an address that is not the
//! tunnel's. That is a live counter-example, not a hypothetical. A green gate
//! means "the fast path carried it", never "the fast path worked"; only a
//! reachability check on the traffic itself can say the second.
//!
//! A working D/TLS fallback is exactly why these bugs stay invisible: the
//! tunnel keeps working while the thing under test does nothing. What follows
//! is what each input here can and cannot prove, because the three are not
//! equally strong and reporting them as one number would be its own kind of
//! silence.
//!
//! - `outside_engine` is **peer-corroborated**. A datagram lands there only
//!   because the peer sent one carrying the ExpressLane flag and the kernel's
//!   reuseport program classified it. No amount of local misconfiguration
//!   manufactures one.
//! - `inside_engine` is **this process's own assertion**. `inside.bpf.c` picks
//!   the engine queue on the `offload_active` map entry alone, and process A
//!   is what writes that entry, so the counter says "A armed the flag and
//!   something was transmitted" and nothing whatever about the peer. A tunnel
//!   whose download side is dead still moves it.
//! - `left_active_after_arming` comes from lightway-core's own state machine,
//!   not from a counter at all, and is the only input that can see *when*
//!   something happened. The counters are cumulative and read once at exit, so
//!   without it a session that reached Active, moved one packet and then spent
//!   the rest of its life degraded to D/TLS is indistinguishable from one that
//!   was offloaded throughout - which is the production failure this gate is
//!   named for.

use std::sync::atomic::{AtomicBool, Ordering};

use lightway_bpf_steering::{InsideSplit, OutsideSplit};

/// What the connection's ExpressLane state machine did over the session.
///
/// Shared with the event handler, which is moved into lightway-client and
/// never comes back, so the answer has to be reachable from somewhere both
/// sides hold.
#[derive(Debug, Default)]
pub struct ArmingLog {
    reached: AtomicBool,
    left: AtomicBool,
}

impl ArmingLog {
    /// Note that ExpressLane is, or is no longer, Active.
    ///
    /// Sticky: a fast path that recovers has still been down, and a session
    /// that flaps is a bug worth failing for, so nothing here clears `left`.
    pub fn record(&self, active: bool) {
        if active {
            self.reached.store(true, Ordering::Relaxed);
        } else if self.reached.load(Ordering::Relaxed) {
            self.left.store(true, Ordering::Relaxed);
        }
    }

    /// Did ExpressLane reach Active and then leave it?
    pub fn left_active_after_arming(&self) -> bool {
        self.left.load(Ordering::Relaxed)
    }
}

/// A snapshot of what the kernel steered, and what the state machine did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Inside packets steered to the engine queue. Process A's own assertion -
    /// see the module docs.
    pub inside_engine: u64,
    /// Inside packets left on the control queue.
    pub inside_control: u64,
    /// Datagrams delivered to the engine socket. Peer-corroborated.
    pub outside_engine: u64,
    /// Datagrams delivered to the control socket.
    pub outside_control: u64,
    /// Datagrams where reuseport selection failed and the kernel fell back to
    /// hash. Nonzero means the split is not doing what it claims.
    pub outside_failed: u64,
    /// ExpressLane reached Active and then left it, so some unknown part of
    /// this session ran over D/TLS. Filled in by [`verdict`] out of the
    /// [`ArmingLog`] it requires; the counters cannot see it.
    pub left_active_after_arming: bool,
}

impl Verdict {
    /// Fold in what the connection's state machine did.
    ///
    /// Private, and that is the point. It used to be a public `self`-taking
    /// step a caller had to remember, and forgetting it left the field at its
    /// `false` default - which silently voids the one veto no counter can
    /// replace. [`verdict`] takes the log as an argument instead, so there is
    /// no way to build a `Verdict` from the maps without it.
    fn with_arming_log(mut self, log: &ArmingLog) -> Self {
        self.left_active_after_arming = log.left_active_after_arming();
        self
    }

    /// True when the offload was in force for the whole session, and the
    /// kernel steered to the engine at least once while it was.
    ///
    /// *Either* direction counts, not both. The two directions are driven by
    /// whatever the user's traffic happened to be: a session that only
    /// uploaded moves `inside_engine` and may never move `outside_engine`, and
    /// a session that only downloaded does the reverse. Demanding both would
    /// fail runs where the offload worked perfectly, and a gate that cries
    /// wolf gets turned off - which costs more than it ever caught. Note what
    /// this trades away: `inside_engine` alone is process A asserting that it
    /// armed the flag, so a session that passes on that counter alone has not
    /// shown the peer doing anything.
    ///
    /// The other two are vetoes rather than evidence, and each covers a way
    /// the counters can be true and meaningless:
    ///
    /// - `outside_failed` counts datagrams for which
    ///   `bpf_sk_select_reuseport` refused the program's choice and the kernel
    ///   delivered by its own hash instead. For that many datagrams the split
    ///   was not in force and either socket could have received them, so no
    ///   count taken from it proves where anything went.
    /// - `left_active_after_arming` covers *time*. The counters are cumulative
    ///   and read once, at exit, so one offloaded packet followed by an hour
    ///   of D/TLS reads identically to an hour of offload. That is the exact
    ///   shape of the failure this gate exists for, and no counter can see it.
    pub fn offloaded(&self) -> bool {
        !self.left_active_after_arming
            && self.outside_failed == 0
            && (self.inside_engine > 0 || self.outside_engine > 0)
    }
}

/// Read both splits' counters, and what the state machine did alongside them.
///
/// A counter that cannot be read at all reads as zero, which fails the gate.
/// That is the safe direction for something whose whole job is to notice that
/// the offload did not happen: an unreadable map is not evidence that it did.
///
/// `arming` is an argument rather than a later step because it is the only
/// input that can see *when* the offload was in force, and a caller that
/// forgets it gets a verdict that passes sessions which degraded after one
/// packet - the exact failure this gate is named for.
pub fn verdict(inside: &InsideSplit, outside: &OutsideSplit, arming: &ArmingLog) -> Verdict {
    let i = inside.counts().unwrap_or([0; 2]);
    let o = outside.counts().unwrap_or([0; 3]);
    Verdict {
        inside_control: i[0],
        inside_engine: i[1],
        outside_control: o[0],
        outside_engine: o[1],
        outside_failed: o[2],
        // Not a counter, and not knowable from either map.
        left_active_after_arming: false,
    }
    .with_arming_log(arming)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure the gate exists for: the tunnel came up, carried the whole
    /// session over D/TLS, and nothing ever reached the engine.
    #[test]
    fn a_session_that_never_left_dtls_does_not_count_as_offloaded() {
        let v = Verdict {
            inside_control: 20_000,
            outside_control: 18_000,
            ..Default::default()
        };
        assert!(!v.offloaded());
    }

    /// One-directional traffic is a real session, not a fault, and it moves
    /// only one of the two counters.
    #[test]
    fn either_direction_alone_is_enough() {
        let upload = Verdict {
            inside_engine: 1,
            ..Default::default()
        };
        let download = Verdict {
            outside_engine: 1,
            ..Default::default()
        };
        assert!(upload.offloaded(), "an upload-only session must pass");
        assert!(download.offloaded(), "a download-only session must pass");
    }

    /// A single failed selection means that datagram went wherever the kernel
    /// hash sent it, so the split was not in force and the counts beside it
    /// prove nothing.
    #[test]
    fn a_split_that_was_not_in_force_fails_however_much_it_steered() {
        let v = Verdict {
            inside_engine: 1_000_000,
            outside_engine: 1_000_000,
            outside_failed: 1,
            ..Default::default()
        };
        assert!(!v.offloaded());
    }

    /// The failure the counters cannot see. Cumulative totals read once at
    /// exit make "offloaded for a moment, then degraded for an hour" identical
    /// to "offloaded throughout" - and the first is the production bug.
    #[test]
    fn a_session_that_degraded_after_one_packet_fails_however_large_the_totals() {
        let v = Verdict {
            inside_engine: 1_000_000,
            outside_engine: 1_000_000,
            left_active_after_arming: true,
            ..Default::default()
        };
        assert!(
            !v.offloaded(),
            "a session that dropped back to D/TLS passed on stale totals"
        );
    }

    /// Reaching Active and staying there is the whole point; only *leaving* it
    /// is the fault.
    #[test]
    fn the_log_distinguishes_never_arming_from_arming_and_falling_back() {
        let never = ArmingLog::default();
        never.record(false);
        never.record(false);
        assert!(
            !never.left_active_after_arming(),
            "a session that never reached Active has not left it"
        );

        let held = ArmingLog::default();
        held.record(true);
        held.record(true);
        assert!(!held.left_active_after_arming());

        let degraded = ArmingLog::default();
        degraded.record(true);
        degraded.record(false);
        assert!(degraded.left_active_after_arming());

        // Sticky: recovering does not undo having been down.
        degraded.record(true);
        assert!(
            degraded.left_active_after_arming(),
            "a fast path that flapped still spent part of the session down"
        );
    }

    /// A session that reached Active and stayed there must read exactly as one
    /// that was never asked about, or every clean run would fail the veto.
    #[test]
    fn folding_in_a_clean_log_changes_nothing() {
        let log = ArmingLog::default();
        log.record(true);
        let v = Verdict {
            outside_engine: 1,
            ..Default::default()
        };
        assert_eq!(v.with_arming_log(&log), v);
        assert!(v.with_arming_log(&log).offloaded());
    }

    /// The veto used to be an opt-in step after `verdict`, so forgetting it
    /// left `left_active_after_arming` at `false` and silently passed the one
    /// failure no counter can see. It is an argument now: this pins that the
    /// log is what fills the field, whatever the maps said.
    #[test]
    fn the_arming_log_is_not_something_a_caller_can_forget() {
        let degraded = ArmingLog::default();
        degraded.record(true);
        degraded.record(false);

        let from_maps = Verdict {
            inside_engine: 1_000_000,
            outside_engine: 1_000_000,
            ..Default::default()
        };
        assert!(
            from_maps.offloaded(),
            "the counters alone say this session was offloaded throughout"
        );
        assert!(
            !from_maps.with_arming_log(&degraded).offloaded(),
            "the log has to be able to overrule them"
        );
    }
}
