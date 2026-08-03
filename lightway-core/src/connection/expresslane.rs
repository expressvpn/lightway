use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::SessionId;
use crate::wire::{ExpresslaneData, ExpresslaneKey, ExpresslaneVersion};

/// Data published when expresslane keys are updated.
#[derive(Debug)]
pub struct ExpresslaneCbData {
    /// Self key
    pub self_key: ExpresslaneKey,
    /// Peer key
    pub peer_key: ExpresslaneKey,
    /// Peer socket address
    pub peer_sockaddr: SocketAddr,
    /// Negotiated expresslane wire version
    pub version: ExpresslaneVersion,
}

/// Callback trait for expresslane key updates.
///
/// Generic over `AppState` so consumers can read connection state directly
/// (e.g. server reads `internal_ip` from its `ConnectionState`).
pub trait ExpresslaneCb<AppState> {
    /// Called when expresslane keys are updated for a session.
    fn update(&self, session_id: SessionId, data: ExpresslaneCbData, state: &AppState);
}

/// Convenience type for [`ExpresslaneCb`] trait objects.
pub type ExpresslaneCbType<AppState> = Arc<dyn ExpresslaneCb<AppState> + Sync + Send>;

/// Default interval between expresslane key rotations
pub const DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL: Duration = Duration::from_mins(15);

/// Strike-bucket level at which a direction degrades expresslane. A single
/// over-threshold window can be an artifact of bursty traffic straddling
/// the peer's counter snapshot, so one is never enough.
pub(crate) const EXPRESSLANE_DEGRADE_STRIKES: u8 = 3;

/// Packet counters for ExpressLane health monitoring.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExpresslanePacketStats {
    /// Total packets sent via expresslane
    pub sent_packets: u64,
    /// Total packets received via expresslane
    pub received_packets: u64,
    /// Total bytes sent via expresslane
    pub sent_bytes: u64,
    /// Total bytes received via expresslane
    pub received_bytes: u64,
}

/// Provider of ExpressLane packet metrics.
///
/// When expresslane encryption/decryption is offloaded, the userspace
/// packet counters stay at zero. Implementors of this trait supply the
/// real packet counters from wherever the offload happens.
pub trait ExpresslaneMetrics {
    /// Returns cumulative packet counters for the given session.
    fn get_stats(&self, session_id: SessionId) -> ExpresslanePacketStats;
}

/// Convenience type for [`ExpresslaneMetrics`] trait objects.
pub type ExpresslaneMetricsType = Arc<dyn ExpresslaneMetrics + Send + Sync>;

/// Expresslane state machine and connection-level state.
///
/// Groups all expresslane-related connection state: the state machine,
/// config exchange tracking, health monitoring snapshots, the wire-level
/// crypto engine, and the key update callback.
pub(crate) struct Expresslane<AppState: Send> {
    /// Current expresslane state
    pub(crate) state: ExpresslaneState,
    /// Counter value last sent in the ExpresslaneConfig message
    pub(crate) config_counter: u64,
    /// Number of retransmissions done with the latest pending expresslane config packet
    pub(crate) retransmit_count: u8,
    /// Last key rotation timestamp
    pub(crate) last_key_rotation: Option<Instant>,
    /// Peer's total packets sent as of the last received Pong
    pub(crate) prev_peer_sent: u64,
    /// Peer's total packets received as of the last received Pong
    pub(crate) prev_peer_recv: u64,
    /// Packets sent at the time of last keepalive exchange
    pub(crate) last_snapshot_sent: u64,
    /// Packets received at the time of last keepalive exchange
    pub(crate) last_snapshot_recv: u64,
    /// Inbound loss strike bucket; +1 per bad window, -1 per good one
    pub(crate) inbound_strikes: u8,
    /// Outbound loss strike bucket; +1 per bad window, -1 per good one
    pub(crate) outbound_strikes: u8,
    /// Wire-level crypto engine (encrypt/decrypt/serialize)
    pub(crate) data: ExpresslaneData,
    /// Callback invoked on session key updates so the application can
    /// propagate them to an external consumer.
    pub(crate) cb: Option<ExpresslaneCbType<AppState>>,
    /// External metrics provider
    pub(crate) metrics: Option<ExpresslaneMetricsType>,
    /// Interval between expresslane key rotations
    pub(crate) keys_rotation_interval: Duration,
}

impl<AppState: Send> Expresslane<AppState> {
    pub(crate) fn new(
        state: ExpresslaneState,
        cb: Option<ExpresslaneCbType<AppState>>,
        metrics: Option<ExpresslaneMetricsType>,
        keys_rotation_interval: Duration,
    ) -> Self {
        Self {
            state,
            config_counter: 0,
            retransmit_count: 0,
            last_key_rotation: None,
            prev_peer_sent: 0,
            prev_peer_recv: 0,
            last_snapshot_sent: 0,
            last_snapshot_recv: 0,
            inbound_strikes: 0,
            outbound_strikes: 0,
            data: ExpresslaneData::default(),
            cb,
            metrics,
            keys_rotation_interval,
        }
    }

    /// Get current Expresslane packet stats
    pub(crate) fn stats(&self, session_id: SessionId) -> (u64, u64) {
        match &self.metrics {
            Some(provider) => {
                let stats = provider.get_stats(session_id);
                (stats.sent_packets, stats.received_packets)
            }
            None => (self.data.packets_sent(), self.data.packets_received()),
        }
    }

    pub(crate) fn retransmit_wait_time(&self) -> Duration {
        const INITIAL_WAIT_TIME: Duration = Duration::from_millis(500);
        INITIAL_WAIT_TIME * ((1 + self.retransmit_count) as u32)
    }

    pub(crate) fn time_to_rotate_key(&self) -> bool {
        match self.last_key_rotation {
            None => true,
            Some(last) => last.elapsed() > self.keys_rotation_interval,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::MAX_RETRANSMISSION_ATTEMPTS;

    const ROTATION_INTERVAL: Duration = Duration::from_secs(15 * 60);

    fn expresslane() -> Expresslane<()> {
        Expresslane::new(ExpresslaneState::Inactive, None, None, ROTATION_INTERVAL)
    }

    /// A config exchange that burns its whole budget leaves the counter at
    /// MAX. Without a reset the next exchange schedules one 3s tick that
    /// immediately re-enters the exhaustion branch, spending no retransmits.
    #[test]
    fn exhausted_budget_leaves_a_single_shot_wait() {
        let mut xp = expresslane();
        assert_eq!(xp.retransmit_wait_time(), Duration::from_millis(500));

        xp.retransmit_count = MAX_RETRANSMISSION_ATTEMPTS;
        assert_eq!(xp.retransmit_wait_time(), Duration::from_secs(3));

        xp.retransmit_count = 0;
        assert_eq!(xp.retransmit_wait_time(), Duration::from_millis(500));
    }

    #[test]
    fn wait_time_grows_with_each_attempt() {
        let mut xp = expresslane();
        let mut prev = Duration::ZERO;
        for attempt in 0..=MAX_RETRANSMISSION_ATTEMPTS {
            xp.retransmit_count = attempt;
            let wait = xp.retransmit_wait_time();
            assert!(wait > prev, "attempt {attempt} did not back off: {wait:?}");
            prev = wait;
        }
    }

    /// The rotation stamp is taken before the peer has acked. Clearing it on
    /// the timeout path is what lets the next inside packet re-arm.
    #[test]
    fn cleared_stamp_reopens_the_rotation_gate() {
        let mut xp = expresslane();
        assert!(xp.time_to_rotate_key(), "first rotation is always allowed");

        xp.last_key_rotation = Some(Instant::now());
        assert!(
            !xp.time_to_rotate_key(),
            "a fresh stamp holds the gate shut for the rotation interval"
        );

        xp.last_key_rotation = None;
        assert!(xp.time_to_rotate_key());
    }
}

/// Expresslane connection state
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExpresslaneState {
    /// Expresslane not enabled in config
    #[default]
    Disabled,
    /// Server side: Waiting for client to initiate key exchange
    WaitingForClient,
    /// Expresslane enabled but handshake not completed
    Inactive,
    /// Expresslane enabled and in use
    Active,
    /// Expresslane enabled but degraded, falling back to D/TLS
    Degraded,
}
