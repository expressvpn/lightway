use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::SessionId;
use crate::wire::{ExpresslaneData, ExpresslaneKey};

/// Data published when expresslane keys are updated.
#[derive(Debug)]
pub struct ExpresslaneCbData {
    /// Self key
    pub self_key: ExpresslaneKey,
    /// Peer key
    pub peer_key: ExpresslaneKey,
}

/// Callback trait for expresslane key updates.
pub trait ExpresslaneCb {
    /// Called when expresslane keys are updated for a session.
    fn update(&self, session_id: SessionId, data: ExpresslaneCbData);
}

/// Convenience type for [`ExpresslaneCb`] trait objects.
pub type ExpresslaneCbType = Arc<dyn ExpresslaneCb + Sync + Send>;

/// Interval between expresslane key rotations
pub(crate) const EXPRESSLANE_KEYS_ROTATION_INTERVAL: Duration = Duration::from_secs(60 * 15);

/// Packet counters for ExpressLane health monitoring.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExpresslanePacketStats {
    /// Total sent via expresslane
    pub sent: u64,
    /// Total received via expresslane
    pub received: u64,
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
pub(crate) struct Expresslane {
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
    /// Wire-level crypto engine (encrypt/decrypt/serialize)
    pub(crate) data: ExpresslaneData,
    /// Callback invoked on session key updates so the application can
    /// propagate them to an external consumer.
    pub(crate) cb: Option<ExpresslaneCbType>,
    /// External metrics provider
    pub(crate) metrics: Option<ExpresslaneMetricsType>,
}

impl Expresslane {
    pub(crate) fn new(
        state: ExpresslaneState,
        cb: Option<ExpresslaneCbType>,
        metrics: Option<ExpresslaneMetricsType>,
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
            data: ExpresslaneData::default(),
            cb,
            metrics,
        }
    }

    /// Get current Expresslane packet stats
    pub(crate) fn stats(&self, session_id: SessionId) -> (u64, u64) {
        match &self.metrics {
            Some(provider) => {
                let stats = provider.get_stats(session_id);
                (stats.sent, stats.received)
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
            Some(last) => last.elapsed() > EXPRESSLANE_KEYS_ROTATION_INTERVAL,
        }
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
