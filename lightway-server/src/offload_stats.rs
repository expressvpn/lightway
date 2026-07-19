use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use lightway_core::{ExpresslaneMetricsType, ExpresslanePacketStats, SessionId};
use tokio_stream::StreamExt;

use crate::connection_manager::ConnectionManager;

/// Per-session cumulative counters last observed by the poll.
#[derive(Clone, Copy, Default)]
struct Seen {
    sent_packets: u64,
    received_packets: u64,
    sent_bytes: u64,
    received_bytes: u64,
}

/// Decide what a poll tick does for one session given the previous observation
/// (None = first time seen) and the current cumulative stats. Returns
/// (rx_active, tx_active, rx_bytes_delta, tx_bytes_delta). First observation
/// records a baseline and does nothing (all false / 0) so a rotation - where a
/// new session id inherits carried-over cumulative counters - can't spike.
fn decide(prev: Option<Seen>, cur: ExpresslanePacketStats) -> (bool, bool, u64, u64) {
    match prev {
        None => (false, false, 0, 0),
        Some(p) => {
            let rx = cur.received_packets > p.received_packets;
            let tx = cur.sent_packets > p.sent_packets;
            let rx_bytes = cur.received_bytes.saturating_sub(p.received_bytes);
            let tx_bytes = cur.sent_bytes.saturating_sub(p.sent_bytes);
            (rx, tx, rx_bytes, tx_bytes)
        }
    }
}

/// Default interval between offload-stats polls.
pub const DEFAULT_OFFLOAD_STATS_INTERVAL: Duration = Duration::from_secs(30);

/// Periodically pull each online session's kernel-offload counters via the
/// ExpresslaneMetrics provider and (a) refresh the connection activity
/// timestamps so offloaded sessions classify active / don't idle-evict, and
/// (b) emit aggregate offload byte metrics. Kernel-ref-free: the ioctl lives
/// behind `metrics`.
pub(crate) async fn run(
    conn_manager: Arc<ConnectionManager>,
    metrics: ExpresslaneMetricsType,
    interval: Duration,
) {
    let weak = Arc::downgrade(&conn_manager);
    let mut seen: HashMap<SessionId, Seen> = HashMap::new();

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticker = tokio_stream::wrappers::IntervalStream::new(ticker);

    while ticker.next().await.is_some() {
        let Some(conn_manager) = weak.upgrade() else {
            return;
        };
        let conns = conn_manager.online_connections();
        let mut live: std::collections::HashSet<SessionId> = std::collections::HashSet::new();

        for conn in conns {
            let sid = conn.session_id();
            live.insert(sid);
            let cur = metrics.get_stats(sid);
            let (rx, tx, rx_bytes, tx_bytes) = decide(seen.get(&sid).copied(), cur);
            if rx || tx {
                conn.mark_offload_activity(rx, tx);
            }
            if rx_bytes > 0 {
                crate::metrics::expresslane_offload_rx_bytes(rx_bytes);
            }
            if tx_bytes > 0 {
                crate::metrics::expresslane_offload_tx_bytes(tx_bytes);
            }
            seen.insert(
                sid,
                Seen {
                    sent_packets: cur.sent_packets,
                    received_packets: cur.received_packets,
                    sent_bytes: cur.sent_bytes,
                    received_bytes: cur.received_bytes,
                },
            );
        }
        seen.retain(|sid, _| live.contains(sid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(sent: u64, received: u64, sb: u64, rb: u64) -> ExpresslanePacketStats {
        ExpresslanePacketStats {
            sent_packets: sent,
            received_packets: received,
            sent_bytes: sb,
            received_bytes: rb,
        }
    }

    #[test]
    fn first_seen_is_baseline_only() {
        assert_eq!(decide(None, stats(5, 9, 500, 900)), (false, false, 0, 0));
    }

    #[test]
    fn rx_and_tx_deltas() {
        let prev = Some(Seen {
            sent_packets: 5,
            received_packets: 9,
            sent_bytes: 500,
            received_bytes: 900,
        });
        assert_eq!(decide(prev, stats(5, 12, 500, 1200)), (true, false, 300, 0));
        assert_eq!(decide(prev, stats(8, 9, 800, 900)), (false, true, 0, 300));
    }

    #[test]
    fn no_growth_is_noop() {
        let prev = Some(Seen {
            sent_packets: 5,
            received_packets: 9,
            sent_bytes: 500,
            received_bytes: 900,
        });
        assert_eq!(decide(prev, stats(5, 9, 500, 900)), (false, false, 0, 0));
    }
}
