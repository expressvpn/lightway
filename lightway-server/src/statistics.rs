use lightway_core::{ConnectionActivity, ExpresslaneState};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio_stream::StreamExt;
use tracing::info;

use crate::{
    connection_manager::ConnectionManager,
    ip_manager::IpManager,
    metrics::{self, ConnectionIntervalStats, ExpresslaneSessionStats},
};

/// Default interval between statistics reports
pub const DEFAULT_STATISTICS_REPORTING_INTERVAL: Duration = Duration::from_secs(30);

const FIVE_MINUTES: Duration = Duration::from_mins(5);
const FIFTEEN_MINUTES: Duration = Duration::from_mins(15);
const SIXTY_MINUTES: Duration = Duration::from_hours(1);

/// Return is (standby, active)
fn calculate_session_stats(
    current_sessions: &[ConnectionActivity],
) -> (ConnectionIntervalStats, ConnectionIntervalStats) {
    let now = std::time::Instant::now();

    let mut standby: ConnectionIntervalStats = Default::default();
    let mut active: ConnectionIntervalStats = Default::default();

    for activity in current_sessions {
        let last_outside_data_received = now.duration_since(activity.last_outside_data_received);
        let last_data_traffic_from_peer = now.duration_since(activity.last_data_traffic_from_peer);

        // Count sessions that have received data but not outgoing traffic
        if last_outside_data_received <= FIVE_MINUTES && last_data_traffic_from_peer > FIVE_MINUTES
        {
            standby.five_minutes += 1;
        }
        if last_outside_data_received <= FIFTEEN_MINUTES
            && last_data_traffic_from_peer > FIFTEEN_MINUTES
        {
            standby.fifteen_minutes += 1;
        }
        if last_outside_data_received <= SIXTY_MINUTES
            && last_data_traffic_from_peer > SIXTY_MINUTES
        {
            standby.sixty_minutes += 1;
        }

        // Count sessions that have received outgoing traffic
        if last_data_traffic_from_peer <= FIVE_MINUTES {
            active.five_minutes += 1;
        }
        if last_data_traffic_from_peer <= FIFTEEN_MINUTES {
            active.fifteen_minutes += 1;
        }
        if last_data_traffic_from_peer <= SIXTY_MINUTES {
            active.sixty_minutes += 1;
        }
    }

    (standby, active)
}

fn calculate_expresslane_stats(states: &[ExpresslaneState]) -> ExpresslaneSessionStats {
    let mut stats: ExpresslaneSessionStats = Default::default();

    for state in states {
        match state {
            ExpresslaneState::Disabled => stats.disabled += 1,
            ExpresslaneState::WaitingForClient => stats.waiting_for_client += 1,
            ExpresslaneState::Inactive => stats.inactive += 1,
            ExpresslaneState::Active => stats.active += 1,
            ExpresslaneState::Degraded => stats.degraded += 1,
        }
    }

    stats
}

/// Connections with expresslane active which also had data traffic
/// (as counted by `sessions_active_5m`) in the most recent five minutes.
fn calculate_expresslane_active_5m(sessions: &[(ConnectionActivity, ExpresslaneState)]) -> usize {
    let now = std::time::Instant::now();

    sessions
        .iter()
        .filter(|(activity, state)| {
            matches!(state, ExpresslaneState::Active)
                && now.duration_since(activity.last_data_traffic_from_peer) <= FIVE_MINUTES
        })
        .count()
}

fn session_stats(conn_manager: &Weak<ConnectionManager>) {
    let Some(conn_manager) = conn_manager.upgrade() else {
        // Conn manager is gone
        return;
    };

    let sessions = conn_manager.online_connection_stats();
    let expresslane_active_5m = calculate_expresslane_active_5m(&sessions);
    let (current_sessions, expresslane_states): (Vec<_>, Vec<_>) = sessions.into_iter().unzip();

    let (standby, active) = calculate_session_stats(&current_sessions);
    let expresslane = calculate_expresslane_stats(&expresslane_states);

    let current = current_sessions.len();
    let total = conn_manager.total_sessions();
    let pending_session_id_rotations = conn_manager.pending_session_id_rotations_count();

    info!(
        total,
        current,
        standby.five_minutes,
        standby.fifteen_minutes,
        standby.sixty_minutes,
        active.five_minutes,
        active.fifteen_minutes,
        active.sixty_minutes,
        pending_session_id_rotations,
        "Session Statistics"
    );
    metrics::sessions_statistics(
        current,
        total,
        pending_session_id_rotations,
        active,
        standby,
    );
    metrics::sessions_expresslane(&expresslane);
    metrics::sessions_expresslane_active_5m(expresslane_active_5m);
}

fn ip_manager_stats(ip_manager: &Weak<IpManager>) {
    let Some(ip_manager) = ip_manager.upgrade() else {
        // IP manager is gone
        return;
    };

    let count = ip_manager.allocated_ips_count();
    info!(current = count, "IP Statistics");
    metrics::assigned_internal_ips(count);
}

pub(crate) async fn run(
    conn_manager: Arc<ConnectionManager>,
    ip_manager: Arc<IpManager>,
    reporting_interval: Duration,
) {
    let weak_conn_manager = Arc::downgrade(&conn_manager);
    let weak_ip_manager = Arc::downgrade(&ip_manager);
    drop(conn_manager);
    drop(ip_manager);

    let mut ticker = tokio::time::interval(reporting_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticker = tokio_stream::wrappers::IntervalStream::new(ticker);

    while ticker.next().await.is_some() {
        session_stats(&weak_conn_manager);
        ip_manager_stats(&weak_ip_manager);
    }
}

#[cfg(test)]
mod tests {
    use more_asserts::*;
    use std::time::Instant;
    use test_case::test_case;

    use super::*;

    impl ConnectionIntervalStats {
        fn fmt(&self) -> String {
            format!(
                "{}:{}:{}",
                self.five_minutes, self.fifteen_minutes, self.sixty_minutes
            )
        }
    }

    #[test]
    fn calculate_stats_empty() {
        let (standby, active) = calculate_session_stats(&[]);

        assert_eq!(format!("{}+{}", standby.fmt(), active.fmt()), "0:0:0+0:0:0");
    }

    #[test_case(Duration::ZERO,              Duration::ZERO              => "0:0:0+1:1:1" ; "active, very recent data")]
    #[test_case(Duration::ZERO,              Duration::from_mins(1)      => "0:0:0+1:1:1" ; "active, 1m since data")]
    #[test_case(Duration::ZERO,              Duration::from_mins(6)      => "1:0:0+0:1:1" ; "active, 5+ mins since data")]
    #[test_case(Duration::ZERO,              Duration::from_mins(16)     => "1:1:0+0:0:1" ; "active, 15+ mins since data")]
    #[test_case(Duration::ZERO,              Duration::from_mins(61)     => "1:1:1+0:0:0" ; "active, 60+ mins since data")]
    #[test_case(Duration::from_mins(1),      Duration::from_hours(2)     => "1:1:1+0:0:0" ; "inactive for 1 min, data older")]
    #[test_case(Duration::from_mins(6),      Duration::from_hours(2)     => "0:1:1+0:0:0" ; "inactive for 5+ min, data older")]
    #[test_case(Duration::from_mins(16),     Duration::from_hours(2)     => "0:0:1+0:0:0" ; "inactive for 15+ min, data older")]
    #[test_case(Duration::from_mins(61),     Duration::from_hours(2)     => "0:0:0+0:0:0" ; "inactive for 60+ min, data older")]
    #[test_case(Duration::from_mins(1),      Duration::from_mins(1)      => "0:0:0+1:1:1" ; "inactive for 1 min, data same age")]
    #[test_case(Duration::from_mins(6),      Duration::from_mins(6)      => "0:0:0+0:1:1" ; "inactive for 5+ min, data same age")]
    #[test_case(Duration::from_mins(16),     Duration::from_mins(16)     => "0:0:0+0:0:1" ; "inactive for 15+ min, data same age")]
    #[test_case(Duration::from_mins(61),     Duration::from_mins(61)     => "0:0:0+0:0:0" ; "inactive for 60+ min, recent data")]
    fn calculate_stats_aging(outside_data_age: Duration, data_traffic_age: Duration) -> String {
        assert_le!(
            outside_data_age,
            data_traffic_age,
            "Outside data can't be older than last data seen"
        );

        let now = Instant::now();

        let sessions = vec![ConnectionActivity {
            last_outside_data_received: now - outside_data_age,
            last_data_traffic_from_peer: now - data_traffic_age,
            last_data_delivered_to_inside: now - data_traffic_age,
        }];

        let (standby, active) = calculate_session_stats(&sessions);

        format!("{}+{}", standby.fmt(), active.fmt())
    }
    #[test_case(ExpresslaneState::Active,   Duration::ZERO         => 1 ; "expresslane active, recent data")]
    #[test_case(ExpresslaneState::Active,   Duration::from_mins(6) => 0 ; "expresslane active, 5+ mins since data")]
    #[test_case(ExpresslaneState::Inactive, Duration::ZERO         => 0 ; "expresslane inactive, recent data")]
    fn calculate_expresslane_active_5m_aging(
        state: ExpresslaneState,
        data_traffic_age: Duration,
    ) -> usize {
        let now = Instant::now();

        let sessions = vec![(
            ConnectionActivity {
                last_outside_data_received: now - data_traffic_age,
                last_data_traffic_from_peer: now - data_traffic_age,
                last_data_delivered_to_inside: now - data_traffic_age,
            },
            state,
        )];

        calculate_expresslane_active_5m(&sessions)
    }

    #[test]
    fn calculate_expresslane_stats_counts_each_state() {
        let states = [
            ExpresslaneState::Disabled,
            ExpresslaneState::WaitingForClient,
            ExpresslaneState::WaitingForClient,
            ExpresslaneState::Inactive,
            ExpresslaneState::Active,
            ExpresslaneState::Active,
            ExpresslaneState::Active,
            ExpresslaneState::Degraded,
        ];

        assert_eq!(
            calculate_expresslane_stats(&states),
            ExpresslaneSessionStats {
                disabled: 1,
                waiting_for_client: 2,
                inactive: 1,
                active: 3,
                degraded: 1,
            }
        );
    }

    #[tokio::test]
    async fn run_does_not_keep_managers_alive() {
        let conn_manager = crate::io::outside::datagram::tests::test_conn_manager();
        let ip_manager = crate::tests::test_ip_manager();
        let weak_conn_manager = Arc::downgrade(&conn_manager);
        let weak_ip_manager = Arc::downgrade(&ip_manager);

        let task = tokio::spawn(run(conn_manager, ip_manager, Duration::from_millis(10)));
        tokio::task::yield_now().await;

        assert!(weak_conn_manager.upgrade().is_none());
        assert!(weak_ip_manager.upgrade().is_none());
        task.abort();
    }
}
