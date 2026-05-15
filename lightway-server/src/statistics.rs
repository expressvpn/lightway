use lightway_core::ConnectionActivity;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio_stream::StreamExt;
use tracing::info;

use crate::{
    connection_manager::ConnectionManager,
    ip_manager::IpManager,
    metrics::{self, ConnectionIntervalStats},
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

fn session_stats(conn_manager: &Weak<ConnectionManager>) {
    let Some(conn_manager) = conn_manager.upgrade() else {
        // Conn manager is gone
        return;
    };

    let current_sessions = conn_manager.online_connection_activity();

    let (standby, active) = calculate_session_stats(&current_sessions);

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
    let conn_manager = Arc::downgrade(&conn_manager);
    let ip_manager = Arc::downgrade(&ip_manager);

    let mut ticker = tokio::time::interval(reporting_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticker = tokio_stream::wrappers::IntervalStream::new(ticker);

    while ticker.next().await.is_some() {
        session_stats(&conn_manager);
        ip_manager_stats(&ip_manager);
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
        }];

        let (standby, active) = calculate_session_stats(&sessions);

        format!("{}+{}", standby.fmt(), active.fmt())
    }
}
