use super::RoutingTableError;

/// Retry state carried across select! iterations while a re-pin is pending.
pub struct RepinState {
    started_at: tokio::time::Instant,
    pub next_at: tokio::time::Instant,
    pub nudge: bool,
    retry_count: u32,
}

impl RepinState {
    pub fn new(nudge: bool) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            started_at: now,
            next_at: now,
            nudge,
            retry_count: 0,
        }
    }

    pub fn elapsed_since_start(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }
}

pub enum RepinMode {
    /// Only re-pin when the gateway or interface index actually changed.
    OnRouteChange,
    /// Always re-pin on every network event — handles within-subnet roaming on
    /// Apple platforms where routing identifiers are identical but the physical
    /// path has changed and the outside socket needs rebinding.
    Always,
}

impl RepinMode {
    pub fn needs_repin(&self, route_changed: bool) -> bool {
        match self {
            RepinMode::OnRouteChange => route_changed,
            RepinMode::Always => true,
        }
    }

    pub fn on_failure(state: &mut RepinState, error: &RoutingTableError) {
        const MIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
        const LONG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

        let next_interval = if state.retry_count > 4 {
            // more than 15.5s
            tracing::error!(
                "Server route update failed ({error:?}) in {:}, retrying",
                state.elapsed_since_start().as_secs()
            );
            LONG_INTERVAL
        } else {
            let exponential =
                MIN_INTERVAL.as_millis() as u64 * 2_u64.saturating_pow(state.retry_count);
            tracing::debug!(
                "Server route update failed ({error:?}) in {:}, retrying",
                state.elapsed_since_start().as_secs()
            );
            std::time::Duration::from_millis(exponential)
        };

        state.retry_count = state.retry_count.saturating_add(1);
        state.next_at = tokio::time::Instant::now() + next_interval;
    }
}
