use super::RoutingTableError;

/// Retry state carried across select! iterations while a re-pin is pending.
pub struct RepinState {
    started_at: tokio::time::Instant,
    pub next_at: tokio::time::Instant,
    pub nudge: bool,
}

impl RepinState {
    pub fn new(nudge: bool) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            started_at: now,
            next_at: now,
            nudge,
        }
    }

    pub fn elapsed_since_start(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }
}

pub enum RepinMode {
    /// Only re-pin when the gateway or interface index actually changed.
    OnRouteChange,
}

impl RepinMode {
    pub fn needs_repin(&self, route_changed: bool) -> bool {
        match self {
            RepinMode::OnRouteChange => route_changed,
        }
    }

    pub fn on_failure(&self, state: &mut RepinState, error: &RoutingTableError) {
        match self {
            RepinMode::OnRouteChange => {
                tracing::warn!("Server route update failed: {error:?}");
                state.next_at = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
            }
        }
    }
}
