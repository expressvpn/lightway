use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

/// Wrapper for compatibility with clap
#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq)]
pub struct Duration(#[serde_as(as = "DisplayFromStr")] humantime::Duration);

impl std::fmt::Display for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Duration> for std::time::Duration {
    fn from(d: Duration) -> Self {
        d.0.into()
    }
}

impl std::str::FromStr for Duration {
    type Err = humantime::DurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Duration(s.parse::<humantime::Duration>()?))
    }
}

impl Duration {
    /// Returns true if this `Duration` spans no time.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Build from std duration
    pub fn from_std_duration(duration: std::time::Duration) -> Self {
        Duration(duration.into())
    }
}
