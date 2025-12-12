use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

/// Wrapper for compatibility with both clap and twelf at the same time
#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct NonZeroDuration(#[serde_as(as = "DisplayFromStr")] humantime::Duration);

impl std::fmt::Display for NonZeroDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for NonZeroDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<NonZeroDuration> for std::time::Duration {
    fn from(d: NonZeroDuration) -> Self {
        d.0.into()
    }
}

impl std::str::FromStr for NonZeroDuration {
    type Err = humantime::DurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let duration = NonZeroDuration(s.parse::<humantime::Duration>()?);
        if duration.0.is_zero() {
            return Err(humantime::DurationError::Empty);
        }
        Ok(duration)
    }
}
