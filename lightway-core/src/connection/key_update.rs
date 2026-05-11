use std::time::{Duration, Instant};

/// Track key updates for a server connection
///
/// After the connection is online call `State::online` and then use
/// `State::required` and `State::complete` to begin/end a key
/// rotation.
pub(crate) enum State {
    /// Key updates are not enabled
    Disabled,

    /// Waiting for connection to be ::Online and Self::online to be called.
    Initializing { interval: Duration },

    /// Waiting for next key update to be due, e.g. for `interval` to have elapsed since `last`.
    Waiting { interval: Duration, last: Instant },

    /// A key update is in flight
    Pending { interval: Duration },
}

impl State {
    pub fn new(interval: Duration) -> Self {
        if interval.is_zero() {
            Self::Disabled
        } else {
            Self::Initializing { interval }
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    pub fn online(&mut self) {
        match *self {
            Self::Disabled => {}
            Self::Initializing { interval } => {
                *self = Self::Waiting {
                    interval,
                    last: Instant::now(),
                };
            }
            Self::Waiting { .. } | Self::Pending { .. } => {}
        }
    }

    /// Returns true if a new key update is required.
    ///
    /// Implicitly transitions to `Self::Pending` if required.
    ///
    /// On a true result the caller must start a key update i.e. call
    /// `Session::try_trigger_update_key()`.
    pub fn required(&mut self) -> bool {
        match *self {
            Self::Disabled | Self::Initializing { .. } | Self::Pending { .. } => false,
            Self::Waiting { interval, last } => {
                if last.elapsed() < interval {
                    false
                } else {
                    *self = Self::Pending { interval };
                    true
                }
            }
        }
    }

    /// Update with potential completion of key update. Returns
    /// whether a completion really did occur.
    ///
    /// Implicitly transitions to `Self::Waiting` if required.
    ///
    /// Should be called whenever
    /// `Session::is_update_keys_pending()` is false.
    pub fn complete(&mut self) -> bool {
        match *self {
            Self::Disabled | Self::Initializing { .. } | Self::Waiting { .. } => false,
            Self::Pending { interval } => {
                *self = Self::Waiting {
                    interval,
                    last: Instant::now(),
                };
                true
            }
        }
    }
}
