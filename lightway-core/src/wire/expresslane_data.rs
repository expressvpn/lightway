//! ExpressLane data-packet types.
//!
//! The implementation lives in the `lightway-expresslane` crate so external
//! offload engines can use it without linking the TLS stack. This module
//! re-exports it under the names the rest of lightway-core already uses.

pub use lightway_expresslane::{
    EXPRESSLANE_KEY_SIZE, ExpresslaneError, ExpresslaneKey, ExpresslaneVersion,
};

/// The concrete session type lightway-core uses: wolfSSL-backed, matching the
/// cipher the rest of the tunnel uses.
pub(crate) type ExpresslaneData =
    lightway_expresslane::ExpresslaneSession<lightway_expresslane::WolfsslAead>;
