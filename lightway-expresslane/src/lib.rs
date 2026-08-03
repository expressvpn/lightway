//! ExpressLane data-packet primitives: wire format, key rotation and replay
//! window, with a caller-supplied AEAD.
//!
//! Split out of `lightway-core` so an offload engine can speak the
//! ExpressLane data plane without linking the TLS stack or reimplementing
//! the protocol.
#![warn(missing_docs)]

mod aead;
mod error;
mod key;
mod version;

pub use aead::ExpresslaneAead;
#[cfg(feature = "wolfssl-backend")]
pub use aead::wolfssl::WolfsslAead;
pub use error::{ExpresslaneError, ExpresslaneResult};
pub use key::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};
pub use version::ExpresslaneVersion;
