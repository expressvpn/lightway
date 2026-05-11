//! TLS library layer — re-exports the wolfssl crate's public API; in-tree
//! code imports TLS types from here rather than from `wolfssl` directly.

pub use wolfssl::get_wolfssl_version_string as get_version_string;
pub use wolfssl::*;
