//! TLS library layer — re-exports the wolfssl crate's public API; in-tree
//! code imports TLS types from here rather than from `wolfssl` directly.

pub use wolfssl::*;

/// Get version string for the TLS library that we're using
pub fn get_version_string() -> String {
    format!("WolfSSL v{}", get_wolfssl_version_string())
}
