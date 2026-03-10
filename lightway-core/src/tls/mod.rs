//! TLS library layer — re-exports the active TLS backend's public API.
//! In-tree code imports TLS types from here rather than from the backend
//! crate directly, allowing the backend to be swapped at compile time via
//! feature flags.

#[cfg(all(wolfssl, boringssl))]
compile_error!("features `wolfssl` and `boringssl` are mutually exclusive");

#[cfg(not(any(wolfssl, boringssl)))]
compile_error!("one of the `wolfssl` or `boringssl` features must be enabled");

#[cfg(wolfssl)]
pub use wolfssl::*;

#[cfg(boringssl)]
pub use boringssl::*;

/// Get version string for the TLS library that we're using
pub fn get_version_string() -> String {
    #[cfg(wolfssl)]
    return format!("WolfSSL v{}", get_wolfssl_version_string());
    #[cfg(boringssl)]
    return format!("BoringSSL - {}", boringssl::get_version_string());
}
