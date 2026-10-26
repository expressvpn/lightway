//! TLS library layer — re-exports the active TLS backend's public API.
//! In-tree code imports TLS types from here rather than from the backend
//! crate directly, allowing the backend to be swapped at compile time via
//! feature flags.

cfg_select! {
    all(wolfssl, boringssl) => {
        compile_error!("features `wolfssl` and `boringssl` are mutually exclusive");
    }
    wolfssl => {
        pub use wolfssl::*;
    }
    boringssl => {
        pub use boringssl::*;
    }
    _ => {
        compile_error!("one of the `wolfssl` or `boringssl` features must be enabled");
    }
}

/// Get version string for the TLS library that we're using
pub fn get_version_string() -> String {
    cfg_select! {
        wolfssl => format!("WolfSSL v{}", get_wolfssl_version_string()),
        boringssl => format!("BoringSSL - {}", boringssl::get_version_string()),
    }
}
