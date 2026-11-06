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

/// Get version string for the TLS library that we're using.
///
/// This is the backend's `build_info()` rendered as a single line, covering
/// the crate versions, the underlying C library version and enabled features.
pub fn get_version_string() -> String {
    build_info().to_string()
}
