// Temporary workaround for cfg_aliases 0.2.1 tripping the nightly
// deny-by-default lint (rust-lang/rust#79813), which breaks test-miri in CI.
// Remove once cfg_aliases ships a fix upstream.
#![allow(semicolon_in_expressions_from_macros)]
use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Desktop Platforms
        linux: { target_os = "linux" },
        macos: { target_os = "macos" },
        // windows - supported natively
        // Mobile Platforms
        android: { target_os = "android" },
        ios: { target_os = "ios" },
        tvos: { target_os = "tvos" },
        // Backends
        desktop: { any(windows, linux, macos) },
        mobile: { any(android, ios, tvos) },
        // Apple platform
        apple: { any(macos, ios, tvos) },
    }
}
