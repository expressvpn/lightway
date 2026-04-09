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
        apple: {
            any(
                macos,
                ios,
                tvos
            )
        },
        // Feature alias
        batch_receive: { all(apple, feature = "batch_receive") },
    }
}
