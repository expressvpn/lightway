use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Desktop Platforms
        linux: { target_os = "linux" },
        macos: { target_os = "macos" },
        // windows - supported natively
    }
}
