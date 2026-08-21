use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Desktop Platforms
        linux: { target_os = "linux" },
        macos: { target_os = "macos" },
        // windows - supported natively
    }

    let git_hash = get_git_hash();
    println!(
        "cargo:rustc-env=GIT_HASH={}",
        &git_hash[..8.min(git_hash.len())]
    );
}

fn get_git_hash() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "dev".to_string())
}
