//! Compiles both BPF programs with clang at build time.
//!
//! clang and libbpf come from the nix dev shell (added in Task 1). A build
//! outside that shell fails here with a clear message rather than silently
//! producing a crate that cannot steer anything.
//!
//! Linux only, at both ends. libbpf-cargo is a Linux-only build dependency, so
//! on another *host* there is nothing here to build with - hence the `cfg` on
//! the module. And the crate itself is `#![cfg(target_os = "linux")]`, so for
//! another *target* there would be nothing to steer - hence the check on
//! `CARGO_CFG_TARGET_OS`.

fn main() {
    #[cfg(target_os = "linux")]
    linux::build_skeletons();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::PathBuf;

    use libbpf_cargo::SkeletonBuilder;

    const PROGRAMS: [&str; 2] = ["outside", "inside"];

    pub fn build_skeletons() {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
            return;
        }

        let out: PathBuf = std::env::var("OUT_DIR").expect("OUT_DIR unset").into();

        // Escape hatch for shells whose `clang` is unwrapped and finds no
        // kernel headers on its own (the musl cross shell). Whitespace-split.
        println!("cargo:rerun-if-env-changed=LW_BPF_CLANG_ARGS");
        let extra_args = std::env::var("LW_BPF_CLANG_ARGS").unwrap_or_default();

        for name in PROGRAMS {
            let src = format!("src/bpf/{name}.bpf.c");
            println!("cargo:rerun-if-changed={src}");
            SkeletonBuilder::new()
                .source(&src)
                .clang_args(extra_args.split_whitespace())
                .build_and_generate(out.join(format!("{name}.skel.rs")))
                .unwrap_or_else(|e| {
                    panic!("failed to build {src}: {e}\nIs clang on PATH? The nix dev shell provides it; run via `direnv exec .`")
                });
        }
    }
}
