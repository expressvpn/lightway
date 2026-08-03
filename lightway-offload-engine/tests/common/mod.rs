//! The privilege gate the integration tests share.
//!
//! Everything here needs `CAP_BPF`, and the inside split `CAP_NET_ADMIN` on
//! top, so an unprivileged `cargo test` skips rather than fails - otherwise
//! nobody could run the suite on a laptop. The cost is that a CI job which
//! silently lost its privileges would report a green, empty suite, which is
//! what `LW_BPF_REQUIRE_PRIVILEGED` is for.

use std::io;

/// Does this error mean "this process may not do that", rather than "the code
/// under test is broken"?
///
/// `PermissionDenied` is the missing capability. `NotFound` is a kernel or
/// container with no `/dev/net/tun` at all, which the inside split hits first.
/// Nothing else counts: a program the verifier rejected arrives as `Other`
/// (see `load::load_error`) and must fail the test.
pub fn is_unprivileged(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
    )
}

/// Was `LW_BPF_REQUIRE_PRIVILEGED=1` set?
///
/// Set it in any job that is *supposed* to be privileged. Every skip then
/// becomes a failure, so a job that loses `CAP_BPF` - a runner image change, a
/// dropped `--privileged` - fails loudly instead of passing with a suite that
/// tested nothing.
pub fn privilege_required() -> bool {
    std::env::var_os("LW_BPF_REQUIRE_PRIVILEGED").is_some_and(|v| v == "1")
}

/// Unwrap, or skip the test when the environment cannot run it.
macro_rules! skip_unless_privileged {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) if $crate::common::is_unprivileged(&e) => {
                assert!(
                    !$crate::common::privilege_required(),
                    "LW_BPF_REQUIRE_PRIVILEGED=1, but this process lacks CAP_BPF/CAP_NET_ADMIN: {e}"
                );
                eprintln!("skipping: needs CAP_BPF + CAP_NET_ADMIN ({e})");
                return;
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    };
}
