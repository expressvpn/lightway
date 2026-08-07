# TLS backends
Lightway delegates all TLS/DTLS handling to a backend library selected at
compile time. Two backends are supported:
* **wolfSSL** (default) - the main, recommended backend, used for all release
  builds. Provided by the [`wolfssl`](https://crates.io/crates/wolfssl) crate.
* **BoringSSL** - now supported as an alternative backend, provided by the
  in-tree `lightway-boring` crate (a thin layer over Cloudflare's
  [`boring`](https://github.com/cloudflare/boring) bindings, designed as a
  drop-in replacement for the `wolfssl` crate's API).

## Selecting a backend
The backend is chosen with the mutually exclusive `wolfssl` and `boringssl`
cargo features. Exactly one must be enabled; `lightway-core` fails the build
with a `compile_error!` if both or neither are enabled.

`wolfssl` is part of the default features of `lightway-core`,
`lightway-client` and `lightway-server`, so a plain `cargo build` uses
wolfSSL. To switch to BoringSSL, do `no-default-features` and enable
`boringssl`:

Note that `--no-default-features` also drops the other default features
(for example `postquantum`), so re-enable any you still want alongside
`boringssl`.

## How the switch actually works

The actual switch lives in `lightway-core/src/tls/mod.rs`. This module:

* re-exports the public API of whichever backend is enabled. The rest of the
  codebase is backend-agnostic and imports its TLS types from `lightway_core::tls`
  rather than from a backend crate directly;
* enforces the mutual exclusivity with `compile_error!` - the build fails
  unless exactly one of the `wolfssl` / `boringssl` features is enabled;
* reports which backend is in use at runtime via `get_version_string()`.
