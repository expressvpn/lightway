//! The data-plane half of a two-process offloaded ExpressLane client.
//!
//! The VPN process keeps the control plane - handshake, key exchange,
//! rotation, degrade - and hands this process two file descriptors: one queue
//! of a multiqueue TUN and one socket of a reuseport pair. eBPF steering in
//! `lightway-bpf-steering` makes the kernel deliver offloaded traffic here
//! directly, so packets never cross the process boundary.
//!
//! # Not a shipped artifact
//!
//! `lightway-offload-engine` and `lightway-offload-client` are a **reference
//! implementation**: they exist to prove the surface lightway-core exports is
//! sufficient to build an offload engine outside it, and to give that claim a
//! test that fails when it stops being true. No release path emits either
//! binary - not the Earthly `+build` output filter, not `nix/default.nix`, not
//! the release workflow - and that omission is deliberate, not an oversight.
//! A product that wants an offloaded client builds its own process A against
//! this crate; adding these to a release would ship a test rig.
#![cfg(target_os = "linux")]
#![warn(missing_docs)]

pub mod control;
pub mod engine;
pub mod fdpass;
pub mod gate;
pub mod ipc;
pub mod ipc_client;
pub mod packet;
