//! The data-plane half of a two-process offloaded ExpressLane client.
//!
//! The VPN process keeps the control plane - handshake, key exchange,
//! rotation, degrade - and hands this process two file descriptors: one queue
//! of a multiqueue TUN and one socket of a reuseport pair. eBPF steering in
//! `lightway-bpf-steering` makes the kernel deliver offloaded traffic here
//! directly, so packets never cross the process boundary.
#![cfg(target_os = "linux")]
#![warn(missing_docs)]

pub mod control;
pub mod engine;
pub mod fdpass;
pub mod ipc;
pub mod packet;
