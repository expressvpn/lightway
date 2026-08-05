#![allow(unsafe_code)]
//! Support some socket options we need.

mod ip_mtu_discover;
#[cfg(unix)]
mod ip_pktinfo;
// `UDP_GRO` is a kernel feature, not a libc one: Android runs the same
// Linux networking stack, so the sockopt works there too.
#[cfg(any(linux, android))]
mod udp_gro;

pub use ip_mtu_discover::*;
#[cfg(unix)]
pub use ip_pktinfo::*;
#[cfg(any(linux, android))]
pub use udp_gro::*;
