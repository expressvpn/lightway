#![allow(unsafe_code)]
//! Support some socket options we need.

mod ip_mtu_discover;
#[cfg(unix)]
mod ip_pktinfo;
#[cfg(linux)]
mod udp_gro;

pub use ip_mtu_discover::*;
#[cfg(unix)]
pub use ip_pktinfo::*;
#[cfg(linux)]
pub use udp_gro::*;
