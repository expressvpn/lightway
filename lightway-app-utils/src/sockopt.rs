#![allow(unsafe_code)]
//! Support some socket options we need.

mod ip_mtu_discover;
#[cfg(unix)]
mod ip_pktinfo;

pub use ip_mtu_discover::*;
#[cfg(unix)]
pub use ip_pktinfo::*;
