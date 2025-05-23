#![allow(unsafe_code)]
//! Support some socket options we need.

mod ip_mtu_discover;
mod ip_pktinfo;

pub use ip_mtu_discover::*;
#[cfg(not(target_vendor = "apple"))]
pub use ip_pktinfo::*;
