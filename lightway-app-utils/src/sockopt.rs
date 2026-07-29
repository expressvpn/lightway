#![allow(unsafe_code)]
//! Support some socket options we need.

mod ip_mtu_discover;
#[cfg(unix)]
mod ip_pktinfo;
#[cfg(linux)]
mod so_mark;

pub use ip_mtu_discover::*;
#[cfg(unix)]
pub use ip_pktinfo::*;
#[cfg(linux)]
pub use so_mark::*;
