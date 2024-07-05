//! Helpers for applications using the ligthway protocol
#![warn(missing_docs)]

pub mod args;

#[cfg(feature = "tokio")]
mod connection_ticker;
#[cfg(feature = "tokio")]
mod dplpmtud_timer;
#[cfg(feature = "tokio")]
mod event_stream;
#[cfg(feature = "io-uring")]
mod iouring;
mod tun;

#[cfg(feature = "tokio")]
pub use connection_ticker::{
    connection_ticker_cb, ConnectionTicker, ConnectionTickerState, ConnectionTickerTask, Tickable,
};
#[cfg(feature = "tokio")]
pub use dplpmtud_timer::{DplpmtudTimer, DplpmtudTimerTask};
#[cfg(feature = "tokio")]
pub use event_stream::{EventStream, EventStreamCallback};

#[cfg(feature = "io-uring")]
pub use iouring::IOUring;

pub use tun::Tun;

#[cfg(feature = "io-uring")]
mod metrics;
mod utils;
pub use utils::is_file_path_valid;
