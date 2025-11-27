//! Helpers for applications using the ligthway protocol
#![warn(missing_docs)]

pub mod args;
pub mod sockopt;

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
    ConnectionTicker, ConnectionTickerState, ConnectionTickerTask, Tickable, connection_ticker_cb,
};
#[cfg(feature = "tokio")]
pub use dplpmtud_timer::{DplpmtudTimer, DplpmtudTimerTask};
#[cfg(feature = "tokio")]
pub use event_stream::{EventStream, EventStreamCallback};

#[cfg(feature = "io-uring")]
pub use iouring::IOUring;

#[cfg(feature = "io-uring")]
pub use tun::TunIoUring;
pub use tun::{Tun, TunConfig, TunDirect};

#[cfg(feature = "io-uring")]
mod metrics;
mod utils;
pub use utils::{Validate, validate_configuration_file_path};

mod packet_codec;
#[cfg(feature = "debug")]
mod wolfssl_tracing;
#[cfg(feature = "debug")]
pub use wolfssl_tracing::wolfssl_tracing_callback;

pub use packet_codec::{PacketCodec, PacketCodecFactory, PacketCodecFactoryType};
