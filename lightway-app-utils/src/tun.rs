use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use lightway_core::IOCallbackResult;

use std::os::fd::{AsRawFd, RawFd};
#[cfg(feature = "io-uring")]
use std::sync::Arc;
use tokio_tun::Tun as TokioTun;

#[cfg(feature = "io-uring")]
use crate::IOUring;

/// TunConfig enum interface to read/write packets
#[derive(Debug)]
pub enum TunConfig {
    /// Tunnel interface name
    Name(String),
}

/// Tun enum interface to read/write packets
pub enum Tun {
    /// using direct read/write
    Direct(TunDirect),
    /// using io_uring read/write
    #[cfg(feature = "io-uring")]
    IoUring(TunIoUring),
}

impl Tun {
    /// Create new `Tun` instance with direct read/write
    pub async fn direct(config: TunConfig, mtu: Option<i32>) -> Result<Self> {
        Ok(Self::Direct(TunDirect::new(config, mtu)?))
    }

    /// Create new `Tun` instance with iouring read/write
    #[cfg(feature = "io-uring")]
    pub async fn iouring(config: TunConfig, mtu: Option<i32>, ring_size: usize) -> Result<Self> {
        Ok(Self::IoUring(TunIoUring::new(config, ring_size, mtu).await?))
    }

    /// Recv a packet from `Tun`
    pub async fn recv_buf(&self) -> IOCallbackResult<bytes::BytesMut> {
        match self {
            Tun::Direct(t) => t.recv_buf().await,
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.recv_buf().await,
        }
    }

    /// Send a packet to `Tun`
    pub fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        match self {
            Tun::Direct(t) => t.try_send(buf),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.try_send(buf),
        }
    }

    /// MTU of `Tun` interface
    pub fn mtu(&self) -> usize {
        match self {
            Tun::Direct(t) => t.mtu(),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.mtu(),
        }
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Tun::Direct(t) => t.as_raw_fd(),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.as_raw_fd(),
        }
    }
}

/// Tun struct
pub struct TunDirect {
    tun: TokioTun,
    mtu: usize,
}

impl TunDirect {
    /// Create a new `Tun` struct
    pub fn new(config: TunConfig, mtu: Option<i32>) -> Result<Self> {
        let tun_builder = match config {
            TunConfig::Name(n) => TokioTun::builder().name(&n).tap(false).packet_info(false)
        };

        let tun_builder = if let Some(mtu) = mtu {
            tun_builder.mtu(mtu)
        } else {
            tun_builder
        };

        let tun = tun_builder
            .try_build()
            .map_err(|e| anyhow!(e))
            .context("Tun creation")?;

        let mtu: usize = tun.mtu()? as usize;

        Ok(TunDirect { tun, mtu })
    }

    /// Recv from Tun
    pub async fn recv_buf(&self) -> IOCallbackResult<bytes::BytesMut> {
        let mut buf = BytesMut::zeroed(self.mtu);
        match self.tun.recv(buf.as_mut()).await {
            // TODO: Check whether we can use poll
            // Getting spurious reads
            Ok(0) => IOCallbackResult::WouldBlock,
            Ok(nr) => {
                let _ = buf.split_off(nr);
                IOCallbackResult::Ok(buf)
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    /// Try write from Tun
    pub fn try_send(&self, mut buf: BytesMut) -> IOCallbackResult<usize> {
        match self.tun.try_send(buf.as_mut()) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    /// MTU of Tun
    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

impl AsRawFd for TunDirect {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

/// TunIoUring struct
#[cfg(feature = "io-uring")]
pub struct TunIoUring {
    tun_io_uring: IOUring<TunDirect>,
}

#[cfg(feature = "io-uring")]
impl TunIoUring {
    /// Create `TunIoUring` struct
    pub async fn new(config: TunConfig, ring_size: usize, mtu: Option<i32>) -> Result<Self> {
        let tun = TunDirect::new(config, mtu)?;
        let mtu = tun.mtu();
        let tun_io_uring = IOUring::new(Arc::new(tun), ring_size, ring_size, mtu).await?;

        Ok(TunIoUring { tun_io_uring })
    }

    /// Recv from Tun
    pub async fn recv_buf(&self) -> IOCallbackResult<BytesMut> {
        match self.tun_io_uring.recv().await {
            Ok(pkt) => IOCallbackResult::Ok(pkt),
            Err(e) => {
                use std::io::{Error, ErrorKind};
                IOCallbackResult::Err(Error::new(ErrorKind::Other, e))
            }
        }
    }

    /// Try send to Tun
    pub fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        let buf_len = buf.len();
        match self.tun_io_uring.try_send(buf) {
            Ok(_) => IOCallbackResult::Ok(buf_len),
            Err(e) => {
                use std::io::{Error, ErrorKind};
                IOCallbackResult::Err(Error::new(ErrorKind::Other, e))
            }
        }
    }

    /// MTU of tun
    pub fn mtu(&self) -> usize {
        self.tun_io_uring.owned_fd().mtu()
    }
}

#[cfg(feature = "io-uring")]
impl AsRawFd for TunIoUring {
    fn as_raw_fd(&self) -> RawFd {
        self.tun_io_uring.owned_fd().as_raw_fd()
    }
}
