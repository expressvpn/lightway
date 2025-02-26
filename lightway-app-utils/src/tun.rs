use anyhow::Result;
use bytes::BytesMut;
use lightway_core::IOCallbackResult;

#[cfg(feature = "io-uring")]
use std::time::Duration;
use std::{
    ops::Deref,
    os::fd::{AsRawFd, RawFd},
};

use tun::{AbstractDevice, AsyncDevice as TokioTun};

pub use tun::Configuration as TunConfig;

#[cfg(feature = "io-uring")]
use std::sync::Arc;

#[cfg(feature = "io-uring")]
use crate::IOUring;

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
    pub async fn direct(config: TunConfig) -> Result<Self> {
        Ok(Self::Direct(TunDirect::new(config)?))
    }

    /// Create new `Tun` instance with iouring read/write
    #[cfg(feature = "io-uring")]
    pub async fn iouring(
        config: TunConfig,
        ring_size: usize,
        sqpoll_idle_time: Duration,
    ) -> Result<Self> {
        Ok(Self::IoUring(
            TunIoUring::new(config, ring_size, sqpoll_idle_time).await?,
        ))
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
    mtu: u16,
    fd: RawFd,
}

impl TunDirect {
    /// Create a new `Tun` struct
    pub fn new(config: TunConfig) -> Result<Self> {
        let tun = tun::create_as_async(&config)?;
        let fd = tun.as_raw_fd();
        let mtu = tun.mtu()?;

        Ok(TunDirect { tun, mtu, fd })
    }

    /// Recv from Tun
    pub async fn recv_buf(&self) -> IOCallbackResult<bytes::BytesMut> {
        let mut buf = BytesMut::zeroed(self.mtu as usize);
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
    pub fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        let try_send_res = self.tun.deref().send(&buf[..]);
        match try_send_res {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    /// MTU of Tun
    pub fn mtu(&self) -> usize {
        self.mtu as usize
    }
}

impl AsRawFd for TunDirect {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
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
    pub async fn new(
        config: TunConfig,
        ring_size: usize,
        sqpoll_idle_time: Duration,
    ) -> Result<Self> {
        let tun = TunDirect::new(config)?;
        let mtu = tun.mtu();
        let tun_io_uring =
            IOUring::new(Arc::new(tun), ring_size, ring_size, mtu, sqpoll_idle_time).await?;

        Ok(TunIoUring { tun_io_uring })
    }

    /// Recv from Tun
    pub async fn recv_buf(&self) -> IOCallbackResult<BytesMut> {
        match self.tun_io_uring.recv().await {
            IOCallbackResult::Ok(pkt) => IOCallbackResult::Ok(pkt),
            IOCallbackResult::WouldBlock => IOCallbackResult::WouldBlock,
            IOCallbackResult::Err(e) => {
                use std::io::{Error, ErrorKind};
                IOCallbackResult::Err(Error::new(ErrorKind::Other, e))
            }
        }
    }

    /// Try send to Tun
    pub fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        self.tun_io_uring.try_send(buf)
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
