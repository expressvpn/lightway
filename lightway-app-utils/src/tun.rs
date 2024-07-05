use anyhow::Result;
#[cfg(feature = "tokio-tun")]
use anyhow::{anyhow, Context};
use bytes::BytesMut;
use lightway_core::IOCallbackResult;
use std::os::fd::{AsRawFd, RawFd};
#[cfg(feature = "io-uring")]
use std::sync::Arc;
#[cfg(feature = "tokio-tun")]
use tokio_tun::Tun as TokioTun;

use crate::tokio_raw_tun::TokioRawTun;
#[cfg(feature = "io-uring")]
use crate::IOUring;

/// Tun enum interface to read/write packets
pub enum Tun {
    /// using direct read/write with a tun device
    #[cfg(feature = "tokio-tun")]
    Direct(TunDirect),
    /// perform direct read/write with a fd
    Raw(TunRaw),
    /// using io_uring read/write
    #[cfg(feature = "io-uring")]
    IoUring(TunIoUring),
}

impl Tun {
    /// Create new `Tun` instance with direct read/write, uses linux APIs to
    /// interact with the tun
    #[cfg(feature = "tokio-tun")]
    pub async fn direct(name: &str, mtu: Option<i32>) -> Result<Self> {
        Ok(Self::Direct(TunDirect::new(name, mtu)?))
    }

    /// Create new `Tun` instance with direct read/write, use a provided fd to
    /// interact with the tun
    pub async fn raw(fd: RawFd, mtu: Option<i32>) -> Result<Self> {
        Ok(Self::Raw(TunRaw::new(fd, mtu)?))
    }

    /// Create new `Tun` instance with iouring read/write
    #[cfg(feature = "io-uring")]
    pub async fn iouring(name: &str, mtu: Option<i32>, ring_size: usize) -> Result<Self> {
        Ok(Self::IoUring(TunIoUring::new(name, ring_size, mtu).await?))
    }

    /// Recv a packet from `Tun`
    pub async fn recv_buf(&self) -> IOCallbackResult<bytes::BytesMut> {
        match self {
            #[cfg(feature = "tokio-tun")]
            Tun::Direct(t) => t.recv_buf().await,
            Tun::Raw(t) => t.recv_buf().await,
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.recv_buf().await,
        }
    }

    /// Send a packet to `Tun`
    pub fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        match self {
            #[cfg(feature = "tokio-tun")]
            Tun::Direct(t) => t.try_send(buf),
            Tun::Raw(t) => t.try_send(buf),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.try_send(buf),
        }
    }

    /// MTU of `Tun` interface
    pub fn mtu(&self) -> usize {
        match self {
            #[cfg(feature = "tokio-tun")]
            Tun::Direct(t) => t.mtu(),
            Tun::Raw(t) => t.mtu(),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.mtu(),
        }
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            #[cfg(feature = "tokio-tun")]
            Tun::Direct(t) => t.as_raw_fd(),
            Tun::Raw(t) => t.as_raw_fd(),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.as_raw_fd(),
        }
    }
}

/// Tun struct
#[cfg(feature = "tokio-tun")]
pub struct TunDirect {
    tun: TokioTun,
    mtu: usize,
}

#[cfg(feature = "tokio-tun")]
impl TunDirect {
    /// Create a new `Tun` struct
    pub fn new(name: &str, mtu: Option<i32>) -> Result<Self> {
        let tun_builder = TokioTun::builder().name(name).tap(false).packet_info(false);

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

#[cfg(feature = "tokio-tun")]
impl AsRawFd for TunDirect {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

pub struct TunRaw {
    tun: TokioRawTun,
    mtu: usize,
}

impl TunRaw {
    /// Create `TunRaw` struct
    pub fn new(fd: RawFd, mtu: Option<i32>) -> Result<Self> {
        let mtu = mtu.unwrap_or(1350) as usize;
        let tun = TokioRawTun::new(fd);
        Ok(TunRaw { tun, mtu })
    }

    /// Recv from Tun
    pub async fn recv_buf(&self) -> IOCallbackResult<BytesMut> {
        let mut buf = BytesMut::zeroed(self.mtu);

        match self.tun.recv(buf.as_mut()).await {
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

    /// Try send to Tun
    pub fn try_send(&self, mut buf: BytesMut) -> IOCallbackResult<usize> {
        match self.tun.try_send(buf.as_mut()) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    /// MTU of tun
    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

impl AsRawFd for TunRaw {
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
    pub async fn new(name: &str, ring_size: usize, mtu: Option<i32>) -> Result<Self> {
        let tun = TunDirect::new(name, mtu)?;
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
