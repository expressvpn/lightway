use anyhow::Result;
use bytes::BytesMut;
use lightway_core::IOCallbackResult;

#[cfg(feature = "io-uring")]
use std::time::Duration;
use std::{
    mem::ManuallyDrop,
    net::{IpAddr, Ipv4Addr},
    os::fd::{AsRawFd, IntoRawFd, RawFd},
};

use tun_rs::{AsyncDevice, DeviceBuilder};

#[cfg(feature = "io-uring")]
use std::sync::Arc;

#[cfg(feature = "io-uring")]
use crate::IOUring;

/// Configuration options for creating a TUN interface
///
/// This struct provides a builder-like interface for configuring TUN interfaces
/// with various network settings including address assignment, routing, and MTU.
#[derive(Clone, Default, Debug)]
pub struct TunConfig {
    /// Optional name for the TUN interface (e.g., "utun3" on macOS)
    pub tun_name: Option<String>,
    /// IP address to assign to the TUN interface (IPv4 or IPv6)
    pub address: Option<IpAddr>,
    /// Destination/gateway address for the TUN interface
    pub destination: Option<Ipv4Addr>,
    /// Network mask for the assigned address (defaults to host route if not specified)
    pub prefix: Option<u8>,
    /// Maximum transmission unit size in bytes
    pub mtu: Option<u16>,
    /// Whether the interface should be brought up after creation
    pub enabled: Option<bool>,
    /// Whether to close the file descriptor when the TUN device is dropped
    pub close_fd_on_drop: Option<bool>,
}
const MAX_PREFIX_LEN_IPV4: u8 = 32;
const MAX_PREFIX_LEN_IPV6: u8 = 128;

impl TunConfig {
    /// Set the tun name.
    ///
    /// [Note: on macOS, the tun name must be the form `utunx` where `x` is a number, such as `utun3`. -- end note]
    pub fn tun_name<T: Into<String>>(&mut self, tun_name: T) -> &mut Self {
        self.tun_name = Some(tun_name.into());
        self
    }

    /// Set the gateway address.
    pub fn address(&mut self, value: IpAddr) -> &mut Self {
        self.address = Some(value);
        self
    }

    /// Set the destination address.
    pub fn destination(&mut self, value: Ipv4Addr) -> &mut Self {
        self.destination = Some(value);
        self
    }

    /// Set the netmask for address
    pub fn prefix(&mut self, prefix: u8) -> &mut Self {
        self.prefix = Some(prefix);
        self
    }

    /// Set the MTU.
    pub fn mtu(&mut self, value: u16) -> &mut Self {
        self.mtu = Some(value);
        self
    }

    /// Set the interface to be enabled once created.
    pub fn up(&mut self) -> &mut Self {
        self.enabled = Some(true);
        self
    }
    /// Set whether to close the received raw file descriptor on drop or not.
    /// The default behaviour is to close the received or tun generated file descriptor.
    /// Note: If this is set to false, it is up to the caller to ensure the
    /// file descriptor (obtainable via [`AsRawFd::as_raw_fd`]) is properly closed.
    pub fn close_fd_on_drop(&mut self, value: bool) -> &mut Self {
        self.close_fd_on_drop = Some(value);
        self
    }

    /// Creates an async device based on TunConfig
    pub fn create_as_async(&self) -> std::io::Result<AsyncDevice> {
        let mut device = DeviceBuilder::new();
        if let Some(mtu) = self.mtu {
            device = device.mtu(mtu);
        }
        if let Some(name) = self.tun_name.as_ref() {
            device = device.name(name);
        }
        device = device.enable(self.enabled.unwrap_or(false));
        #[cfg(target_os = "macos")]
        {
            device = device.associate_route(false);
        }
        if let Some(address) = self.address {
            match address {
                IpAddr::V4(ipv4_addr) => {
                    let netmask = self
                        .prefix
                        .map(|x| x.min(MAX_PREFIX_LEN_IPV4))
                        .unwrap_or(MAX_PREFIX_LEN_IPV4);
                    device = device.ipv4(ipv4_addr, netmask, self.destination);
                }
                IpAddr::V6(ipv6_addr) => {
                    let netmask = self
                        .prefix
                        .map(|x| x.min(MAX_PREFIX_LEN_IPV6))
                        .unwrap_or(MAX_PREFIX_LEN_IPV6);
                    device = device.ipv6(ipv6_addr, netmask);
                }
            }
        }
        device.build_async()
    }
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

    /// Interface index of 'Tun' interface
    pub fn if_index(&self) -> std::io::Result<u32> {
        match self {
            Tun::Direct(t) => t.if_index(),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.if_index(),
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
    tun: ManuallyDrop<AsyncDevice>,
    mtu: u16,
    fd: RawFd,
    close_fd_on_drop: bool,
}

impl TunDirect {
    /// Create a new `Tun` struct
    pub fn new(config: TunConfig) -> Result<Self> {
        let tun_device = config.create_as_async()?;
        let fd = tun_device.as_raw_fd();
        let mtu = tun_device.mtu()?;
        let tun = ManuallyDrop::new(tun_device);

        Ok(TunDirect {
            tun,
            mtu,
            fd,
            close_fd_on_drop: config.close_fd_on_drop.unwrap_or(true),
        })
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
        match self.tun.try_send(&buf[..]) {
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

    /// Interface index of Tun
    pub fn if_index(&self) -> std::io::Result<u32> {
        self.tun.if_index()
    }
}

impl AsRawFd for TunDirect {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for TunDirect {
    fn into_raw_fd(mut self) -> RawFd {
        // Alters state to prevent drop from closing fd
        self.close_fd_on_drop = false;
        self.fd
    }
}

impl Drop for TunDirect {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if self.close_fd_on_drop {
            // Manually drop the AsyncDevice (closes the fd)
            // SAFETY: This is the final drop of TunDirect, so we have exclusive access to self.tun.
            // ManuallyDrop::drop is safe here because we never access self.tun again after this call.
            unsafe {
                ManuallyDrop::drop(&mut self.tun);
            }
        } else {
            // Take ownership and call into_raw_fd (prevents fd closure)
            // SAFETY: This is the final drop of TunDirect, so we have exclusive access to self.tun.
            // ManuallyDrop::take is safe here because we immediately consume the value and never access self.tun again.
            let tun = unsafe { ManuallyDrop::take(&mut self.tun) };
            let _ = tun.into_raw_fd();
        }
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
            Ok(pkt) => IOCallbackResult::Ok(pkt),
            Err(e) => IOCallbackResult::Err(std::io::Error::other(e)),
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

    /// Interface index of tun
    pub fn if_index(&self) -> std::io::Result<u32> {
        self.tun_io_uring.owned_fd().if_index()
    }
}

#[cfg(feature = "io-uring")]
impl AsRawFd for TunIoUring {
    fn as_raw_fd(&self) -> RawFd {
        self.tun_io_uring.owned_fd().as_raw_fd()
    }
}
