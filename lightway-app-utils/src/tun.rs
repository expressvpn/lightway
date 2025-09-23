use anyhow::Result;
use bytes::BytesMut;
use educe::Educe;
use lightway_core::IOCallbackResult;

#[cfg(unix)]
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
#[cfg(feature = "io-uring")]
use std::time::Duration;
use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr},
};

#[cfg(mobile)]
use std::os::fd::FromRawFd;
#[cfg(feature = "io-uring")]
use std::sync::Arc;
use tun_rs::AsyncDevice;
#[cfg(desktop)]
use tun_rs::DeviceBuilder;

#[cfg(feature = "io-uring")]
use crate::IOUring;

/// Configuration options for creating a interface
///
/// This struct provides a builder-like interface for configuring TUN interfaces
/// with various network settings including address assignment, routing, and MTU.
#[derive(Clone, Educe)]
#[educe(Default)]
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
    pub enabled: bool,
    /// File Descriptor of the Tunnel
    #[cfg(unix)]
    pub fd: Option<RawFd>,
    /// Whether to close the file descriptor when the TUN device is dropped
    #[cfg(unix)]
    #[educe(Default = true)]
    pub close_fd_on_drop: bool,
}

impl Debug for TunConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("TunConfig");
        s.field("enabled", &self.enabled);

        if let Some(tun_name) = self.tun_name.as_ref() {
            s.field("prefix", tun_name);
        }
        if let Some(address) = self.address.as_ref() {
            s.field("address", address);
        }
        if let Some(destination) = self.destination.as_ref() {
            s.field("destination", destination);
        }
        if let Some(prefix) = self.prefix.as_ref() {
            s.field("prefix", prefix);
        }
        if let Some(mtu) = self.mtu.as_ref() {
            s.field("mtu", mtu);
        }
        #[cfg(unix)]
        if let Some(fd) = self.fd.as_ref() {
            s.field("fd", fd);
        }
        #[cfg(unix)]
        s.field("close_fd_on_drop", &self.close_fd_on_drop);
        s.finish()
    }
}

impl TunConfig {
    /// Set the tun name.
    /// # Note:
    /// On macOS, the tun name must be the form `utunx` where `x` is a number, such as `utun3`
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
        self.enabled = true;
        self
    }

    /// Set the file descriptor
    #[cfg(unix)]
    pub fn raw_fd(&mut self, fd: RawFd) -> &mut Self {
        self.fd = Some(fd);
        self
    }

    /// Set whether to close the received raw file descriptor on drop or not.
    /// The default behaviour is to close the received or tun generated file descriptor.
    /// Note: If this is set to true, it is up to the caller to ensure the
    /// file descriptor (obtainable via [`AsRawFd::as_raw_fd`]) is properly closed.
    #[cfg(unix)]
    pub fn close_fd_on_drop(&mut self, value: bool) -> &mut Self {
        self.close_fd_on_drop = value;
        self
    }

    /// Creates an async device based on TunConfig
    #[cfg(desktop)]
    pub fn create_as_async(&self) -> std::io::Result<AsyncDevice> {
        let mut builder = DeviceBuilder::new();
        if let Some(name) = self.tun_name.as_ref() {
            builder = builder.name(name);
        }
        #[cfg(target_os = "macos")]
        {
            builder = builder.associate_route(false);
        }
        let device = builder.build_async()?;

        if let Some(mtu) = self.mtu {
            device.set_mtu(mtu)?;
        }

        device.enabled(self.enabled)?;

        if let Some(address) = self.address {
            match address {
                IpAddr::V4(ipv4_addr) => {
                    let netmask = self
                        .prefix
                        .map(|x| x.min(Ipv4Addr::BITS as u8))
                        .unwrap_or(Ipv4Addr::BITS as u8);
                    // Windows if destination provided create a default route with
                    // high priority
                    if cfg!(windows) {
                        device.add_address_v4(ipv4_addr, netmask)?;
                    } else {
                        device.set_network_address(ipv4_addr, netmask, self.destination)?;
                    }
                }
                IpAddr::V6(ipv6_addr) => {
                    use std::net::Ipv6Addr;

                    let netmask = self
                        .prefix
                        .map(|x| x.min(Ipv6Addr::BITS as u8))
                        .unwrap_or(Ipv6Addr::BITS as u8);
                    device.add_address_v6(ipv6_addr, netmask)?;
                }
            }
        }
        Ok(device)
    }

    /// Creates an async device based on TunConfig
    #[allow(unsafe_code)]
    #[cfg(mobile)]
    pub fn create_as_async(&self) -> std::io::Result<AsyncDevice> {
        let device = match self.fd {
            Some(fd) => {
                // SAFETY: The caller must ensure `fd` is a valid TUN device file descriptor
                // and transfer exclusive ownership to this function. The AsyncDevice will
                // properly close the fd when dropped.
                unsafe { tun_rs::AsyncDevice::from_raw_fd(fd) }
            }
            None => {
                return Err(std::io::Error::other("Unable to create device without fd"));
            }
        };

        Ok(device)
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
    pub async fn direct(config: &TunConfig) -> Result<Self> {
        Ok(Self::Direct(TunDirect::new(config)?))
    }

    /// Create new `Tun` instance with iouring read/write
    #[cfg(feature = "io-uring")]
    pub async fn iouring(
        config: &TunConfig,
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

    /// Set the DNS servers for the tunnel interface
    #[cfg(windows)]
    pub fn set_dns_servers(&self, dns_servers: &[IpAddr]) -> std::io::Result<()> {
        if let Tun::Direct(t) = self {
            t.set_dns_servers(dns_servers)
        } else {
            Ok(())
        }
    }

    /// Clear the DNS servers for the tunnel interface
    #[cfg(windows)]
    pub fn clear_dns_servers(&self) -> std::io::Result<()> {
        if let Tun::Direct(t) = self {
            t.clear_dns_servers()
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
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
    tun: Option<AsyncDevice>,
    mtu: u16,
    #[cfg(unix)]
    fd: RawFd,
    #[cfg(unix)]
    close_fd_on_drop: bool,
}

impl TunDirect {
    /// Create a new `Tun` struct
    pub fn new(config: &TunConfig) -> Result<Self> {
        let tun_device = config.create_as_async()?;
        #[cfg(unix)]
        let fd = tun_device.as_raw_fd();
        #[cfg(desktop)]
        let mtu = tun_device.mtu()?;
        // This currently is not supported for Android and IOS
        #[cfg(mobile)]
        let mtu = 1350;
        let tun = Some(tun_device);

        Ok(TunDirect {
            tun,
            mtu,
            #[cfg(unix)]
            fd,
            #[cfg(unix)]
            close_fd_on_drop: config.close_fd_on_drop,
        })
    }

    /// Recv from Tun
    pub async fn recv_buf(&self) -> IOCallbackResult<bytes::BytesMut> {
        let tun = self.tun.as_ref().unwrap();
        let mut buf = BytesMut::zeroed(self.mtu as usize);
        match tun.recv(buf.as_mut()).await {
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
        let tun = self.tun.as_ref().unwrap();
        match tun.try_send(&buf[..]) {
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

    /// Set the DNS servers for the tunnel interface
    #[cfg(windows)]
    pub fn set_dns_servers(&self, dns_servers: &[IpAddr]) -> std::io::Result<()> {
        Ok(())
    }

    /// Clear the DNS servers for the tunnel interface
    #[cfg(windows)]
    pub fn clear_dns_servers(&self) -> std::io::Result<()> {
        Ok(())
    }

    /// Interface index of Tun
    pub fn if_index(&self) -> std::io::Result<u32> {
        #[cfg(desktop)]
        {
            let tun = self.tun.as_ref().unwrap();
            tun.if_index()
        }
        #[cfg(mobile)]
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

#[cfg(unix)]
impl AsRawFd for TunDirect {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(unix)]
impl IntoRawFd for TunDirect {
    fn into_raw_fd(mut self) -> RawFd {
        // Alters state to prevent drop from closing fd
        self.close_fd_on_drop = false;
        self.fd
    }
}

#[cfg(unix)]
impl Drop for TunDirect {
    fn drop(&mut self) {
        if !self.close_fd_on_drop {
            let tun = self.tun.take().unwrap();
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
        config: &TunConfig,
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
