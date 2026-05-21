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

#[cfg(unix)]
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
    /// File Descriptor of the Tunnel. If this is set, it will not create a TUN device from scratch.
    #[cfg(unix)]
    pub fd: Option<RawFd>,
    /// Whether to close the file descriptor when the TUN device is dropped
    #[cfg(unix)]
    #[educe(Default = true)]
    pub close_fd_on_drop: bool,
    /// Enable TUN offload (`IFF_VNET_HDR`) so reads/writes carry a
    /// `virtio_net_hdr` and the kernel performs GRO/GSO across the
    /// device. Required for the GSO inside-IO path.
    #[cfg(target_os = "linux")]
    pub offload: bool,
    #[cfg(windows)]
    /// Optional wintun file path for Windows TUN interfaces
    pub wintun_file: Option<String>,
    #[cfg(windows)]
    /// Wintun ring buffer capacity in bytes. Larger values improve throughput.
    /// Must be a power of two between 128KiB and 64MiB.
    pub ring_capacity: Option<u32>,
    #[cfg(windows)]
    /// Optional fixed GUID for the Wintun adapter. Using a stable GUID ensures
    /// that adapter creation retries reuse the same device node rather than
    /// leaking duplicates.
    pub device_guid: Option<u128>,
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
    pub fn tun_name(&mut self, tun_name: String) -> &mut Self {
        #[cfg(macos)]
        assert!(
            tun_name.starts_with("utun"),
            "On macOS, the tun name must be the form `utunx` where `x` is a number, such as `utun3`"
        );
        self.tun_name = Some(tun_name);
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

    /// Set the file descriptor. If this is set, it will not create a TUN device from scratch.
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

    /// Set the wintun file path (Windows only).
    #[cfg(windows)]
    pub fn wintun_file<T: Into<String>>(&mut self, wintun_file: T) -> &mut Self {
        self.wintun_file = Some(wintun_file.into());
        self
    }

    /// Set the wintun ring buffer capacity in bytes (Windows only).
    /// Must be a power of two between 128KiB and 64MiB.
    #[cfg(windows)]
    pub fn ring_capacity(&mut self, capacity: u32) -> Result<&mut Self> {
        const MIN: u32 = 128 * 1024;
        const MAX: u32 = 64 * 1024 * 1024;
        anyhow::ensure!(
            capacity.is_power_of_two() && (MIN..=MAX).contains(&capacity),
            "ring capacity must be a power of two between 128KiB and 64MiB, got {capacity}"
        );
        self.ring_capacity = Some(capacity);
        Ok(self)
    }

    /// Set a fixed GUID for the Wintun adapter (Windows only).
    #[cfg(windows)]
    pub fn device_guid(&mut self, guid: u128) -> &mut Self {
        self.device_guid = Some(guid);
        self
    }

    /// Creates an async device based on TunConfig
    pub fn create_as_async(&self) -> std::io::Result<AsyncDevice> {
        // If a fd was provided (e.g. Apple Network Extension), wrap it directly
        // instead of creating a new TUN device, which would require elevated privileges.
        #[cfg(unix)]
        match self.fd {
            Some(fd) => {
                // SAFETY: The caller must ensure `fd` is a valid TUN device file descriptor
                // and transfer exclusive ownership to this function. The AsyncDevice will
                // properly close the fd when dropped (unless close_fd_on_drop is false).
                #[allow(unsafe_code)]
                return Ok(unsafe { tun_rs::AsyncDevice::from_raw_fd(fd) });
            }
            #[cfg(mobile)]
            None => return Err(std::io::Error::other("Unable to create device without fd")),
            #[cfg(not(mobile))]
            None => {}
        };

        #[cfg(desktop)]
        {
            let mut builder = DeviceBuilder::new();
            if let Some(name) = self.tun_name.as_ref() {
                builder = builder.name(name);
            }
            #[cfg(windows)]
            {
                if let Some(wintun_file) = self.wintun_file.as_ref() {
                    builder = builder.wintun_file(wintun_file.clone());
                }
                if let Some(ring_capacity) = self.ring_capacity {
                    builder = builder.with(|opt| {
                        opt.ring_capacity(ring_capacity);
                    });
                }
            }
            #[cfg(windows)]
            if let Some(guid) = self.device_guid {
                builder = builder.device_guid(guid);
            }
            #[cfg(macos)]
            {
                builder = builder.associate_route(false);
            }
            #[cfg(target_os = "linux")]
            if self.offload {
                builder = builder.offload(true);
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

    /// Recv a packet from `Tun` into `buf`.
    ///
    /// On success, `buf` holds the packet bytes and `buf.len()` equals the
    /// returned size. The caller must size `buf` to at least the interface
    /// MTU before calling (e.g. via `resize(mtu, 0)`).
    ///
    /// The [`Tun::Direct`] backend fills `buf` in place. The `IoUring` backend
    /// swaps `buf` for a buffer from its internal pool, so the underlying
    /// allocation may differ between calls.
    pub async fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize> {
        match self {
            Tun::Direct(t) => t.recv_buf(buf).await,
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.recv_buf(buf).await,
        }
    }

    /// Recv a GSO frame from `Tun` into `buf`, stripping and decoding the
    /// leading `virtio_net_hdr`.
    ///
    /// On success `buf` holds the IP payload (header already advanced past)
    /// and the returned tuple is `(buf.len(), hdr)`. Short reads and headers
    /// that fail to decode are reported as [`IOCallbackResult::WouldBlock`] so
    /// the caller's recv loop retries instead of treating them as hard errors.
    #[cfg(target_os = "linux")]
    pub async fn recv_gso(
        &self,
        buf: &mut BytesMut,
    ) -> IOCallbackResult<(usize, lightway_core::VirtioNetHdr)> {
        match self {
            Tun::Direct(t) => t.recv_gso(buf).await,
            #[cfg(feature = "io-uring")]
            Tun::IoUring(_) => {
                IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
            }
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

    /// Name of 'Tun' interface
    pub fn name(&self) -> std::io::Result<String> {
        match self {
            Tun::Direct(t) => t.name(),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.name(),
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
    /// `IFF_VNET_HDR` enabled — sends must be prefixed with a 12-byte
    /// `virtio_net_hdr`, reads include it.
    #[cfg(target_os = "linux")]
    vnet_hdr: bool,
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
            #[cfg(target_os = "linux")]
            vnet_hdr: config.offload,
        })
    }

    /// Recv from Tun
    pub async fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize> {
        let tun = self.tun.as_ref().unwrap();
        match tun.recv(buf).await {
            // TODO: Check whether we can use poll
            // Getting spurious reads
            Ok(0) => IOCallbackResult::WouldBlock,
            Ok(nr) => {
                buf.truncate(nr);
                IOCallbackResult::Ok(nr)
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    /// Recv a GSO frame into `buf`. See [`Tun::recv_gso`] for the
    /// buffer/result contract.
    #[cfg(target_os = "linux")]
    pub async fn recv_gso(
        &self,
        buf: &mut BytesMut,
    ) -> IOCallbackResult<(usize, lightway_core::VirtioNetHdr)> {
        use bytes::Buf;
        use lightway_core::gso::VIRTIO_NET_HDR_LEN;

        let tun = self.tun.as_ref().unwrap();

        // Read directly into the spare capacity. BytesMut's
        // spare_capacity_mut returns &mut [MaybeUninit<u8>] so there's
        // no zero-init pass on the hot path.
        let spare = buf.spare_capacity_mut();
        // SAFETY: `tun_rs::AsyncDevice::recv` takes `&mut [u8]` and forwards
        // to `libc::read(2)`. The kernel only writes — it never dereferences
        // userspace memory for reading — so handing it our uninitialized slab
        // is sound at the syscall boundary. The unsoundness lives in *Rust*:
        // constructing a `&mut [u8]` over uninitialized bytes is UB per strict
        // aliasing rules, even if no one reads them. This cast is the only
        // place we paper over that gap. Delete it once `tun-rs` exposes a
        // `MaybeUninit`-aware recv.
        #[allow(unsafe_code)]
        let raw =
            unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr().cast::<u8>(), spare.len()) };

        let n = match tun.recv(raw).await {
            Ok(0) => return IOCallbackResult::WouldBlock,
            Ok(n) => n,
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                return IOCallbackResult::WouldBlock;
            }
            Err(err) => return IOCallbackResult::Err(err),
        };

        if n <= VIRTIO_NET_HDR_LEN {
            tracing::warn!(n, "tun recv_gso: read shorter than virtio header");
            crate::metrics::tun_recv_gso_short_read();
            // Discard the partial read (buf is untouched — no set_len)
            // and return WouldBlock so the caller's recv loop retries
            // immediately instead of treating this as a hard error.
            return IOCallbackResult::WouldBlock;
        }

        // SAFETY: the kernel wrote exactly `n` bytes into the spare
        // slab; `n <= buf.capacity()` because the kernel wrote into a
        // slice of that length.
        #[allow(unsafe_code)]
        unsafe {
            buf.set_len(n);
        }

        // SAFETY for VirtioNetHdr::from_bytes: BytesMut is heap-backed
        // and 8-byte aligned; `n > VIRTIO_NET_HDR_LEN` was just checked.
        let hdr = match lightway_core::VirtioNetHdr::from_bytes(&buf[..VIRTIO_NET_HDR_LEN]) {
            Ok(h) => *h,
            Err(e) => {
                tracing::warn!(?e, "tun recv_gso: virtio header decode failed");
                buf.clear();
                return IOCallbackResult::WouldBlock;
            }
        };
        buf.advance(VIRTIO_NET_HDR_LEN);

        IOCallbackResult::Ok((buf.len(), hdr))
    }

    /// Try write from Tun
    pub fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        let tun = self.tun.as_ref().unwrap();
        #[cfg(target_os = "linux")]
        let res = if self.vnet_hdr {
            // IFF_VNET_HDR requires a zeroed `virtio_net_hdr` prefix
            // on every write (NEEDS_CSUM=0, GSO_NONE).
            let hdr_len = tun_rs::VIRTIO_NET_HDR_LEN;
            let mut prefixed = bytes::BytesMut::zeroed(hdr_len);
            prefixed.extend_from_slice(&buf[..]);
            tun.try_send(&prefixed[..])
                .map(|n| n.saturating_sub(hdr_len))
        } else {
            tun.try_send(&buf[..])
        };
        #[cfg(not(target_os = "linux"))]
        let res = tun.try_send(&buf[..]);
        match res {
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
        #[cfg(desktop)]
        {
            let tun = self.tun.as_ref().unwrap();
            tun.if_index()
        }
        #[cfg(mobile)]
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    /// Name of 'Tun' interface
    pub fn name(&self) -> std::io::Result<String> {
        #[cfg(desktop)]
        {
            let tun = self.tun.as_ref().unwrap();
            tun.name()
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
    pub async fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize> {
        match self.tun_io_uring.recv().await {
            Ok(pkt) => {
                let len = pkt.len();
                *buf = pkt;
                IOCallbackResult::Ok(len)
            }
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

    /// Name of 'Tun' interface
    pub fn name(&self) -> std::io::Result<String> {
        self.tun_io_uring.owned_fd().name()
    }
}

#[cfg(feature = "io-uring")]
impl AsRawFd for TunIoUring {
    fn as_raw_fd(&self) -> RawFd {
        self.tun_io_uring.owned_fd().as_raw_fd()
    }
}
