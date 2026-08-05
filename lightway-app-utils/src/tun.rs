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
                            // remove address before adding it to prevent error
                            // when address is already present
                            let _ = device.remove_address(address);
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
    ///
    /// If the device negotiated `IFF_VNET_HDR`, the [`Tun::Direct`] backend
    /// strips the `virtio_net_hdr` the kernel prepends, so `buf` always holds
    /// a bare IP packet regardless of framing. Size the buffer
    /// [`Tun::mtu`] + [`Tun::vnet_headroom`].
    pub async fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize> {
        match self {
            Tun::Direct(t) => t.recv_buf(buf).await,
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.recv_buf(buf).await,
        }
    }

    /// Recv up to `max` packets from Tun, appending to `pkts` (each
    /// buffer sized to the interface MTU by the backend). Waits only
    /// when nothing is immediately available. Only the io_uring backend
    /// returns more than one packet per call; the direct backend reads
    /// a single packet.
    #[cfg_attr(not(feature = "io-uring"), allow(unused_variables))]
    pub async fn recv_buf_many(
        &self,
        pkts: &mut Vec<BytesMut>,
        max: usize,
    ) -> IOCallbackResult<usize> {
        match self {
            Tun::Direct(t) => t.recv_buf_many(pkts).await,
            #[cfg(feature = "io-uring")]
            Tun::IoUring(t) => t.recv_buf_many(pkts, max).await,
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

    /// Whether this Tun supports GSO reads/writes. Only the direct
    /// backend, opened with [`TunConfig::offload`], does.
    #[cfg(linux)]
    pub fn supports_gso(&self) -> bool {
        match self {
            Tun::Direct(t) => t.supports_gso(),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(_) => false,
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

    /// Send a packet with an explicit virtio header (e.g. a TSO
    /// superpacket assembled by userspace GRO). Requires the device to
    /// have been opened with offload ([`TunConfig::offload`]). Only the
    /// direct backend supports this; the `IoUring` backend reports
    /// [`std::io::ErrorKind::Unsupported`].
    #[cfg(target_os = "linux")]
    pub fn try_send_gso(
        &self,
        buf: BytesMut,
        hdr: &lightway_core::VirtioNetHdr,
    ) -> IOCallbackResult<usize> {
        match self {
            Tun::Direct(t) => t.try_send_gso(buf, hdr),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(_) => {
                IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
            }
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

    /// Extra bytes a [`Tun::recv_buf`] buffer needs on top of [`Tun::mtu`].
    ///
    /// When the device negotiated `IFF_VNET_HDR` the kernel prepends a
    /// `virtio_net_hdr` to every read, so a buffer sized to the MTU alone
    /// cannot hold a full-size packet. The kernel truncates in that case
    /// and reports only the bytes it wrote — no flag the caller inspects
    /// says the tail was lost — so the shortfall is silent. Callers must
    /// size their buffer `mtu() + vnet_headroom()`.
    ///
    /// Zero unless offload is in use, and zero for the `IoUring` backend,
    /// which reads with its own pooled buffers.
    pub fn vnet_headroom(&self) -> usize {
        match self {
            Tun::Direct(t) => t.vnet_headroom(),
            #[cfg(feature = "io-uring")]
            Tun::IoUring(_) => 0,
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
    /// `IFF_VNET_HDR` enabled — sends must be prefixed with a 10-byte
    /// `virtio_net_hdr` (`size_of::<VirtioNetHdr>()`, the kernel's
    /// `TUNGETVNETHDRSZ` default), reads include it.
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

        // Reflect the capability the device negotiated, not what was
        // requested: `build_async` succeeds even when the kernel rejects
        // `TUNSETOFFLOAD` (tun-rs only warns), and `tcp_gso()` then reports
        // false. Note this tracks TSO/USO capability, not IFF_VNET_HDR
        // framing: tun-rs runs TUNSETIFF first and leaves the flag set on a
        // later TUNSETOFFLOAD failure, so the fd keeps vnet framing while
        // this flag says false. Harmless because supports_gso() returns this
        // flag and the as_gso() startup check aborts before traffic moves.
        #[cfg(target_os = "linux")]
        let vnet_hdr = {
            let negotiated = tun_device.tcp_gso();
            if config.offload && !negotiated {
                tracing::warn!(
                    "TUN offload requested but the kernel did not negotiate IFF_VNET_HDR; \
                     continuing without GSO/GRO offload"
                );
            }
            negotiated
        };

        let tun = Some(tun_device);

        Ok(TunDirect {
            tun,
            mtu,
            #[cfg(unix)]
            fd,
            #[cfg(unix)]
            close_fd_on_drop: config.close_fd_on_drop,
            #[cfg(target_os = "linux")]
            vnet_hdr,
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
                #[cfg(target_os = "linux")]
                if self.vnet_hdr {
                    return Self::strip_vnet_hdr(buf);
                }
                IOCallbackResult::Ok(nr)
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    /// Strip the leading `virtio_net_hdr` from a packet just read from a
    /// device opened with offload, leaving `buf` holding the IP payload.
    ///
    /// A read no longer than the header carries no packet, so it is
    /// discarded and reported as [`IOCallbackResult::WouldBlock`] to make
    /// the caller's recv loop retry rather than treat it as a hard error.
    ///
    /// Also checks the IPv4 length field against what was actually read.
    /// They disagree only if the buffer was not sized
    /// `mtu + vnet_headroom()` and the kernel truncated the tail — a
    /// caller bug that is otherwise silent, since the packet still looks
    /// well-formed. Warn rather than drop: with `TUN_F_TSO*` enabled the
    /// kernel may also deliver an aggregate here whose length field
    /// legitimately exceeds one MTU, and dropping those would trade a
    /// diagnostic for data loss.
    #[cfg(target_os = "linux")]
    fn strip_vnet_hdr(buf: &mut BytesMut) -> IOCallbackResult<usize> {
        use bytes::Buf;
        use lightway_core::gso::VIRTIO_NET_HDR_LEN;

        if buf.len() <= VIRTIO_NET_HDR_LEN {
            tracing::warn!(
                n = buf.len(),
                "tun recv_buf: read shorter than the virtio header"
            );
            buf.clear();
            return IOCallbackResult::WouldBlock;
        }

        buf.advance(VIRTIO_NET_HDR_LEN);

        if buf.len() >= 4 && (buf[0] >> 4) == 4 {
            let total_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            if total_length > buf.len() {
                tracing::warn!(
                    have = buf.len(),
                    total_length,
                    "tun recv_buf: IPv4 length exceeds the bytes read; \
                     receive buffer is missing Tun::vnet_headroom()"
                );
            }
        }

        IOCallbackResult::Ok(buf.len())
    }

    /// Recv one packet from Tun, appending it to `pkts` as a buffer
    /// sized to the interface MTU. The direct backend has no batched
    /// read, so this is the single-packet counterpart of the io_uring
    /// backend's `recv_buf_many`.
    pub async fn recv_buf_many(&self, pkts: &mut Vec<BytesMut>) -> IOCallbackResult<usize> {
        // `mtu + vnet_headroom` so an `IFF_VNET_HDR` read is not
        // truncated by the length of the prepended header.
        let cap = self.mtu() + self.vnet_headroom();
        let mut buf = BytesMut::with_capacity(cap);
        buf.resize(cap, 0);
        match self.recv_buf(&mut buf).await {
            IOCallbackResult::Ok(_n) => {
                pkts.push(buf);
                IOCallbackResult::Ok(1)
            }
            IOCallbackResult::WouldBlock => IOCallbackResult::WouldBlock,
            IOCallbackResult::Err(e) => IOCallbackResult::Err(e),
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
        #[cfg(target_os = "linux")]
        if self.vnet_hdr {
            // IFF_VNET_HDR requires a zeroed `virtio_net_hdr` prefix on
            // every write (NEEDS_CSUM=0, GSO_NONE). Send it vectored so the
            // header is not copied onto the packet; the returned count
            // excludes it to match a plain send.
            let hdr = [0u8; tun_rs::VIRTIO_NET_HDR_LEN];
            let chunks = [std::io::IoSlice::new(&hdr), std::io::IoSlice::new(&buf[..])];
            return Self::map_send_result(
                self.send_chunks(&chunks)
                    .map(|n| n.saturating_sub(hdr.len())),
            );
        }

        let tun = self.tun.as_ref().unwrap();
        Self::map_send_result(tun.try_send(&buf[..]))
    }

    /// Map the result of a TUN write onto an [`IOCallbackResult`], shared by
    /// every send path. A full write queue is retried by the caller;
    /// anything else is fatal. Mirrors `map_send_result` on the outside UDP
    /// path.
    fn map_send_result(res: std::io::Result<usize>) -> IOCallbackResult<usize> {
        match res {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    /// Send a packet with an explicit virtio header (e.g. a TSO
    /// superpacket assembled by userspace GRO). Requires the device to
    /// have been opened with offload ([`TunConfig::offload`]).
    #[cfg(target_os = "linux")]
    pub fn try_send_gso(
        &self,
        buf: BytesMut,
        hdr: &lightway_core::VirtioNetHdr,
    ) -> IOCallbackResult<usize> {
        if !self.vnet_hdr {
            debug_assert!(false, "try_send_gso called on a Tun opened without offload");
            // The device won't accept a virtio header; fall back to a
            // plain write rather than corrupt traffic in release builds.
            return self.try_send(buf);
        }

        // The returned count excludes the virtio header to match a plain send.
        let hdr = hdr.to_bytes();
        let chunks = [std::io::IoSlice::new(&hdr), std::io::IoSlice::new(&buf[..])];
        Self::map_send_result(
            self.send_chunks(&chunks)
                .map(|n| n.saturating_sub(hdr.len())),
        )
    }

    /// Write `chunks` to the TUN in one vectored send — no copy, no
    /// allocation. Returns the total number of bytes written across all
    /// chunks.
    #[cfg(target_os = "linux")]
    fn send_chunks(&self, chunks: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        self.tun.as_ref().unwrap().try_send_vectored(chunks)
    }

    /// MTU of Tun
    pub fn mtu(&self) -> usize {
        self.mtu as usize
    }

    /// Whether this device was opened with offload (`IFF_VNET_HDR`), so
    /// reads and writes carry a `virtio_net_hdr`.
    #[cfg(linux)]
    pub fn supports_gso(&self) -> bool {
        self.vnet_hdr
    }

    /// See [`Tun::vnet_headroom`].
    pub fn vnet_headroom(&self) -> usize {
        #[cfg(target_os = "linux")]
        {
            if self.vnet_hdr {
                return lightway_core::gso::VIRTIO_NET_HDR_LEN;
            }
        }
        0
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

#[cfg(windows)]
impl Drop for TunDirect {
    fn drop(&mut self) {
        let tun = self.tun.as_ref().unwrap();
        for address in tun.addresses().unwrap() {
            let _ = tun.remove_address(address);
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

    /// Recv up to `max` packets from Tun via the io_uring rx queue.
    pub async fn recv_buf_many(
        &self,
        pkts: &mut Vec<BytesMut>,
        max: usize,
    ) -> IOCallbackResult<usize> {
        match self.tun_io_uring.recv_many(pkts, max).await {
            Ok(n) => IOCallbackResult::Ok(n),
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
