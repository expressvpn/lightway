#[cfg(any(linux, android))]
use std::os::fd::AsRawFd;
#[cfg(linux)]
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
#[cfg(feature = "io-uring")]
use std::time::Duration;
use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use pnet_packet::ipv4::Ipv4Packet;

use lightway_app_utils::{Tun as AppUtilsTun, TunConfig};
#[cfg(linux)]
use lightway_core::VirtioNetHdr;
#[cfg(linux)]
use lightway_core::gro::TcpGroTable;
use lightway_core::{
    IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg, InsideIpConfig,
    ipv4_update_destination, ipv4_update_source,
};

#[cfg(linux)]
use crate::io::inside::InsideIORecvGso;
#[cfg(any(linux, android))]
use crate::io::inside::raw_gro::{self, RawGro, RawTunIo};
use crate::{ConnectionState, io::inside::InsideIORecv};

pub struct Tun {
    tun: AppUtilsTun,
    ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
    #[cfg(linux)]
    gro: Gro,
    /// Raw downlink TCP coalescer for a device with no
    /// `virtio_net_hdr` framing (see [`raw_gro`]): the Android
    /// `VpnService` fd, which can never have it, or a Linux device
    /// opened without `enable_tun_offload`. Gated off by default —
    /// callers opt in via [`Self::set_tcp_coalescing_configured`] plus
    /// [`raw_gro::set_tun_tcp_coalescing_allowed`]. Where the device
    /// *did* negotiate `IFF_VNET_HDR`, [`Self::gro`] is used instead
    /// and this stays dormant.
    #[cfg(any(linux, android))]
    raw_gro: RawGro,
}

impl Tun {
    pub async fn new(tun: &TunConfig, ip: Ipv4Addr, dns_ip: Ipv4Addr) -> Result<Self> {
        let tun = AppUtilsTun::direct(tun).await?;
        Ok(Self::from_app_utils_tun(tun, ip, dns_ip))
    }

    #[cfg(feature = "io-uring")]
    pub async fn new_with_iouring(
        tun: &TunConfig,
        ip: Ipv4Addr,
        dns_ip: Ipv4Addr,
        iouring_ring_size: usize,
        iouring_sqpoll_idle_time: Duration,
    ) -> Result<Self> {
        let tun = AppUtilsTun::iouring(tun, iouring_ring_size, iouring_sqpoll_idle_time).await?;
        Ok(Self::from_app_utils_tun(tun, ip, dns_ip))
    }

    fn from_app_utils_tun(tun: AppUtilsTun, ip: Ipv4Addr, dns_ip: Ipv4Addr) -> Self {
        Tun {
            tun,
            ip,
            dns_ip,
            #[cfg(linux)]
            gro: Gro::new(),
            #[cfg(any(linux, android))]
            raw_gro: RawGro::new(raw_gro::DEFAULT_MAX_SUPERPACKET),
        }
    }

    pub fn if_index(&self) -> std::io::Result<u32> {
        self.tun.if_index()
    }

    /// Apply the `enable_tun_tcp_coalescing` config flag — the static
    /// rollout gate for the raw downlink TCP coalescer. Off by
    /// default. `&mut self` restricts this to device setup, before the
    /// `Tun` is shared; the runtime kill switch
    /// ([`raw_gro::set_tun_tcp_coalescing_allowed`]) and the
    /// capability probe still apply on top.
    ///
    /// Has no effect on a device that negotiated `IFF_VNET_HDR`
    /// (`enable_tun_offload`): there the kernel is told `gso_size`
    /// explicitly and the vnet-hdr path is strictly better, so
    /// [`Self::send_packet`] never consults the raw coalescer.
    #[cfg(any(linux, android))]
    pub fn set_tcp_coalescing_configured(&mut self, enabled: bool) {
        self.raw_gro.set_configured(enabled);
    }

    fn name(&self) -> std::io::Result<String> {
        self.tun.name()
    }

    /// Write one already-address-rewritten packet to the device,
    /// through whichever coalescer this device can use when a window
    /// is open.
    ///
    /// A device that negotiated `IFF_VNET_HDR` takes the vnet-hdr
    /// path: the superpacket carries `gso_size` and checksum metadata,
    /// so the kernel re-splits it properly and the write is a real TSO
    /// frame. Without that framing — the Android `VpnService` fd, or a
    /// Linux device opened without `enable_tun_offload` — coalesced
    /// runs must instead be injected as single oversized IPv4 packets;
    /// see [`raw_gro`] for the constraints and gates on that.
    ///
    /// The two are mutually exclusive by construction: exactly one
    /// coalescer is ever consulted for a given device, and the other's
    /// window is never opened (see [`Self::gro_open`]).
    #[cfg(any(linux, android))]
    fn send_packet(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        #[cfg(linux)]
        if self.tun.supports_gso() {
            return self.gro.send(&self.tun, buf);
        }
        self.raw_gro.send(&self.tun, buf)
    }

    /// Write one already-address-rewritten packet to the device. No
    /// coalescing on the remaining platforms — `virtio_net_hdr` writes
    /// are a Linux TUN feature, and the raw oversized write is probed
    /// only where its kernel behaviour is known.
    #[cfg(not(any(linux, android)))]
    fn send_packet(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        self.tun.try_send(buf)
    }
}

/// The device writes the raw coalescer performs, on the real TUN.
/// `send_slice` borrows so a rejected superpacket can be re-split and
/// re-sent from the same bytes.
#[cfg(any(linux, android))]
impl RawTunIo for AppUtilsTun {
    fn vnet_hdr_framing(&self) -> Option<bool> {
        /// `IFF_VNET_HDR` in `ifreq.ifr_flags`.
        const IFF_VNET_HDR: libc::c_short = 0x4000;
        Some(tun_iff_flags(self.as_raw_fd())? & IFF_VNET_HDR != 0)
    }

    fn send_slice(&self, pkt: &[u8]) -> IOCallbackResult<usize> {
        AppUtilsTun::try_send_slice(self, pkt)
    }

    fn send_owned(&self, pkt: BytesMut) -> IOCallbackResult<usize> {
        AppUtilsTun::try_send(self, pkt)
    }
}

/// Read the interface flags via `TUNGETIFF` — `_IOR('T', 210, unsigned
/// int)`. On Android this is the one tun ioctl SELinux whitelists for
/// app domains (`TUNSETIFF`/`TUNSETOFFLOAD` and friends all return
/// `EACCES` or fail structurally); on Linux it is simply the cheapest
/// way to confirm the fd's framing before probing an oversized write.
/// `None` if the ioctl failed.
#[cfg(any(linux, android))]
fn tun_iff_flags(fd: std::os::fd::RawFd) -> Option<libc::c_short> {
    // `ioctl`'s request argument is `c_ulong` on glibc/musl and
    // `c_int` on bionic, so keep the constant untyped-ish and let the
    // `as _` at the call site pick the right width. The value is
    // bit-identical either way.
    const TUNGETIFF: u32 = 0x800454d2;

    // SAFETY: `ifreq` is plain old data — an all-zero bit pattern is a
    // valid value of it, and the kernel fills in the parts it needs.
    #[allow(unsafe_code)]
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // SAFETY: `TUNGETIFF` only writes within the `ifreq` handed to it,
    // which is live and exclusively borrowed for the call.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::ioctl(fd, TUNGETIFF as _, &mut ifr) };
    if rc != 0 {
        return None;
    }

    // SAFETY: on success `TUNGETIFF` has populated the flags variant of
    // the `ifr_ifru` union.
    #[allow(unsafe_code)]
    Some(unsafe { ifr.ifr_ifru.ifru_flags })
}

/// The device writes the GRO coalescer performs. Implemented for
/// [`AppUtilsTun`] in production; tests substitute a fake that records
/// every write in call order, which is the only way to observe the
/// ordering guarantee [`Gro::coalesce_send`] relies on.
#[cfg(linux)]
trait TunSend {
    /// Whether the device negotiated `IFF_VNET_HDR`, i.e. whether it
    /// can accept a segmentation-offload write at all.
    fn supports_gso(&self) -> bool;

    /// Write one packet with no offload metadata.
    fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize>;

    /// Write one packet behind `hdr` as a `virtio_net_hdr` prefix.
    fn try_send_gso(&self, buf: BytesMut, hdr: &VirtioNetHdr) -> IOCallbackResult<usize>;
}

#[cfg(linux)]
impl TunSend for AppUtilsTun {
    // Spelled as associated-function calls so these forward to the
    // inherent methods and cannot recurse into the trait impl.
    fn supports_gso(&self) -> bool {
        AppUtilsTun::supports_gso(self)
    }

    fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        AppUtilsTun::try_send(self, buf)
    }

    fn try_send_gso(&self, buf: BytesMut, hdr: &VirtioNetHdr) -> IOCallbackResult<usize> {
        AppUtilsTun::try_send_gso(self, buf, hdr)
    }
}

/// Receive-side coalescing state: the window flag and the flow table
/// it gates.
#[cfg(linux)]
struct Gro {
    /// Whether a GRO coalescing window is open (see
    /// [`InsideIORecv::gro_open`]/[`InsideIORecv::gro_flush`]). Kept
    /// outside the table mutex so the per-packet send path pays only a
    /// relaxed load when offload is disabled. Opens, sends and flushes
    /// all happen on the outside IO task, so no stronger ordering is
    /// needed.
    open: AtomicBool,
    table: Mutex<TcpGroTable>,
}

#[cfg(linux)]
impl Gro {
    fn new() -> Self {
        Self {
            open: AtomicBool::new(false),
            table: Mutex::new(TcpGroTable::new()),
        }
    }

    /// Open a coalescing window. A device without `IFF_VNET_HDR` could
    /// not be handed a superpacket, so the window never opens there and
    /// every send stays on the direct write path.
    fn open(&self, tun: &impl TunSend) {
        if !tun.supports_gso() {
            return;
        }
        self.open.store(true, Ordering::Relaxed);
    }

    /// Close the window and write every superpacket the table still
    /// holds.
    fn flush(&self, tun: &impl TunSend) {
        self.open.store(false, Ordering::Relaxed);
        let mut table = self.table.lock().unwrap();
        for (pkt, hdr) in table.drain() {
            write_super(tun, pkt, hdr);
        }
    }

    /// Send one packet. Outside an open window the table is not even
    /// locked and the packet goes straight to the device.
    fn send(&self, tun: &impl TunSend, buf: BytesMut) -> IOCallbackResult<usize> {
        if !self.open.load(Ordering::Relaxed) {
            return tun.try_send(buf);
        }
        let mut table = self.table.lock().unwrap();
        Self::coalesce_send(tun, &mut table, buf)
    }

    /// Route a packet through the GRO coalescer. Returns `Ok(len)`
    /// whenever the table consumed the packet — core treats that as
    /// sent.
    fn coalesce_send(
        tun: &impl TunSend,
        table: &mut TcpGroTable,
        buf: BytesMut,
    ) -> IOCallbackResult<usize> {
        let len = buf.len();
        let result = table.append(&buf);
        // Any flushed superpackets must reach the TUN before this
        // packet to preserve within-flow delivery order. Pinned by
        // `flushed_superpackets_are_written_before_the_direct_write`.
        for (pkt, hdr) in result.flushes {
            write_super(tun, pkt, hdr);
        }
        if result.consumed {
            IOCallbackResult::Ok(len)
        } else {
            tun.try_send(buf)
        }
    }
}

/// Write one coalesced superpacket to the TUN. Failures are counted,
/// logged and dropped (datagram semantics) — the sends whose packets
/// were absorbed into it already reported success, so there is no
/// caller left to return the error to.
///
/// Both failure arms record the batch *and* its segment count, split
/// by cause (would-block is shedding under backpressure, `Err` is a
/// device fault). One dropped superpacket costs up to 64 segments
/// (`gro`'s `MAX_GSO_SEGS`; ~48 at a 1350-byte MSS), so the hole
/// punched in the local TCP stream is far larger than the single
/// packet the non-coalesced path would have lost — the ratio of the
/// segment counter to the batch counter makes that amplification
/// measurable instead of inferred.
///
/// A single-segment batch comes back with a default header, which
/// `try_send_gso` writes as the zeroed prefix a plain vnet-hdr
/// write uses — no special-casing needed.
#[cfg(linux)]
fn write_super(tun: &impl TunSend, pkt: BytesMut, hdr: VirtioNetHdr) {
    let segments = superpacket_segments(pkt.len(), &hdr);
    match tun.try_send_gso(pkt, &hdr) {
        IOCallbackResult::Ok(_) => {}
        IOCallbackResult::WouldBlock => {
            crate::metrics::tun_gro_batch_dropped_would_block(segments);
            tracing::warn!("Dropping coalesced GRO batch of {segments} segments: TUN would block");
        }
        IOCallbackResult::Err(err) => {
            crate::metrics::tun_gro_batch_dropped_err(segments);
            tracing::warn!("Dropping coalesced GRO batch of {segments} segments: {err}");
        }
    }
}

/// How many segments a superpacket expands to on the wire — the size
/// of the gap the local TCP stack sees if the write is dropped.
///
/// A single-segment batch carries a default header (`gso_size == 0`)
/// and is one segment; otherwise the payload beyond `hdr_len` splits
/// into `gso_size` chunks, the last of which may be short.
#[cfg(linux)]
fn superpacket_segments(len: usize, hdr: &VirtioNetHdr) -> u64 {
    let gso_size = hdr.gso_size as usize;
    if gso_size == 0 {
        return 1;
    }
    let payload = len.saturating_sub(hdr.hdr_len as usize);
    payload.div_ceil(gso_size).max(1) as u64
}

/// Counters for the GRO write path.

#[async_trait]
impl<ExtAppState: Send + Sync> InsideIORecv<ExtAppState> for Tun {
    async fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize> {
        self.tun.recv_buf(buf).await
    }

    /// Api to send packet in the tunnel
    fn try_send(&self, mut pkt: BytesMut, ip_config: Option<InsideIpConfig>) -> Result<usize> {
        let pkt_len = pkt.len();
        // Update destination IP from server provided inside ip to TUN device ip
        ipv4_update_destination(pkt.as_mut(), self.ip);

        // Update source IP from server DNS ip to TUN DNS ip
        if let Some(ip_config) = ip_config {
            let packet = Ipv4Packet::new(pkt.as_ref());
            if let Some(packet) = packet
                && packet.get_source() == ip_config.dns_ip
            {
                ipv4_update_source(pkt.as_mut(), self.dns_ip);
            };
        }

        self.tun.try_send(pkt);
        Ok(pkt_len)
    }

    fn mtu(&self) -> usize {
        self.tun.mtu()
    }

    #[cfg(linux)]
    fn as_gso(self: Arc<Self>) -> Option<Arc<dyn InsideIORecvGso<ExtAppState>>> {
        if self.tun.supports_gso() {
            Some(self)
        } else {
            None
        }
    }

    /// Open a window on whichever coalescer this device can use. The
    /// same predicate as [`Tun::send_packet`], so only one of the two
    /// ever holds an open window.
    #[cfg(any(linux, android))]
    fn gro_open(&self) {
        #[cfg(linux)]
        if self.tun.supports_gso() {
            self.gro.open(&self.tun);
            return;
        }
        self.raw_gro.open(&self.tun, self.ip);
    }

    #[cfg(any(linux, android))]
    fn gro_flush(&self) {
        #[cfg(linux)]
        if self.tun.supports_gso() {
            self.gro.flush(&self.tun);
            return;
        }
        self.raw_gro.flush(&self.tun);
    }

    fn into_io_send_callback(
        self: Arc<Self>,
    ) -> InsideIOSendCallbackArg<ConnectionState<ExtAppState>> {
        self
    }
}

#[cfg(linux)]
#[async_trait]
impl<ExtAppState: Send + Sync> InsideIORecvGso<ExtAppState> for Tun {
    async fn recv_gso(&self, buf: &mut BytesMut) -> IOCallbackResult<(usize, VirtioNetHdr)> {
        self.tun.recv_gso(buf).await
    }
}

impl<ExtAppState: Send + Sync> InsideIOSendCallback<ConnectionState<ExtAppState>> for Tun {
    fn send(
        &self,
        mut buf: BytesMut,
        state: &mut ConnectionState<ExtAppState>,
    ) -> IOCallbackResult<usize> {
        // Update destination IP from server provided inside ip to TUN device ip
        ipv4_update_destination(buf.as_mut(), self.ip);

        // Update source IP from server DNS ip to TUN DNS ip
        if let Some(ip_config) = state.ip_config {
            let packet = Ipv4Packet::new(buf.as_ref());
            if let Some(packet) = packet
                && packet.get_source() == ip_config.dns_ip
            {
                ipv4_update_source(buf.as_mut(), self.dns_ip);
            };
        }

        // Inside an open GRO window, TCP segments are coalesced into
        // TSO superpackets instead of written individually; outside
        // one this is a direct device write.
        self.send_packet(buf)
    }

    fn mtu(&self) -> usize {
        self.tun.mtu()
    }

    fn if_index(&self) -> std::io::Result<u32> {
        self.if_index()
    }

    fn name(&self) -> std::io::Result<String> {
        self.name()
    }
}

#[cfg(all(test, linux))]
mod tests {
    use super::*;
    use pnet_packet::ipv4::MutableIpv4Packet;
    use pnet_packet::tcp::{MutableTcpPacket, TcpFlags};
    use std::collections::VecDeque;

    const IPV4_HDR_LEN: usize = 20;
    const TCP_HDR_LEN: usize = 20;
    const HDR_LEN: usize = IPV4_HDR_LEN + TCP_HDR_LEN;
    /// Payload bytes per segment; also the batch's `gso_size`.
    const MSS: usize = 100;
    /// `lightway_core::gro::MAX_GRO_FLOWS` — the table's slot count.
    const MAX_GRO_FLOWS: usize = 8;
    const SRC: [u8; 4] = [10, 0, 0, 1];
    const DST: [u8; 4] = [10, 0, 0, 2];

    /// Which write path a packet took to the device.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Kind {
        /// [`TunSend::try_send`] — a plain write.
        Plain,
        /// [`TunSend::try_send_gso`] — a coalesced superpacket.
        Super,
    }

    /// One recorded device write.
    struct Write {
        kind: Kind,
        bytes: Vec<u8>,
        hdr: VirtioNetHdr,
    }

    /// TUN stand-in that records `(bytes, VirtioNetHdr)` for every
    /// write in call order, so relative ordering of superpacket and
    /// plain writes is observable.
    struct FakeTun {
        supports_gso: bool,
        /// Results handed out in order; once drained every write
        /// succeeds with the byte count.
        results: Mutex<VecDeque<IOCallbackResult<usize>>>,
        writes: Mutex<Vec<Write>>,
    }

    impl FakeTun {
        fn new() -> Self {
            Self {
                supports_gso: true,
                results: Mutex::new(VecDeque::new()),
                writes: Mutex::new(Vec::new()),
            }
        }

        /// A device that never negotiated `IFF_VNET_HDR`.
        fn without_gso() -> Self {
            Self {
                supports_gso: false,
                ..Self::new()
            }
        }

        /// A device whose first writes return `results`.
        fn with_results(results: Vec<IOCallbackResult<usize>>) -> Self {
            Self {
                results: Mutex::new(results.into()),
                ..Self::new()
            }
        }

        fn record(&self, kind: Kind, buf: &BytesMut, hdr: VirtioNetHdr) -> IOCallbackResult<usize> {
            self.writes.lock().unwrap().push(Write {
                kind,
                bytes: buf.to_vec(),
                hdr,
            });
            match self.results.lock().unwrap().pop_front() {
                Some(r) => r,
                None => IOCallbackResult::Ok(buf.len()),
            }
        }

        /// The write kinds, in call order.
        fn kinds(&self) -> Vec<Kind> {
            self.writes.lock().unwrap().iter().map(|w| w.kind).collect()
        }

        /// `(bytes, gso_size)` of the `n`th write.
        fn write(&self, n: usize) -> (Vec<u8>, u16) {
            let writes = self.writes.lock().unwrap();
            let w = &writes[n];
            (w.bytes.clone(), w.hdr.gso_size)
        }
    }

    impl TunSend for FakeTun {
        fn supports_gso(&self) -> bool {
            self.supports_gso
        }

        fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
            self.record(Kind::Plain, &buf, VirtioNetHdr::default())
        }

        fn try_send_gso(&self, buf: BytesMut, hdr: &VirtioNetHdr) -> IOCallbackResult<usize> {
            self.record(Kind::Super, &buf, *hdr)
        }
    }

    /// One IPv4/TCP segment of flow `src_port` carrying `payload_len`
    /// bytes at `seq`. Checksums are real, so the bytes are a
    /// plausible decrypted inside packet.
    fn seg(src_port: u16, seq: u32, payload_len: usize, flags: u8) -> BytesMut {
        let total = HDR_LEN + payload_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[6] = 0x40; // DF
        pkt[8] = 64; // TTL
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&SRC);
        pkt[16..20].copy_from_slice(&DST);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&5678u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&seq.to_be_bytes());
        pkt[32] = ((TCP_HDR_LEN / 4) as u8) << 4; // data offset
        pkt[33] = flags;
        pkt[34..36].copy_from_slice(&0xFFFFu16.to_be_bytes()); // window
        for (i, b) in pkt[HDR_LEN..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        {
            let mut ip = MutableIpv4Packet::new(&mut pkt[..IPV4_HDR_LEN]).unwrap();
            let csum = pnet_packet::ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(csum);
        }
        {
            let mut tcp = MutableTcpPacket::new(&mut pkt[IPV4_HDR_LEN..]).unwrap();
            let csum = pnet_packet::tcp::ipv4_checksum(
                &tcp.to_immutable(),
                &Ipv4Addr::from(SRC),
                &Ipv4Addr::from(DST),
            );
            tcp.set_checksum(csum);
        }
        BytesMut::from(&pkt[..])
    }

    /// A coalescable, full-MSS data segment.
    fn data(src_port: u16, seq: u32) -> BytesMut {
        seg(src_port, seq, MSS, TcpFlags::ACK)
    }

    /// A pure ACK: same flow, but never coalescable — it forces the
    /// held batch out and is then written directly.
    fn pure_ack(src_port: u16, seq: u32) -> BytesMut {
        seg(src_port, seq, 0, TcpFlags::ACK)
    }

    /// Fresh instances of both failure modes of a TUN write.
    fn failures() -> Vec<IOCallbackResult<usize>> {
        vec![
            IOCallbackResult::WouldBlock,
            IOCallbackResult::Err(std::io::Error::other("tun write failed")),
        ]
    }

    /// The ordering guarantee `coalesce_send` documents: a superpacket
    /// displaced by a packet must be written *before* that packet's
    /// direct write, or the flow's bytes reach the kernel out of order.
    /// Swapping the two blocks in `coalesce_send` fails only this.
    #[test]
    fn flushed_superpackets_are_written_before_the_direct_write() {
        let tun = FakeTun::new();
        let mut table = TcpGroTable::new();

        // Two in-order full-MSS segments coalesce and stay pending.
        for seq in [0, MSS as u32] {
            let pkt = data(1234, seq);
            let len = pkt.len();
            let r = Gro::coalesce_send(&tun, &mut table, pkt);
            assert!(matches!(r, IOCallbackResult::Ok(n) if n == len));
        }
        assert!(
            tun.kinds().is_empty(),
            "a pending batch must not be written before something forces it out"
        );

        // A same-flow pure ACK cannot join the batch: the batch is
        // flushed and the ACK written directly.
        let ack = pure_ack(1234, 2 * MSS as u32);
        let ack_bytes = ack.to_vec();
        let r = Gro::coalesce_send(&tun, &mut table, ack);
        assert!(matches!(r, IOCallbackResult::Ok(n) if n == ack_bytes.len()));

        assert_eq!(
            tun.kinds(),
            vec![Kind::Super, Kind::Plain],
            "the flushed superpacket must reach the TUN before the packet that displaced it"
        );
        let (sup, gso_size) = tun.write(0);
        assert_eq!(sup.len(), HDR_LEN + 2 * MSS);
        assert_eq!(gso_size, MSS as u16);
        assert_eq!(tun.write(1).0, ack_bytes);
    }

    /// `gro_open` is a no-op without `IFF_VNET_HDR`: a device that
    /// cannot take a `virtio_net_hdr` write must never have a window
    /// opened on it.
    #[test]
    fn gro_open_is_a_no_op_without_gso_support() {
        let gro = Gro::new();
        gro.open(&FakeTun::without_gso());
        assert!(!gro.open.load(Ordering::Relaxed));

        // Same call against a capable device does open the window.
        gro.open(&FakeTun::new());
        assert!(gro.open.load(Ordering::Relaxed));
    }

    /// `gro_flush` empties *every* occupied slot, not just the first —
    /// a partial drain would strand segments until the next window
    /// closed, or forever.
    #[test]
    fn gro_flush_drains_every_occupied_slot() {
        let tun = FakeTun::new();
        let gro = Gro::new();
        gro.open(&tun);

        // One pending two-segment batch per slot.
        for flow in 0..MAX_GRO_FLOWS {
            let port = 1000 + flow as u16;
            for seq in [0, MSS as u32] {
                let pkt = data(port, seq);
                let len = pkt.len();
                let r = gro.send(&tun, pkt);
                assert!(matches!(r, IOCallbackResult::Ok(n) if n == len));
            }
        }
        assert!(tun.kinds().is_empty(), "nothing should have flushed yet");

        gro.flush(&tun);

        assert_eq!(tun.kinds(), vec![Kind::Super; MAX_GRO_FLOWS]);
        for n in 0..MAX_GRO_FLOWS {
            let (bytes, gso_size) = tun.write(n);
            assert_eq!(bytes.len(), HDR_LEN + 2 * MSS);
            assert_eq!(gso_size, MSS as u16);
        }
        assert!(gro.table.lock().unwrap().is_empty());
        assert!(!gro.open.load(Ordering::Relaxed), "flush closes the window");
    }

    /// With no window open the packet bypasses the table entirely: a
    /// plain write, and nothing left buffered for a later flush.
    #[test]
    fn send_outside_a_window_bypasses_the_table() {
        let tun = FakeTun::new();
        let gro = Gro::new();

        let pkt = data(1234, 0);
        let bytes = pkt.to_vec();
        let r = gro.send(&tun, pkt);

        assert!(matches!(r, IOCallbackResult::Ok(n) if n == bytes.len()));
        assert_eq!(tun.kinds(), vec![Kind::Plain]);
        assert_eq!(tun.write(0).0, bytes);
        assert!(
            gro.table.lock().unwrap().is_empty(),
            "a closed window must not buffer anything"
        );

        // Consequently a later flush has nothing to write.
        gro.flush(&tun);
        assert_eq!(tun.kinds(), vec![Kind::Plain]);
    }

    /// A superpacket write that fails inside `coalesce_send` is
    /// invisible to the caller: the segments it carried were already
    /// reported as sent, so the consumed packet still returns `Ok`.
    #[test]
    fn superpacket_write_failure_does_not_reach_the_caller() {
        for fail in failures() {
            // The first write is the superpacket flush; it fails.
            let tun = FakeTun::with_results(vec![fail]);
            let gro = Gro::new();
            gro.open(&tun);

            let seed = data(1234, 0);
            assert!(matches!(gro.send(&tun, seed), IOCallbackResult::Ok(_)));

            // PSH ends the train, so this segment is absorbed and the
            // batch flushed in the same call.
            let psh = seg(1234, MSS as u32, MSS, TcpFlags::ACK | TcpFlags::PSH);
            let len = psh.len();
            let r = gro.send(&tun, psh);

            assert!(
                matches!(r, IOCallbackResult::Ok(n) if n == len),
                "a consumed packet reports success even when the superpacket write fails"
            );
            assert_eq!(tun.kinds(), vec![Kind::Super]);
            assert!(gro.table.lock().unwrap().is_empty());
        }
    }

    /// The same for a failure during `gro_flush`, which returns `()`
    /// and must not panic or leave the batch stuck in its slot.
    #[test]
    fn flush_write_failure_is_swallowed_and_still_drains() {
        for fail in failures() {
            let tun = FakeTun::with_results(vec![fail]);
            let gro = Gro::new();
            gro.open(&tun);

            for seq in [0, MSS as u32] {
                assert!(matches!(
                    gro.send(&tun, data(1234, seq)),
                    IOCallbackResult::Ok(_)
                ));
            }

            gro.flush(&tun);

            assert_eq!(tun.kinds(), vec![Kind::Super]);
            assert!(
                gro.table.lock().unwrap().is_empty(),
                "a failed write still frees the slot"
            );
        }
    }

    /// The segment count the drop metrics record — the amplification
    /// factor over a single-packet drop.
    #[test]
    fn segment_accounting_matches_the_superpacket_shape() {
        // Single-segment batch: default header, `gso_size` zero.
        assert_eq!(superpacket_segments(1400, &VirtioNetHdr::default()), 1);

        let hdr = VirtioNetHdr {
            hdr_len: 40,
            gso_size: 1350,
            ..Default::default()
        };
        assert_eq!(superpacket_segments(40 + 1350 * 3, &hdr), 3);
        // A short trailing segment still costs a segment.
        assert_eq!(superpacket_segments(40 + 1350 * 3 + 7, &hdr), 4);
        // A full 64KiB superpacket — the worst case the metric exists
        // to expose.
        assert_eq!(superpacket_segments(65535, &hdr), 49);
    }
}
