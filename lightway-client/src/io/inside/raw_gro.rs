//! Downlink TCP coalescing for a TUN with no offload metadata channel
//! — the Android `VpnService` fd.
//!
//! The fd handed over by `VpnService.establish()` is already attached
//! to the tun, so `TUNSETIFF` with `IFF_VNET_HDR` fails with `EEXIST`
//! before any capability check, and SELinux ioctl xperms block
//! `TUNSETOFFLOAD` (only `TUNGETIFF` is whitelisted for app domains).
//! There is therefore no `virtio_net_hdr` framing in either direction:
//! one `write()` injects exactly one packet, and neither `gso_size`
//! nor checksum metadata can accompany it. The vnet-hdr GRO path in
//! [`super::tun`] does not apply.
//!
//! What does work — verified on Android GKI 6.6 — is that
//! `tun_get_user()` performs no MTU check: a single oversized IPv4
//! packet up to 65535 bytes is accepted and locally delivered intact.
//! So instead of writing N decrypted TCP segments with N `write()`
//! calls, a run of same-flow, sequence-contiguous segments is merged
//! into one oversized packet ([`TcpGroBatch::take_raw`]) and written
//! once. TCP sockets observe an identical byte stream because TCP has
//! no packet boundaries at the socket API.
//!
//! The constraints, in rough order of importance:
//!
//! - **TCP only, unconditionally.** UDP datagram boundaries are
//!   semantic; without `gso_size` the kernel cannot re-split, and the
//!   receiving socket would get one fabricated datagram, breaking
//!   QUIC, DNS, RTP and DTLS. [`TcpGroBatch`]'s predicate (a port of
//!   the kernel's `tcp_gro_receive`) admits only IPv4 TCP payload
//!   segments; everything else passes through 1:1.
//! - **Tethering kill switch.** A coalesced packet that is *forwarded*
//!   rather than locally delivered is dropped by `ip_forward()` with
//!   an ICMP frag-needed sent to the remote origin — which already
//!   respects the path MTU and has nothing to fix — so its
//!   retransmission is coalesced and dropped again: a permanent
//!   blackhole for tethered flows. Locally-delivered and forwarded
//!   packets cannot be told apart here (Android masquerades tethered
//!   clients to the tun address; the fork happens inside conntrack
//!   after our write), so coalescing is gated on a global allow flag
//!   that **defaults to off** and must only be enabled by the app
//!   layer while no tethering or local forwarding is active — see
//!   [`set_tun_tcp_coalescing_allowed`].
//! - **Probed capability, permanent fallback.** Unbounded tun writes
//!   are a fuzzed attack surface and a future GKI may bound the write
//!   path, so the oversized write is probed at runtime (after
//!   confirming via `TUNGETIFF` that the fd really has no
//!   `IFF_VNET_HDR` framing) and never assumed. Any `EMSGSIZE`,
//!   `EINVAL` or short write afterwards trips a permanent, logged
//!   fallback to per-packet writes; the failed run is re-split into
//!   its wire segments ([`RawSuperpacket::build_segment`]) so nothing
//!   is lost.
//! - **Strict arrival order, no buffering across batches.** A single
//!   run accumulator coalesces only adjacent packets: anything that
//!   cannot join the run flushes it first, and the window is opened
//!   and flushed around one decrypt batch by the outside IO loop —
//!   packets never wait for future traffic and no timer exists. This
//!   also means flow A's packets are never held while flow B's pass
//!   through, which would be read as reordering/loss.
//!
//! Expect the kernel to log `TCP: tunN: Driver has suspect GRO
//! implementation, TCP performance may be compromised` once per boot
//! (`tcp_gro_dev_warn()`): the coalesced lengths correspond to no real
//! wire segment. It is harmless, but it is one reason the default run
//! cap ([`DEFAULT_MAX_SUPERPACKET`]) stays well below the 65535
//! ceiling — `tcp_measure_rcv_mss()` feeds those lengths into quickack
//! and window-growth heuristics.
//!
//! The tun MTU is deliberately left at the real tunnel MTU: apps read
//! `IP_MTU`, and QUIC would start probing oversized datagrams if it
//! were raised.

// On non-Android targets this module exists only for its unit tests
// (see the declaration in `io::inside`), so the items the Android
// wiring consumes look unused there.
#![cfg_attr(not(android), allow(dead_code))]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use bytes::BytesMut;
use lightway_core::IOCallbackResult;
use lightway_core::gro::{GroAppend, MAX_IPV4_PACKET_LEN, RawSuperpacket, TcpGroBatch};

/// IPv4 header length with IHL == 5 — the only shape the coalescer
/// emits and the probe packet uses.
const IPV4_HDR_LEN: usize = 20;

/// RFC 3692 experimental protocol number carried by the probe packet:
/// no local handler exists, so the stack drops it after accepting the
/// write, which is all the probe needs to observe.
const IPPROTO_EXPERIMENTAL: u8 = 253;

/// Default cap on a coalesced superpacket (headers + payload).
///
/// The hard ceiling is 65535 (IPv4 `total_length`), but the target
/// stays well below it to bound per-write latency and buffer memory,
/// and to keep the fake segment lengths fed to the peer stack's
/// `tcp_measure_rcv_mss()` moderate. Per-write cost decomposes to
/// ~0.9µs fixed + ~31ns/KB, so 32KB already removes ~95% of the
/// per-packet overhead; doubling it again buys almost nothing.
pub(crate) const DEFAULT_MAX_SUPERPACKET: usize = 32 * 1024;

/// Errno values as Linux/Android define them, spelled locally so this
/// module (which is compiled for host tests too) does not depend on
/// per-platform `libc` constants.
const EINVAL: i32 = 22;
const EMSGSIZE: i32 = 90;

/// The global coalescing allow flag — the tethering kill switch.
/// Defaults to **off**: an app that never opts in gets the plain
/// per-packet write path.
static COALESCING_ALLOWED: AtomicBool = AtomicBool::new(false);

/// Allow or forbid downlink TCP coalescing on the Android TUN write
/// path. **Correctness gate, not a tuning knob** — the caller owns the
/// tethering contract:
///
/// - Enable only while no tethering or local packet forwarding is
///   active. A coalesced packet that gets forwarded is blackholed
///   (see the module docs), and the split between locally-delivered
///   and forwarded packets is invisible at this layer.
/// - Subscribe to tethering state changes and call
///   `set_tun_tcp_coalescing_allowed(false)` the moment tethering
///   comes up. The store is immediate: every packet offered after
///   this returns is written per-packet (at most one already
///   in-flight oversized write can still complete), so there is no
///   need to wait for a batch boundary.
///
/// Enabling is lazy and safe to call before the tunnel exists: the
/// first coalescing window after enablement runs the capability probe,
/// and the flag has no effect on platforms without the raw path.
pub fn set_tun_tcp_coalescing_allowed(allowed: bool) {
    COALESCING_ALLOWED.store(allowed, Ordering::Relaxed);
    tracing::info!(allowed, "tun TCP coalescing allow flag set");
}

/// The device writes the raw coalescer performs. Implemented for
/// `lightway_app_utils::Tun` on Android; tests substitute a fake that
/// records every write in call order, which is how the ordering and
/// fallback guarantees are observed.
pub(crate) trait RawTunIo {
    /// Whether the fd carries `IFF_VNET_HDR` framing, read via
    /// `TUNGETIFF` (the one tun ioctl Android whitelists). `None` when
    /// the ioctl itself failed.
    fn vnet_hdr_framing(&self) -> Option<bool>;

    /// Write one raw IP packet from a borrowed slice, so the caller
    /// can retain the bytes if the write fails.
    fn send_slice(&self, pkt: &[u8]) -> IOCallbackResult<usize>;

    /// Write one raw IP packet, consuming the buffer.
    fn send_owned(&self, pkt: BytesMut) -> IOCallbackResult<usize>;
}

/// Single-run downlink TCP coalescer over a raw (no `virtio_net_hdr`)
/// TUN write path. See the module docs for the whole contract.
pub(crate) struct RawGro {
    /// Whether a coalescing window is open (between the outside IO
    /// loop's `gro_open` and `gro_flush` around one decrypt batch).
    /// Kept outside the batch mutex so the send path pays only a
    /// relaxed load when coalescing is off. Opens, sends and flushes
    /// all happen on the outside IO task, so no stronger ordering is
    /// needed.
    open: AtomicBool,
    /// Probe outcome, run at most once per device: `TUNGETIFF`
    /// confirms the framing, then one oversized write must return the
    /// full count. Never re-probed — a capability, not an ABI.
    capable: OnceLock<bool>,
    /// Permanent per-packet fallback, tripped by `EMSGSIZE`, `EINVAL`
    /// or a short write on a coalesced packet.
    fell_back: AtomicBool,
    /// The single run accumulator (strict arrival order — deliberately
    /// not the multi-flow table the vnet-hdr path uses, which holds
    /// one flow's packets while another's pass through).
    batch: Mutex<TcpGroBatch>,
    /// Superpacket byte cap; also the probe write's size, so the probe
    /// validates exactly the envelope of writes that will follow.
    max_len: usize,
    /// The allow flag consulted on every packet; the global
    /// [`COALESCING_ALLOWED`] in production, injectable for tests.
    allowed: &'static AtomicBool,
}

impl RawGro {
    pub(crate) fn new(max_len: usize) -> Self {
        Self::with_allowed(max_len, &COALESCING_ALLOWED)
    }

    fn with_allowed(max_len: usize, allowed: &'static AtomicBool) -> Self {
        let max_len = max_len.min(MAX_IPV4_PACKET_LEN);
        Self {
            open: AtomicBool::new(false),
            capable: OnceLock::new(),
            fell_back: AtomicBool::new(false),
            batch: Mutex::new(TcpGroBatch::with_max_len(max_len)),
            max_len,
            allowed,
        }
    }

    fn allowed(&self) -> bool {
        self.allowed.load(Ordering::Relaxed)
    }

    /// Open a coalescing window for one decrypt batch. No-op unless
    /// the app has allowed coalescing and the device passed (or now
    /// passes — the probe is lazy) the capability probe.
    pub(crate) fn open(&self, tun: &impl RawTunIo, local_ip: Ipv4Addr) {
        if !self.allowed() || self.fell_back.load(Ordering::Relaxed) {
            return;
        }
        let capable = *self
            .capable
            .get_or_init(|| Self::probe(tun, local_ip, self.max_len));
        if !capable {
            return;
        }
        self.open.store(true, Ordering::Relaxed);
    }

    /// Close the window and write out whatever the run still holds.
    /// Never holds packets past this point: the window covers exactly
    /// one decrypt batch, with no timer.
    pub(crate) fn flush(&self, tun: &impl RawTunIo) {
        if !self.open.swap(false, Ordering::Relaxed) {
            // Never opened (or already closed by a mid-window kill
            // switch flip, which drained the batch itself).
            return;
        }
        let mut batch = self.batch.lock().unwrap();
        if let Some(sp) = batch.take_raw() {
            self.write_run(tun, sp);
        }
    }

    /// Send one packet. Outside an open window the batch is not even
    /// locked and the packet goes straight to the device.
    pub(crate) fn send(&self, tun: &impl RawTunIo, buf: BytesMut) -> IOCallbackResult<usize> {
        if !self.open.load(Ordering::Relaxed) {
            return tun.send_owned(buf);
        }
        let mut batch = self.batch.lock().unwrap();

        if !self.allowed() || self.fell_back.load(Ordering::Relaxed) {
            // Kill switch flipped (or the fallback tripped) inside an
            // open window: stop coalescing immediately. Drain the held
            // run — `write_run` re-splits it per segment in this state,
            // so no further oversized packet is emitted — and only then
            // write this packet, preserving within-flow order.
            self.open.store(false, Ordering::Relaxed);
            if let Some(sp) = batch.take_raw() {
                self.write_run(tun, sp);
            }
            return tun.send_owned(buf);
        }

        self.coalesce_send(tun, &mut batch, buf)
    }

    /// Route a packet through the run accumulator. Returns `Ok(len)`
    /// whenever the run consumed the packet — core treats that as
    /// sent.
    fn coalesce_send(
        &self,
        tun: &impl RawTunIo,
        batch: &mut TcpGroBatch,
        buf: BytesMut,
    ) -> IOCallbackResult<usize> {
        let len = buf.len();
        match batch.append(&buf) {
            GroAppend::Coalesced => IOCallbackResult::Ok(len),
            GroAppend::CoalescedFlush => {
                let sp = batch.take_raw().expect("batch just absorbed a segment");
                self.write_run(tun, sp);
                IOCallbackResult::Ok(len)
            }
            GroAppend::Incompatible => {
                // Anything the run cannot absorb ends it: the held
                // segments must reach the device before this packet to
                // preserve within-flow order. The packet then re-seeds
                // the empty run when it can (it may be non-coalescable
                // outright — UDP, pure ACK, PSH-first — in which case
                // it is written directly).
                if let Some(sp) = batch.take_raw() {
                    self.write_run(tun, sp);
                }
                match batch.append(&buf) {
                    GroAppend::Coalesced => IOCallbackResult::Ok(len),
                    GroAppend::CoalescedFlush => {
                        let sp = batch.take_raw().expect("batch just absorbed a segment");
                        self.write_run(tun, sp);
                        IOCallbackResult::Ok(len)
                    }
                    GroAppend::Incompatible => tun.send_owned(buf),
                }
            }
        }
    }

    /// Write one finalized run to the device. The sends whose packets
    /// were absorbed into it already reported success, so failures here
    /// are counted and logged, never propagated.
    fn write_run(&self, tun: &impl RawTunIo, sp: RawSuperpacket) {
        if sp.segs == 1 {
            // A run of one is the original packet, bytes untouched —
            // an ordinary-sized write with no capability implications.
            match tun.send_slice(&sp.pkt) {
                IOCallbackResult::Ok(_) => {}
                IOCallbackResult::WouldBlock => {
                    crate::metrics::tun_gro_batch_dropped_would_block(1);
                    tracing::warn!("Dropping coalesced packet: TUN would block");
                }
                IOCallbackResult::Err(err) => {
                    crate::metrics::tun_gro_batch_dropped_err(1);
                    tracing::warn!("Dropping coalesced packet: {err}");
                }
            }
            return;
        }

        if self.fell_back.load(Ordering::Relaxed) || !self.allowed() {
            // Fallback already tripped, or the kill switch flipped
            // after these segments were absorbed: emit them per
            // segment rather than as one oversized packet.
            self.write_resplit(tun, &sp);
            return;
        }

        match tun.send_slice(&sp.pkt) {
            IOCallbackResult::Ok(n) if n == sp.pkt.len() => {}
            IOCallbackResult::Ok(n) => {
                // The kernel drops the truncated injection at
                // `ip_rcv` (total_length exceeds the bytes), so the
                // re-split below is a clean resend, not a duplicate.
                self.trip_fallback(&format!("short write ({n} of {} bytes)", sp.pkt.len()));
                self.write_resplit(tun, &sp);
            }
            IOCallbackResult::WouldBlock => {
                // Load shedding under backpressure, exactly like the
                // vnet-hdr path: the inside device is the bottleneck
                // and re-splitting would write into the same full
                // queue. One dropped run costs up to `segs` segments;
                // the counters keep that amplification measurable.
                crate::metrics::tun_gro_batch_dropped_would_block(sp.segs as u64);
                tracing::warn!(
                    segments = sp.segs,
                    "Dropping coalesced run: TUN would block"
                );
            }
            IOCallbackResult::Err(err)
                if matches!(err.raw_os_error(), Some(EMSGSIZE) | Some(EINVAL)) =>
            {
                self.trip_fallback(&format!("{err}"));
                self.write_resplit(tun, &sp);
            }
            IOCallbackResult::Err(err) => {
                crate::metrics::tun_gro_batch_dropped_err(sp.segs as u64);
                tracing::warn!(segments = sp.segs, "Dropping coalesced run: {err}");
            }
        }
    }

    /// Write a run segment-by-segment — the no-loss path when the
    /// oversized write was refused or is no longer permitted.
    fn write_resplit(&self, tun: &impl RawTunIo, sp: &RawSuperpacket) {
        let mut out = BytesMut::with_capacity(sp.hdr_len + sp.gso_size);
        for idx in 0..sp.segs {
            if !sp.build_segment(idx, &mut out) {
                crate::metrics::tun_raw_gro_resplit_segment_dropped();
                tracing::warn!(idx, "re-split segment rebuild failed");
                continue;
            }
            match tun.send_slice(&out) {
                IOCallbackResult::Ok(_) => {}
                IOCallbackResult::WouldBlock => {
                    crate::metrics::tun_raw_gro_resplit_segment_dropped();
                    tracing::warn!(idx, "Dropping re-split segment: TUN would block");
                }
                IOCallbackResult::Err(err) => {
                    crate::metrics::tun_raw_gro_resplit_segment_dropped();
                    tracing::warn!(idx, "Dropping re-split segment: {err}");
                }
            }
        }
    }

    /// Latch the permanent per-packet fallback. Idempotent; the first
    /// trip is the one that logs and counts.
    fn trip_fallback(&self, cause: &str) {
        if !self.fell_back.swap(true, Ordering::Relaxed) {
            crate::metrics::tun_raw_gro_permanent_fallback();
            tracing::warn!(
                cause,
                "oversized TUN write rejected; permanently falling back to per-packet writes"
            );
        }
    }

    /// One-shot capability probe.
    ///
    /// First `TUNGETIFF`: if the fd somehow carries `IFF_VNET_HDR`
    /// (a future Android, or a misrouted platform), raw oversized
    /// writes are the wrong tool — the standard virtio GSO path is
    /// strictly better — so this path disables itself. If the ioctl
    /// fails outright the framing cannot be verified, which is treated
    /// the same way.
    ///
    /// Then one oversized write of exactly `max_len` bytes — the
    /// largest packet the coalescer will ever emit — of a harmless
    /// probe packet (see [`probe_packet`]) must return the full count.
    fn probe(tun: &impl RawTunIo, local_ip: Ipv4Addr, max_len: usize) -> bool {
        match tun.vnet_hdr_framing() {
            Some(false) => {}
            Some(true) => {
                tracing::info!(
                    "TUN has IFF_VNET_HDR framing; raw TCP coalescing does not apply \
                     (the virtio GSO path should be used instead)"
                );
                crate::metrics::tun_raw_gro_probe_failed();
                return false;
            }
            None => {
                tracing::warn!(
                    "TUNGETIFF failed; cannot verify TUN framing, raw TCP coalescing disabled"
                );
                crate::metrics::tun_raw_gro_probe_failed();
                return false;
            }
        }

        let pkt = probe_packet(local_ip, max_len);
        match tun.send_slice(&pkt) {
            IOCallbackResult::Ok(n) if n == pkt.len() => {
                tracing::info!(
                    max_len,
                    "oversized TUN write probe succeeded; TCP coalescing available"
                );
                true
            }
            IOCallbackResult::Ok(n) => {
                tracing::warn!(
                    n,
                    max_len,
                    "oversized TUN write probe was short; TCP coalescing disabled"
                );
                crate::metrics::tun_raw_gro_probe_failed();
                false
            }
            IOCallbackResult::WouldBlock => {
                // A fresh tun's queue should never be full; treat an
                // indeterminate probe as unavailable rather than risk
                // assuming capability.
                tracing::warn!("oversized TUN write probe would block; TCP coalescing disabled");
                crate::metrics::tun_raw_gro_probe_failed();
                false
            }
            IOCallbackResult::Err(err) => {
                tracing::warn!("oversized TUN write probe failed ({err}); TCP coalescing disabled");
                crate::metrics::tun_raw_gro_probe_failed();
                false
            }
        }
    }
}

/// Build the probe packet: a valid IPv4 header (checksum included, so
/// `ip_rcv` accepts it) of `len` total bytes, protocol 253
/// (experimental — no handler, silently discarded), addressed from and
/// to the tun's own address so it is always locally delivered and can
/// never be forwarded, even mid-probe on a tethered device.
fn probe_packet(local_ip: Ipv4Addr, len: usize) -> Vec<u8> {
    use pnet_packet::ipv4::MutableIpv4Packet;

    let len = len.clamp(IPV4_HDR_LEN, MAX_IPV4_PACKET_LEN);
    let mut pkt = vec![0u8; len];
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = IPPROTO_EXPERIMENTAL;
    let ip = local_ip.octets();
    pkt[12..16].copy_from_slice(&ip);
    pkt[16..20].copy_from_slice(&ip);
    let mut hdr = MutableIpv4Packet::new(&mut pkt[..IPV4_HDR_LEN])
        .expect("buffer always holds a full IPv4 header");
    let csum = pnet_packet::ipv4::checksum(&hdr.to_immutable());
    hdr.set_checksum(csum);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::ipv4::MutableIpv4Packet;
    use pnet_packet::tcp::{MutableTcpPacket, TcpFlags};
    use std::collections::VecDeque;

    const TCP_HDR_LEN: usize = 20;
    const HDR_LEN: usize = IPV4_HDR_LEN + TCP_HDR_LEN;
    /// Payload bytes per segment; also the run's MSS.
    const MSS: usize = 100;
    const MAX_LEN: usize = 4096;
    const SRC: [u8; 4] = [10, 0, 0, 1];
    const DST: [u8; 4] = [10, 0, 0, 2];

    fn local_ip() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 2)
    }

    /// A fresh allow flag per test — the production global would make
    /// concurrently-running tests interfere.
    fn allow_flag(initial: bool) -> &'static AtomicBool {
        Box::leak(Box::new(AtomicBool::new(initial)))
    }

    fn raw_gro(allowed: bool) -> RawGro {
        RawGro::with_allowed(MAX_LEN, allow_flag(allowed))
    }

    /// TUN stand-in recording every write in call order. Queued
    /// results are handed out in order; once drained every write
    /// succeeds with the byte count.
    struct FakeRawTun {
        vnet: Option<bool>,
        results: Mutex<VecDeque<IOCallbackResult<usize>>>,
        writes: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeRawTun {
        fn new() -> Self {
            Self {
                vnet: Some(false),
                results: Mutex::new(VecDeque::new()),
                writes: Mutex::new(Vec::new()),
            }
        }

        fn with_vnet(vnet: Option<bool>) -> Self {
            Self {
                vnet,
                ..Self::new()
            }
        }

        /// Queue `result` for the next write.
        fn push_result(&self, result: IOCallbackResult<usize>) {
            self.results.lock().unwrap().push_back(result);
        }

        fn writes(&self) -> Vec<Vec<u8>> {
            self.writes.lock().unwrap().clone()
        }

        fn write_count(&self) -> usize {
            self.writes.lock().unwrap().len()
        }
    }

    impl RawTunIo for FakeRawTun {
        fn vnet_hdr_framing(&self) -> Option<bool> {
            self.vnet
        }

        fn send_slice(&self, pkt: &[u8]) -> IOCallbackResult<usize> {
            self.writes.lock().unwrap().push(pkt.to_vec());
            match self.results.lock().unwrap().pop_front() {
                Some(r) => r,
                None => IOCallbackResult::Ok(pkt.len()),
            }
        }

        fn send_owned(&self, pkt: BytesMut) -> IOCallbackResult<usize> {
            self.send_slice(&pkt[..])
        }
    }

    /// One IPv4/TCP segment with real checksums, so the coalesced
    /// output can be checksum-verified end to end. The IP id advances
    /// with the sequence number, as a real sender's train does — which
    /// also makes a re-split run byte-identical to the originals
    /// (re-splitting regenerates sequential ids from the first
    /// segment's).
    fn seg(src_port: u16, seq: u32, payload_len: usize, flags: u8) -> BytesMut {
        let total = HDR_LEN + payload_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[4..6].copy_from_slice(&((seq / MSS as u32) as u16).to_be_bytes()); // IP id
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
    fn data(seq: u32) -> BytesMut {
        seg(1234, seq, MSS, TcpFlags::ACK)
    }

    /// Assert a recorded write is a self-contained packet with valid
    /// IP and TCP checksums.
    fn check_checksums(pkt: &[u8]) {
        let mut ip_copy = pkt[..IPV4_HDR_LEN].to_vec();
        let mut ip = MutableIpv4Packet::new(&mut ip_copy).unwrap();
        assert_eq!(ip.get_total_length() as usize, pkt.len(), "IP total_len");
        let stored = ip.get_checksum();
        ip.set_checksum(0);
        assert_eq!(
            stored,
            pnet_packet::ipv4::checksum(&ip.to_immutable()),
            "IP csum"
        );

        let mut l4 = pkt[IPV4_HDR_LEN..].to_vec();
        let mut tcp = MutableTcpPacket::new(&mut l4).unwrap();
        let stored = tcp.get_checksum();
        tcp.set_checksum(0);
        assert_eq!(
            stored,
            pnet_packet::tcp::ipv4_checksum(
                &tcp.to_immutable(),
                &Ipv4Addr::from(SRC),
                &Ipv4Addr::from(DST)
            ),
            "TCP csum"
        );
    }

    fn send_ok(gro: &RawGro, tun: &FakeRawTun, pkt: BytesMut) {
        let len = pkt.len();
        let r = gro.send(tun, pkt);
        assert!(matches!(r, IOCallbackResult::Ok(n) if n == len));
    }

    /// The default-off gate (the tethering kill switch): without the
    /// app's opt-in, opening a window is a no-op — no probe packet is
    /// ever injected and every packet is written 1:1.
    #[test]
    fn disallowed_never_probes_or_coalesces() {
        let tun = FakeRawTun::new();
        let gro = raw_gro(false);

        gro.open(&tun, local_ip());
        assert!(!gro.open.load(Ordering::Relaxed));

        for seq in [0, MSS as u32] {
            send_ok(&gro, &tun, data(seq));
        }
        gro.flush(&tun);

        let writes = tun.writes();
        assert_eq!(writes.len(), 2, "1:1 writes, no probe");
        assert_eq!(writes[0], data(0).to_vec());
        assert_eq!(writes[1], data(MSS as u32).to_vec());
    }

    /// First allowed window probes exactly once (an oversized valid
    /// IPv4 packet, protocol 253, tun address to itself), then
    /// coalesces: two in-order segments become one write with full
    /// checksums and the first sequence number.
    #[test]
    fn first_open_probes_once_then_coalesces() {
        let tun = FakeRawTun::new();
        let gro = raw_gro(true);

        gro.open(&tun, local_ip());
        assert_eq!(tun.write_count(), 1, "probe written");
        {
            let writes = tun.writes();
            let probe = &writes[0];
            assert_eq!(probe.len(), MAX_LEN, "probe is the full write envelope");
            assert_eq!(probe[0], 0x45);
            assert_eq!(probe[9], IPPROTO_EXPERIMENTAL);
            assert_eq!(&probe[12..16], &local_ip().octets());
            assert_eq!(&probe[16..20], &local_ip().octets());
        }

        for seq in [0, MSS as u32] {
            send_ok(&gro, &tun, data(seq));
        }
        assert_eq!(tun.write_count(), 1, "segments held in the run");

        gro.flush(&tun);
        let writes = tun.writes();
        assert_eq!(writes.len(), 2, "one coalesced write");
        let sp = &writes[1];
        assert_eq!(sp.len(), HDR_LEN + 2 * MSS);
        assert_eq!(u32::from_be_bytes(sp[24..28].try_into().unwrap()), 0);
        check_checksums(sp);

        // Second window: no re-probe.
        gro.open(&tun, local_ip());
        assert_eq!(tun.write_count(), 2, "probe ran exactly once");
        assert!(gro.open.load(Ordering::Relaxed));
    }

    /// `IFF_VNET_HDR` framing (or an unverifiable fd) disables the raw
    /// path outright: raw writes would be misparsed as vnet frames.
    #[test]
    fn vnet_hdr_framing_disables() {
        for vnet in [Some(true), None] {
            let tun = FakeRawTun::with_vnet(vnet);
            let gro = raw_gro(true);

            gro.open(&tun, local_ip());
            assert!(!gro.open.load(Ordering::Relaxed), "vnet {vnet:?}");
            assert_eq!(tun.write_count(), 0, "no probe write attempted");

            send_ok(&gro, &tun, data(0));
            assert_eq!(tun.writes()[0], data(0).to_vec(), "direct write");

            // The verdict is cached: no retry on the next window.
            gro.open(&tun, local_ip());
            assert!(!gro.open.load(Ordering::Relaxed));
        }
    }

    /// A failed (or short, or blocking) probe write disables the path
    /// permanently — probed capability, never assumed, never retried.
    #[test]
    fn probe_write_failure_disables_permanently() {
        let failures = [
            IOCallbackResult::Err(std::io::Error::from_raw_os_error(EINVAL)),
            IOCallbackResult::Ok(1500), // short
            IOCallbackResult::WouldBlock,
        ];
        for failure in failures {
            let tun = FakeRawTun::new();
            let gro = raw_gro(true);
            tun.push_result(failure);

            gro.open(&tun, local_ip());
            assert!(!gro.open.load(Ordering::Relaxed));
            assert_eq!(tun.write_count(), 1, "the probe attempt");

            send_ok(&gro, &tun, data(0));
            gro.open(&tun, local_ip());
            assert_eq!(tun.write_count(), 2, "no re-probe: only the direct write");
        }
    }

    /// EMSGSIZE / EINVAL / a short write on a coalesced packet trips
    /// the permanent fallback: the failed run is re-split and written
    /// segment-by-segment (no loss), and later windows never coalesce
    /// again.
    #[test]
    fn capability_error_falls_back_permanently_without_loss() {
        let failures = [
            IOCallbackResult::Err(std::io::Error::from_raw_os_error(EMSGSIZE)),
            IOCallbackResult::Err(std::io::Error::from_raw_os_error(EINVAL)),
            IOCallbackResult::Ok(HDR_LEN + MSS), // short write
        ];
        for failure in failures {
            let tun = FakeRawTun::new();
            let gro = raw_gro(true);

            gro.open(&tun, local_ip());
            for seq in [0, MSS as u32] {
                send_ok(&gro, &tun, data(seq));
            }
            tun.push_result(failure);
            gro.flush(&tun);

            // probe + failed oversized attempt + 2 re-split segments.
            let writes = tun.writes();
            assert_eq!(writes.len(), 4, "re-split after the failed write");
            assert_eq!(writes[1].len(), HDR_LEN + 2 * MSS, "oversized attempt");
            assert_eq!(writes[2], data(0).to_vec(), "segment 0 re-sent");
            assert_eq!(writes[3], data(MSS as u32).to_vec(), "segment 1 re-sent");
            assert!(gro.fell_back.load(Ordering::Relaxed));

            // Permanent: the next window never opens, packets go 1:1.
            gro.open(&tun, local_ip());
            assert!(!gro.open.load(Ordering::Relaxed));
            send_ok(&gro, &tun, data(2 * MSS as u32));
            assert_eq!(tun.write_count(), 5);
            assert_eq!(tun.writes()[4], data(2 * MSS as u32).to_vec());
        }
    }

    /// WouldBlock on the coalesced write is load shedding, not a
    /// capability verdict: the run is dropped (re-splitting would hit
    /// the same full queue) and coalescing continues afterwards.
    #[test]
    fn would_block_sheds_run_without_fallback() {
        let tun = FakeRawTun::new();
        let gro = raw_gro(true);

        gro.open(&tun, local_ip());
        for seq in [0, MSS as u32] {
            send_ok(&gro, &tun, data(seq));
        }
        tun.push_result(IOCallbackResult::WouldBlock);
        gro.flush(&tun);

        assert_eq!(tun.write_count(), 2, "probe + dropped attempt, no re-split");
        assert!(!gro.fell_back.load(Ordering::Relaxed));

        // Coalescing still works on the next window.
        gro.open(&tun, local_ip());
        assert!(gro.open.load(Ordering::Relaxed));
        for seq in [2 * MSS as u32, 3 * MSS as u32] {
            send_ok(&gro, &tun, data(seq));
        }
        gro.flush(&tun);
        assert_eq!(tun.write_count(), 3);
        assert_eq!(tun.writes()[2].len(), HDR_LEN + 2 * MSS);
    }

    /// The kill switch honours R5's "immediately and synchronously":
    /// flipped mid-window, the held run is drained *per segment* (no
    /// further oversized packet) before the triggering packet's direct
    /// write, preserving within-flow order.
    #[test]
    fn kill_switch_mid_window_drains_per_segment_in_order() {
        let allowed = allow_flag(true);
        let tun = FakeRawTun::new();
        let gro = RawGro::with_allowed(MAX_LEN, allowed);

        gro.open(&tun, local_ip());
        for seq in [0, MSS as u32] {
            send_ok(&gro, &tun, data(seq));
        }

        // Tethering comes up.
        allowed.store(false, Ordering::Relaxed);

        let third = data(2 * MSS as u32);
        send_ok(&gro, &tun, third.clone());

        let writes = tun.writes();
        assert_eq!(writes.len(), 4, "probe + 2 drained segments + direct");
        assert_eq!(writes[1], data(0).to_vec(), "held segment 0 first");
        assert_eq!(writes[2], data(MSS as u32).to_vec(), "held segment 1 next");
        assert_eq!(writes[3], third.to_vec(), "triggering packet last");
        assert!(!gro.open.load(Ordering::Relaxed), "window closed");

        // The end-of-batch flush has nothing left to write.
        gro.flush(&tun);
        assert_eq!(tun.write_count(), 4);
    }

    /// Same-flow ordering: a packet the run cannot absorb (here a pure
    /// ACK) forces the held run out *before* its own direct write.
    #[test]
    fn incompatible_packet_flushes_run_before_direct_write() {
        let tun = FakeRawTun::new();
        let gro = raw_gro(true);

        gro.open(&tun, local_ip());
        for seq in [0, MSS as u32] {
            send_ok(&gro, &tun, data(seq));
        }
        let ack = seg(1234, 2 * MSS as u32, 0, TcpFlags::ACK);
        send_ok(&gro, &tun, ack.clone());

        let writes = tun.writes();
        assert_eq!(writes.len(), 3, "probe + run + ack");
        assert_eq!(writes[1].len(), HDR_LEN + 2 * MSS, "run written first");
        check_checksums(&writes[1]);
        assert_eq!(writes[2], ack.to_vec(), "ack after the run");
    }

    /// R1: non-TCP traffic passes through 1:1 even inside an open
    /// window — UDP boundaries are semantic and there is no gso_size
    /// to tell the kernel how to restore them.
    #[test]
    fn udp_passes_through_one_to_one() {
        let tun = FakeRawTun::new();
        let gro = raw_gro(true);
        gro.open(&tun, local_ip());

        let mut udp0 = seg(1234, 0, MSS, TcpFlags::ACK);
        udp0[9] = 17; // IPPROTO_UDP
        let mut udp1 = seg(1234, MSS as u32, MSS, TcpFlags::ACK);
        udp1[9] = 17;

        for pkt in [udp0.clone(), udp1.clone()] {
            send_ok(&gro, &tun, pkt);
        }
        gro.flush(&tun);

        let writes = tun.writes();
        assert_eq!(writes.len(), 3, "probe + two 1:1 datagram writes");
        assert_eq!(writes[1], udp0.to_vec());
        assert_eq!(writes[2], udp1.to_vec());
    }

    /// A flush with no open window (never opened, or after a
    /// mid-window drain) writes nothing.
    #[test]
    fn flush_without_window_is_noop() {
        let tun = FakeRawTun::new();
        let gro = raw_gro(true);
        gro.flush(&tun);
        assert_eq!(tun.write_count(), 0);
    }

    /// PSH ends the run in the same call that absorbs it (the kernel's
    /// own flush point), so request/response traffic is never delayed
    /// until the end of the decrypt batch.
    #[test]
    fn psh_flushes_run_immediately() {
        let tun = FakeRawTun::new();
        let gro = raw_gro(true);
        gro.open(&tun, local_ip());

        send_ok(&gro, &tun, data(0));
        let psh = seg(1234, MSS as u32, MSS, TcpFlags::ACK | TcpFlags::PSH);
        send_ok(&gro, &tun, psh);

        assert_eq!(tun.write_count(), 2, "flushed before the window closed");
        let writes = tun.writes();
        let sp = &writes[1];
        assert_eq!(sp.len(), HDR_LEN + 2 * MSS);
        assert_eq!(
            sp[33] & (TcpFlags::PSH | TcpFlags::ACK),
            TcpFlags::PSH | TcpFlags::ACK,
            "PSH propagated"
        );
        check_checksums(sp);
    }
}
