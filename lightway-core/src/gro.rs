//! GRO (Generic Receive Offload) TCP coalescing.
//!
//! The receive-side mirror of [`crate::gso`]: where `gso` splits a TSO
//! superpacket into per-segment wire packets, this module merges
//! decrypted, same-flow IPv4 TCP segments (each with valid checksums,
//! arriving in order from the tunnel) into one TSO superpacket that is
//! written to a Linux TUN device behind a `virtio_net_hdr`, so the
//! kernel traverses its receive path once per batch instead of once
//! per segment.
//!
//! Coalescing rules mirror the kernel's `tcp_gro_receive`: segments
//! must belong to the same flow, be strictly in sequence, and carry
//! byte-identical headers apart from the fields that legitimately
//! change per segment (IP total length / id / checksum, TCP seq /
//! checksum and the PSH/FIN bits). Anything else — including a short
//! or PSH/FIN-marked segment — ends the batch, exactly where the
//! kernel flushes.

use bytes::BytesMut;
use pnet_packet::tcp::TcpFlags;

use crate::gso::{
    MAX_GSO_SEGS, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_TCPV4, VirtioNetHdr,
};

/// IPv4 header length when IHL == 5 — the only shape we coalesce
/// (packets with IP options are rejected), so every header offset
/// below is fixed.
const IPV4_HDR_LEN: usize = 20;
/// Minimum TCP header length (Data Offset == 5).
const TCP_MIN_HDR_LEN: usize = 20;
/// Largest IPv4 packet: `total_length` is a u16.
const MAX_IPV4_PACKET_LEN: usize = u16::MAX as usize;
/// IPv4 protocol number for TCP.
const IPPROTO_TCP: u8 = 6;
/// The TCP flag bits a segment may set without breaking the batch;
/// they end the batch and are OR'd onto the superpacket flags.
const TCP_PSH_FIN: u8 = TcpFlags::PSH | TcpFlags::FIN;
/// TCP flags that make a segment non-coalescable outright.
const TCP_NO_COALESCE_FLAGS: u8 = TcpFlags::SYN | TcpFlags::RST | TcpFlags::URG | TcpFlags::CWR;

/// Outcome of offering a packet to [`TcpGroBatch::append`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroAppend {
    /// Packet absorbed into the batch.
    Coalesced,
    /// Packet absorbed, but the batch must be flushed now.
    CoalescedFlush,
    /// Packet cannot join the batch (or is not coalescable at all).
    /// Caller must take()+write the batch, then re-offer or write the
    /// packet directly.
    Incompatible,
}

/// Fields extracted from a packet that passed the coalescability
/// checks in [`parse_coalescable`].
struct SegInfo {
    /// TCP header length in bytes (Data Offset × 4).
    tcp_hdr_len: usize,
    /// TCP payload length in bytes (>= 1).
    payload_len: usize,
    /// TCP sequence number.
    seq: u32,
    /// The segment's PSH/FIN bits (other flush-worthy flags never
    /// reach here — they fail the coalescability check).
    psh_fin: u8,
}

/// Validate that `pkt` is a coalescable IPv4 TCP segment and extract
/// the fields the batch logic needs. Returns `None` for anything we
/// must not coalesce: non-IPv4, IP options, length mismatch,
/// fragments, non-TCP, truncated/short TCP header, empty payload
/// (pure ACKs), or SYN/RST/URG/CWR flags.
fn parse_coalescable(pkt: &[u8]) -> Option<SegInfo> {
    if pkt.len() < IPV4_HDR_LEN + TCP_MIN_HDR_LEN {
        return None;
    }
    // Version 4 with IHL == 5 in a single byte; IHL > 5 (IP options)
    // is rejected to keep all header offsets fixed.
    if pkt[0] != 0x45 {
        return None;
    }
    if u16::from_be_bytes([pkt[2], pkt[3]]) as usize != pkt.len() {
        return None;
    }
    // Fragmented: MF set or non-zero fragment offset (DF is fine).
    if pkt[6] & 0x3F != 0 || pkt[7] != 0 {
        return None;
    }
    if pkt[9] != IPPROTO_TCP {
        return None;
    }
    let tcp = &pkt[IPV4_HDR_LEN..];
    let tcp_hdr_len = (tcp[12] >> 4) as usize * 4;
    if tcp_hdr_len < TCP_MIN_HDR_LEN || tcp_hdr_len > tcp.len() {
        return None;
    }
    let payload_len = tcp.len() - tcp_hdr_len;
    if payload_len == 0 {
        // Pure ACKs are not coalescable.
        return None;
    }
    let flags = tcp[13];
    if flags & TCP_NO_COALESCE_FLAGS != 0 {
        return None;
    }
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    Some(SegInfo {
        tcp_hdr_len,
        payload_len,
        seq,
        psh_fin: flags & TCP_PSH_FIN,
    })
}

/// One's-complement sum of the TCP pseudo header (src ip, dst ip,
/// protocol, TCP length), folded to 16 bits and *not* complemented.
///
/// This is the value `VIRTIO_NET_HDR_F_NEEDS_CSUM` expects in the
/// checksum field: the receiver completes it by summing from
/// `csum_start` and complementing — the inverse of what
/// [`crate::gso::gso_none_checksum`] does when the kernel hands *us*
/// such a packet.
fn pseudo_header_partial(pkt: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    for chunk in pkt[12..20].chunks_exact(2) {
        acc += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    acc += IPPROTO_TCP as u32;
    acc += (pkt.len() - IPV4_HDR_LEN) as u32;
    while acc > 0xFFFF {
        acc = (acc >> 16) + (acc & 0xFFFF);
    }
    acc as u16
}

/// Accumulates in-order, same-flow IPv4 TCP segments into a single
/// TSO superpacket.
///
/// The first segment is stored whole (headers + payload) and fixes
/// the batch's flow identity and `gso_size`; each later segment
/// contributes payload bytes only. [`Self::take`] finalizes the
/// buffer and returns it with the `virtio_net_hdr` to prepend when
/// writing to the TUN device.
pub struct TcpGroBatch {
    /// First segment's full bytes followed by later segments' payloads.
    buf: BytesMut,
    /// Number of segments absorbed so far.
    segs: usize,
    /// First segment's payload length; fixes the batch MSS.
    gso_size: usize,
    /// First segment's TCP header length (Data Offset × 4).
    tcp_hdr_len: usize,
    /// Sequence number the next in-order segment must carry.
    next_seq: u32,
    /// PSH/FIN bits accumulated from absorbed segments, OR'd into the
    /// superpacket's flags by [`Self::take`].
    psh_fin: u8,
}

impl TcpGroBatch {
    /// Create an empty batch.
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            segs: 0,
            gso_size: 0,
            tcp_hdr_len: 0,
            next_seq: 0,
            psh_fin: 0,
        }
    }

    /// True if no segment has been absorbed since the last
    /// [`Self::take`].
    pub fn is_empty(&self) -> bool {
        self.segs == 0
    }

    /// Offer a packet (a full IPv4 frame, no virtio header). If the
    /// batch is empty, a coalescable packet starts it.
    ///
    /// On [`GroAppend::Incompatible`] nothing was absorbed and the
    /// batch is unchanged; the caller must [`Self::take`]+write the
    /// batch, then re-offer or write the packet directly.
    pub fn append(&mut self, pkt: &[u8]) -> GroAppend {
        let Some(info) = parse_coalescable(pkt) else {
            return GroAppend::Incompatible;
        };

        if self.segs == 0 {
            debug_assert!(self.buf.is_empty());
            self.buf.extend_from_slice(pkt);
            self.segs = 1;
            self.gso_size = info.payload_len;
            self.tcp_hdr_len = info.tcp_hdr_len;
            self.next_seq = info.seq.wrapping_add(info.payload_len as u32);
            self.psh_fin = info.psh_fin;
            // Kernel GRO flushes on PSH: a starting PSH/FIN segment
            // forms a single-segment batch flushed immediately.
            return if info.psh_fin != 0 {
                GroAppend::CoalescedFlush
            } else {
                GroAppend::Coalesced
            };
        }

        // ---- flow/header identity checks against the first segment ----

        if info.tcp_hdr_len != self.tcp_hdr_len {
            return GroAppend::Incompatible;
        }
        let hdr_len = IPV4_HDR_LEN + self.tcp_hdr_len;
        // IPv4 header bytes must match except total_length (2..4),
        // identification (4..6) and header checksum (10..12). This
        // enforces same addresses, TOS, TTL, DF and flow.
        let b = &self.buf;
        if pkt[0..2] != b[0..2] || pkt[6..10] != b[6..10] || pkt[12..20] != b[12..20] {
            return GroAppend::Incompatible;
        }
        // TCP header bytes must match except seq (4..8), checksum
        // (16..18) and the PSH/FIN bits of the flags byte — same
        // ports, ack, window, urgent pointer and options, or the
        // kernel would have flushed.
        let (p, q) = (&pkt[IPV4_HDR_LEN..hdr_len], &b[IPV4_HDR_LEN..hdr_len]);
        if p[0..4] != q[0..4]
            || p[8..13] != q[8..13]
            || (p[13] & !TCP_PSH_FIN) != (q[13] & !TCP_PSH_FIN)
            || p[14..16] != q[14..16]
            || p[18..] != q[18..]
        {
            return GroAppend::Incompatible;
        }

        // ---- ordering and size checks ----

        // Strictly in-order: no overlap, no gap.
        if info.seq != self.next_seq {
            return GroAppend::Incompatible;
        }
        // A segment larger than the batch MSS cannot be part of the
        // same TSO train.
        if info.payload_len > self.gso_size {
            return GroAppend::Incompatible;
        }
        // The superpacket's IP total_length is a u16.
        if self.buf.len() + info.payload_len > MAX_IPV4_PACKET_LEN {
            return GroAppend::Incompatible;
        }

        // ---- absorb payload ----

        self.buf.extend_from_slice(&pkt[hdr_len..]);
        self.segs += 1;
        self.next_seq = self.next_seq.wrapping_add(info.payload_len as u32);
        self.psh_fin |= info.psh_fin;

        // Flush on a short segment (it ends the train, like the
        // kernel), on PSH/FIN, or at the segment cap.
        if info.payload_len < self.gso_size || info.psh_fin != 0 || self.segs >= MAX_GSO_SEGS {
            GroAppend::CoalescedFlush
        } else {
            GroAppend::Coalesced
        }
    }

    /// Take the assembled superpacket and its virtio header, resetting
    /// the batch. None if empty.
    ///
    /// A single-segment batch is returned untouched with a default
    /// (`GSO_NONE`, no flags) header — its checksums are already
    /// valid, the caller writes it as a plain packet. A multi-segment
    /// batch gets its IP header fixed up (total length, recomputed
    /// header checksum), accumulated PSH/FIN bits OR'd into the TCP
    /// flags, and the TCP checksum field seeded with the pseudo-header
    /// partial sum as `VIRTIO_NET_HDR_F_NEEDS_CSUM` requires.
    pub fn take(&mut self) -> Option<(BytesMut, VirtioNetHdr)> {
        if self.segs == 0 {
            return None;
        }
        let segs = self.segs;
        let gso_size = self.gso_size;
        let tcp_hdr_len = self.tcp_hdr_len;
        let psh_fin = self.psh_fin;
        let mut buf = self.buf.split();
        self.segs = 0;
        self.gso_size = 0;
        self.tcp_hdr_len = 0;
        self.next_seq = 0;
        self.psh_fin = 0;

        if segs == 1 {
            return Some((buf, VirtioNetHdr::default()));
        }

        // IP-layer fixups: total length over the whole aggregate,
        // first segment's id kept, header checksum recomputed.
        {
            use pnet_packet::ipv4::MutableIpv4Packet;
            let total_len = buf.len() as u16;
            let mut ip = MutableIpv4Packet::new(&mut buf[..IPV4_HDR_LEN])
                .expect("batch buffer always holds a full IPv4 header");
            ip.set_total_length(total_len);
            ip.set_checksum(0);
            let csum = pnet_packet::ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(csum);
        }

        // TCP fixups: propagate PSH/FIN collected from absorbed
        // segments, seed the checksum field with the pseudo-header
        // partial (big-endian, not complemented).
        buf[IPV4_HDR_LEN + 13] |= psh_fin;
        let partial = pseudo_header_partial(&buf);
        buf[IPV4_HDR_LEN + 16..IPV4_HDR_LEN + 18].copy_from_slice(&partial.to_be_bytes());

        let vhdr = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: (IPV4_HDR_LEN + tcp_hdr_len) as u16,
            gso_size: gso_size as u16,
            csum_start: IPV4_HDR_LEN as u16,
            csum_offset: 16,
        };
        Some((buf, vhdr))
    }
}

impl Default for TcpGroBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet_packet::tcp::MutableTcpPacket;
    use std::net::Ipv4Addr;

    const TCP_FLAG_ACK: u8 = TcpFlags::ACK;
    const TCP_FLAG_FIN: u8 = TcpFlags::FIN;
    const TCP_FLAG_PSH: u8 = TcpFlags::PSH;
    const SRC: [u8; 4] = [10, 0, 0, 1];
    const DST: [u8; 4] = [10, 0, 0, 2];

    fn src() -> Ipv4Addr {
        SRC.into()
    }

    fn dst() -> Ipv4Addr {
        DST.into()
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    // ---- builders ----

    /// One IPv4 TCP segment with real, valid IP and TCP checksums
    /// (computed via pnet, the same way gso.rs recomputes them) so
    /// coalesce-then-resplit round trips are byte-exact.
    struct Seg {
        seq: u32,
        id: u16,
        flags: u8,
        ack: u32,
        window: u16,
        ttl: u8,
        src_port: u16,
        tcp_opts: Vec<u8>,
        payload: Vec<u8>,
    }

    impl Seg {
        fn new(seq: u32, id: u16, payload_len: usize) -> Self {
            Self {
                seq,
                id,
                flags: TCP_FLAG_ACK,
                ack: 0x2222_0000,
                window: 0xFFFF,
                ttl: 64,
                src_port: 1234,
                tcp_opts: Vec::new(),
                payload: payload(payload_len),
            }
        }

        fn flags(mut self, flags: u8) -> Self {
            self.flags = flags;
            self
        }

        fn ack(mut self, ack: u32) -> Self {
            self.ack = ack;
            self
        }

        fn window(mut self, window: u16) -> Self {
            self.window = window;
            self
        }

        fn ttl(mut self, ttl: u8) -> Self {
            self.ttl = ttl;
            self
        }

        fn src_port(mut self, port: u16) -> Self {
            self.src_port = port;
            self
        }

        fn tcp_opts(mut self, opts: &[u8]) -> Self {
            assert_eq!(opts.len() % 4, 0, "TCP options must pad to 32-bit words");
            self.tcp_opts = opts.to_vec();
            self
        }

        fn build(&self) -> Vec<u8> {
            let tcp_hdr_len = TCP_MIN_HDR_LEN + self.tcp_opts.len();
            let total = IPV4_HDR_LEN + tcp_hdr_len + self.payload.len();
            let mut pkt = Vec::with_capacity(total);

            let mut ip = [0u8; IPV4_HDR_LEN];
            ip[0] = 0x45; // version=4, IHL=5
            ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            ip[4..6].copy_from_slice(&self.id.to_be_bytes());
            ip[6] = 0x40; // DF
            ip[8] = self.ttl;
            ip[9] = IPPROTO_TCP;
            ip[12..16].copy_from_slice(&SRC);
            ip[16..20].copy_from_slice(&DST);
            pkt.extend_from_slice(&ip);

            let mut tcp = vec![0u8; tcp_hdr_len];
            tcp[0..2].copy_from_slice(&self.src_port.to_be_bytes());
            tcp[2..4].copy_from_slice(&5678u16.to_be_bytes());
            tcp[4..8].copy_from_slice(&self.seq.to_be_bytes());
            tcp[8..12].copy_from_slice(&self.ack.to_be_bytes());
            tcp[12] = ((tcp_hdr_len / 4) as u8) << 4;
            tcp[13] = self.flags;
            tcp[14..16].copy_from_slice(&self.window.to_be_bytes());
            tcp[TCP_MIN_HDR_LEN..].copy_from_slice(&self.tcp_opts);
            pkt.extend_from_slice(&tcp);

            pkt.extend_from_slice(&self.payload);

            let mut ip = MutableIpv4Packet::new(&mut pkt[..IPV4_HDR_LEN]).unwrap();
            let csum = pnet_packet::ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(csum);
            let mut tcp = MutableTcpPacket::new(&mut pkt[IPV4_HDR_LEN..]).unwrap();
            let csum = pnet_packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src(), &dst());
            tcp.set_checksum(csum);
            pkt
        }
    }

    // ---- verifiers ----

    /// Hand-folded pseudo-header partial sum, independent of the
    /// implementation's helper.
    fn expected_partial(tcp_len: usize) -> u16 {
        let mut acc: u32 = 0;
        for addr in [SRC, DST] {
            acc += u16::from_be_bytes([addr[0], addr[1]]) as u32;
            acc += u16::from_be_bytes([addr[2], addr[3]]) as u32;
        }
        acc += IPPROTO_TCP as u32;
        acc += tcp_len as u32;
        while acc > 0xFFFF {
            acc = (acc >> 16) + (acc & 0xFFFF);
        }
        acc as u16
    }

    /// Verify the superpacket's stored IPv4 header checksum against a
    /// recomputed one over the header with the field zeroed.
    fn check_ip_csum(sp: &[u8]) {
        let mut copy = sp[..IPV4_HDR_LEN].to_vec();
        let mut ip = MutableIpv4Packet::new(&mut copy).unwrap();
        let stored = ip.get_checksum();
        ip.set_checksum(0);
        assert_eq!(
            stored,
            pnet_packet::ipv4::checksum(&ip.to_immutable()),
            "IPv4 header csum"
        );
    }

    // ---- tests ----

    /// Three equal-size segments coalesce into one superpacket with
    /// fixed-up IP header, first seq preserved, the pseudo-header
    /// partial in the TCP checksum field and a fully-populated
    /// VirtioNetHdr.
    #[test]
    fn three_full_segments_coalesce() {
        let p = 500usize;
        let seq0 = 0xAABB_0000u32;
        let id0 = 0x0042u16;
        let mut batch = TcpGroBatch::new();
        assert!(batch.is_empty());
        for i in 0..3u32 {
            let pkt = Seg::new(seq0 + i * p as u32, id0 + i as u16, p).build();
            assert_eq!(batch.append(&pkt), GroAppend::Coalesced, "seg {i}");
        }
        assert!(!batch.is_empty());

        let (sp, vhdr) = batch.take().unwrap();
        assert!(batch.is_empty());
        let total = IPV4_HDR_LEN + TCP_MIN_HDR_LEN + 3 * p;
        assert_eq!(sp.len(), total);

        let ip = Ipv4Packet::new(&sp[..IPV4_HDR_LEN]).unwrap();
        assert_eq!(ip.get_total_length() as usize, total, "IP total_len");
        assert_eq!(ip.get_identification(), id0, "first segment's IP id");
        check_ip_csum(&sp);

        // TCP: first seq preserved, checksum field holds the
        // pseudo-header partial (not complemented).
        assert_eq!(u32::from_be_bytes(sp[24..28].try_into().unwrap()), seq0);
        let tcp_len = total - IPV4_HDR_LEN;
        assert_eq!(
            u16::from_be_bytes(sp[36..38].try_into().unwrap()),
            expected_partial(tcp_len),
            "pseudo-header partial"
        );

        // Completing the partial the way the kernel would on transmit
        // (gso_none_checksum is the exact inverse contract) must yield
        // a valid TCP checksum over the whole aggregate.
        let mut full = sp.to_vec();
        crate::gso::gso_none_checksum(&mut full, 20, 16);
        let mut l4 = full[IPV4_HDR_LEN..].to_vec();
        let mut tcp = MutableTcpPacket::new(&mut l4).unwrap();
        let stored = tcp.get_checksum();
        tcp.set_checksum(0);
        assert_eq!(
            stored,
            pnet_packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src(), &dst()),
            "completed TCP csum"
        );

        assert_eq!(vhdr.flags, VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(vhdr.gso_type, VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(vhdr.hdr_len, (IPV4_HDR_LEN + TCP_MIN_HDR_LEN) as u16);
        assert_eq!(vhdr.gso_size, p as u16);
        assert_eq!(vhdr.csum_start, IPV4_HDR_LEN as u16);
        assert_eq!(vhdr.csum_offset, 16);
    }

    /// Coalesce N in-order segments (sequential IP ids, valid
    /// checksums), then re-split with gso.rs. Every rebuilt segment
    /// must be byte-identical to its original.
    #[test]
    fn round_trip_with_gso_split() {
        let p = 1000usize;
        let n = 4usize;
        let seq0 = 0x1000_0000u32;
        let id0 = 0x0100u16;
        let originals: Vec<Vec<u8>> = (0..n)
            .map(|i| Seg::new(seq0 + (i * p) as u32, id0 + i as u16, p).build())
            .collect();

        let mut batch = TcpGroBatch::new();
        for (i, pkt) in originals.iter().enumerate() {
            assert_eq!(batch.append(pkt), GroAppend::Coalesced, "seg {i}");
        }
        let (sp, vhdr) = batch.take().unwrap();

        let hdr_len = crate::gso::calc_hdr_len(&sp).unwrap();
        assert_eq!(hdr_len, IPV4_HDR_LEN + TCP_MIN_HDR_LEN);
        assert_eq!(
            crate::gso::calc_gso_segs(sp.len(), hdr_len, vhdr.gso_size as usize),
            n
        );
        let mut out = BytesMut::with_capacity(4096);
        for (i, orig) in originals.iter().enumerate() {
            crate::gso::build_segment(&vhdr, hdr_len, &sp, i, &mut out).unwrap();
            assert_eq!(&out[..], &orig[..], "rebuilt segment {i} differs");
        }
    }

    /// A short trailing segment is absorbed and flushes the batch; the
    /// superpacket length reflects it and re-splitting yields the
    /// short final segment byte-for-byte.
    #[test]
    fn short_trailing_segment_flushes() {
        let p = 300usize;
        let s = 120usize;
        let seq0 = 0x0500_0000u32;
        let id0 = 0x0777u16;
        let seg0 = Seg::new(seq0, id0, p).build();
        let seg1 = Seg::new(seq0 + p as u32, id0 + 1, p).build();
        let seg2 = Seg::new(seq0 + 2 * p as u32, id0 + 2, s).build();

        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&seg0), GroAppend::Coalesced);
        assert_eq!(batch.append(&seg1), GroAppend::Coalesced);
        assert_eq!(batch.append(&seg2), GroAppend::CoalescedFlush);

        let (sp, vhdr) = batch.take().unwrap();
        assert_eq!(sp.len(), IPV4_HDR_LEN + TCP_MIN_HDR_LEN + 2 * p + s);
        let hdr_len = crate::gso::calc_hdr_len(&sp).unwrap();
        assert_eq!(
            crate::gso::calc_gso_segs(sp.len(), hdr_len, vhdr.gso_size as usize),
            3
        );
        let mut out = BytesMut::with_capacity(2048);
        crate::gso::build_segment(&vhdr, hdr_len, &sp, 2, &mut out).unwrap();
        assert_eq!(&out[..], &seg2[..], "short final segment");
    }

    /// PSH on a follower segment is absorbed, flushes the batch and is
    /// propagated into the superpacket's TCP flags.
    #[test]
    fn psh_mid_train_flushes_and_propagates() {
        let p = 200usize;
        let seq0 = 0x0100_0000u32;
        let seg0 = Seg::new(seq0, 1, p).build();
        let seg1 = Seg::new(seq0 + p as u32, 2, p)
            .flags(TCP_FLAG_ACK | TCP_FLAG_PSH)
            .build();

        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&seg0), GroAppend::Coalesced);
        assert_eq!(batch.append(&seg1), GroAppend::CoalescedFlush);

        let (sp, _vhdr) = batch.take().unwrap();
        assert_eq!(sp.len(), IPV4_HDR_LEN + TCP_MIN_HDR_LEN + 2 * p);
        assert_eq!(sp[33], TCP_FLAG_ACK | TCP_FLAG_PSH, "PSH propagated");
    }

    /// FIN behaves like PSH: absorbed, flushes, propagated.
    #[test]
    fn fin_mid_train_flushes_and_propagates() {
        let p = 200usize;
        let seq0 = 0x0200_0000u32;
        let seg0 = Seg::new(seq0, 1, p).build();
        let seg1 = Seg::new(seq0 + p as u32, 2, p)
            .flags(TCP_FLAG_ACK | TCP_FLAG_FIN)
            .build();

        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&seg0), GroAppend::Coalesced);
        assert_eq!(batch.append(&seg1), GroAppend::CoalescedFlush);

        let (sp, _vhdr) = batch.take().unwrap();
        assert_eq!(sp.len(), IPV4_HDR_LEN + TCP_MIN_HDR_LEN + 2 * p);
        assert_eq!(sp[33], TCP_FLAG_ACK | TCP_FLAG_FIN, "FIN propagated");
    }

    /// A sequence gap is Incompatible and leaves the batch unchanged —
    /// take() still yields the earlier segments, and the rejected
    /// packet can start a fresh batch afterwards.
    #[test]
    fn sequence_gap_incompatible_batch_unchanged() {
        let p = 100usize;
        let seq0 = 0x0300_0000u32;
        let seg0 = Seg::new(seq0, 1, p).build();
        let seg1 = Seg::new(seq0 + p as u32, 2, p).build();
        // Gap: skips one segment's worth of payload.
        let gap = Seg::new(seq0 + 3 * p as u32, 3, p).build();

        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&seg0), GroAppend::Coalesced);
        assert_eq!(batch.append(&seg1), GroAppend::Coalesced);
        assert_eq!(batch.append(&gap), GroAppend::Incompatible);

        let (sp, vhdr) = batch.take().unwrap();
        assert_eq!(sp.len(), IPV4_HDR_LEN + TCP_MIN_HDR_LEN + 2 * p);
        assert_eq!(vhdr.gso_size as usize, p);

        // Batch is reusable: the rejected packet starts a new one.
        assert_eq!(batch.append(&gap), GroAppend::Coalesced);
        let (sp, vhdr) = batch.take().unwrap();
        assert_eq!(&sp[..], &gap[..]);
        assert_eq!(vhdr.to_bytes(), VirtioNetHdr::default().to_bytes());
    }

    /// Any flow/header difference beyond the per-segment mutable
    /// fields is Incompatible: ack_seq, source port, TTL, window, and
    /// TCP options (both different length and same-length different
    /// bytes).
    #[test]
    fn flow_and_header_mismatches_incompatible() {
        let p = 100usize;
        let seq0 = 0x0400_0000u32;
        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&Seg::new(seq0, 1, p).build()), GroAppend::Coalesced);

        let follower = || Seg::new(seq0 + p as u32, 2, p);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("ack", follower().ack(0x2222_0001).build()),
            ("src port", follower().src_port(4321).build()),
            ("ttl", follower().ttl(63).build()),
            ("window", follower().window(0x1234).build()),
            ("options length", follower().tcp_opts(&[1, 1, 1, 0]).build()),
        ];
        for (what, pkt) in cases {
            assert_eq!(
                batch.append(&pkt),
                GroAppend::Incompatible,
                "differing {what}"
            );
        }
        // Sanity: an identical-flow follower still coalesces.
        assert_eq!(batch.append(&follower().build()), GroAppend::Coalesced);

        // Same-length but different option bytes also mismatch.
        let mut batch = TcpGroBatch::new();
        let first = Seg::new(seq0, 1, p).tcp_opts(&[1, 1, 1, 1]).build();
        assert_eq!(batch.append(&first), GroAppend::Coalesced);
        let diff_opts = follower().tcp_opts(&[1, 1, 1, 0]).build();
        assert_eq!(batch.append(&diff_opts), GroAppend::Incompatible);
        let same_opts = follower().tcp_opts(&[1, 1, 1, 1]).build();
        assert_eq!(batch.append(&same_opts), GroAppend::Coalesced);
    }

    /// A pure ACK (no payload) is never coalescable, even into an
    /// empty batch.
    #[test]
    fn pure_ack_incompatible() {
        let ack = Seg::new(0x0600_0000, 1, 0).build();
        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&ack), GroAppend::Incompatible);
        assert!(batch.is_empty());
        assert!(batch.take().is_none());
    }

    /// Non-TCP (UDP) and non-IPv4 (v6 version nibble) packets are
    /// Incompatible.
    #[test]
    fn non_tcp_and_ipv6_incompatible() {
        let mut batch = TcpGroBatch::new();

        let mut udp = Seg::new(0x0700_0000, 1, 100).build();
        udp[9] = 17; // IPPROTO_UDP
        assert_eq!(batch.append(&udp), GroAppend::Incompatible);

        let mut v6 = Seg::new(0x0700_0000, 1, 100).build();
        v6[0] = 0x60;
        assert_eq!(batch.append(&v6), GroAppend::Incompatible);

        assert!(batch.is_empty());
    }

    /// An append that would push the superpacket past 65535 bytes
    /// (IPv4 total_length is a u16) is Incompatible and absorbs
    /// nothing.
    #[test]
    fn byte_cap_incompatible_nothing_appended() {
        let p = 30000usize;
        let seq0 = 0x0800_0000u32;
        let mut batch = TcpGroBatch::new();
        for i in 0..2u32 {
            let pkt = Seg::new(seq0 + i * p as u32, 1 + i as u16, p).build();
            assert_eq!(batch.append(&pkt), GroAppend::Coalesced, "seg {i}");
        }
        let len_before = batch.buf.len();
        assert_eq!(len_before, IPV4_HDR_LEN + TCP_MIN_HDR_LEN + 2 * p);

        // 60040 + 30000 > 65535 — must be rejected without absorbing.
        let third = Seg::new(seq0 + 2 * p as u32, 3, p).build();
        assert_eq!(batch.append(&third), GroAppend::Incompatible);
        assert_eq!(batch.buf.len(), len_before, "nothing appended");

        let (sp, vhdr) = batch.take().unwrap();
        assert_eq!(sp.len(), len_before);
        assert_eq!(vhdr.gso_size as usize, p);
    }

    /// A single-segment take() returns the packet bytes untouched with
    /// a default (GSO_NONE, no flags) header.
    #[test]
    fn single_segment_take_untouched() {
        let pkt = Seg::new(0x0900_0000, 0x0055, 333).build();
        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&pkt), GroAppend::Coalesced);
        let (sp, vhdr) = batch.take().unwrap();
        assert_eq!(&sp[..], &pkt[..], "bytes untouched");
        assert_eq!(vhdr.to_bytes(), VirtioNetHdr::default().to_bytes());
        assert!(batch.is_empty());
    }

    /// A follower whose payload exceeds the batch's gso_size cannot be
    /// part of the same TSO train.
    #[test]
    fn oversized_follower_incompatible() {
        let p = 100usize;
        let seq0 = 0x0A00_0000u32;
        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&Seg::new(seq0, 1, p).build()), GroAppend::Coalesced);
        let big = Seg::new(seq0 + p as u32, 2, 150).build();
        assert_eq!(batch.append(&big), GroAppend::Incompatible);
        // Batch still holds only the first segment.
        let (sp, vhdr) = batch.take().unwrap();
        assert_eq!(sp.len(), IPV4_HDR_LEN + TCP_MIN_HDR_LEN + p);
        assert_eq!(vhdr.to_bytes(), VirtioNetHdr::default().to_bytes());
    }

    /// A starting packet with PSH flushes immediately as a
    /// single-segment batch.
    #[test]
    fn starting_psh_flushes_immediately() {
        let pkt = Seg::new(0x0B00_0000, 1, 100)
            .flags(TCP_FLAG_ACK | TCP_FLAG_PSH)
            .build();
        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&pkt), GroAppend::CoalescedFlush);
        let (sp, vhdr) = batch.take().unwrap();
        assert_eq!(&sp[..], &pkt[..], "single-seg bytes untouched");
        assert_eq!(vhdr.to_bytes(), VirtioNetHdr::default().to_bytes());
    }

    /// The 64th segment (MAX_GSO_SEGS) is absorbed and flushes the
    /// batch.
    #[test]
    fn segment_cap_flushes_at_max_gso_segs() {
        let p = 8usize;
        let seq0 = 0x0C00_0000u32;
        let mut batch = TcpGroBatch::new();
        for i in 0..MAX_GSO_SEGS {
            let pkt = Seg::new(seq0 + (i * p) as u32, i as u16, p).build();
            let want = if i == MAX_GSO_SEGS - 1 {
                GroAppend::CoalescedFlush
            } else {
                GroAppend::Coalesced
            };
            assert_eq!(batch.append(&pkt), want, "seg {i}");
        }
        let (sp, vhdr) = batch.take().unwrap();
        assert_eq!(sp.len(), IPV4_HDR_LEN + TCP_MIN_HDR_LEN + MAX_GSO_SEGS * p);
        assert_eq!(vhdr.gso_size as usize, p);
    }
}
