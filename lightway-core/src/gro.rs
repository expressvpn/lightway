//! GRO (Generic Receive Offload) TCP coalescing.
//!
//! Receive-side mirror of [`crate::gso`]: merges decrypted, in-order,
//! same-flow IPv4 TCP segments into one TSO superpacket written to a Linux
//! TUN behind a `virtio_net_hdr`, so the kernel traverses its receive path
//! once per batch. Rules mirror the kernel's `tcp_gro_receive`: same flow,
//! strictly in sequence, headers byte-identical apart from the per-segment
//! fields (IP length/id/checksum, TCP seq/checksum, PSH/FIN). Anything else
//! ends the batch, where the kernel flushes.

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
pub const MAX_IPV4_PACKET_LEN: usize = u16::MAX as usize;
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
    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::ipv4::{Ipv4Flags, Ipv4Packet};
    use pnet_packet::tcp::TcpPacket;

    if pkt.len() < IPV4_HDR_LEN + TCP_MIN_HDR_LEN {
        return None;
    }
    // Version 4 with IHL == 5 in a single byte; IHL > 5 (IP options)
    // is rejected to keep all header offsets fixed. Raw bytes here
    // (as in `gso::calc_hdr_len`): the version has to be known before
    // an `Ipv4Packet` may be constructed.
    if pkt[0] != 0x45 {
        return None;
    }
    // The length check above guarantees both views can be built.
    let ip = Ipv4Packet::new(pkt)?;
    if ip.get_total_length() as usize != pkt.len() {
        return None;
    }
    // Fragmented: MF set or non-zero fragment offset (DF is fine).
    if ip.get_flags() & Ipv4Flags::MoreFragments != 0 || ip.get_fragment_offset() != 0 {
        return None;
    }
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let tcp_bytes = &pkt[IPV4_HDR_LEN..];
    let tcp = TcpPacket::new(tcp_bytes)?;
    let tcp_hdr_len = tcp.get_data_offset() as usize * 4;
    if tcp_hdr_len < TCP_MIN_HDR_LEN || tcp_hdr_len > tcp_bytes.len() {
        return None;
    }
    let payload_len = tcp_bytes.len() - tcp_hdr_len;
    if payload_len == 0 {
        // Pure ACKs are not coalescable.
        return None;
    }
    let flags = tcp.get_flags();
    if flags & TCP_NO_COALESCE_FLAGS != 0 {
        return None;
    }
    // Most expensive check last: a segment with a bad TCP checksum must not
    // coalesce, or `take` would reseed a valid checksum over corrupt bytes.
    // See [`tcp_checksum_valid`].
    if !tcp_checksum_valid(pkt) {
        return None;
    }
    let seq = tcp.get_sequence();
    Some(SegInfo {
        tcp_hdr_len,
        payload_len,
        seq,
        psh_fin: flags & TCP_PSH_FIN,
    })
}

/// Verify a segment's TCP checksum (pseudo-header + TCP header + payload).
/// Kernel GRO validates before coalescing so a corrupt segment cannot be
/// laundered: [`TcpGroBatch::take`] reseeds `NEEDS_CSUM`, which makes the
/// kernel *complete* the checksum rather than check it, so a bad segment
/// merged here would reach the app with a freshly-valid checksum over
/// corrupt bytes. A segment that fails is left for the caller to write
/// directly, where a plain (non-`NEEDS_CSUM`) write lets the kernel
/// validate and drop it and TCP retransmits. `pkt` is a full IHL==5 IPv4
/// TCP frame.
fn tcp_checksum_valid(pkt: &[u8]) -> bool {
    let tcp_len = (pkt.len() - IPV4_HDR_LEN) as u16;
    let mut c = internet_checksum::Checksum::new();
    c.add_bytes(&pkt[12..20]); // src + dst addresses
    c.add_bytes(&[0, IPPROTO_TCP, (tcp_len >> 8) as u8, tcp_len as u8]);
    c.add_bytes(&pkt[IPV4_HDR_LEN..]); // TCP header + payload, checksum field included
    // A valid segment folds to 0xFFFF, whose complement (what `checksum`
    // returns) is zero.
    c.checksum() == [0, 0]
}

/// Folded one's-complement sum of the TCP pseudo header, *not*
/// complemented. This is what `VIRTIO_NET_HDR_F_NEEDS_CSUM` expects: the
/// receiver completes it by summing from `csum_start` and complementing —
/// the inverse of [`crate::gso::gso_none_checksum`].
fn pseudo_header_partial(pkt: &[u8]) -> u16 {
    let tcp_len = (pkt.len() - IPV4_HDR_LEN) as u16;
    let mut c = internet_checksum::Checksum::new();
    c.add_bytes(&pkt[12..20]);
    // [zero, proto, len_hi, len_lo] — the big-endian pseudo-header trailer.
    c.add_bytes(&[0, IPPROTO_TCP, (tcp_len >> 8) as u8, tcp_len as u8]);
    // `checksum()` returns the complemented sum; undo the complement to
    // get the partial the receiver will continue summing from.
    !u16::from_be_bytes(c.checksum())
}

/// Accumulates in-order, same-flow IPv4 TCP segments into one TSO
/// superpacket. The first segment is stored whole and fixes the flow
/// identity and `gso_size`; later segments contribute payload only.
/// [`Self::take`] returns the buffer with the `virtio_net_hdr` to prepend.
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
    /// batch is empty, a coalescable packet starts it — except a
    /// PSH/FIN-marked one, which could never grow beyond a single
    /// segment and is rejected so the caller writes it directly.
    ///
    /// On [`GroAppend::Incompatible`] nothing was absorbed and the
    /// batch is unchanged; the caller must [`Self::take`]+write the
    /// batch, then re-offer or write the packet directly.
    pub fn append(&mut self, pkt: &[u8]) -> GroAppend {
        let Some(info) = parse_coalescable(pkt) else {
            return GroAppend::Incompatible;
        };

        if self.segs == 0 {
            // Kernel GRO flushes on PSH: a starting PSH/FIN segment
            // would only ever form a single-segment batch flushed
            // immediately with its bytes untouched, so absorbing it
            // would copy the packet just to hand it straight back.
            // Reject it and let the caller write it directly.
            if info.psh_fin != 0 {
                return GroAppend::Incompatible;
            }
            debug_assert!(self.buf.is_empty());
            // Reserve the full superpacket size up front so absorbing
            // segments never grows the buffer by doubling.
            self.buf.reserve(MAX_IPV4_PACKET_LEN);
            self.buf.extend_from_slice(pkt);
            self.segs = 1;
            self.gso_size = info.payload_len;
            self.tcp_hdr_len = info.tcp_hdr_len;
            self.next_seq = info.seq.wrapping_add(info.payload_len as u32);
            self.psh_fin = 0;
            return GroAppend::Coalesced;
        }

        // ---- flow/header identity checks against the first segment ----

        if info.tcp_hdr_len != self.tcp_hdr_len {
            return GroAppend::Incompatible;
        }
        let hdr_len = IPV4_HDR_LEN + self.tcp_hdr_len;
        // The two comparisons below are deliberately raw byte ranges — a
        // whitelist of *exclusions*, not field accessors — and must stay
        // that way: they are exhaustive by construction (every byte except
        // the few excluded is compared, so any unanticipated field forces a
        // safe flush; a blacklist of accessors would splice two TCP states
        // on a forgotten field), and they cover the variable-length TCP
        // options region, which the kernel also compares byte-wise.
        //
        // IPv4 bytes must match except total_length (2..4), id (4..6) and
        // checksum (10..12): same addresses, TOS, TTL, DF and flow.
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

    /// True iff the batch holds segments and `pkt` belongs to the same
    /// flow as its first segment: IPv4 with IHL 5, protocol TCP, long
    /// enough to carry the ports, and src/dst addresses (bytes 12..20)
    /// plus TCP ports (bytes 20..24) byte-equal to the batch's.
    ///
    /// A cheap identity test only — [`Self::append`] still performs
    /// the full coalescability checks.
    fn matches_flow(&self, pkt: &[u8]) -> bool {
        self.segs != 0
            && pkt.len() >= IPV4_HDR_LEN + 4
            && pkt[0] == 0x45
            && pkt[9] == IPPROTO_TCP
            && pkt[12..IPV4_HDR_LEN + 4] == self.buf[12..IPV4_HDR_LEN + 4]
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
        // partial (big-endian, not complemented — `set_checksum`
        // writes a host `u16` big-endian).
        //
        // The partial is computed before the mutable TCP view is taken;
        // it reads only the IP addresses and the total length, none of
        // which the fixups below touch.
        let partial = pseudo_header_partial(&buf);
        {
            use pnet_packet::tcp::MutableTcpPacket;
            let mut tcp = MutableTcpPacket::new(&mut buf[IPV4_HDR_LEN..])
                .expect("batch buffer always holds a full TCP header");
            tcp.set_flags(tcp.get_flags() | psh_fin);
            tcp.set_checksum(partial);
        }

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

/// Maximum concurrently-open flows in a [`TcpGroTable`] window.
const MAX_GRO_FLOWS: usize = 8;

/// Result of offering a packet to a [`TcpGroTable`].
pub struct GroTableAppend {
    /// Superpackets that must be written to the TUN now, in order.
    /// Usually empty (no allocation): flushes only happen on PSH/FIN,
    /// caps, or same-flow incompatibility.
    pub flushes: Vec<(BytesMut, VirtioNetHdr)>,
    /// False: the packet was not absorbed — the caller must write it
    /// directly AFTER writing `flushes` (same-flow ordering).
    pub consumed: bool,
}

/// A bounded pool of [`TcpGroBatch`]es keyed by flow, so several concurrent
/// TCP flows coalesce within one GRO window without flushing each other.
/// Within-flow write order is preserved (a flow's pending superpacket is
/// flushed before any packet of that flow is handed back for a direct
/// write); cross-flow order is arbitrary.
pub struct TcpGroTable {
    /// Fixed pool of batches; a slot is free when its batch is empty.
    slots: [TcpGroBatch; MAX_GRO_FLOWS],
}

impl TcpGroTable {
    /// Create a table with all slots empty.
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| TcpGroBatch::new()),
        }
    }

    /// True if no batch holds segments.
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(TcpGroBatch::is_empty)
    }

    /// Offer a packet (a full IPv4 frame, no virtio header) to the
    /// table. The caller must write every entry of
    /// [`GroTableAppend::flushes`] to the TUN in order, then — iff
    /// `consumed` is false — write the packet itself directly.
    ///
    /// A packet matching a held flow goes to that flow's batch; if the
    /// batch rejects it (seq gap, ack change, pure ACK, PSH/FIN-first…)
    /// the batch is flushed first so its segments reach the TUN before
    /// the packet, and the packet re-offered as a fresh seed. With no
    /// matching flow and no free slot the packet is simply not
    /// consumed — nothing held belongs to its flow, so a direct write
    /// cannot reorder within a flow.
    pub fn append(&mut self, pkt: &[u8]) -> GroTableAppend {
        if let Some(batch) = self.slots.iter_mut().find(|b| b.matches_flow(pkt)) {
            return match batch.append(pkt) {
                GroAppend::Coalesced => GroTableAppend {
                    flushes: Vec::new(),
                    consumed: true,
                },
                GroAppend::CoalescedFlush => {
                    let out = batch.take().expect("batch just absorbed a segment");
                    GroTableAppend {
                        flushes: vec![out],
                        consumed: true,
                    }
                }
                GroAppend::Incompatible => {
                    // Same flow but unmergeable: the held segments
                    // must hit the TUN before this packet. The packet
                    // then re-seeds the freed slot when it can.
                    let old = batch.take().expect("matches_flow implies non-empty");
                    let mut flushes = vec![old];
                    let consumed = Self::seed(batch, pkt, &mut flushes);
                    GroTableAppend { flushes, consumed }
                }
            };
        }

        // New flow: seed a free slot if the table has room.
        let Some(slot) = self.slots.iter_mut().find(|b| b.is_empty()) else {
            return GroTableAppend {
                flushes: Vec::new(),
                consumed: false,
            };
        };
        let mut flushes = Vec::new();
        let consumed = Self::seed(slot, pkt, &mut flushes);
        GroTableAppend { flushes, consumed }
    }

    /// Offer `pkt` to an empty `batch`. Returns whether it was
    /// consumed; a segment that flushes immediately is pushed onto
    /// `flushes`. Not consumed when the packet is not coalescable at
    /// all (non-IPv4, non-TCP, pure ACK, PSH/FIN-first…).
    fn seed(
        batch: &mut TcpGroBatch,
        pkt: &[u8],
        flushes: &mut Vec<(BytesMut, VirtioNetHdr)>,
    ) -> bool {
        match batch.append(pkt) {
            GroAppend::Coalesced => true,
            GroAppend::CoalescedFlush => {
                flushes.push(batch.take().expect("batch just absorbed a segment"));
                true
            }
            GroAppend::Incompatible => false,
        }
    }

    /// Take every pending superpacket (window close). Cross-flow order
    /// is arbitrary. Slots retain no data and are reused afterwards.
    pub fn drain(&mut self) -> Vec<(BytesMut, VirtioNetHdr)> {
        self.slots
            .iter_mut()
            .filter_map(TcpGroBatch::take)
            .collect()
    }
}

impl Default for TcpGroTable {
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

    /// A segment whose TCP checksum is wrong (a flipped payload byte)
    /// must not coalesce: `take` would otherwise reseed a valid checksum
    /// over corrupt bytes, laundering a packet the kernel would have
    /// dropped on the non-offload path. As the first segment it fails to
    /// start a batch; mid-train it flushes the good prefix and is left for
    /// a direct write.
    #[test]
    fn bad_tcp_checksum_not_coalesced() {
        let p = 400usize;
        let seq0 = 0x9000_0000u32;

        // As the opening segment: rejected, batch stays empty.
        let mut corrupt = Seg::new(seq0, 1, p).build();
        *corrupt.last_mut().unwrap() ^= 0xFF; // flip a payload byte -> bad TCP csum
        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&corrupt), GroAppend::Incompatible);
        assert!(batch.is_empty(), "corrupt opener must not start a batch");

        // Mid-train: a good segment starts the batch, the corrupt follower
        // flushes it and is not absorbed.
        let good = Seg::new(seq0, 1, p).build();
        assert_eq!(batch.append(&good), GroAppend::Coalesced);
        let mut corrupt2 = Seg::new(seq0 + p as u32, 2, p).build();
        *corrupt2.last_mut().unwrap() ^= 0xFF;
        assert_eq!(batch.append(&corrupt2), GroAppend::Incompatible);
        // Only the one good segment is in the batch.
        let (sp, _) = batch.take().unwrap();
        assert_eq!(sp.len(), IPV4_HDR_LEN + TCP_MIN_HDR_LEN + p);
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
        assert_eq!(
            batch.append(&Seg::new(seq0, 1, p).build()),
            GroAppend::Coalesced
        );

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
        assert_eq!(
            batch.append(&Seg::new(seq0, 1, p).build()),
            GroAppend::Coalesced
        );
        let big = Seg::new(seq0 + p as u32, 2, 150).build();
        assert_eq!(batch.append(&big), GroAppend::Incompatible);
        // Batch still holds only the first segment.
        let (sp, vhdr) = batch.take().unwrap();
        assert_eq!(sp.len(), IPV4_HDR_LEN + TCP_MIN_HDR_LEN + p);
        assert_eq!(vhdr.to_bytes(), VirtioNetHdr::default().to_bytes());
    }

    /// A starting packet with PSH is rejected without being absorbed —
    /// it could only ever flush immediately as a single-segment batch,
    /// so the caller writes it directly instead of copying it through
    /// the batch.
    #[test]
    fn starting_psh_incompatible() {
        let pkt = Seg::new(0x0B00_0000, 1, 100)
            .flags(TCP_FLAG_ACK | TCP_FLAG_PSH)
            .build();
        let mut batch = TcpGroBatch::new();
        assert_eq!(batch.append(&pkt), GroAppend::Incompatible);
        assert!(batch.is_empty());
        assert!(batch.take().is_none());
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

    // ---- TcpGroTable tests ----

    /// Two flows interleaved segment-by-segment coalesce independently
    /// with zero intermediate flushes; drain() yields one superpacket
    /// per flow, byte-identical to coalescing that flow alone.
    #[test]
    fn table_interleaved_flows_coalesce_independently() {
        let p = 400usize;
        let seg_a = |i: u32| Seg::new(0x1000_0000 + i * p as u32, i as u16, p).src_port(1111);
        let seg_b = |i: u32| Seg::new(0x2000_0000 + i * p as u32, 100 + i as u16, p).src_port(2222);

        let mut table = TcpGroTable::new();
        assert!(table.is_empty());
        for i in 0..3u32 {
            for pkt in [seg_a(i).build(), seg_b(i).build()] {
                let r = table.append(&pkt);
                assert!(r.consumed, "seg {i} consumed");
                assert!(r.flushes.is_empty(), "seg {i} no intermediate flush");
            }
        }
        assert!(!table.is_empty());

        // Reference: each flow coalesced alone in a plain batch.
        let alone = |mk: &dyn Fn(u32) -> Seg| {
            let mut batch = TcpGroBatch::new();
            for i in 0..3u32 {
                assert_eq!(batch.append(&mk(i).build()), GroAppend::Coalesced);
            }
            batch.take().unwrap()
        };
        let (sp_a, vh_a) = alone(&seg_a);
        let (sp_b, vh_b) = alone(&seg_b);

        let mut out = table.drain();
        assert!(table.is_empty());
        assert_eq!(out.len(), 2);
        // Cross-flow order is arbitrary: identify flows by src port.
        out.sort_by_key(|(sp, _)| u16::from_be_bytes([sp[20], sp[21]]));
        assert_eq!(&out[0].0[..], &sp_a[..], "flow A superpacket");
        assert_eq!(out[0].1.to_bytes(), vh_a.to_bytes());
        assert_eq!(&out[1].0[..], &sp_b[..], "flow B superpacket");
        assert_eq!(out[1].1.to_bytes(), vh_b.to_bytes());
    }

    /// A same-flow sequence gap flushes the held superpacket, and the
    /// gap packet seeds a fresh batch that drains with its own seq.
    #[test]
    fn table_same_flow_seq_gap_flushes_and_reseeds() {
        let p = 100usize;
        let seq0 = 0x0300_0000u32;
        let mut table = TcpGroTable::new();
        for i in 0..2u32 {
            let r = table.append(&Seg::new(seq0 + i * p as u32, 1 + i as u16, p).build());
            assert!(r.consumed && r.flushes.is_empty(), "seg {i}");
        }
        // Gap: skips one segment's worth of payload.
        let gap = Seg::new(seq0 + 3 * p as u32, 3, p).build();
        let r = table.append(&gap);
        assert!(r.consumed, "gap packet seeds a fresh batch");
        assert_eq!(r.flushes.len(), 1);
        assert_eq!(
            r.flushes[0].0.len(),
            IPV4_HDR_LEN + TCP_MIN_HDR_LEN + 2 * p,
            "held 2-segment superpacket flushed"
        );

        let out = table.drain();
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].0[..], &gap[..], "fresh batch holds the gap packet");
    }

    /// A same-flow pure ACK flushes the held superpacket but is not
    /// consumed — the caller writes it directly after the flush.
    #[test]
    fn table_same_flow_pure_ack_flushes_not_consumed() {
        let p = 100usize;
        let seq0 = 0x0400_0000u32;
        let held = Seg::new(seq0, 1, p).build();
        let mut table = TcpGroTable::new();
        assert!(table.append(&held).consumed);

        let ack = Seg::new(seq0 + p as u32, 2, 0).build();
        let r = table.append(&ack);
        assert!(!r.consumed, "pure ACK never coalesces");
        assert_eq!(r.flushes.len(), 1);
        assert_eq!(
            &r.flushes[0].0[..],
            &held[..],
            "held segments flushed first"
        );
        assert!(table.is_empty());
    }

    /// A packet of a different flow lands in its own slot without
    /// flushing the flow already held.
    #[test]
    fn table_different_flow_no_cross_flush() {
        let p = 100usize;
        let mut table = TcpGroTable::new();
        assert!(table.append(&Seg::new(0x0500_0000, 1, p).build()).consumed);

        let other = Seg::new(0x0600_0000, 2, p).src_port(4321).build();
        let r = table.append(&other);
        assert!(r.consumed, "new flow takes its own slot");
        assert!(r.flushes.is_empty(), "no cross-flow flush");
        assert_eq!(table.drain().len(), 2);
    }

    /// With MAX_GRO_FLOWS flows held, a packet of yet another flow is
    /// not consumed and flushes nothing; the held flows drain intact.
    #[test]
    fn table_overflow_rejects_extra_flow() {
        let p = 100usize;
        let mut table = TcpGroTable::new();
        for i in 0..MAX_GRO_FLOWS {
            let pkt = Seg::new(0x0700_0000, i as u16, p)
                .src_port(1000 + i as u16)
                .build();
            let r = table.append(&pkt);
            assert!(r.consumed && r.flushes.is_empty(), "flow {i}");
        }

        let extra = Seg::new(0x0700_0000, 99, p)
            .src_port(1000 + MAX_GRO_FLOWS as u16)
            .build();
        let r = table.append(&extra);
        assert!(!r.consumed, "table full: not absorbed");
        assert!(r.flushes.is_empty(), "table full: nothing flushed");

        let out = table.drain();
        assert_eq!(out.len(), MAX_GRO_FLOWS);
        let mut ports: Vec<u16> = out
            .iter()
            .map(|(sp, _)| u16::from_be_bytes([sp[20], sp[21]]))
            .collect();
        ports.sort_unstable();
        let want: Vec<u16> = (0..MAX_GRO_FLOWS).map(|i| 1000 + i as u16).collect();
        assert_eq!(ports, want, "all held flows drain intact");
    }

    /// A PSH-marked first segment of a fresh flow is not consumed and
    /// occupies no slot — the caller writes the original bytes
    /// directly, with no copy through the table.
    #[test]
    fn table_psh_start_fresh_flow_not_consumed() {
        let pkt = Seg::new(0x0800_0000, 1, 100)
            .flags(TCP_FLAG_ACK | TCP_FLAG_PSH)
            .build();
        let mut table = TcpGroTable::new();
        let r = table.append(&pkt);
        assert!(!r.consumed, "caller writes the packet directly");
        assert!(r.flushes.is_empty());
        assert!(table.is_empty(), "no slot occupied");
        assert!(table.drain().is_empty());
    }

    /// A PSH-marked same-flow segment that cannot join the held train
    /// (seq gap) flushes the train and — being PSH-first for the
    /// freed slot — is itself not consumed: it reaches the TUN as a
    /// direct write after the flush, preserving in-flow order.
    #[test]
    fn table_psh_after_seq_gap_flushes_then_direct() {
        let p = 100usize;
        let seq0 = 0x0810_0000u32;
        let held = Seg::new(seq0, 1, p).build();
        let mut table = TcpGroTable::new();
        assert!(table.append(&held).consumed);

        // Gap: skips one segment's worth of payload.
        let psh = Seg::new(seq0 + 2 * p as u32, 2, p)
            .flags(TCP_FLAG_ACK | TCP_FLAG_PSH)
            .build();
        let r = table.append(&psh);
        assert!(!r.consumed);
        assert_eq!(r.flushes.len(), 1);
        assert_eq!(&r.flushes[0].0[..], &held[..], "held segment flushed first");
        assert!(table.is_empty());
    }

    /// Non-coalescable packets (UDP, IPv6) are not consumed and do not
    /// disturb a held flow.
    #[test]
    fn table_non_tcp_and_ipv6_not_consumed() {
        let p = 100usize;
        let held = Seg::new(0x0900_0000, 1, p).build();
        let mut table = TcpGroTable::new();
        assert!(table.append(&held).consumed);

        let mut udp = Seg::new(0x0A00_0000, 2, p).build();
        udp[9] = 17; // IPPROTO_UDP
        let mut v6 = Seg::new(0x0A00_0000, 3, p).build();
        v6[0] = 0x60;
        for pkt in [udp, v6] {
            let r = table.append(&pkt);
            assert!(!r.consumed);
            assert!(r.flushes.is_empty());
        }

        let out = table.drain();
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].0[..], &held[..]);
    }

    /// After a drain the slots are reusable: the table coalesces a new
    /// train exactly as a fresh one would.
    #[test]
    fn table_reusable_after_drain() {
        let p = 200usize;
        let mut table = TcpGroTable::new();
        assert!(table.append(&Seg::new(0x0B00_0000, 1, p).build()).consumed);
        assert_eq!(table.drain().len(), 1);
        assert!(table.is_empty());

        let seq0 = 0x0C00_0000u32;
        for i in 0..2u32 {
            let r = table.append(&Seg::new(seq0 + i * p as u32, 1 + i as u16, p).build());
            assert!(r.consumed && r.flushes.is_empty(), "seg {i}");
        }
        let out = table.drain();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.len(), IPV4_HDR_LEN + TCP_MIN_HDR_LEN + 2 * p);
        assert_eq!(out[0].1.gso_size as usize, p);
    }
}
