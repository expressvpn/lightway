//! GSO (Generic Segmentation Offload) segment fixup functions.
//!
//! When a GSO superpacket is processed as a single packet through
//! plugins/encoder, the individual segments need per-segment header
//! fixups (IP ID, TCP seq, checksums) before encryption and wire send.
//!
//! All functions take `&VirtioNetHdr` directly for metadata.

/// Virtio network header for GSO/checksum offload.
///
/// This is a local copy of the kernel `virtio_net_hdr` structure, since
/// tun-rs defines this type internally but does not re-export it.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct VirtioNetHdr {
    /// Flags (e.g. VIRTIO_NET_HDR_F_NEEDS_CSUM).
    pub flags: u8,
    /// GSO type (e.g. GSO_NONE, GSO_TCPV4, GSO_TCPV6, GSO_UDP_L4).
    pub gso_type: u8,
    /// Ethernet + IP + transport header length in bytes.
    pub hdr_len: u16,
    /// Bytes per GSO segment (payload only).
    pub gso_size: u16,
    /// Offset from packet start where checksum computation begins.
    pub csum_start: u16,
    /// Offset from csum_start to the checksum field.
    pub csum_offset: u16,
}

/// Size of the VirtioNetHdr in bytes.
pub const VIRTIO_NET_HDR_LEN: usize = std::mem::size_of::<VirtioNetHdr>();

/// GSO type: not a GSO frame.
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
/// Flag: checksum needs to be computed.
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

/// Maximum number of segments in a single UDP GSO superpacket —
/// matches the kernel's `UDP_MAX_SEGMENTS` (`1 << 6`); a `sendmsg`
/// with `UDP_SEGMENT` and more than this is rejected with `EINVAL`.
pub(crate) const MAX_GSO_SEGS: usize = 64;

/// Upper bound on the bytes a single GSO coalescing buffer can hold:
/// `MAX_GSO_SEGS` segments, each at most `MAX_OUTSIDE_MTU`.
pub(crate) const MAX_GSO_FRAME_BYTES: usize = MAX_GSO_SEGS * crate::MAX_OUTSIDE_MTU;

/// Upper bound on the UDP payload bytes a single `sendmsg` with
/// `UDP_SEGMENT` may carry. The kernel assembles the whole batch into
/// one skb before segmenting, so the total is bounded by the maximum
/// IP datagram size (65535) minus the UDP header (8) and the larger
/// IPv6 header (40); exceeding it fails with `EMSGSIZE`. A TUN TSO
/// aggregate can be up to 65535 bytes *before* the per-segment
/// `wire::Header` is added, so flushes must be chunked to this limit.
pub(crate) const MAX_GSO_SEND_BYTES: usize = 65535 - 8 - 40;

impl VirtioNetHdr {
    /// Interpret the first [`VIRTIO_NET_HDR_LEN`] bytes of `buf` as a
    /// `&VirtioNetHdr` without copying.
    ///
    /// Returns `Err(InvalidInput)` if `buf` is shorter than
    /// `VIRTIO_NET_HDR_LEN` or not 2-byte aligned.
    #[allow(unsafe_code)]
    pub fn from_bytes(buf: &[u8]) -> std::io::Result<&Self> {
        if buf.len() < VIRTIO_NET_HDR_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "buffer too short for VirtioNetHdr",
            ));
        }
        let ptr = buf.as_ptr();
        if ptr.align_offset(std::mem::align_of::<VirtioNetHdr>()) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "buffer not aligned for VirtioNetHdr",
            ));
        }
        // SAFETY: We verified length and alignment. VirtioNetHdr is repr(C)
        // with no padding, and the returned lifetime is tied to `buf`.
        unsafe { Ok(&*(ptr as *const VirtioNetHdr)) }
    }

    /// True if `gso_type` indicates a TCP segmentation aggregate (v4 or v6).
    ///
    /// Linux ORs `VIRTIO_NET_HDR_GSO_ECN` (0x80) into `gso_type` for
    /// ECN-marked flows, so a TCPv4 ECN aggregate has `gso_type =
    /// 0x81`. Mask the ECN bit before comparing.
    pub fn is_tcp(&self) -> bool {
        let base = self.gso_type & !VIRTIO_NET_HDR_GSO_ECN;
        base == VIRTIO_NET_HDR_GSO_TCPV4 || base == VIRTIO_NET_HDR_GSO_TCPV6
    }
}

/// Compute and fill the transport-layer checksum for a non-GSO packet
/// that has `VIRTIO_NET_HDR_F_NEEDS_CSUM` set.
///
/// The kernel deposits the pseudo-header partial sum (src + dst + proto + len)
/// at `[csum_start + csum_offset]` before delivering the packet.
/// We seed our sum with that value, then sum from `csum_start` and complement.
pub fn gso_none_checksum(buf: &mut [u8], csum_start: u16, csum_offset: u16) {
    let start = csum_start as usize;
    let offset = csum_offset as usize;
    let at = start + offset;
    if at + 2 > buf.len() || start > buf.len() {
        tracing::warn!(
            buf_len = buf.len(),
            csum_start,
            csum_offset,
            "csum_start/offset outside buffer, cannot write checksum"
        );
        crate::metrics::gso_none_checksum_skipped();
        return;
    }

    // Read the kernel-deposited pseudo-header partial, then zero the
    // field so it doesn't double-count when we sum the segment.
    let initial = read_u16(&buf[at..at + 2]) as u64;
    buf[at] = 0;
    buf[at + 1] = 0;

    let csum = !checksum(&buf[start..], initial);
    buf[at] = (csum >> 8) as u8;
    buf[at + 1] = csum as u8;
}

// Internet checksum used only by `gso_none_checksum` below — the
// build_segment path uses pnet_packet's protocol-aware helpers.
#[inline]
fn read_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes(b[..2].try_into().unwrap())
}

// One's-complement folded checksum with a kernel-seeded initial value.
// The inner loop unrolls to read 8 bytes per iteration; on x86_64
// release LLVM auto-vectorizes the resulting straight-line code.
#[inline]
fn checksum(mut b: &[u8], initial: u64) -> u16 {
    let mut acc = initial;
    while b.len() >= 8 {
        acc += u32::from_be_bytes(b[..4].try_into().unwrap()) as u64;
        acc += u32::from_be_bytes(b[4..8].try_into().unwrap()) as u64;
        b = &b[8..];
    }
    if b.len() >= 4 {
        acc += u32::from_be_bytes(b[..4].try_into().unwrap()) as u64;
        b = &b[4..];
    }
    if b.len() >= 2 {
        acc += read_u16(&b[..2]) as u64;
        b = &b[2..];
    }
    if let Some(&byte) = b.first() {
        acc += (byte as u64) << 8;
    }
    while acc > 0xFFFF {
        acc = (acc >> 16) + (acc & 0xFFFF);
    }
    acc as u16
}

/// GSO type: TCP segmentation aggregate over IPv4.
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
/// GSO type: TCP segmentation aggregate over IPv6.
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
/// ECN flag OR'd into `gso_type` for ECN-marked aggregates.
const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

/// Why `calc_hdr_len` could not decode the protocol header length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GsoHdrError {
    /// Buffer was empty.
    Empty,
    /// Buffer was shorter than the named header (e.g. `"ipv4_hdr"`,
    /// `"ipv6_hdr"`, `"tcp_hdr"`).
    Truncated { stage: &'static str },
    /// IP version is neither 4 nor 6.
    UnsupportedIpVersion(u8),
    /// IPv4 IHL field encoded a header length smaller than the minimum.
    BadIpv4Ihl,
    /// TCP Data Offset field encoded a header length smaller than the minimum.
    BadTcpDataOffset,
    /// Layer-4 protocol is neither TCP nor UDP.
    UnsupportedL4Proto(u8),
}

impl GsoHdrError {
    /// Stable, low-cardinality label used as the `reason` field of the
    /// `gso_dropped_invalid_hdr_len` counter. Production has no
    /// datapath logs, so this label is the only way to distinguish
    /// failure modes.
    #[cfg(target_os = "linux")]
    pub(crate) fn metric_reason(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Truncated { stage } => stage,
            Self::UnsupportedIpVersion(_) => "unsupported_ip_version",
            Self::BadIpv4Ihl => "bad_ipv4_ihl",
            Self::BadTcpDataOffset => "bad_tcp_data_offset",
            Self::UnsupportedL4Proto(_) => "unsupported_l4_proto",
        }
    }
}

/// Why `build_segment` could not produce one wire-format segment.
///
/// Each variant corresponds to a `pnet_packet` constructor returning
/// `None` (or, for [`Self::Tcp`], the TCP sequence-number slice in
/// `gso_pkt` falling out of bounds). The kernel violated the
/// invariant that `virtio_net_hdr.csum_start` and `hdr_len` match
/// the actual packet bytes — typically a truncated header in the
/// GSO aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GsoSegError {
    /// Superpacket buffer was empty.
    Empty,
    /// IPv4 header parse failed.
    Ipv4,
    /// IPv6 header parse failed.
    Ipv6,
    /// TCP header parse failed (or `gso_pkt` shorter than
    /// `csum_start + 8` when reading the first sequence number).
    Tcp,
    /// UDP header parse failed.
    Udp,
}

impl GsoSegError {
    /// Stable, low-cardinality label for the `reason` field of the
    /// `gso_build_segment_failed` counter.
    #[cfg(target_os = "linux")]
    pub(crate) fn metric_reason(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Ipv4 => "ipv4_parse",
            Self::Ipv6 => "ipv6_parse",
            Self::Tcp => "tcp_parse",
            Self::Udp => "udp_parse",
        }
    }
}

/// Compute the protocol-header length (IP + transport) from an IPv4/IPv6 packet.
///
/// Linux's TUN driver writes `skb_headlen` (a hint about linearity) into
/// `virtio_net_hdr.hdr_len` — NOT the protocol header length the virtio-net
/// spec calls for. For multi-segment GSO aggregates the linearity hint is
/// roughly the size of the first segment (≈ MTU), not the headers, so any
/// code that copies a per-segment header template based on `vhdr.hdr_len`
/// will get a wildly wrong value. Parse the real length from the packet.
pub(crate) fn calc_hdr_len(pkt: &[u8]) -> Result<usize, GsoHdrError> {
    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::tcp::TcpPacket;

    if pkt.is_empty() {
        return Err(GsoHdrError::Empty);
    }
    // The server's inside-IO loop is IPv4-only today, and a correct
    // IPv6 header length requires walking the extension-header chain.
    // Add IPv6 handling here when we have an end-to-end IPv6 path.
    let (ip_hdr_len, proto) = match pkt[0] >> 4 {
        4 => {
            let ip = Ipv4Packet::new(pkt).ok_or(GsoHdrError::Truncated { stage: "ipv4_hdr" })?;
            let ihl = ip.get_header_length() as usize * 4;
            if ihl < 20 {
                return Err(GsoHdrError::BadIpv4Ihl);
            }
            if pkt.len() < ihl {
                return Err(GsoHdrError::Truncated { stage: "ipv4_hdr" });
            }
            (ihl, ip.get_next_level_protocol())
        }
        v => return Err(GsoHdrError::UnsupportedIpVersion(v)),
    };
    let l4_hdr_len = if proto == IpNextHeaderProtocols::Tcp {
        let tcp = TcpPacket::new(&pkt[ip_hdr_len..])
            .ok_or(GsoHdrError::Truncated { stage: "tcp_hdr" })?;
        let doff = tcp.get_data_offset() as usize * 4;
        if doff < 20 {
            return Err(GsoHdrError::BadTcpDataOffset);
        }
        doff
    } else if proto == IpNextHeaderProtocols::Udp {
        8
    } else {
        return Err(GsoHdrError::UnsupportedL4Proto(proto.0));
    };
    Ok(ip_hdr_len + l4_hdr_len)
}

/// Number of segments in a GSO superpacket.
pub(crate) fn calc_gso_segs(pkt_len: usize, hdr_len: usize, gso_size: usize) -> usize {
    if gso_size == 0 {
        return 0;
    }
    let payload_len = pkt_len.saturating_sub(hdr_len);
    payload_len.div_ceil(gso_size)
}

/// Build segment `gso_idx` from the superpacket into `out`.
///
/// Resets `out` and writes header template + payload slice into its
/// spare capacity, applies all per-segment fixups (IP ID, TCP seq,
/// checksums), then commits the segment via `set_len`. On return,
/// `out` holds exactly the one segment's wire bytes.
///
/// `hdr_len` is the real header length the caller derived once via
/// [`calc_hdr_len`] for the whole superpacket.
///
/// `out.capacity()` must be ≥ one segment's maximum wire length.
pub(crate) fn build_segment(
    hdr: &VirtioNetHdr,
    hdr_len: usize,
    gso_pkt: &[u8],
    gso_idx: usize,
    out: &mut bytes::BytesMut,
) -> Result<(), GsoSegError> {
    use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet_packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
    use pnet_packet::tcp::{MutableTcpPacket, TcpFlags};
    use pnet_packet::udp::MutableUdpPacket;

    if gso_pkt.is_empty() {
        return Err(GsoSegError::Empty);
    }
    let gso_size = hdr.gso_size as usize;
    let csum_start = hdr.csum_start as usize;
    let v6 = (gso_pkt[0] >> 4) == 6;

    // This segment's payload range within the superpacket.
    let seg_start = hdr_len + gso_idx * gso_size;
    let seg_end = std::cmp::min(seg_start + gso_size, gso_pkt.len());
    let seg_len = seg_end - seg_start;
    let out_len = hdr_len + seg_len;
    let is_last = seg_end == gso_pkt.len();

    // Materialize the segment: header template + payload.
    // BytesMut::extend_from_slice memcpys without zero-init.
    out.clear();
    out.extend_from_slice(&gso_pkt[..hdr_len]);
    out.extend_from_slice(&gso_pkt[seg_start..seg_end]);
    debug_assert_eq!(out.len(), out_len);

    // Read IP source/destination addresses once before taking any
    // mutable borrow on `out`. Used downstream for the L4 checksum
    // pseudo-header.
    let (v4_addrs, v6_addrs) = if v6 {
        let ip = Ipv6Packet::new(&out[..csum_start]).ok_or(GsoSegError::Ipv6)?;
        (None, Some((ip.get_source(), ip.get_destination())))
    } else {
        let ip = Ipv4Packet::new(&out[..csum_start]).ok_or(GsoSegError::Ipv4)?;
        (Some((ip.get_source(), ip.get_destination())), None)
    };

    // IP-layer fixups.
    if v6 {
        let mut ip = MutableIpv6Packet::new(&mut out[..csum_start]).ok_or(GsoSegError::Ipv6)?;
        // payload_length excludes the 40-byte fixed IPv6 header.
        ip.set_payload_length((out_len - 40) as u16);
    } else {
        let mut ip = MutableIpv4Packet::new(&mut out[..csum_start]).ok_or(GsoSegError::Ipv4)?;
        if gso_idx > 0 {
            ip.set_identification(ip.get_identification().wrapping_add(gso_idx as u16));
        }
        ip.set_total_length(out_len as u16);
        ip.set_checksum(0);
        let csum = pnet_packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(csum);
    }

    // Transport-layer fixups.
    if hdr.is_tcp() {
        let mut tcp =
            MutableTcpPacket::new(&mut out[csum_start..out_len]).ok_or(GsoSegError::Tcp)?;
        // Bounds-safe read of 4 bytes at csum_start+4 in gso_pkt.
        let seq_bytes = gso_pkt
            .get(csum_start + 4..csum_start + 8)
            .ok_or(GsoSegError::Tcp)?;
        let first_seq =
            u32::from_be_bytes([seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3]]);
        tcp.set_sequence(first_seq.wrapping_add(gso_size as u32 * gso_idx as u32));
        if !is_last {
            tcp.set_flags(tcp.get_flags() & !(TcpFlags::FIN | TcpFlags::PSH));
        }
        tcp.set_checksum(0);
        let csum = match (v4_addrs, v6_addrs) {
            (Some((src, dst)), None) => {
                pnet_packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src, &dst)
            }
            (None, Some((src, dst))) => {
                pnet_packet::tcp::ipv6_checksum(&tcp.to_immutable(), &src, &dst)
            }
            _ => unreachable!(),
        };
        tcp.set_checksum(csum);
    } else {
        let mut udp =
            MutableUdpPacket::new(&mut out[csum_start..out_len]).ok_or(GsoSegError::Udp)?;
        udp.set_length((out_len - csum_start) as u16);
        udp.set_checksum(0);
        let csum = match (v4_addrs, v6_addrs) {
            (Some((src, dst)), None) => {
                pnet_packet::udp::ipv4_checksum(&udp.to_immutable(), &src, &dst)
            }
            (None, Some((src, dst))) => {
                pnet_packet::udp::ipv6_checksum(&udp.to_immutable(), &src, &dst)
            }
            _ => unreachable!(),
        };
        udp.set_checksum(csum);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
    use pnet_packet::udp::{MutableUdpPacket, UdpPacket};

    const TCP_FLAG_ACK: u8 = TcpFlags::ACK;
    const TCP_FLAG_FIN: u8 = TcpFlags::FIN;
    const TCP_FLAG_PSH: u8 = TcpFlags::PSH;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
    const IPV4_HDR_LEN: usize = 20;
    const TCP_HDR_LEN: usize = 20;
    const UDP_HDR_LEN: usize = 8;
    const SRC: [u8; 4] = [10, 0, 0, 1];
    const DST: [u8; 4] = [10, 0, 0, 2];

    // ---- builders ----

    fn ipv4_hdr(total_len: u16, id: u16, proto: u8) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0] = 0x45; // version=4, IHL=5
        h[2..4].copy_from_slice(&total_len.to_be_bytes());
        h[4..6].copy_from_slice(&id.to_be_bytes());
        h[8] = 64; // TTL
        h[9] = proto;
        h[12..16].copy_from_slice(&SRC);
        h[16..20].copy_from_slice(&DST);
        h
    }

    fn tcp_hdr(seq: u32, flags: u8) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0..2].copy_from_slice(&1234u16.to_be_bytes());
        h[2..4].copy_from_slice(&5678u16.to_be_bytes());
        h[4..8].copy_from_slice(&seq.to_be_bytes());
        h[12] = 0x50; // data offset = 5 32-bit words (20 bytes)
        h[13] = flags;
        h[14..16].copy_from_slice(&0xFFFFu16.to_be_bytes());
        h
    }

    fn udp_hdr(length: u16) -> [u8; 8] {
        let mut h = [0u8; 8];
        h[0..2].copy_from_slice(&1234u16.to_be_bytes());
        h[2..4].copy_from_slice(&5678u16.to_be_bytes());
        h[4..6].copy_from_slice(&length.to_be_bytes());
        h
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn tcpv4_super(
        gso_size: u16,
        payload_len: usize,
        seq: u32,
        id: u16,
        flags: u8,
    ) -> (VirtioNetHdr, Vec<u8>) {
        let hdr_len = (IPV4_HDR_LEN + TCP_HDR_LEN) as u16;
        let total = hdr_len as usize + payload_len;
        let mut pkt = Vec::with_capacity(total);
        pkt.extend_from_slice(&ipv4_hdr(total as u16, id, IPPROTO_TCP));
        pkt.extend_from_slice(&tcp_hdr(seq, flags));
        pkt.extend(payload(payload_len));
        let vhdr = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len,
            gso_size,
            csum_start: IPV4_HDR_LEN as u16,
            csum_offset: 16,
        };
        (vhdr, pkt)
    }

    fn udpv4_super(gso_size: u16, payload_len: usize) -> (VirtioNetHdr, Vec<u8>) {
        let hdr_len = (IPV4_HDR_LEN + UDP_HDR_LEN) as u16;
        let total = hdr_len as usize + payload_len;
        let mut pkt = Vec::with_capacity(total);
        pkt.extend_from_slice(&ipv4_hdr(total as u16, 0x1234, IPPROTO_UDP));
        pkt.extend_from_slice(&udp_hdr((UDP_HDR_LEN + payload_len) as u16));
        pkt.extend(payload(payload_len));
        let vhdr = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
            hdr_len,
            gso_size,
            csum_start: IPV4_HDR_LEN as u16,
            csum_offset: 6,
        };
        (vhdr, pkt)
    }

    // ---- verifiers ----

    fn check_ipv4(out: &[u8], total_len: usize, expected_id: u16) {
        let ip = Ipv4Packet::new(&out[..total_len]).expect("v4 hdr fits");
        assert_eq!(ip.get_total_length() as usize, total_len, "IP total_len");
        assert_eq!(ip.get_identification(), expected_id, "IP id");
        // Verify stored checksum equals a re-computed one over the
        // header with the checksum field zeroed.
        let mut copy = out[..IPV4_HDR_LEN].to_vec();
        let mut ip_mut = MutableIpv4Packet::new(&mut copy).unwrap();
        let stored = ip_mut.get_checksum();
        ip_mut.set_checksum(0);
        assert_eq!(
            stored,
            pnet_packet::ipv4::checksum(&ip_mut.to_immutable()),
            "IPv4 header csum"
        );
    }

    fn check_transport_v4(hdr: &VirtioNetHdr, out: &[u8], total_len: usize, proto: u8) {
        let ip = Ipv4Packet::new(&out[..hdr.csum_start as usize]).expect("v4 hdr fits");
        let (src, dst) = (ip.get_source(), ip.get_destination());
        let mut l4 = out[hdr.csum_start as usize..total_len].to_vec();
        if proto == IPPROTO_TCP {
            let mut tcp = MutableTcpPacket::new(&mut l4).unwrap();
            let stored = tcp.get_checksum();
            tcp.set_checksum(0);
            assert_eq!(
                stored,
                pnet_packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src, &dst),
                "TCP csum"
            );
        } else {
            let mut udp = MutableUdpPacket::new(&mut l4).unwrap();
            let stored = udp.get_checksum();
            udp.set_checksum(0);
            assert_eq!(
                stored,
                pnet_packet::udp::ipv4_checksum(&udp.to_immutable(), &src, &dst),
                "UDP csum"
            );
        }
    }

    // ---- tests ----

    /// PSH/FIN must only stick on the final segment of a TCPv4 superpacket.
    /// gso=100, payload=250 → segs (100, 100, 50). Asserts flags cleared
    /// to ACK-only on segs 0–1, restored to PSH|FIN|ACK on seg 2, plus
    /// per-seg seq (orig + 100·i), IP id (orig + i), and both checksums.
    #[test]
    fn tcpv4_psh_fin_cleared_until_last_segment() {
        let psh_fin_ack = TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_ACK;
        let (vhdr, pkt) = tcpv4_super(100, 250, 0x1000_0000, 0x0001, psh_fin_ack);
        let hdr_len = calc_hdr_len(&pkt).unwrap();
        let mut out = BytesMut::with_capacity(2048);

        // seg 0 — full, not last
        build_segment(&vhdr, hdr_len, &pkt, 0, &mut out).unwrap();
        let t0 = out.len();
        assert_eq!(t0, 40 + 100);
        let tcp = TcpPacket::new(&out[IPV4_HDR_LEN..t0]).unwrap();
        assert_eq!(tcp.get_flags(), TCP_FLAG_ACK);
        assert_eq!(tcp.get_sequence(), 0x1000_0000);
        check_ipv4(&out, t0, 0x0001);
        check_transport_v4(&vhdr, &out, t0, IPPROTO_TCP);

        // seg 1 — full, not last
        build_segment(&vhdr, hdr_len, &pkt, 1, &mut out).unwrap();
        let t1 = out.len();
        assert_eq!(t1, 40 + 100);
        let tcp = TcpPacket::new(&out[IPV4_HDR_LEN..t1]).unwrap();
        assert_eq!(tcp.get_flags(), TCP_FLAG_ACK);
        assert_eq!(tcp.get_sequence(), 0x1000_0064);
        check_ipv4(&out, t1, 0x0002);
        check_transport_v4(&vhdr, &out, t1, IPPROTO_TCP);

        // seg 2 — short, last: PSH+FIN restored
        build_segment(&vhdr, hdr_len, &pkt, 2, &mut out).unwrap();
        let t2 = out.len();
        assert_eq!(t2, 40 + 50);
        let tcp = TcpPacket::new(&out[IPV4_HDR_LEN..t2]).unwrap();
        assert_eq!(tcp.get_flags(), psh_fin_ack);
        assert_eq!(tcp.get_sequence(), 0x1000_00C8);
        check_ipv4(&out, t2, 0x0003);
        check_transport_v4(&vhdr, &out, t2, IPPROTO_TCP);
    }

    /// Odd gso_size + odd-length last segment: every checksum still folds
    /// correctly. gso=1001, payload=2003 → segs (1001, 1001, 1) — the 1-byte
    /// trailing seg drives the lone-byte branch in checksum_no_fold, and
    /// 1001-byte segs make the total odd so the trailing path runs there too.
    #[test]
    fn tcpv4_odd_mss_checksum_valid() {
        let (vhdr, pkt) = tcpv4_super(1001, 2003, 0, 0x0010, TCP_FLAG_ACK);
        let hdr_len = calc_hdr_len(&pkt).unwrap();
        let mut out = BytesMut::with_capacity(4096);
        let expected_sizes = [1001, 1001, 1];
        for (i, &want) in expected_sizes.iter().enumerate() {
            build_segment(&vhdr, hdr_len, &pkt, i, &mut out).unwrap();
            let t = out.len();
            assert_eq!(t, 40 + want, "seg {i} size");
            check_ipv4(&out, t, 0x0010 + i as u16);
            check_transport_v4(&vhdr, &out, t, IPPROTO_TCP);
        }
    }

    /// UDPv4 GSO (UDP_L4) takes the non-TCP branch: the UDP length field
    /// must be rewritten per segment (not just the IP total_len), and the
    /// UDP checksum recomputed with the pseudo header reflecting the
    /// per-segment length. gso=1000, payload=2500 → segs (1000, 1000, 500).
    #[test]
    fn udpv4_superframe_per_segment_length_and_csum() {
        let (vhdr, pkt) = udpv4_super(1000, 2500);
        let hdr_len = calc_hdr_len(&pkt).unwrap();
        let mut out = BytesMut::with_capacity(2048);
        let expected_sizes = [1000usize, 1000, 500];
        for (i, &want) in expected_sizes.iter().enumerate() {
            build_segment(&vhdr, hdr_len, &pkt, i, &mut out).unwrap();
            let t = out.len();
            assert_eq!(t, 28 + want);
            // UDP length field = UDP hdr + segment payload
            let udp = UdpPacket::new(&out[IPV4_HDR_LEN..t]).unwrap();
            assert_eq!(
                udp.get_length() as usize,
                UDP_HDR_LEN + want,
                "seg {i} UDP length"
            );
            check_ipv4(&out, t, 0x1234 + i as u16);
            check_transport_v4(&vhdr, &out, t, IPPROTO_UDP);
        }
    }

    /// N=1: with a single segment, all per-index fixups must be no-ops.
    /// index=0 skips the IP-ID bump and adds 0 to seq; is_last=true keeps
    /// PSH. Output payload bytes must equal input payload bytes verbatim.
    #[test]
    fn tcpv4_n_equals_one_is_noop_fixup() {
        let psh_ack = TCP_FLAG_PSH | TCP_FLAG_ACK;
        let (vhdr, pkt) = tcpv4_super(100, 50, 0xDEAD_BEEF, 0x4242, psh_ack);
        let hdr_len = calc_hdr_len(&pkt).unwrap();
        let mut out = BytesMut::with_capacity(2048);

        build_segment(&vhdr, hdr_len, &pkt, 0, &mut out).unwrap();
        let t = out.len();
        assert_eq!(t, 40 + 50);
        let ip = Ipv4Packet::new(&out[..IPV4_HDR_LEN]).unwrap();
        assert_eq!(ip.get_identification(), 0x4242, "IP ID unchanged");
        let tcp = TcpPacket::new(&out[IPV4_HDR_LEN..t]).unwrap();
        assert_eq!(tcp.get_sequence(), 0xDEAD_BEEF, "seq unchanged");
        assert_eq!(tcp.get_flags(), psh_ack, "flags preserved");
        // Payload identical to source.
        assert_eq!(&out[40..t], &pkt[40..], "payload");
        check_ipv4(&out, t, 0x4242);
        check_transport_v4(&vhdr, &out, t, IPPROTO_TCP);
    }

    /// Boundary cases for `calc_gso_segs`: 0 payload → 0 segs, exact-multiple
    /// of gso_size → integer count, leftover bytes spill to next seg.
    #[test]
    fn calc_gso_segs_counts_segments() {
        // (pkt_len, want_segs) — hdr_len=40 (IPv4+TCP), gso_size=100
        let cases = [(40, 0), (41, 1), (140, 1), (141, 2), (340, 3)];
        for (pkt_len, want_segs) in cases {
            assert_eq!(
                calc_gso_segs(pkt_len, 40, 100),
                want_segs,
                "pkt_len={pkt_len} should yield {want_segs} segs"
            );
        }
    }

    /// IPv4 ID is u16 and uses wrapping_add — bumps past 0xFFFF must roll
    /// over cleanly, not panic in debug. Initial id 0xFFFE with 3 segs
    /// yields {0xFFFE, 0xFFFF, 0x0000}. Also verifies the IP header
    /// checksum still validates around the wrap.
    #[test]
    fn tcpv4_ip_id_wraps_at_0xffff() {
        let (vhdr, pkt) = tcpv4_super(100, 250, 0, 0xFFFE, TCP_FLAG_ACK);
        let hdr_len = calc_hdr_len(&pkt).unwrap();
        let mut out = BytesMut::with_capacity(2048);
        let expected_ids = [0xFFFEu16, 0xFFFF, 0x0000];
        for (i, &want_id) in expected_ids.iter().enumerate() {
            build_segment(&vhdr, hdr_len, &pkt, i, &mut out).unwrap();
            let t = out.len();
            let ip = Ipv4Packet::new(&out[..IPV4_HDR_LEN]).unwrap();
            assert_eq!(ip.get_identification(), want_id, "seg {i} IP id");
            check_ipv4(&out, t, want_id);
            check_transport_v4(&vhdr, &out, t, IPPROTO_TCP);
        }
    }

    /// When payload is exactly N·gso_size, the last segment is full-sized
    /// (not short) — is_last is computed by `seg_end == pkt.len()`, not
    /// by short length. Asserts PSH is still preserved on the full-sized
    /// final seg and stripped from the identical-sized prior segs.
    #[test]
    fn tcpv4_exact_mtu_boundary_last_segment_is_full() {
        let psh_ack = TCP_FLAG_PSH | TCP_FLAG_ACK;
        let (vhdr, pkt) = tcpv4_super(100, 300, 0x4000_0000, 0x0007, psh_ack);
        let hdr_len = calc_hdr_len(&pkt).unwrap();
        let mut out = BytesMut::with_capacity(2048);

        // Segs 0 and 1: full + not last → PSH cleared
        for i in 0..2 {
            build_segment(&vhdr, hdr_len, &pkt, i, &mut out).unwrap();
            let t = out.len();
            assert_eq!(t, 40 + 100);
            let tcp = TcpPacket::new(&out[IPV4_HDR_LEN..t]).unwrap();
            assert_eq!(tcp.get_flags(), TCP_FLAG_ACK, "seg {i} PSH cleared");
            check_ipv4(&out, t, 0x0007 + i as u16);
            check_transport_v4(&vhdr, &out, t, IPPROTO_TCP);
        }

        // Seg 2: full-sized, but is_last → PSH preserved
        build_segment(&vhdr, hdr_len, &pkt, 2, &mut out).unwrap();
        let t = out.len();
        assert_eq!(t, 40 + 100, "last seg same size as others");
        let tcp = TcpPacket::new(&out[IPV4_HDR_LEN..t]).unwrap();
        assert_eq!(tcp.get_flags(), psh_ack, "last seg PSH preserved");
        check_ipv4(&out, t, 0x0009);
        check_transport_v4(&vhdr, &out, t, IPPROTO_TCP);
    }

    /// IPv6 is rejected at the calc_hdr_len boundary. The fixed
    /// `(40, next_header)` returned previously was wrong for any
    /// packet carrying extension headers; until v6 is wired end-to-
    /// end we surface this as `UnsupportedIpVersion(6)`.
    #[test]
    fn calc_hdr_len_rejects_ipv6() {
        // Minimal IPv6 header: version=6 in the first nibble; payload
        // doesn't matter, we never reach parsing.
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        match calc_hdr_len(&pkt) {
            Err(GsoHdrError::UnsupportedIpVersion(6)) => {}
            other => panic!("expected UnsupportedIpVersion(6), got {other:?}"),
        }
    }

    /// `build_segment` must not panic on an empty superpacket — it
    /// reads `gso_pkt[0]` to dispatch v4/v6. Empty input goes through
    /// the explicit guard.
    #[test]
    fn build_segment_rejects_empty_input() {
        let vhdr = VirtioNetHdr {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 100,
            csum_start: 20,
            csum_offset: 16,
        };
        let mut out = BytesMut::with_capacity(2048);
        assert_eq!(
            build_segment(&vhdr, 40, &[], 0, &mut out),
            Err(GsoSegError::Empty)
        );
    }

    /// `calc_gso_segs(_, _, 0)` must not panic from `div_ceil(0)` —
    /// callers should gate, but the function guards regardless.
    #[test]
    fn calc_gso_segs_zero_gso_size_returns_zero() {
        assert_eq!(calc_gso_segs(1000, 40, 0), 0);
        assert_eq!(calc_gso_segs(0, 0, 0), 0);
    }
}
