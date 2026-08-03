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

/// Maximum number of segments in a single UDP GSO superpacket. A
/// `sendmsg` with `UDP_SEGMENT` carrying more than the kernel's
/// `UDP_MAX_SEGMENTS` is rejected with `EINVAL`.
///
/// That kernel constant is **not** fixed: it was `1 << 6` (64) before
/// Linux 6.x and is `1 << 7` (128) on current kernels (measured). We
/// pin the conservative 64 so a batch built here is accepted on both,
/// which also keeps [`MAX_GSO_FRAME_BYTES`] bounded.
pub(crate) const MAX_GSO_SEGS: usize = 64;

/// Upper bound on the bytes a single GSO coalescing buffer can hold:
/// `MAX_GSO_SEGS` segments, each at most `MAX_OUTSIDE_MTU`.
// Only the Linux vnet-hdr offload paths consult this; Android compiles
// the module for `gro`'s raw coalescer only.
#[cfg(any(target_os = "linux", test))]
pub(crate) const MAX_GSO_FRAME_BYTES: usize = MAX_GSO_SEGS * crate::MAX_OUTSIDE_MTU;

/// Upper bound on the UDP payload bytes a single `sendmsg` with
/// `UDP_SEGMENT` may carry. The kernel assembles the whole batch into
/// one skb before segmenting, so the total is bounded by the maximum
/// IP datagram size (65535) minus the UDP header (8) and the larger
/// IPv6 header (40); exceeding it fails with `EMSGSIZE`. A TUN TSO
/// aggregate can be up to 65535 bytes *before* the per-segment
/// `wire::Header` is added, so flushes must be chunked to this limit.
// Only the Linux `UDP_SEGMENT` send path consults this; gating keeps
// non-Linux builds free of a `dead_code` warning.
#[cfg(target_os = "linux")]
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

    /// Serialize to the on-wire layout used by the TUN vnet header.
    ///
    /// virtio-net fields are guest-endian, which is native endian for
    /// every target we build for.
    pub fn to_bytes(&self) -> [u8; VIRTIO_NET_HDR_LEN] {
        let mut b = [0u8; VIRTIO_NET_HDR_LEN];
        b[0] = self.flags;
        b[1] = self.gso_type;
        b[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        b[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        b[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        b[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
        b
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

    /// True if `gso_type` indicates a non-GSO packet, i.e. a single
    /// segment rather than an aggregate.
    ///
    /// Masks `VIRTIO_NET_HDR_GSO_ECN` for the same reason [`Self::is_tcp`]
    /// does. Prefer this over comparing `gso_type` to
    /// [`VIRTIO_NET_HDR_GSO_NONE`] directly: the raw comparison silently
    /// misclassifies an ECN-marked packet, and it keeps the ECN constant
    /// from having to be mirrored outside this module.
    pub fn is_gso_none(&self) -> bool {
        self.gso_type & !VIRTIO_NET_HDR_GSO_ECN == VIRTIO_NET_HDR_GSO_NONE
    }
}

/// Layer-4 protocol number, needed to decide whether the RFC 768 zero
/// substitution applies. IPv4 keeps it at offset 9, IPv6 at offset 6.
const IPPROTO_UDP: u8 = 17;

/// Read the layer-4 protocol number out of the IP header at the start of
/// `buf`.
///
/// Returns `None` when the version nibble is neither 4 nor 6, or the
/// buffer is too short to hold the field.
///
/// For IPv6 this reads the *immediate* Next Header field, so a packet
/// carrying extension headers yields the first extension header's number
/// rather than the transport protocol. That is deliberately conservative:
/// the value is then never [`IPPROTO_UDP`], so the only consequence is
/// that the zero substitution is skipped, matching the behaviour before
/// it existed. It can never mis-identify TCP as UDP, which is the
/// direction that would corrupt a packet. Walk the chain here if an IPv6
/// path with extension headers ever becomes reachable.
#[inline]
fn ip_l4_proto(buf: &[u8]) -> Option<u8> {
    match buf.first()? >> 4 {
        4 => buf.get(9).copied(),
        6 => buf.get(6).copied(),
        _ => None,
    }
}

/// Compute and fill the transport-layer checksum for a non-GSO packet
/// that has `VIRTIO_NET_HDR_F_NEEDS_CSUM` set.
///
/// The kernel deposits the pseudo-header partial sum (src + dst + proto + len)
/// at `[csum_start + csum_offset]` before delivering the packet.
/// We seed our sum with that value, then sum from `csum_start` and complement.
///
/// For UDP the RFC 768 substitution of `0xFFFF` for a computed zero is
/// applied (see [`transport_checksum`]). `csum_start`/`csum_offset` alone
/// cannot distinguish UDP from TCP and `0x0000` is a legal TCP checksum,
/// so the protocol is read from the IP header via [`ip_l4_proto`] and the
/// substitution is applied only for protocol 17.
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

    // Protocol must be read before the transport bytes are borrowed.
    let is_udp = ip_l4_proto(buf) == Some(IPPROTO_UDP);

    // Read the kernel-deposited pseudo-header partial, then zero the
    // field so it doesn't double-count when we sum the segment.
    let partial = u16::from_be_bytes([buf[at], buf[at + 1]]);
    buf[at] = 0;
    buf[at + 1] = 0;

    // Seed with the big-endian partial (one 16-bit word), then sum the
    // transport bytes from `csum_start` with the field zeroed.
    let mut c = internet_checksum::Checksum::new();
    c.add_bytes(&partial.to_be_bytes());
    c.add_bytes(&buf[start..]);
    let csum = u16::from_be_bytes(c.checksum());
    // RFC 768: a computed UDP checksum of zero goes on the wire as
    // 0xFFFF, which is the same value in one's complement. Never for
    // TCP, where 0x0000 is legal.
    let csum = if is_udp && csum == 0 { 0xFFFF } else { csum };
    buf[at..at + 2].copy_from_slice(&csum.to_be_bytes());
}

/// One's-complement transport checksum over a TCP/UDP pseudo-header
/// (source address, destination address, zero-padded protocol byte, and
/// transport length) plus the transport bytes, which must already have
/// their checksum field zeroed. Works for IPv4 (4-byte) and IPv6 (16-byte)
/// addresses; returns the host-order value to store via `set_checksum`.
///
/// For UDP (`proto == 17`) a computed checksum of zero is returned as
/// `0xFFFF` per RFC 768: `0x0000` is the IPv4 "no checksum computed"
/// sentinel and is outright invalid over IPv6 (RFC 8200 §8.1), while
/// `0xFFFF` and `0x0000` are the same value in one's complement so any
/// verifier accepts it. TCP is left alone — `0x0000` is a legal TCP
/// checksum.
///
/// Otherwise matches `pnet_packet::{tcp,udp}::ipv{4,6}_checksum` exactly —
/// pnet skips the checksum word while we zero it, and a zeroed word
/// contributes 0. pnet does not apply the RFC 768 substitution, so UDP
/// output differs from pnet's only for the ~1-in-65536 zero case.
#[inline]
fn transport_checksum(src: &[u8], dst: &[u8], proto: u8, transport: &[u8]) -> u16 {
    // The pseudo-header length field is 16 bits; a longer slice would
    // wrap it and silently produce a wrong checksum. Unreachable from
    // `build_segment`, whose slices are bounded by `gso_size`.
    debug_assert!(
        transport.len() <= u16::MAX as usize,
        "transport too long for pseudo-header"
    );
    let transport_len = transport.len() as u16;
    let mut c = internet_checksum::Checksum::new();
    c.add_bytes(src);
    c.add_bytes(dst);
    // [zero, proto, len_hi, len_lo] — the big-endian pseudo-header trailer.
    c.add_bytes(&[0, proto, (transport_len >> 8) as u8, transport_len as u8]);
    c.add_bytes(transport);
    let csum = u16::from_be_bytes(c.checksum());
    if proto == IPPROTO_UDP && csum == 0 {
        0xFFFF
    } else {
        csum
    }
}

/// GSO type: TCP segmentation aggregate over IPv4.
pub(crate) const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
/// GSO type: TCP segmentation aggregate over IPv6.
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
/// ECN flag OR'd into `gso_type` for ECN-marked aggregates.
const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

/// Why `calc_hdr_len` could not decode the protocol header length.
// Only the Linux vnet-hdr offload paths parse superpackets handed in
// by the kernel; see `MAX_GSO_FRAME_BYTES` above.
#[cfg(any(target_os = "linux", test))]
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

#[cfg(any(target_os = "linux", test))]
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
#[cfg(any(target_os = "linux", test))]
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
#[cfg(any(target_os = "linux", test))]
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
    use pnet_packet::Packet;
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

    // Transport-layer fixups. See [`transport_checksum`] for the pseudo-
    // header + zeroed-field formula and its pnet equivalence.
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
                transport_checksum(&src.octets(), &dst.octets(), 6, tcp.packet())
            }
            (None, Some((src, dst))) => {
                transport_checksum(&src.octets(), &dst.octets(), 6, tcp.packet())
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
                transport_checksum(&src.octets(), &dst.octets(), 17, udp.packet())
            }
            (None, Some((src, dst))) => {
                transport_checksum(&src.octets(), &dst.octets(), 17, udp.packet())
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

    /// A 16-byte UDP datagram (header + 8 payload bytes, checksum field
    /// already zeroed) whose one's-complement sum folds to exactly
    /// `0xFFFF` — so the complement is `0x0000` — under the address
    /// pairs used by the two tests below. Captured from the differential
    /// review harness; nothing about it is crafted beyond the addresses
    /// chosen to land the sum on the boundary.
    const ZERO_SUM_UDP: [u8; 16] = [
        0x92, 0x95, 0x48, 0xde, 0x00, 0x10, 0x00, 0x00, 0x89, 0xc2, 0xf5, 0xce, 0x27, 0x45, 0x13,
        0x7f,
    ];

    /// The uncomplemented pseudo-header partial (src + dst + proto + len)
    /// for [`ZERO_SUM_UDP`] under both address pairs below — the value the
    /// kernel deposits in the checksum field for `NEEDS_CSUM`.
    const ZERO_SUM_UDP_PARTIAL: u16 = 0x6a26;

    /// RFC 768 / RFC 8200 §8.1: a computed UDP checksum of zero must be
    /// transmitted as `0xFFFF`. Pins one datagram whose folded sum is
    /// `0xFFFF` (complement `0x0000`) over both IPv4 and IPv6, and one
    /// whose folded sum is also `0xFFFF` but is TCP, where `0x0000` is a
    /// legal checksum and must be emitted unchanged.
    #[test]
    fn transport_checksum_substitutes_zero_udp_only() {
        // IPv6: 2001::1 -> 2001:2a00::2
        let v6_src = std::net::Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1).octets();
        let v6_dst = std::net::Ipv6Addr::new(0x2001, 0x2a00, 0, 0, 0, 0, 0, 2).octets();
        assert_eq!(
            transport_checksum(&v6_src, &v6_dst, IPPROTO_UDP, &ZERO_SUM_UDP),
            0xFFFF,
            "IPv6 UDP zero checksum must be emitted as 0xFFFF"
        );

        // IPv4: 10.0.0.1 -> 96.0.0.4
        assert_eq!(
            transport_checksum(&[10, 0, 0, 1], &[96, 0, 0, 4], IPPROTO_UDP, &ZERO_SUM_UDP),
            0xFFFF,
            "IPv4 UDP zero checksum must be emitted as 0xFFFF"
        );

        // TCP over 10.0.0.1 -> 96.0.0.15 folds to 0xFFFF for the same
        // bytes (the pseudo-header proto/addresses differ). 0x0000 is a
        // valid TCP checksum and must survive untouched.
        assert_eq!(
            transport_checksum(&[10, 0, 0, 1], &[96, 0, 0, 15], IPPROTO_TCP, &ZERO_SUM_UDP),
            0x0000,
            "TCP zero checksum must not be substituted"
        );
    }

    /// `gso_none_checksum` gets only `csum_start`/`csum_offset`, so it
    /// reads the protocol from the IP header to decide whether the RFC 768
    /// substitution applies. Same transport bytes and same kernel partial
    /// throughout — only the IPv4 protocol byte / IPv6 next-header byte
    /// changes — so the assertions isolate exactly that decision.
    #[test]
    fn gso_none_checksum_substitutes_zero_udp_only() {
        /// Build `ip_hdr ++ ZERO_SUM_UDP`, with the kernel's partial sum
        /// deposited in the checksum field, run `gso_none_checksum` and
        /// return the checksum it wrote.
        fn run(ip_hdr: &[u8], csum_offset: u16) -> u16 {
            let csum_start = ip_hdr.len();
            let mut buf = ip_hdr.to_vec();
            buf.extend_from_slice(&ZERO_SUM_UDP);
            let at = csum_start + csum_offset as usize;
            buf[at..at + 2].copy_from_slice(&ZERO_SUM_UDP_PARTIAL.to_be_bytes());
            gso_none_checksum(&mut buf, csum_start as u16, csum_offset);
            u16::from_be_bytes([buf[at], buf[at + 1]])
        }

        // IPv6 header, next_header at offset 6.
        let mut v6 = [0u8; 40];
        v6[0] = 0x60;
        v6[4..6].copy_from_slice(&(ZERO_SUM_UDP.len() as u16).to_be_bytes());
        v6[6] = IPPROTO_UDP;
        v6[8..24].copy_from_slice(&std::net::Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1).octets());
        v6[24..40]
            .copy_from_slice(&std::net::Ipv6Addr::new(0x2001, 0x2a00, 0, 0, 0, 0, 0, 2).octets());
        assert_eq!(run(&v6, 6), 0xFFFF, "IPv6 UDP zero -> 0xFFFF");

        // Same bytes, next_header = TCP: 0x0000 must stand.
        let mut v6_tcp = v6;
        v6_tcp[6] = IPPROTO_TCP;
        assert_eq!(run(&v6_tcp, 6), 0x0000, "IPv6 TCP zero left as 0x0000");

        // IPv4 header, protocol at offset 9.
        let v4 = {
            let mut h = ipv4_hdr((IPV4_HDR_LEN + ZERO_SUM_UDP.len()) as u16, 0, IPPROTO_UDP);
            h[12..16].copy_from_slice(&[10, 0, 0, 1]);
            h[16..20].copy_from_slice(&[96, 0, 0, 4]);
            h
        };
        assert_eq!(run(&v4, 6), 0xFFFF, "IPv4 UDP zero -> 0xFFFF");

        let mut v4_tcp = v4;
        v4_tcp[9] = IPPROTO_TCP;
        assert_eq!(run(&v4_tcp, 6), 0x0000, "IPv4 TCP zero left as 0x0000");

        // Unrecognised IP version: protocol unknown, so no substitution.
        let mut bogus = v4;
        bogus[0] = 0x95;
        assert_eq!(
            run(&bogus, 6),
            0x0000,
            "unknown IP version -> no substitution"
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
