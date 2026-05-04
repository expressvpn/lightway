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

impl VirtioNetHdr {
    /// Interpret the first [`VIRTIO_NET_HDR_LEN`] bytes of `buf` as a
    /// `&VirtioNetHdr` without copying.
    ///
    /// # Requirements
    /// `buf` must be at least `VIRTIO_NET_HDR_LEN` bytes and 2-byte
    /// aligned (any `Vec<u8>` or heap allocation satisfies this).
    #[allow(unsafe_code)]
    pub fn from_bytes(buf: &[u8]) -> std::io::Result<&Self> {
        if buf.len() < VIRTIO_NET_HDR_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "buffer too short for VirtioNetHdr",
            ));
        }
        let ptr = buf.as_ptr();
        assert!(
            ptr.align_offset(std::mem::align_of::<VirtioNetHdr>()) == 0,
            "buffer is not aligned for VirtioNetHdr"
        );
        // SAFETY: We verified length and alignment. VirtioNetHdr is repr(C)
        // with no padding, and the returned lifetime is tied to `buf`.
        unsafe { Ok(&*(ptr as *const VirtioNetHdr)) }
    }
}

/// Compute and fill the transport-layer checksum for a non-GSO packet
/// that has `VIRTIO_NET_HDR_F_NEEDS_CSUM` set.
///
/// The kernel deposits the pseudo-header partial sum (src + dst + proto +
/// transport_len) at `[csum_start + csum_offset]` before delivering the
/// packet. We seed our sum with that value, then sum from `csum_start`
/// to end and complement.
pub fn gso_none_checksum(buf: &mut [u8], csum_start: u16, csum_offset: u16) {
    let start = csum_start as usize;
    let offset = csum_offset as usize;
    let at = start + offset;
    if at + 2 > buf.len() || start > buf.len() {
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

#[inline]
fn read_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes(b[..2].try_into().unwrap())
}

#[inline]
fn write_u16(b: &mut [u8], v: u16) {
    b[..2].copy_from_slice(&v.to_be_bytes());
}

#[inline]
fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

#[inline]
fn write_u32(b: &mut [u8], v: u32) {
    b[..4].copy_from_slice(&v.to_be_bytes());
}

// Internet checksum (one's complement sum over 16-bit words), folded at
// the end. The inner loop unrolls to read 8 bytes (two u32s) per
// iteration so the compiler can keep more in flight; on x86_64 release
// LLVM further auto-vectorizes the resulting straight-line code.
#[inline]
fn checksum_no_fold(mut b: &[u8], initial: u64) -> u64 {
    let mut acc = initial;
    while b.len() >= 8 {
        acc += read_u32(&b[..4]) as u64;
        acc += read_u32(&b[4..8]) as u64;
        b = &b[8..];
    }
    if b.len() >= 4 {
        acc += read_u32(&b[..4]) as u64;
        b = &b[4..];
    }
    if b.len() >= 2 {
        acc += read_u16(&b[..2]) as u64;
        b = &b[2..];
    }
    if let Some(&byte) = b.first() {
        acc += (byte as u64) << 8;
    }
    acc
}

#[inline]
fn checksum(b: &[u8], initial: u64) -> u16 {
    let mut acc = checksum_no_fold(b, initial);
    while acc > 0xFFFF {
        acc = (acc >> 16) + (acc & 0xFFFF);
    }
    acc as u16
}

fn pseudo_header_checksum_no_fold(
    protocol: u8,
    src_addr: &[u8],
    dst_addr: &[u8],
    total_len: u16,
) -> u64 {
    let sum = checksum_no_fold(src_addr, 0);
    let sum = checksum_no_fold(dst_addr, sum);
    let len_bytes = total_len.to_be_bytes();
    checksum_no_fold(&[0, protocol, len_bytes[0], len_bytes[1]], sum)
}

const TCP_FLAGS_OFFSET: usize = 13;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;
const IPV4_SRC_ADDR_OFFSET: usize = 12;
const IPV6_SRC_ADDR_OFFSET: usize = 8;
const IPV6_FIXED_HDR_LEN: usize = 40;

const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

fn is_v6(pkt: &[u8]) -> bool {
    pkt[0] >> 4 == 6
}

fn is_tcp(hdr: &VirtioNetHdr) -> bool {
    hdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV4 || hdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV6
}

fn addr_info(pkt: &[u8]) -> (usize, usize) {
    if is_v6(pkt) {
        (IPV6_SRC_ADDR_OFFSET, 16)
    } else {
        (IPV4_SRC_ADDR_OFFSET, 4)
    }
}

fn transport_pseudo_csum(hdr: &VirtioNetHdr, pkt: &[u8], segment_data_len: usize) -> u64 {
    let (src_offset, addr_len) = addr_info(pkt);
    let transport_header_len = (hdr.hdr_len - hdr.csum_start) as usize;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    let protocol = if is_tcp(hdr) {
        IPPROTO_TCP
    } else {
        IPPROTO_UDP
    };
    pseudo_header_checksum_no_fold(
        protocol,
        &pkt[src_offset..src_offset + addr_len],
        &pkt[src_offset + addr_len..src_offset + 2 * addr_len],
        (transport_header_len + segment_data_len) as u16,
    )
}

/// Number of segments in a GSO superpacket.
pub(crate) fn segment_count(hdr: &VirtioNetHdr, pkt_len: usize) -> usize {
    let payload_len = pkt_len.saturating_sub(hdr.hdr_len as usize);
    payload_len.div_ceil(hdr.gso_size as usize)
}

/// Build segment `index` from the superpacket into `out`.
///
/// Copies the header template + payload slice, then applies all
/// per-segment fixups (IP ID, TCP seq, checksums).
/// Returns the total byte length written to `out`.
pub(crate) fn build_segment(hdr: &VirtioNetHdr, pkt: &[u8], out: &mut [u8], index: usize) -> usize {
    let hdr_len = hdr.hdr_len as usize;
    let gso_size = hdr.gso_size as usize;
    let csum_start = hdr.csum_start as usize;
    let csum_offset = hdr.csum_offset as usize;
    let transport_csum_at = csum_start + csum_offset;
    let v6 = is_v6(pkt);

    // Compute this segment's payload range
    let data_offset = hdr_len + index * gso_size;
    let data_end = std::cmp::min(data_offset + gso_size, pkt.len());
    let segment_data_len = data_end - data_offset;
    let total_len = hdr_len + segment_data_len;
    let is_last = data_end == pkt.len();

    // Copy header template + payload
    out[..hdr_len].copy_from_slice(&pkt[..hdr_len]);
    out[hdr_len..total_len].copy_from_slice(&pkt[data_offset..data_end]);

    // Clear checksums before recomputation
    if !v6 {
        out[10] = 0;
        out[11] = 0;
    }
    out[transport_csum_at] = 0;
    out[transport_csum_at + 1] = 0;

    // IP fixups
    if !v6 {
        if index > 0 {
            let id = read_u16(&out[4..6]).wrapping_add(index as u16);
            write_u16(&mut out[4..6], id);
        }
        write_u16(&mut out[2..4], total_len as u16);
        let ip_csum = !checksum(&out[..csum_start], 0);
        write_u16(&mut out[10..12], ip_csum);
    } else {
        write_u16(&mut out[4..6], (total_len - IPV6_FIXED_HDR_LEN) as u16);
    }

    // Transport fixups
    if is_tcp(hdr) {
        let first_seq = read_u32(&pkt[csum_start + 4..]);
        let seq = first_seq.wrapping_add(gso_size as u32 * index as u32);
        write_u32(&mut out[csum_start + 4..csum_start + 8], seq);
        if !is_last {
            out[csum_start + TCP_FLAGS_OFFSET] &= !(TCP_FLAG_FIN | TCP_FLAG_PSH);
        }
    } else {
        let transport_header_len = hdr_len - csum_start;
        write_u16(
            &mut out[csum_start + 4..csum_start + 6],
            (transport_header_len + segment_data_len) as u16,
        );
    }

    // Transport checksum
    let pseudo = transport_pseudo_csum(hdr, pkt, segment_data_len);
    let csum = !checksum(&out[csum_start..total_len], pseudo);
    write_u16(&mut out[transport_csum_at..transport_csum_at + 2], csum);

    total_len
}
