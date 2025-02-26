use pnet::packet::{
    MutablePacket, PacketSize,
    ip::IpNextHeaderProtocols,
    ipv4::MutableIpv4Packet,
    tcp::{MutableTcpOptionPacket, MutableTcpPacket, TcpFlags, TcpOptionNumbers},
    udp::MutableUdpPacket,
};
use std::net::Ipv4Addr;
use std::ops;
use tracing::warn;

// #[cfg(target_arch = "x86_64")]
// use std::arch::x86_64::*;

// // Check if AVX2 is available on the current CPU (unused until we support IPv6)
// #[inline(always)]
// fn has_avx2() -> bool {
//     #[cfg(target_arch = "x86_64")]
//     {
//         is_x86_feature_detected!("avx2")
//     }
//     #[cfg(not(target_arch = "x86_64"))]
//     {
//         false
//     }
// }

// HOT/COLD path implementation until RUST adds
// https://github.com/rust-lang/rust/issues/26179

#[inline]
#[cold]
fn cold() {}

#[inline]
pub(crate) fn likely(b: bool) -> bool {
    if !b {
        cold()
    }
    b
}

#[inline]
pub(crate) fn unlikely(b: bool) -> bool {
    if b {
        cold()
    }
    b
}

/// Validate if a buffer contains a valid IPv4 packet
pub(crate) fn ipv4_is_valid_packet(buf: &[u8]) -> bool {
    if buf.len() < 20 {
        // IPv4 header is at least 20 bytes
        return false;
    }
    let first_byte = buf[0];
    let ip_version = first_byte >> 4;
    ip_version == 4
}

/// Structure to calculate incremental checksum
#[derive(Clone, Copy)]
struct Checksum(u16);

impl ops::Deref for Checksum {
    type Target = u16;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::Sub<u16> for Checksum {
    type Output = Checksum;
    fn sub(self, rhs: u16) -> Checksum {
        let (n, of) = self.0.overflowing_sub(rhs);
        Checksum(if of { n.wrapping_sub(1) } else { n })
    }
}

/// Structure to handle checksum updates when modifying IP addresses
struct ChecksumUpdate(Vec<(u16, u16)>);

impl Checksum {
    /// Update checksum when replacing one word with another
    /// Based on RFC-1624 [Eqn. 4]
    fn update_word(self, old_word: u16, new_word: u16) -> Self {
        self - !old_word - new_word
    }

    /// Apply multiple checksum updates
    fn update(self, updates: &ChecksumUpdate) -> Self {
        updates
            .0
            .iter()
            .fold(self, |c, &(old, new)| c.update_word(old, new))
    }

    // AVX2-accelerated checksum update (unused until we support IPv6)
    // #[allow(unsafe_code)]
    // #[cfg(target_arch = "x86_64")]
    // #[target_feature(enable = "avx2")]
    // unsafe fn update_avx2(self, updates: &ChecksumUpdate) -> Self {
    //     let mut sum = u32::from(self.0);

    //     // Process 8 words at a time using AVX2
    //     for chunk in updates.0.chunks(8) {
    //         // Pre-allocate with known size
    //         let mut old_words = Vec::with_capacity(8);
    //         let mut new_words = Vec::with_capacity(8);

    //         // Fill vectors with data or zeros
    //         for i in 0..8 {
    //             if let Some(&(old, new)) = chunk.get(i) {
    //                 old_words.push(i32::from(old));
    //                 new_words.push(i32::from(new));
    //             } else {
    //                 old_words.push(0);
    //                 new_words.push(0);
    //             }
    //         }

    //         // SAFETY: Vectors are guaranteed to have exactly 8 elements
    //         unsafe {
    //             // Load data into AVX2 registers
    //             let old_vec = _mm256_set_epi32(
    //                 old_words[7],
    //                 old_words[6],
    //                 old_words[5],
    //                 old_words[4],
    //                 old_words[3],
    //                 old_words[2],
    //                 old_words[1],
    //                 old_words[0],
    //             );
    //             let new_vec = _mm256_set_epi32(
    //                 new_words[7],
    //                 new_words[6],
    //                 new_words[5],
    //                 new_words[4],
    //                 new_words[3],
    //                 new_words[2],
    //                 new_words[1],
    //                 new_words[0],
    //             );

    //             // Compute NOT(old) + new using AVX2
    //             let not_old = _mm256_xor_si256(old_vec, _mm256_set1_epi32(-1));
    //             let sum_vec = _mm256_add_epi32(not_old, new_vec);

    //             // Horizontal sum
    //             let hadd = _mm256_hadd_epi32(sum_vec, sum_vec);
    //             let hadd = _mm256_hadd_epi32(hadd, hadd);

    //             sum = sum.wrapping_add(_mm256_extract_epi32(hadd, 0) as u32);
    //         }
    //     }

    //     // Fold 32-bit sum to 16 bits
    //     while sum > 0xFFFF {
    //         sum = (sum & 0xFFFF) + (sum >> 16);
    //     }

    //     Checksum(sum as u16)
    // }
}

impl ChecksumUpdate {
    /// Create checksum update data from IP address change
    fn from_ipv4_address(old: Ipv4Addr, new: Ipv4Addr) -> Self {
        let old_bytes = old.octets();
        let new_bytes = new.octets();

        // Convert to u16 pairs for checksum calculation
        let old_words = [
            u16::from_be_bytes([old_bytes[0], old_bytes[1]]),
            u16::from_be_bytes([old_bytes[2], old_bytes[3]]),
        ];
        let new_words = [
            u16::from_be_bytes([new_bytes[0], new_bytes[1]]),
            u16::from_be_bytes([new_bytes[2], new_bytes[3]]),
        ];

        Self(vec![
            (old_words[0], new_words[0]),
            (old_words[1], new_words[1]),
        ])
    }
}

/// Update transport protocol checksums after IP address changes
fn update_transport_checksums(packet: &mut MutableIpv4Packet, updates: ChecksumUpdate) {
    // Skip if this is not the first fragment
    if packet.get_fragment_offset() != 0 {
        return;
    }

    match packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => update_tcp_checksum(packet, updates),
        IpNextHeaderProtocols::Udp => update_udp_checksum(packet, updates),
        IpNextHeaderProtocols::Icmp => {} // ICMP doesn't need checksum update for IP changes
        protocol => {
            if unlikely(true) {
                warn!(protocol = ?protocol, "Unknown protocol, skipping checksum update");
            }
        }
    }
}

fn update_tcp_checksum(packet: &mut MutableIpv4Packet, updates: ChecksumUpdate) {
    if likely(MutableTcpPacket::new(packet.payload_mut()).is_some()) {
        let mut tcp_packet = MutableTcpPacket::new(packet.payload_mut()).unwrap();
        let checksum = tcp_packet.get_checksum();
        // Only update if checksum is present (not 0)
        if checksum != 0 {
            let checksum = Checksum(checksum).update(&updates);
            tcp_packet.set_checksum(*checksum);
        }
    } else {
        warn!("Invalid packet size (less than TCP header)!");
    }
}

fn update_udp_checksum(packet: &mut MutableIpv4Packet, updates: ChecksumUpdate) {
    if likely(MutableUdpPacket::new(packet.payload_mut()).is_some()) {
        let mut udp_packet = MutableUdpPacket::new(packet.payload_mut()).unwrap();
        let checksum = udp_packet.get_checksum();
        // Only update if checksum is present (not 0)
        if checksum != 0 {
            let checksum = Checksum(checksum).update(&updates);
            udp_packet.set_checksum(*checksum);
        }
    } else {
        warn!("Invalid packet size (less than UDP header)!");
    }
}

#[derive(Clone, Copy)]
enum IpField {
    Source,
    Destination,
}

// NOTE: the field is compile-time known, so gets optimized, this is for better maintanance
#[inline(always)]
fn ipv4_update_field(buf: &mut [u8], new_ip: Ipv4Addr, field: IpField) {
    let Some(mut packet) = MutableIpv4Packet::new(buf) else {
        if unlikely(true) {
            warn!("Failed to create IPv4 packet!");
        }
        return;
    };

    // Get old IP before updating
    let old_ip = match field {
        IpField::Source => packet.get_source(),
        IpField::Destination => packet.get_destination(),
    };

    // Update IP field
    match field {
        IpField::Source => packet.set_source(new_ip),
        IpField::Destination => packet.set_destination(new_ip),
    };

    // Update checksums
    let updates = ChecksumUpdate::from_ipv4_address(old_ip, new_ip);
    let checksum = packet.get_checksum();
    if checksum != 0 {
        let checksum = Checksum(checksum).update(&updates);
        packet.set_checksum(*checksum);
    }

    // Update transport protocol checksums
    update_transport_checksums(&mut packet, updates);
}

/// Update source IP address in an IPv4 packet
#[inline]
pub fn ipv4_update_source(buf: &mut [u8], new_ip: Ipv4Addr) {
    ipv4_update_field(buf, new_ip, IpField::Source)
}

/// Update destination IP address in an IPv4 packet
#[inline]
pub fn ipv4_update_destination(buf: &mut [u8], new_ip: Ipv4Addr) {
    ipv4_update_field(buf, new_ip, IpField::Destination)
}

/// Clamp TCP MSS option if present in a TCP SYN packet
pub fn tcp_clamp_mss(pkt: &mut [u8], mss: u16) -> Option<u16> {
    let mut ipv4_packet = MutableIpv4Packet::new(pkt)?;

    let transport_protocol = ipv4_packet.get_next_level_protocol();
    if !matches!(transport_protocol, IpNextHeaderProtocols::Tcp) {
        return None;
    }

    let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut())?;

    // Skip if the packet is not TCP SYN packet
    if tcp_packet.get_flags() & TcpFlags::SYN == 0 {
        return None;
    }

    let mut option_raw = tcp_packet.get_options_raw_mut();
    // TCP MSS option len is 4, so options lesser than 4 does not have MSS option
    while option_raw.len() >= 4 {
        let mut option = MutableTcpOptionPacket::new(option_raw)?;
        if option.get_number() == TcpOptionNumbers::MSS {
            let bytes = option.payload_mut();
            let existing_mss = u16::from_be_bytes([bytes[0], bytes[1]]);
            // If existing MSS is lesser than clamped value, skip updating
            if existing_mss <= mss {
                return None;
            }
            [bytes[0], bytes[1]] = mss.to_be_bytes();

            update_tcp_checksum(&mut ipv4_packet, ChecksumUpdate(vec![(existing_mss, mss)]));
            return Some(existing_mss);
        }
        let start = std::cmp::min(option.packet_size(), option_raw.len());
        option_raw = &mut option_raw[start..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::util;
    use test_case::test_case;

    const TO_SOURCE_1: &str = "10.4.23.33";
    const TO_SOURCE_2: &str = "10.4.20.208";
    const TO_DEST_1: &str = "74.125.200.113";
    const TO_DEST_2: &str = "74.125.24.139";
    const SOURCE_1_DEST_1: &[u8] = &[
        0x45, 0x00, 0x00, 0x54, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x46, 0x95, 0x0a, 0x04, 0x17,
        0x21, 0x4a, 0x7d, 0xc8, 0x71,
    ];
    const SOURCE_1_DEST_2: &[u8] = &[
        0x45, 0x00, 0x00, 0x54, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0xf6, 0x7b, 0x0a, 0x04, 0x17,
        0x21, 0x4a, 0x7d, 0x18, 0x8b,
    ];
    const SOURCE_2_DEST_1: &[u8] = &[
        0x45, 0x00, 0x00, 0x54, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x48, 0xe6, 0x0a, 0x04, 0x14,
        0xd0, 0x4a, 0x7d, 0xc8, 0x71,
    ];
    const SOURCE_2_DEST_2: &[u8] = &[
        0x45, 0x00, 0x00, 0x54, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0xf8, 0xcc, 0x0a, 0x04, 0x14,
        0xd0, 0x4a, 0x7d, 0x18, 0x8b,
    ];
    const SOURCE_1_DEST_1_TCP: &[u8] = &[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x46, 0xbc, 0x0a, 0x04, 0x17,
        0x21, 0x4a, 0x7d, 0xc8, 0x71, 0x9f, 0xba, 0x5b, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x60, 0x8c, 0x00, 0x00,
    ];
    const SOURCE_1_DEST_2_TCP: &[u8] = &[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf6, 0xa2, 0x0a, 0x04, 0x17,
        0x21, 0x4a, 0x7d, 0x18, 0x8b, 0x9f, 0xba, 0x5b, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x10, 0x73, 0x00, 0x00,
    ];
    const SOURCE_2_DEST_1_TCP: &[u8] = &[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x49, 0x0d, 0x0a, 0x04, 0x14,
        0xd0, 0x4a, 0x7d, 0xc8, 0x71, 0x9f, 0xba, 0x5b, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x62, 0xdd, 0x00, 0x00,
    ];
    const SOURCE_2_DEST_2_TCP: &[u8] = &[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf8, 0xf3, 0x0a, 0x04, 0x14,
        0xd0, 0x4a, 0x7d, 0x18, 0x8b, 0x9f, 0xba, 0x5b, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x12, 0xc4, 0x00, 0x00,
    ];

    const SOURCE_1_DEST_1_UDP: &[u8] = &[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x46, 0xbd, 0x0a, 0x04, 0x17,
        0x21, 0x4a, 0x7d, 0xc8, 0x71, 0x9f, 0xba, 0x5b, 0xf7, 0x00, 0x08, 0xd0, 0x18,
    ];
    const SOURCE_1_DEST_2_UDP: &[u8] = &[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0xf6, 0xa3, 0x0a, 0x04, 0x17,
        0x21, 0x4a, 0x7d, 0x18, 0x8b, 0x9f, 0xba, 0x5b, 0xf7, 0x00, 0x08, 0x7f, 0xff,
    ];
    const SOURCE_2_DEST_1_UDP: &[u8] = &[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x49, 0x0e, 0x0a, 0x04, 0x14,
        0xd0, 0x4a, 0x7d, 0xc8, 0x71, 0x9f, 0xba, 0x5b, 0xf7, 0x00, 0x08, 0xd2, 0x69,
    ];
    const SOURCE_2_DEST_2_UDP: &[u8] = &[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0xf8, 0xf4, 0x0a, 0x04, 0x14,
        0xd0, 0x4a, 0x7d, 0x18, 0x8b, 0x9f, 0xba, 0x5b, 0xf7, 0x00, 0x08, 0x82, 0x50,
    ];

    #[test_case(&[] => false; "empty")]
    #[test_case(&[0x40; 19] => false; "buffer too small")]
    #[test_case(&[0x45; 20] => true; "minimum valid v4")]
    #[test_case(&[0x60; 20] => false; "v6 header")]
    #[test_case(SOURCE_1_DEST_1 => true; "SOURCE_1_TO_DEST_1")]
    #[test_case(SOURCE_1_DEST_2 => true; "SOURCE_1_TO_DEST_2")]
    #[test_case(SOURCE_2_DEST_1 => true; "SOURCE_2_TO_DEST_1")]
    #[test_case(SOURCE_2_DEST_2 => true; "SOURCE_2_TO_DEST_2")]
    fn test_ipv4_is_valid_packet(buf: &[u8]) -> bool {
        ipv4_is_valid_packet(buf)
    }

    #[test]
    fn test_checksum() {
        // Covers both overflowing and non overflowing of sub cases
        let old: Ipv4Addr = TO_SOURCE_1.parse().unwrap();
        let new: Ipv4Addr = TO_SOURCE_2.parse().unwrap();
        let c = Checksum(0x46BD);
        let u = ChecksumUpdate::from_ipv4_address(old, new);
        let c = c.update(&u);
        assert_eq!(c.0, 0x490E);
    }

    #[test_case(SOURCE_1_DEST_1, TO_SOURCE_2 => SOURCE_2_DEST_1)]
    #[test_case(SOURCE_1_DEST_2, TO_SOURCE_2 => SOURCE_2_DEST_2)]
    #[test_case(SOURCE_2_DEST_1, TO_SOURCE_1 => SOURCE_1_DEST_1)]
    #[test_case(SOURCE_2_DEST_2, TO_SOURCE_1 => SOURCE_1_DEST_2)]
    fn test_ipv4_update_source(buf: &[u8], new_ip: &str) -> Vec<u8> {
        let mut buf = Vec::from(buf);
        let new_ip: Ipv4Addr = new_ip.parse().unwrap();

        // Check total packet checksum is 0 before and after the update
        assert_eq!(util::checksum(&buf, usize::MAX), 0);
        ipv4_update_source(buf.as_mut_slice(), new_ip);
        assert_eq!(util::checksum(&buf, usize::MAX), 0);
        buf
    }

    #[test_case(SOURCE_1_DEST_1_TCP, TO_SOURCE_2 => SOURCE_2_DEST_1_TCP)]
    #[test_case(SOURCE_1_DEST_2_TCP, TO_SOURCE_2 => SOURCE_2_DEST_2_TCP)]
    #[test_case(SOURCE_2_DEST_1_TCP, TO_SOURCE_1 => SOURCE_1_DEST_1_TCP)]
    #[test_case(SOURCE_2_DEST_2_TCP, TO_SOURCE_1 => SOURCE_1_DEST_2_TCP)]
    #[test_case(SOURCE_1_DEST_1_UDP, TO_SOURCE_2 => SOURCE_2_DEST_1_UDP)]
    #[test_case(SOURCE_1_DEST_2_UDP, TO_SOURCE_2 => SOURCE_2_DEST_2_UDP)]
    #[test_case(SOURCE_2_DEST_1_UDP, TO_SOURCE_1 => SOURCE_1_DEST_1_UDP)]
    #[test_case(SOURCE_2_DEST_2_UDP, TO_SOURCE_1 => SOURCE_1_DEST_2_UDP)]
    fn test_ipv4_update_source_with_transport_layer(buf: &[u8], new_ip: &str) -> Vec<u8> {
        let mut buf = Vec::from(buf);
        let new_ip: Ipv4Addr = new_ip.parse().unwrap();
        ipv4_update_source(buf.as_mut_slice(), new_ip);
        buf
    }

    #[test_case(SOURCE_1_DEST_1, TO_DEST_2 => SOURCE_1_DEST_2)]
    #[test_case(SOURCE_2_DEST_1, TO_DEST_2 => SOURCE_2_DEST_2)]
    #[test_case(SOURCE_1_DEST_2, TO_DEST_1 => SOURCE_1_DEST_1)]
    #[test_case(SOURCE_2_DEST_2, TO_DEST_1 => SOURCE_2_DEST_1)]
    fn test_ipv4_update_destination(buf: &[u8], new_ip: &str) -> Vec<u8> {
        let mut buf = Vec::from(buf);
        let new_ip: Ipv4Addr = new_ip.parse().unwrap();

        // Check total packet checksum is 0 before and after the update
        assert_eq!(util::checksum(&buf, usize::MAX), 0);
        ipv4_update_destination(buf.as_mut_slice(), new_ip);
        assert_eq!(util::checksum(&buf, usize::MAX), 0);
        buf
    }

    #[test_case(SOURCE_1_DEST_1_TCP, TO_DEST_2 => SOURCE_1_DEST_2_TCP)]
    #[test_case(SOURCE_2_DEST_1_TCP, TO_DEST_2 => SOURCE_2_DEST_2_TCP)]
    #[test_case(SOURCE_1_DEST_2_TCP, TO_DEST_1 => SOURCE_1_DEST_1_TCP)]
    #[test_case(SOURCE_2_DEST_2_TCP, TO_DEST_1 => SOURCE_2_DEST_1_TCP)]
    #[test_case(SOURCE_1_DEST_1_UDP, TO_DEST_2 => SOURCE_1_DEST_2_UDP)]
    #[test_case(SOURCE_2_DEST_1_UDP, TO_DEST_2 => SOURCE_2_DEST_2_UDP)]
    #[test_case(SOURCE_1_DEST_2_UDP, TO_DEST_1 => SOURCE_1_DEST_1_UDP)]
    #[test_case(SOURCE_2_DEST_2_UDP, TO_DEST_1 => SOURCE_2_DEST_1_UDP)]
    fn test_ipv4_update_destination_with_transport_layer(buf: &[u8], new_ip: &str) -> Vec<u8> {
        let mut buf = Vec::from(buf);
        let new_ip: Ipv4Addr = new_ip.parse().unwrap();
        ipv4_update_destination(buf.as_mut_slice(), new_ip);
        buf
    }

    const TCP_SYN_WITH_MSS1412: &[u8] = &[
        0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xa9, 0x50, 0xc0, 0xa8, 0x00,
        0xc3, 0x08, 0x08, 0x08, 0x08, 0x00, 0x14, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x60, 0x02, 0x20, 0x00, 0xa6, 0x92, 0x00, 0x00, 0x02, 0x04, 0x05, 0x84,
    ];

    const TCP_SYN_WITH_MSS1200: &[u8] = &[
        0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xa9, 0x50, 0xc0, 0xa8, 0x00,
        0xc3, 0x08, 0x08, 0x08, 0x08, 0x00, 0x14, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x60, 0x02, 0x20, 0x00, 0xa7, 0x66, 0x00, 0x00, 0x02, 0x04, 0x04, 0xb0,
    ];

    const TCP_SYN_WITH_NOP_NOP_MSS1412: &[u8] = &[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xa9, 0x4c, 0xc0, 0xa8, 0x00,
        0xc3, 0x08, 0x08, 0x08, 0x08, 0x00, 0x14, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x70, 0x02, 0x20, 0x00, 0x95, 0x8d, 0x00, 0x00, 0x01, 0x01, 0x02, 0x04, 0x05,
        0x84, 0x00, 0x00,
    ];

    const TCP_SYN_WITH_NOP_NOP_MSS1200: &[u8] = &[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xa9, 0x4c, 0xc0, 0xa8, 0x00,
        0xc3, 0x08, 0x08, 0x08, 0x08, 0x00, 0x14, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x70, 0x02, 0x20, 0x00, 0x96, 0x61, 0x00, 0x00, 0x01, 0x01, 0x02, 0x04, 0x04,
        0xb0, 0x00, 0x00,
    ];

    const TCP_SYN_ACK_WITH_MSS1412: &[u8] = &[
        0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xa9, 0x50, 0xc0, 0xa8, 0x00,
        0xc3, 0x08, 0x08, 0x08, 0x08, 0x00, 0x14, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x60, 0x12, 0x20, 0x00, 0xa6, 0x82, 0x00, 0x00, 0x02, 0x04, 0x05, 0x84,
    ];

    const TCP_SYN_ACK_WITH_MSS1200: &[u8] = &[
        0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xa9, 0x50, 0xc0, 0xa8, 0x00,
        0xc3, 0x08, 0x08, 0x08, 0x08, 0x00, 0x14, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x60, 0x12, 0x20, 0x00, 0xa7, 0x56, 0x00, 0x00, 0x02, 0x04, 0x04, 0xb0,
    ];

    const TCP_SYN_WITH_INVALID_0_LEN_OPT: &[u8] = &[
        0x45, 0x50, 0xff, 0x60, 0xa3, 0x0c, 0x00, 0x00, 0x40, 0x06, 0xa9, 0x50, 0x01, 0x00, 0x00,
        0xfd, 0x00, 0x00, 0x08, 0x08, 0x00, 0x14, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x60, 0x02, 0x20, 0x00, 0xa6, 0xff, 0x00, 0x00, 0x01, 0x03, 0x00, 0xff,
    ];

    const TCP_SYN_WITH_MALFORMED_OPT: &[u8] = &[
        0x45, 0x50, 0xff, 0x60, 0xa3, 0x0c, 0x00, 0x00, 0x40, 0x06, 0xa9, 0x50, 0x01, 0x00, 0x00,
        0xfd, 0x00, 0x00, 0x08, 0x08, 0x00, 0x14, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x60, 0x02, 0x20, 0x00, 0xa6, 0xff, 0x00, 0x00, 0x01, 0x01, 0x01, 0x02,
    ];

    const TCP_ACK_WITH_NOP: &[u8] = &[
        0x45, 0x00, 0x00, 0x34, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0xb3, 0xde, 0x0a, 0x04, 0x17,
        0x60, 0x6f, 0x5f, 0xf6, 0x22, 0xf0, 0x77, 0x1f, 0x90, 0x14, 0xa2, 0x0f, 0xde, 0x5e, 0x28,
        0x2a, 0xd4, 0x80, 0x10, 0x08, 0x0a, 0x82, 0xc0, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xdd,
        0x19, 0xf7, 0x7e, 0x41, 0x39, 0x91, 0xb6,
    ];

    const TCP_IPV6_TCP_SYN: &[u8] = &[
        0x60, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x06, 0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x01, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01, 0xf0, 0x77, 0x1f, 0x90, 0x14,
        0xa2, 0x0f, 0xdd, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0xa7, 0x1a, 0x00, 0x00,
        0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01, 0x08, 0x0a, 0xdd, 0x19, 0xf7,
        0x5a, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00,
    ];

    const UDP_PACKET: &[u8] = &[
        0x45, 0x00, 0x00, 0x39, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xad, 0x0c, 0x0a, 0x04, 0x17,
        0x60, 0x22, 0x60, 0x49, 0xe4, 0xfa, 0xc0, 0x01, 0xbb, 0x00, 0x25, 0x90, 0xd1, 0x44, 0xef,
        0x9f, 0x48, 0x41, 0xab, 0x21, 0x7f, 0x6e, 0xb0, 0xd1, 0xc5, 0xf9, 0x7f, 0xd9, 0x18, 0x1a,
        0x17, 0x5f, 0x2c, 0x4b, 0x55, 0xd8, 0x0a, 0xb0, 0xda, 0xd5, 0xbe, 0x67,
    ];

    #[test_case(TCP_SYN_WITH_MSS1412, 1200 => (TCP_SYN_WITH_MSS1200.to_vec(), Some(1412)))]
    #[test_case(TCP_SYN_WITH_NOP_NOP_MSS1412, 1200 => (TCP_SYN_WITH_NOP_NOP_MSS1200.to_vec(), Some(1412)))]
    #[test_case(TCP_SYN_ACK_WITH_MSS1412, 1200 => (TCP_SYN_ACK_WITH_MSS1200.to_vec(), Some(1412)))]
    #[test_case(TCP_SYN_WITH_MSS1412, 1412 => (TCP_SYN_WITH_MSS1412.to_vec(), None))]
    #[test_case(TCP_SYN_WITH_MSS1412, 1460 => (TCP_SYN_WITH_MSS1412.to_vec(), None))]
    #[test_case(TCP_SYN_WITH_INVALID_0_LEN_OPT, 1200 => (TCP_SYN_WITH_INVALID_0_LEN_OPT.to_vec(), None))]
    #[test_case(TCP_SYN_WITH_MALFORMED_OPT, 1200 => (TCP_SYN_WITH_MALFORMED_OPT.to_vec(), None))]
    #[test_case(TCP_ACK_WITH_NOP, 1200 => (TCP_ACK_WITH_NOP.to_vec(), None))]
    #[test_case(TCP_IPV6_TCP_SYN, 1200 => (TCP_IPV6_TCP_SYN.to_vec(), None))]
    #[test_case(UDP_PACKET, 1200 => (UDP_PACKET.to_vec(), None))]
    fn test_tcp_clamp(buf: &[u8], mss: u16) -> (Vec<u8>, Option<u16>) {
        let mut buf = Vec::from(buf);
        let old_mss = tcp_clamp_mss(buf.as_mut_slice(), mss);
        (buf, old_mss)
    }
}
