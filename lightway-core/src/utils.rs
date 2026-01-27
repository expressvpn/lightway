use pnet_packet::{
    MutablePacket, PacketSize,
    ip::IpNextHeaderProtocols,
    ipv4::MutableIpv4Packet,
    tcp::{MutableTcpOptionPacket, MutableTcpPacket, TcpFlags, TcpOptionNumbers},
    udp::MutableUdpPacket,
};
use std::net::Ipv4Addr;
use std::ops;
use tracing::warn;

pub(crate) fn ipv4_is_valid_packet(buf: &[u8]) -> bool {
    // Minimum IPv4 header is 20 bytes
    if buf.len() < 20 {
        return false;
    }

    let first_byte = buf[0];
    let ip_version = first_byte >> 4;

    // Must be IPv4
    if ip_version != 4 {
        return false;
    }

    // Header length is in 4-byte words, must be at least 5 (20 bytes)
    let header_len = (first_byte & 0x0f) as usize;
    if header_len < 5 {
        return false;
    }

    let header_bytes = header_len * 4;

    // Header length must not exceed total packet length
    if header_bytes > buf.len() {
        return false;
    }

    // Validate total length field is reasonable (handles truncated/corrupted packets)
    // Allow packets where total_length >= buffer.len() (we might have partial data)
    let total_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    // Reject if total_length is impossibly small (< header) or doesn't cover what we have
    if total_length < header_bytes || total_length < buf.len() {
        return false;
    }

    // Check for valid source and destination addresses (non-zero, non-broadcast)
    // This is a basic check - production systems may want more strict validation
    let src_ip: [u8; 4] = match buf[12..16].try_into() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let dst_ip: [u8; 4] = match buf[16..20].try_into() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    // Skip loopback and reserved addresses (127.x.x.x, 0.x.x.x)
    // Also reject limited broadcast (255.255.255.255) to prevent broadcast storms
    if src_ip[0] == 127 || src_ip[0] == 0 {
        return false;
    }
    if dst_ip[0] == 127 || dst_ip[0] == 0 || dst_ip == [255, 255, 255, 255] {
        return false;
    }

    true
}

// Structure to calculate incremental checksum
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
        Checksum(match of {
            true => n - 1,
            false => n,
        })
    }
}

impl Checksum {
    // Based on RFC-1624 [Eqn. 4]
    fn update_word(self, old_word: u16, new_word: u16) -> Self {
        self - !old_word - new_word
    }

    fn update(self, updates: &ChecksumUpdate) -> Self {
        updates.0.iter().fold(self, |c, x| c.update_word(x.0, x.1))
    }
}

/// Represents a collection of checksum updates for packets.
///
/// Each tuple contains (old_value, new_value) where:
/// * `old_value` - The original value in the packet in u16
/// * `new_value` - The updated value to replace it in u16
pub struct ChecksumUpdate(Vec<(u16, u16)>);

impl ChecksumUpdate {
    /// Returns a new [`ChecksumUpdate`] based on old and new IPv4 address
    pub fn from_ipv4_address(old: Ipv4Addr, new: Ipv4Addr) -> Self {
        let mut result = vec![];
        let old: [u8; 4] = old.octets();
        let new: [u8; 4] = new.octets();
        for i in 0..2 {
            let old_word = u16::from_be_bytes([old[i * 2], old[i * 2 + 1]]);
            let new_word = u16::from_be_bytes([new[i * 2], new[i * 2 + 1]]);
            result.push((old_word, new_word));
        }
        Self(result)
    }

    /// Returns a new [`ChecksumUpdate`] with a single value update
    ///
    /// # Arguments
    /// * `old` - The original value
    /// * `new` - The replacement value
    pub fn from_port(old: u16, new: u16) -> Self {
        Self(vec![(old, new)])
    }
}

impl From<Vec<(u16, u16)>> for ChecksumUpdate {
    fn from(value: Vec<(u16, u16)>) -> Self {
        Self(value)
    }
}

/// Utility function to update TCP packet when we modify any of the packet payload/headers
pub fn tcp_adjust_packet_checksum(mut packet: MutableIpv4Packet, updates: ChecksumUpdate) {
    let packet = MutableTcpPacket::new(packet.payload_mut());
    let Some(mut packet) = packet else {
        warn!("Invalid packet size (less than Tcp header)!");
        return;
    };

    let checksum = Checksum(packet.get_checksum());
    let checksum = checksum.update(&updates);
    packet.set_checksum(*checksum);
}

/// Utility function to update UDP packet when we modify any of the packet payload/headers
pub fn udp_adjust_packet_checksum(mut packet: MutableIpv4Packet, updates: ChecksumUpdate) {
    let packet = MutableUdpPacket::new(packet.payload_mut());
    let Some(mut packet) = packet else {
        warn!("Invalid packet size (less than Udp header)!");
        return;
    };

    let checksum = Checksum(packet.get_checksum());

    // UDP checksums are optional, and we should respect that when doing NAT
    if *checksum != 0 {
        let checksum = checksum.update(&updates);
        packet.set_checksum(checksum.0);
    }
}

/// Utility function to update ipv4 packet header checksum when we modify any of the ipv4 packet headers
pub fn ipv4_adjust_packet_checksum(mut packet: MutableIpv4Packet, updates: ChecksumUpdate) {
    let checksum = Checksum(packet.get_checksum());
    let checksum = checksum.update(&updates);
    packet.set_checksum(*checksum);

    // In case of fragmented packets, TCP/UDP header will be present only in the first fragment.
    // So skip updating the checksum, if it is not the first fragment (i.e frag_offset != 0)
    if 0 != packet.get_fragment_offset() {
        return;
    }

    let transport_protocol = packet.get_next_level_protocol();
    match transport_protocol {
        IpNextHeaderProtocols::Tcp => tcp_adjust_packet_checksum(packet, updates),
        IpNextHeaderProtocols::Udp => udp_adjust_packet_checksum(packet, updates),
        IpNextHeaderProtocols::Icmp => {}
        protocol => {
            warn!(protocol = ?protocol, "Unknown protocol, skipping checksum adjust")
        }
    }
}

/// Utility function to update source ip address in ipv4 packet buffer
/// Nop if buf is not a valid IPv4 packet
pub fn ipv4_update_source(buf: &mut [u8], ip: Ipv4Addr) {
    let packet = MutableIpv4Packet::new(buf);
    let Some(mut packet) = packet else {
        warn!("Ipv4 src update: Invalid packet size {:?}!", buf.len());
        return;
    };

    let old = packet.get_source();
    // Set new source only after getting old source ip address
    packet.set_source(ip);

    ipv4_adjust_packet_checksum(packet, ChecksumUpdate::from_ipv4_address(old, ip));
}

/// Utility function to update destination ip address in ipv4 packet buffer
/// Nop if buf is not a valid IPv4 packet
pub fn ipv4_update_destination(buf: &mut [u8], ip: Ipv4Addr) {
    let packet = MutableIpv4Packet::new(buf);
    let Some(mut packet) = packet else {
        warn!("Ipv4 dest update: Invalid packet size {:?}!", buf.len());
        return;
    };

    let old = packet.get_destination();
    // Set new destination only after getting old destination ip address
    packet.set_destination(ip);

    ipv4_adjust_packet_checksum(packet, ChecksumUpdate::from_ipv4_address(old, ip));
}

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

            tcp_adjust_packet_checksum(ipv4_packet, ChecksumUpdate(vec![(existing_mss, mss)]));
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
    #[test_case(&[0x40] => false; "too_short_for_ipv4")]
    #[test_case(&[0x60] => false; "v6_not_supported")]
    // Valid IPv4 packets
    #[test_case(SOURCE_1_DEST_1 => true; "SOURCE_1_TO_DEST_1")]
    #[test_case(SOURCE_1_DEST_2 => true; "SOURCE_1_TO_DEST_2")]
    #[test_case(SOURCE_2_DEST_1 => true; "SOURCE_2_TO_DEST_1")]
    #[test_case(SOURCE_2_DEST_2 => true; "SOURCE_2_TO_DEST_2")]
    // Invalid: loopback source
    #[test_case(&[0x45, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0xd0, 0x00, 0x00, 0x00, 0x00] => false; "loopback_source")]
    // Invalid: zero source
    #[test_case(&[0x45, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0xd0, 0x00, 0x00, 0x00, 0x00] => false; "zero_source")]
    // Invalid: header length too small
    #[test_case(&[0x40, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x04, 0x14, 0x01, 0x0a, 0x04, 0x14, 0x02, 0x00, 0x00, 0x08, 0xd0] => false; "header_too_small")]
    // Invalid: limited broadcast destination (255.255.255.255)
    #[test_case(&[0x45, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x04, 0x14, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x08, 0xd0, 0x00, 0x00, 0x00, 0x00] => false; "broadcast_destination")]
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
