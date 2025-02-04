use std::io::{self, Read};

/// A lightweight data frame for encapsulating and transferring packets.
#[derive(Debug)]
pub struct LightwayDataFrame {
    packets: Vec<Vec<u8>>, // A vector of packets, where each packet is a Vec<u8>
    number: u16,           // The frane counter
}

#[derive(Debug)]
pub struct LightwayRaptorFrame {
    number: u16,
    encoder_config: [u8; 12],
}

impl LightwayRaptorFrame {
    pub fn new(number: u16, encoder_config: [u8; 12]) -> Self {
        Self {
            number,
            encoder_config,
        }
    }

    pub fn number(&self) -> u16 {
        self.number
    }

    pub fn encoder_config(&self) -> [u8; 12] {
        self.encoder_config
    }
}

impl LightwayDataFrame {
    /// Creates a new, empty `LightwayDataFrame`.
    pub fn new(packets: Vec<Vec<u8>>) -> Self {
        Self { packets, number: 0 }
    }

    pub fn new_empty() -> Self {
        Self {
            packets: vec![],
            number: 0,
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 0;
        for packet in &self.packets {
            len += packet.len();
        }

        len
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.number = self.number.wrapping_add(1);
    }

    pub fn number(&self) -> u16 {
        self.number
    }
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }

    pub fn largest_packet_length(&self) -> usize {
        let mut largest_packet_length = 0;
        for packet in &self.packets {
            if packet.len() > largest_packet_length {
                largest_packet_length = packet.len();
            }
        }
        largest_packet_length
    }

    /// Adds a new packet to the `LightwayDataFrame`.
    pub fn add_packet(&mut self, packet: Vec<u8>) {
        self.packets.push(packet);
    }

    /// Retrieves a packet by its index.
    pub fn get_packet(&self, index: usize) -> Option<&[u8]> {
        self.packets.get(index).map(|packet| packet.as_slice())
    }

    /// Retrieves all packets as slices.
    pub fn get_all_packets(&self) -> Vec<&[u8]> {
        self.packets
            .iter()
            .map(|packet| packet.as_slice())
            .collect()
    }

    /// Serializes the `LightwayDataFrame` into a contiguous byte vector.
    pub fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer = Vec::new();

        let num_packets = self.packets.len() as u16;
        buffer.extend(&num_packets.to_be_bytes());

        for packet in &self.packets {
            let packet_len = packet.len() as u16;
            buffer.extend(&packet_len.to_be_bytes());
        }

        for packet in &self.packets {
            buffer.extend(packet);
        }

        Ok(buffer)
    }

    /// Deserializes a byte slice into a `LightwayDataFrame`.
    pub fn deserialize(data: &[u8]) -> Result<Self, io::Error> {
        let mut cursor = io::Cursor::new(data);

        let mut num_packets_bytes = [0u8; 2];
        cursor.read_exact(&mut num_packets_bytes)?;
        let num_packets = u16::from_be_bytes(num_packets_bytes);

        let mut lengths = Vec::new();

        for _ in 0..num_packets {
            let mut len_bytes = [0u8; 2];
            cursor.read_exact(&mut len_bytes)?;
            let length = u16::from_be_bytes(len_bytes);
            lengths.push(length as usize);
        }

        let mut packets = Vec::new();

        for length in lengths {
            let mut packet = vec![0u8; length];
            cursor.read_exact(&mut packet)?;
            packets.push(packet);
        }

        Ok(Self { packets, number: 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_empty_frame() {
        let frame = LightwayDataFrame::new(Vec::new());
        assert!(frame.packets.is_empty());
    }

    #[test]
    fn test_add_packet() {
        let mut frame = LightwayDataFrame::new(Vec::new());
        frame.add_packet(vec![1, 2, 3]);
        frame.add_packet(vec![4, 5, 6, 7]);

        assert_eq!(frame.packets.len(), 2);
        assert_eq!(frame.packets[0], vec![1, 2, 3]);
        assert_eq!(frame.packets[1], vec![4, 5, 6, 7]);
    }

    #[test]
    fn test_serialize_and_deserialize() {
        let mut frame = LightwayDataFrame::new(Vec::new());
        frame.add_packet(vec![1, 2, 3]);
        frame.add_packet(vec![4, 5, 6, 7]);

        let serialized = frame.serialize().expect("Serialization failed");
        let deserialized_frame =
            LightwayDataFrame::deserialize(&serialized).expect("Deserialization failed");

        assert_eq!(deserialized_frame.packets.len(), 2);
        assert_eq!(deserialized_frame.packets[0], vec![1, 2, 3]);
        assert_eq!(deserialized_frame.packets[1], vec![4, 5, 6, 7]);
    }

    #[test]
    fn test_get_packet() {
        let mut frame = LightwayDataFrame::new(Vec::new());
        frame.add_packet(vec![1, 2, 3]);
        frame.add_packet(vec![4, 5, 6, 7]);

        let first_packet = frame.get_packet(0);
        assert_eq!(first_packet, Some(&[1, 2, 3][..]));

        let second_packet = frame.get_packet(1);
        assert_eq!(second_packet, Some(&[4, 5, 6, 7][..]));

        let out_of_bounds_packet = frame.get_packet(2);
        assert_eq!(out_of_bounds_packet, None);
    }

    #[test]
    fn test_get_all_packets() {
        let mut frame = LightwayDataFrame::new(Vec::new());
        frame.add_packet(vec![1, 2, 3]);
        frame.add_packet(vec![4, 5, 6, 7]);

        let packets = frame.get_all_packets();

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], &[1, 2, 3][..]);
        assert_eq!(packets[1], &[4, 5, 6, 7][..]);
    }

    #[test]
    fn test_empty_serialization() {
        let frame = LightwayDataFrame::new(Vec::new());
        let serialized = frame.serialize().expect("Serialization failed");
        let deserialized_frame =
            LightwayDataFrame::deserialize(&serialized).expect("Deserialization failed");

        assert!(deserialized_frame.packets.is_empty());
    }
}
