use anyhow::Result;
use bytes::BytesMut;
use lightway_core::{
    AccumulatorState, PacketAccumulation, PacketAccumulatorFactory, PacketAccumulatorResult,
    PacketAccumulatorType,
};
use std::io::Read;

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
use std::collections::HashMap;
use thiserror::Error;
use tokio::time::{Duration, Instant};

/// Error types from Raptor Encoder and Decoder
#[derive(Debug, Error)]
pub enum RaptorError {
    /// Packet size is invalid
    #[error("Invalid packet size")]
    InvalidPacketSize,

    /// Failed to de-serialize a raptor frame
    #[error("Raptor Frame deserialization failed. Error: {0}")]
    RaptorFrameDeserializationFailed(std::io::Error),
}

/// RaptorQ ingress packet accumulator
struct RaptorEncoder {
    /// Aggregator that stores packets to be encoded.
    frame: RaptorFrame,

    /// MTU of the raptor-encoded packets
    mtu: u16,

    /// Internal counter for sending frames (frame IDs).
    next_frame_id: u16,

    /// Minimum number of repair symbols per frame
    min_num_of_repair_symbols: u32,

    /// Number of bytes in the frame that would trigger the flush
    send_buffer_limit_bytes: usize,

    /// Controls the number of repair symbols created for a frame. Should be between 0.0 and 1.0
    /// Number of packets in the frame * percentage = number of repair symbols created for the frame.
    /// If the resulting number of repair symbols created is less than min_num_of_repair_symbols, min_num_of_repair_symbols will be used instead.
    repair_symbol_percentage: f64,

    encoding_status: bool,
}

impl RaptorEncoder {
    /// Creates a new RaptorQ ingress accumulator
    pub fn new(
        mtu: u16,
        min_num_of_repair_symbols: u32,
        send_buffer_limit_bytes: usize,
        repair_symbol_percentage: f64,
    ) -> Self {
        Self {
            frame: RaptorFrame::new(),
            mtu: mtu - 14, // 14 bytes reserved for the header (frame_id and OTI)
            next_frame_id: 0,
            min_num_of_repair_symbols,
            send_buffer_limit_bytes,
            repair_symbol_percentage,
            encoding_status: false,
        }
    }
}

impl PacketAccumulation for RaptorEncoder {
    /// Store one packet to the accumulator
    fn store(&mut self, data: &BytesMut) -> PacketAccumulatorResult<AccumulatorState> {
        if !self.encoding_status {
            // Skipping packet as encoder is not enabled.
            return Ok(AccumulatorState::Skip);
        }

        self.frame.add_packet(data.clone());

        let current_frame_num_of_bytes = self.frame.get_number_of_bytes();

        if current_frame_num_of_bytes >= self.send_buffer_limit_bytes {
            Ok(AccumulatorState::ReadyToFlush)
        } else {
            Ok(AccumulatorState::Pending)
        }
    }

    fn get_accumulated_pkts(&mut self) -> PacketAccumulatorResult<Vec<BytesMut>> {
        if self.frame.is_empty() {
            return Ok(Vec::new());
        }

        let serialized_data = self.frame.serialize();
        let encoder = Encoder::with_defaults(&serialized_data, self.mtu);

        // Number of packets in the frame * percentage = number of repair symbols created for the frame.
        // If the resulting number of repair symbols created is less than min_num_of_repair_symbols, min_num_of_repair_symbols will be used instead.
        let num_of_repair_packets =
            (self.frame.packet_count() as f64 * self.repair_symbol_percentage) as u32;
        let num_of_repair_packets =
            std::cmp::max(self.min_num_of_repair_symbols, num_of_repair_packets);

        let encoded_symbols: Vec<Vec<u8>> = encoder
            .get_encoded_packets(num_of_repair_packets)
            .iter()
            .map(|sym| sym.serialize())
            .collect();

        // Get the frame id of the current frame
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);

        let num_of_encoded_packets = encoded_symbols.len();

        let mut prepended_pkts = Vec::with_capacity(num_of_encoded_packets);

        // For each symbol of the frame, prepend frame_id (2 bytes) + OTI (12 bytes)
        for symbol in encoded_symbols {
            let mut buf = BytesMut::with_capacity(symbol.len() + 14);
            // 2 bytes frame_id (LE)
            buf.extend_from_slice(&frame_id.to_le_bytes());
            // 12 bytes OTI
            buf.extend_from_slice(&encoder.get_config().serialize());
            // payload
            buf.extend_from_slice(&symbol);

            prepended_pkts.push(buf);
        }

        // Clear aggregator
        self.frame.clear();

        Ok(prepended_pkts)
    }

    fn cleanup_stale_states(&mut self) {
        // Do nothing
    }

    fn get_encoding_status(&self) -> bool {
        self.encoding_status
    }

    fn set_encoding_status(&mut self, enabled: bool) {
        self.encoding_status = enabled;
    }
}

/// Raptor Q ingress packet accumulator factory
pub struct RaptorEncoderFactory {
    /// MTU of the raptor-encoded packets
    mtu: u16,

    /// Minimum number of repair symbols per frame
    min_num_of_repair_symbols: u32,

    /// Number of bytes in the frame that would trigger the flush
    send_buffer_limit_bytes: usize,

    /// Controls the number of repair symbols created for a frame. Should be between 0.0 and 1.0
    /// Number of packets in the frame * percentage = number of repair symbols created for the frame.
    /// If the resulting number of repair symbols created is less than min_num_of_repair_symbols, min_num_of_repair_symbols will be used instead.
    repair_symbol_percentage: f64,
}

impl RaptorEncoderFactory {
    /// Creates a new RaptorQ ingress accumulator factory
    pub fn new(
        mtu: u16,
        min_num_of_repair_symbols: u32,
        send_buffer_limit_bytes: usize,
        repair_symbol_percentage: f64,
    ) -> Self {
        Self {
            mtu,
            min_num_of_repair_symbols,
            send_buffer_limit_bytes,
            repair_symbol_percentage,
        }
    }
}

impl PacketAccumulatorFactory for RaptorEncoderFactory {
    fn build(&self) -> PacketAccumulatorType {
        Box::new(RaptorEncoder::new(
            self.mtu,
            self.min_num_of_repair_symbols,
            self.send_buffer_limit_bytes,
            self.repair_symbol_percentage,
        ))
    }

    fn get_accumulator_name(&self) -> String {
        String::from("Raptor Q Encoder")
    }
}

struct RaptorDecoder {
    decoders: HashMap<u16, DecoderState>,
    completed_packets: Vec<BytesMut>,
    stale_decoder_timeout: Duration,
}

impl RaptorDecoder {
    /// Creates a raptor Q decoder
    pub fn new(stale_decoder_timeout: Duration) -> Self {
        Self {
            decoders: HashMap::new(),
            completed_packets: Vec::new(),
            stale_decoder_timeout,
        }
    }

    fn get_accumulator_state(&self) -> AccumulatorState {
        if self.completed_packets.is_empty() {
            AccumulatorState::Pending
        } else {
            AccumulatorState::ReadyToFlush
        }
    }
}

impl PacketAccumulation for RaptorDecoder {
    fn store(&mut self, data: &BytesMut) -> PacketAccumulatorResult<AccumulatorState> {
        if data.len() < 14 {
            // Frame should be at least 14 bytes long
            // Discarding the packet
            return Err(RaptorError::InvalidPacketSize.into());
        }

        // Extract frame_id
        let frame_id = u16::from_le_bytes([data[0], data[1]]);
        // Extract OTI
        let oti_slice: &[u8; 12] = &data[2..14].try_into()?;

        let symbol_data = &data[14..];

        let decoder_state = self.decoders.entry(frame_id).or_insert_with(|| {
            let oti = ObjectTransmissionInformation::deserialize(oti_slice);

            DecoderState {
                decoder: Decoder::new(oti),
                last_updated: Instant::now(),
                completed: false,
            }
        });

        if decoder_state.completed {
            // Already done? Possibly a duplicate
            return Ok(self.get_accumulator_state());
        }

        decoder_state.last_updated = Instant::now();

        let maybe_data = decoder_state
            .decoder
            .decode(EncodingPacket::deserialize(symbol_data));

        if let Some(decoded_bytes) = maybe_data {
            decoder_state.completed = true;

            match RaptorFrame::deserialize(&decoded_bytes) {
                Ok(mut pkts) => {
                    self.completed_packets.append(&mut pkts);
                }
                Err(e) => {
                    return Err(RaptorError::RaptorFrameDeserializationFailed(e).into());
                }
            }
        }

        Ok(self.get_accumulator_state())
    }

    fn get_accumulated_pkts(&mut self) -> PacketAccumulatorResult<Vec<BytesMut>> {
        Ok(std::mem::take(&mut self.completed_packets))
    }

    fn cleanup_stale_states(&mut self) {
        let current_time = Instant::now();
        self.decoders.retain(|_frame_id, decoder_state| {
            let age = current_time.duration_since(decoder_state.last_updated);
            age <= self.stale_decoder_timeout
        });
    }

    fn get_encoding_status(&self) -> bool {
        true
    }

    fn set_encoding_status(&mut self, _enabled: bool) {
        // Do nothing.
    }
}

/// Raptor Q egress packet accumulator factory
pub struct RaptorDecoderFactory {
    /// How long to keep incomplete decoders before discarding
    stale_decoder_timeout: Duration,
}

impl RaptorDecoderFactory {
    /// Creates a new RaptorQ egress accumulator factory
    pub fn new(stale_decoder_timeout: Duration) -> Self {
        Self {
            stale_decoder_timeout,
        }
    }
}

impl PacketAccumulatorFactory for RaptorDecoderFactory {
    fn build(&self) -> PacketAccumulatorType {
        Box::new(RaptorDecoder::new(self.stale_decoder_timeout))
    }

    fn get_accumulator_name(&self) -> String {
        String::from("Raptor Q Decoder")
    }
}

#[derive(Debug)]
struct DecoderState {
    decoder: Decoder,
    last_updated: Instant,
    completed: bool,
}

struct RaptorFrame {
    packets: Vec<BytesMut>, // A vector of packets, where each packet is a Vec<u8>
    number_of_bytes: usize,
}

impl RaptorFrame {
    pub fn new() -> Self {
        Self {
            packets: Vec::new(),
            number_of_bytes: 0,
        }
    }

    pub fn get_number_of_bytes(&self) -> usize {
        self.number_of_bytes
    }

    pub fn clear(&mut self) {
        self.packets = Vec::new();
        self.number_of_bytes = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }

    /// Adds a new packet to the `RaptorFrame`.
    pub fn add_packet(&mut self, packet: BytesMut) {
        self.number_of_bytes += packet.len();
        self.packets.push(packet);
    }

    /// Serializes the `RaptorFrame` into a contiguous byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        // 2 bytes for number of packets + 2 * self.packets.len() bytes for packet length + data
        let mut buffer = Vec::with_capacity(2 + 2 * self.packets.len() + self.number_of_bytes);

        let num_packets = self.packets.len() as u16;
        buffer.extend(&num_packets.to_be_bytes());

        for packet in &self.packets {
            let packet_len = packet.len() as u16;
            buffer.extend(&packet_len.to_be_bytes());
        }

        for packet in &self.packets {
            buffer.extend(packet);
        }

        buffer
    }

    /// Deserializes a byte slice into a vector of packets.
    pub fn deserialize(data: &[u8]) -> Result<Vec<BytesMut>, std::io::Error> {
        let mut cursor = std::io::Cursor::new(data);

        let mut num_packets_bytes = [0u8; 2];
        cursor.read_exact(&mut num_packets_bytes)?;
        let num_of_packets = u16::from_be_bytes(num_packets_bytes);

        let mut lengths = Vec::with_capacity(num_of_packets as usize);

        for _ in 0..num_of_packets {
            let mut len_bytes = [0u8; 2];
            cursor.read_exact(&mut len_bytes)?;
            let length = u16::from_be_bytes(len_bytes);
            lengths.push(length as usize);
        }

        let mut packets = Vec::with_capacity(num_of_packets as usize);

        for length in lengths {
            let mut packet = BytesMut::zeroed(length);
            cursor.read_exact(&mut packet)?;

            packets.push(packet);
        }

        Ok(packets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::seq::SliceRandom;

    #[test]
    fn raptor_frame_new() {
        let frame = RaptorFrame::new();
        assert!(frame.is_empty());
        assert_eq!(frame.get_number_of_bytes(), 0);
        assert_eq!(frame.packet_count(), 0);
    }

    #[test]
    fn raptor_frame_count_and_clear() {
        let mut frame = RaptorFrame::new();

        let pkt1 = BytesMut::zeroed(1000);
        frame.add_packet(pkt1);
        assert_eq!(frame.get_number_of_bytes(), 1000);
        assert_eq!(frame.packet_count(), 1);
        assert!(!frame.is_empty());

        let pkt2 = BytesMut::zeroed(1248);
        frame.add_packet(pkt2);
        assert_eq!(frame.get_number_of_bytes(), 2248);
        assert_eq!(frame.packet_count(), 2);
        assert!(!frame.is_empty());

        frame.clear();
        assert_eq!(frame.get_number_of_bytes(), 0);
        assert_eq!(frame.packet_count(), 0);
        assert!(frame.is_empty());
    }

    #[test]
    fn raptor_frame_serialize() {
        let mut frame = RaptorFrame::new();
        let pkt1 = BytesMut::zeroed(1000);
        let mut pkt2 = BytesMut::zeroed(1248);
        pkt2.fill(1);
        frame.add_packet(pkt1.clone());
        frame.add_packet(pkt2.clone());

        let serialized = frame.serialize();
        let serialized_slice = serialized.as_slice();

        // Number of bytes = num of pkts (2 bytes) + length of pkts (num of pkts * 2 bytes) + payload
        assert_eq!(serialized_slice.len(), 2 + 2 * 2 + 1000 + 1248);

        // Number of packets
        let length = u16::from_be_bytes(serialized_slice[0..2].try_into().unwrap());
        assert_eq!(length, 2);

        // Length of each packet
        let length_of_pkt_1 = u16::from_be_bytes(serialized_slice[2..4].try_into().unwrap());
        assert_eq!(length_of_pkt_1, 1000);

        let length_of_pkt_2 = u16::from_be_bytes(serialized_slice[4..6].try_into().unwrap());
        assert_eq!(length_of_pkt_2, 1248);

        // Payload of each packet
        assert_eq!(pkt1, serialized_slice[6..1006]);
        assert_eq!(pkt2, serialized_slice[1006..2254]);
    }

    #[test]
    fn raptor_frame_deserialize() {
        let mut serialized_frame: Vec<u8> = Vec::new();

        // Number of packets
        serialized_frame.extend_from_slice(&u16::to_be_bytes(2));

        // Length of first and second packets
        serialized_frame.extend_from_slice(&u16::to_be_bytes(1000));
        serialized_frame.extend_from_slice(&u16::to_be_bytes(1248));

        // Packets
        serialized_frame.extend_from_slice(&[1; 1000]);
        serialized_frame.extend_from_slice(&[2; 1248]);

        // Deserialize
        let frame =
            RaptorFrame::deserialize(&serialized_frame.as_slice()).expect("deserializing a frame");

        // Number of packets
        assert_eq!(frame.len(), 2);

        // Packet and its payload
        let mut pkt1 = BytesMut::zeroed(1000);
        pkt1.fill(1);
        assert_eq!(frame[0], pkt1);

        let mut pkt2 = BytesMut::zeroed(1248);
        pkt2.fill(2);
        assert_eq!(frame[1], pkt2);
    }

    #[test]
    fn raptor_encoder_no_packets() {
        let factory = RaptorEncoderFactory::new(1350, 2, 3000, 0.1);
        let mut encoder: Box<dyn PacketAccumulation + Send> = factory.build();
        encoder.set_encoding_status(true);

        assert!(encoder.get_accumulated_pkts().unwrap().is_empty());
    }

    #[test]
    fn raptor_decoder_no_packets_after_getting_accumulated_pkts() {
        let factory = RaptorEncoderFactory::new(1350, 2, 3000, 0.1);
        let mut encoder: Box<dyn PacketAccumulation + Send> = factory.build();
        encoder.set_encoding_status(true);

        let pkt = BytesMut::zeroed(1408);
        assert!(encoder.store(&pkt).is_ok());

        assert!(!encoder.get_accumulated_pkts().unwrap().is_empty());
        assert!(encoder.get_accumulated_pkts().unwrap().is_empty());
    }

    #[test]
    fn raptor_encoder_byte_limit() {
        let factory = RaptorEncoderFactory::new(1350, 2, 3000, 0.1);
        let mut encoder: Box<dyn PacketAccumulation + Send> = factory.build();
        encoder.set_encoding_status(true);

        let pkt = BytesMut::zeroed(1408);
        assert!(matches!(encoder.store(&pkt), Ok(AccumulatorState::Pending))); // Total now: 1408 bytes
        assert!(matches!(encoder.store(&pkt), Ok(AccumulatorState::Pending))); // Total now: 2816 bytes
        assert!(matches!(
            encoder.store(&pkt),
            Ok(AccumulatorState::ReadyToFlush)
        )); // Total now: 4224 bytes, which is higher than the byte limit.
    }

    #[test]
    fn raptor_encoder_minimum_number_of_repair_packets() {
        let factory = RaptorEncoderFactory::new(1350, 3, 1350 * 50, 0.2);
        let mut encoder = factory.build();
        encoder.set_encoding_status(true);

        let pkt = BytesMut::zeroed(1000);
        assert!(encoder.store(&pkt).is_ok());

        let pkts = encoder
            .get_accumulated_pkts()
            .expect("failed to get accumulated pkts");
        assert_eq!(pkts.len(), 4); // 1 source packet + 3 repair packets.
    }

    #[test]
    fn raptor_encoder_percentage_of_repair_packets() {
        let factory = RaptorEncoderFactory::new(1350, 3, 1350 * 50, 0.2);
        let mut encoder = factory.build();
        encoder.set_encoding_status(true);

        // Adding 20 packets with the size of MTU
        // In total there will be 21 source packets as the RaptorFrame serialization adds some extra bytes
        let pkt = BytesMut::zeroed(1350);
        for _ in 0..20 {
            assert!(encoder.store(&pkt).is_ok());
        }

        // In total floor(21 * 0.2) = 4 repair packets will be created.
        let pkts = encoder
            .get_accumulated_pkts()
            .expect("failed to get accumulated pkts");
        assert_eq!(pkts.len(), 25); // 21 source packet + 4 repair packets.
    }

    #[test]
    fn raptor_decoder_no_packets() {
        let decoder_factory = RaptorDecoderFactory::new(Duration::from_secs_f64(0.5));
        let mut decoder = decoder_factory.build();

        assert!(decoder.get_accumulated_pkts().unwrap().is_empty());
    }

    #[test]
    fn raptor_encoder_and_decoder_integration() {
        let encoder_factory = RaptorEncoderFactory::new(1350, 3, 1350 * 50, 0.2);
        assert_eq!(
            encoder_factory.get_accumulator_name(),
            String::from("Raptor Q Encoder")
        );
        let mut encoder = encoder_factory.build();
        encoder.set_encoding_status(true);

        let decoder_factory = RaptorDecoderFactory::new(Duration::from_secs_f64(0.5));
        assert_eq!(
            decoder_factory.get_accumulator_name(),
            String::from("Raptor Q Decoder")
        );
        let mut decoder = decoder_factory.build();

        // Frame 1
        let mut pkt1 = BytesMut::zeroed(1408);
        pkt1.fill(1);
        let mut pkt2 = BytesMut::zeroed(1300);
        pkt2.fill(2);
        assert!(encoder.store(&pkt1).is_ok());
        assert!(encoder.store(&pkt2).is_ok());
        let mut encoded_pkts_frame_1 = encoder.get_accumulated_pkts().unwrap();

        // Frame 2
        let mut pkt3 = BytesMut::zeroed(1500);
        pkt3.fill(3);
        assert!(encoder.store(&pkt3).is_ok());
        let mut encoded_pkts_frame_2 = encoder.get_accumulated_pkts().unwrap();

        // Shuffle the packets
        let mut chaotic_network = Vec::new();
        chaotic_network.append(&mut encoded_pkts_frame_1);
        chaotic_network.append(&mut encoded_pkts_frame_2);
        chaotic_network.shuffle(&mut rand::thread_rng());

        for encoded_pkt in chaotic_network {
            assert!(decoder.store(&encoded_pkt).is_ok());
        }

        // Verify that the packets are re-generated
        let pkts = decoder.get_accumulated_pkts().unwrap();
        assert_eq!(pkts.len(), 3);

        let mut pkt1_is_seen = false;
        let mut pkt2_is_seen = false;
        let mut pkt3_is_seen = false;

        for pkt in pkts {
            // Check the first byte.
            // pkt1 is filled with 1, pkt2 is filled with 2, pkt3 is filled with 3.
            match pkt[0] {
                1 => {
                    assert_eq!(pkt, pkt1);
                    pkt1_is_seen = true;
                }
                2 => {
                    assert_eq!(pkt, pkt2);
                    pkt2_is_seen = true;
                }
                3 => {
                    assert_eq!(pkt, pkt3);
                    pkt3_is_seen = true;
                }
                _ => panic!("unknown packet"),
            }
        }

        assert!(pkt1_is_seen);
        assert!(pkt2_is_seen);
        assert!(pkt3_is_seen);

        // No packet left in Decoder
        assert!(decoder.get_accumulated_pkts().unwrap().is_empty());
    }
}
