use anyhow::Result;
use bytes::BytesMut;
use lightway_core::{
    AccumulatorState, PacketAccumulation, PacketAccumulatorFactory, PacketAccumulatorType,
};
use std::io::Read;

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
use std::collections::HashMap;
use thiserror::Error;
use tokio::time::{Duration, Instant};

const RAPTOR_FRAME_DEFAULT_PKT_BUF_SIZE: usize = 20;

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
        }
    }
}

impl PacketAccumulation for RaptorEncoder {
    /// Store one packet to the accumulator
    fn store(&mut self, data: BytesMut) -> Result<AccumulatorState> {
        self.frame.add_packet(data);

        let current_frame_num_of_bytes = self.frame.get_number_of_bytes();

        if current_frame_num_of_bytes >= self.send_buffer_limit_bytes {
            Ok(AccumulatorState::ReadyToFlush)
        } else {
            Ok(AccumulatorState::Pending)
        }
    }

    fn get_accumulated_pkts(&mut self) -> Result<Vec<BytesMut>> {
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
            let mut buf: Vec<u8> = Vec::with_capacity(symbol.len() + 14);
            // 2 bytes frame_id (LE)
            buf.extend_from_slice(&frame_id.to_le_bytes());
            // 12 bytes OTI
            buf.extend_from_slice(&encoder.get_config().serialize());
            // payload
            buf.extend_from_slice(&symbol);

            let mut bytes = BytesMut::with_capacity(buf.len());
            bytes.extend(buf);

            prepended_pkts.push(bytes);
        }

        // Clear aggregator
        self.frame.clear();

        Ok(prepended_pkts)
    }

    fn cleanup_stale_states(&mut self) {
        // Do nothing
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
    pkt_buffer_size: usize,
}

impl RaptorDecoder {
    /// Creates a raptor Q decoder
    pub fn new(initial_pkt_buffer_size: usize, stale_decoder_timeout: Duration) -> Self {
        Self {
            decoders: HashMap::new(),
            completed_packets: Vec::with_capacity(initial_pkt_buffer_size),
            stale_decoder_timeout,
            pkt_buffer_size: initial_pkt_buffer_size,
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
    fn store(&mut self, data: BytesMut) -> Result<AccumulatorState> {
        if data.len() < 14 {
            // Frame should be at least 14 bytes long
            // Discarding the packet
            return Err(RaptorError::InvalidPacketSize.into());
        }

        // Extract frame_id
        let frame_id = u16::from_le_bytes([data[0], data[1]]);
        // Extract OTI
        let oti_slice: &[u8; 12] = &data[2..14].try_into().unwrap();

        let symbol_data = &data[14..];

        let oti = ObjectTransmissionInformation::deserialize(oti_slice);

        let decoder_state = self
            .decoders
            .entry(frame_id)
            .or_insert_with(|| DecoderState {
                decoder: Decoder::new(oti),
                last_updated: Instant::now(),
                completed: false,
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

    fn get_accumulated_pkts(&mut self) -> Result<Vec<BytesMut>> {
        Ok(std::mem::replace(
            &mut self.completed_packets,
            Vec::with_capacity(self.pkt_buffer_size),
        ))
    }

    fn cleanup_stale_states(&mut self) {
        let current_time = Instant::now();
        self.decoders.retain(|_frame_id, decoder_state| {
            let age = current_time.duration_since(decoder_state.last_updated);
            age <= self.stale_decoder_timeout
        });
    }
}

/// Raptor Q egress packet accumulator factory
pub struct RaptorDecoderFactory {
    /// The initial size of the completed packets buffer
    initial_pkt_buffer_size: usize,

    /// How long to keep incomplete decoders before discarding
    stale_decoder_timeout: Duration,
}

impl RaptorDecoderFactory {
    /// Creates a new RaptorQ egress accumulator factory
    pub fn new(initial_pkt_buffer_size: usize, stale_decoder_timeout: Duration) -> Self {
        Self {
            initial_pkt_buffer_size,
            stale_decoder_timeout,
        }
    }
}

impl PacketAccumulatorFactory for RaptorDecoderFactory {
    fn build(&self) -> PacketAccumulatorType {
        Box::new(RaptorDecoder::new(
            self.initial_pkt_buffer_size,
            self.stale_decoder_timeout,
        ))
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
    number: u16,            // The frame counter
    number_of_bytes: usize,
}

impl RaptorFrame {
    pub fn new() -> Self {
        Self {
            packets: Vec::with_capacity(RAPTOR_FRAME_DEFAULT_PKT_BUF_SIZE),
            number: 0,
            number_of_bytes: 0,
        }
    }

    pub fn get_number_of_bytes(&self) -> usize {
        self.number_of_bytes
    }

    pub fn clear(&mut self) {
        self.packets = Vec::with_capacity(RAPTOR_FRAME_DEFAULT_PKT_BUF_SIZE);
        self.number = self.number.wrapping_add(1);
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

    /// Serializes the `LightwayDataFrame` into a contiguous byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity((RAPTOR_FRAME_DEFAULT_PKT_BUF_SIZE + 1) * 1350);

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

        let mut packets = Vec::with_capacity(RAPTOR_FRAME_DEFAULT_PKT_BUF_SIZE + 1);

        for length in lengths {
            let mut packet = BytesMut::zeroed(length);
            cursor.read_exact(&mut packet)?;

            packets.push(packet);
        }

        Ok(packets)
    }
}
