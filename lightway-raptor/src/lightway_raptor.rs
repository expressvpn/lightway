use crate::LightwayDataFrame;
use anyhow::Result;
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation}; // Replace `some_module` with the actual module name where LightwayDataFrame is defined.

use std::collections::HashMap;
use tokio::{
    net::UdpSocket,
    time::{Duration, Instant},
};

#[derive(Debug)]
struct DecoderState {
    decoder: Decoder,
    last_updated: Instant,
    completed: bool,
}

/// A single struct that can *send* (encode) and *receive* (decode)
/// Lightway frames over a UDP socket.
pub struct Raptor {
    /// Maximum Transmission Unit (MTU) size. Used to control the size of symbols.
    mtu: Option<u16>,
    /// The underlying UDP socket. We can both send & receive on this socket.
    socket: UdpSocket,

    /// The remote to which we send frames. If you’re truly P2P,
    /// you might store multiple remotes or discover them dynamically.
    remote_addr: Option<std::net::SocketAddr>,

    /// Outgoing aggregator that stores packets to be encoded.
    outgoing_frame: LightwayDataFrame,

    /// Size limit (in bytes) before we decide to flush.
    x_kb_limit: usize,

    /// Time in ms before a flush is triggered due to inactivity.
    y_ms_timeout: u64,

    /// Internal counter for sending frames (frame IDs).
    next_frame_id: u16,

    /// RaptorQ decoders, keyed by frame_id.
    decoders: HashMap<u16, DecoderState>,

    /// How long to keep incomplete decoders before discarding.
    decode_timeout_secs: u64,
}

impl Raptor {
    /// Runs the main Raptor engine loop to process incoming packets and handle send/timeout logic.
    ///
    /// This future must be awaited in your asynchronous runtime.
    pub async fn run_engine(&mut self) -> Result<()> {
        let mut deadline = Instant::now() + Duration::from_millis(self.y_ms_timeout);

        loop {
            println!("[Raptor] Waiting for incoming data...");
            let mut pkt = vec![0u8; 1500]; // Max UDP packet size

            tokio::select! {
                result = self.socket.recv_from(&mut pkt) => {
                    let (len, _addr) = result?;
                    pkt.truncate(len);

                    // Add the received data to the outgoing aggregator
                    self.outgoing_frame.add_packet(pkt);

                    // If size limit is reached, flush the aggregator
                    if self.outgoing_frame.len() >= self.x_kb_limit {
                        self.flush().await?;
                        deadline = Instant::now() + Duration::from_millis(self.y_ms_timeout);
                    } else {
                        // Reset the deadline as we received data
                        deadline = Instant::now() + Duration::from_millis(self.y_ms_timeout);
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                        println!("[Raptor] Timeout reached!");
                    // Timeout occurred, check if there is data to flush
                    if !self.outgoing_frame.is_empty() {
                        self.flush().await?;
                    }
                    // Reset the deadline for the next timeout
                    deadline = Instant::now() + Duration::from_millis(self.y_ms_timeout);
                }
            }
        }
    }
    /// Create a new Raptor instance.
    ///
    /// * `socket` is a bound UdpSocket that we’ll use to both send & receive.
    /// * `remote_addr` is optional if you might discover peers dynamically (you can pass `None`).
    /// * `x_kb_limit` is the max aggregator size before flush (like 64 * 1024).
    /// * `y_ms_timeout` is the flush timeout in milliseconds.
    /// * `decode_timeout_secs` is how long to keep a partial decoder alive.
    pub fn new(
        socket: UdpSocket,
        remote_addr: Option<std::net::SocketAddr>,
        x_kb_limit: usize,
        y_ms_timeout: u64,
        decode_timeout_secs: u64,
        mtu: Option<u16>,
    ) -> Self {
        Self {
            socket,
            remote_addr,
            outgoing_frame: LightwayDataFrame::new_empty(),
            x_kb_limit,
            y_ms_timeout,
            next_frame_id: 0,
            decoders: HashMap::new(),
            decode_timeout_secs,
            mtu: None,
        }
    }

    // -------------------------------------------------
    // Sending part
    // -------------------------------------------------

    /// Add a single IP packet (or any arbitrary data packet) to our aggregator.
    /// We’ll flush later if we reach x_kb_limit or after y_ms_timeout.
    pub fn send_packet(&mut self, data: &[u8]) {
        self.outgoing_frame.add_packet(data.to_vec());
    }

    /// Encode and send the current aggregator as a single RaptorQ frame.
    ///
    /// You can call this manually or from a background loop after a timeout.
    pub async fn flush(&mut self) -> Result<()> {
        // If empty, do nothing
        if self.outgoing_frame.is_empty() {
            return Ok(());
        }

        let serialized_data = self.outgoing_frame.serialize()?;
        // Create RaptorQ encoder
        //let encoder = Encoder::with_defaults(&serialized_data, self.outgoing_frame.largest_packet_length() as u16);

        // Determine the maximum symbol size, using the smaller of mtu (if set) and largest_packet_length
        let max_symbol_size = match self.mtu {
            Some(mtu) => mtu.min(self.outgoing_frame.largest_packet_length() as u16),
            None => self.outgoing_frame.largest_packet_length() as u16,
        };

        // Create RaptorQ encoder with the determined max symbol size
        let encoder = Encoder::with_defaults(&serialized_data, max_symbol_size);

        // Decide how many encoding packets to send
        let symbol_count = self.outgoing_frame.packet_count() as u32 + 4;
        let encoded_symbols: Vec<Vec<u8>> = encoder
            .get_encoded_packets(symbol_count)
            .iter()
            .map(|sym| sym.serialize())
            .collect();

        // For each symbol, prepend frame_id + OTI (12 bytes) to form one UDP packet
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);

        for symbol in encoded_symbols {
            let mut buf = Vec::with_capacity(symbol.len() + 14);
            // 2 bytes frame_id (LE)
            buf.extend_from_slice(&frame_id.to_le_bytes());
            // 12 bytes OTI
            buf.extend_from_slice(&encoder.get_config().serialize());
            // symbol
            buf.extend_from_slice(&symbol);

            // Send out
            if let Some(remote) = self.remote_addr {
                self.socket.send_to(&buf, remote).await?;
            } else {
                // If remote_addr is None, you might handle that differently:
                // e.g. broadcast, or store a list of remote peers, etc.
                eprintln!("No remote_addr configured for sending!");
            }
        }

        println!(
            "[Raptor] Flushed frame_id={} with {} symbols (packets={})",
            frame_id,
            symbol_count as usize,
            self.outgoing_frame.packet_count()
        );

        // Clear aggregator
        self.outgoing_frame.clear();
        Ok(())
    }

    // -------------------------------------------------
    // Receiving part
    // -------------------------------------------------

    /// Process an incoming Raptor-encoded symbol from `data`.
    /// If a frame completes, returns `Ok(Some(Vec<Vec<u8>>))`
    /// containing the original packets that were encoded.
    /// If the frame is not yet complete, returns `Ok(None)`.
    pub fn process_incoming(&mut self, data: &[u8]) -> Result<Option<Vec<Vec<u8>>>> {
        // Minimal check
        if data.len() < 14 {
            eprintln!("Incoming packet too short: len={}", data.len());
            return Ok(None);
        }

        // Extract frame_id
        let frame_id = u16::from_le_bytes([data[0], data[1]]);
        // Extract OTI
        let oti_data = &data[2..14];
        let symbol_data = &data[14..];

        // Build OTI
        let oti = ObjectTransmissionInformation::deserialize(oti_data.try_into()?);

        // Get or create a DecoderState
        let entry = self
            .decoders
            .entry(frame_id)
            .or_insert_with(|| DecoderState {
                decoder: Decoder::new(oti),
                last_updated: Instant::now(),
                completed: false,
            });

        if entry.completed {
            // Already done? Possibly a duplicate
            return Ok(None);
        }

        entry.last_updated = Instant::now();

        // Decode
        let maybe_data = entry
            .decoder
            .decode(EncodingPacket::deserialize(symbol_data.into()).into());

        if let Some(decoded_bytes) = maybe_data {
            // Mark as complete
            entry.completed = true;
            println!("[Raptor] Decoded complete frame_id={}", frame_id);

            // Attempt to parse as LightwayDataFrame
            match LightwayDataFrame::deserialize(&decoded_bytes) {
                Ok(lw_frame) => {
                    // Extract all original packets
                    let packets = lw_frame
                        .get_all_packets()
                        .into_iter()
                        .map(|p| p.to_vec())
                        .collect();
                    // Optionally remove from the map
                    // self.decoders.remove(&frame_id);
                    return Ok(Some(packets));
                }
                Err(e) => {
                    eprintln!("Failed to deserialize LightwayDataFrame: {e}");
                    // We have the raw bytes, but can’t parse them.
                    // Return None (or Some(...) if you want to just pass raw).
                    return Ok(None);
                }
            }
        }

        // Not yet complete
        Ok(None)
    }

    /// Remove stale decoders older than `decode_timeout_secs`.
    /// You might call this periodically in a background task.
    pub fn cleanup_decoders(&mut self) {
        let now = Instant::now();
        let timeout = Duration::from_secs(self.decode_timeout_secs);
        let before = self.decoders.len();
        self.decoders.retain(|_frame_id, st| {
            let age = now.duration_since(st.last_updated);
            if age > timeout {
                println!("[Raptor] Removing stale decoder after {age:?}");
                false
            } else {
                true
            }
        });
        let after = self.decoders.len();
        if after < before {
            println!("[Raptor] Cleaned up {} old decoders", before - after);
        }
    }
}
