use std::{fmt::Debug, time::Duration};

use crate::borrowed_bytesmut::BorrowedBytesMut;
use bytes::{Buf, BufMut, BytesMut};
use more_asserts::*;
use rand::Rng;

use super::{FromWireError, FromWireResult, SessionId, expresslane_config::ExpresslaneVersion};

/// A expresslane data frame
///
/// This is a variable sized request.
/// Note that this is not a regular lightway protocol packet. Expresslane
/// data packets are send only with [`crate::wire::Header`] prefixed and no other
/// lightway headers. i.e There is no [`crate::wire::Frame`] corresponding to this
/// packet.
/// Packets will be encrypted/decrypted directly with `express_data` set in
/// [`crate::wire::Header`]
///
/// Wire Format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Counter                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Counter                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           IV                                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           IV                                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           IV                                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        AuthTag                                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        AuthTag                                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        AuthTag                                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        AuthTag                                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        data length            |         RESERVED              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | ... length bytes of data
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub struct ExpresslaneKey(pub [u8; EXPRESSLANE_KEY_SIZE]);

pub const EXPRESSLANE_KEY_SIZE: usize = 32;

impl rand::distr::Distribution<ExpresslaneKey> for rand::distr::StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ExpresslaneKey {
        ExpresslaneKey(rng.random())
    }
}

impl From<[u8; EXPRESSLANE_KEY_SIZE]> for ExpresslaneKey {
    fn from(value: [u8; EXPRESSLANE_KEY_SIZE]) -> Self {
        Self(value)
    }
}

// Make sure WolfSsl Aes256Gcm key size is as expected
const _: () = {
    assert!(wolfssl::Aes256Gcm::KEY_SIZE == EXPRESSLANE_KEY_SIZE);
};

struct ExpresslaneDataCipher {
    // Expresslane key
    pub key: ExpresslaneKey,
    // Underlying cipher algo
    cipher: wolfssl::Aes256Gcm,
}

impl Debug for ExpresslaneDataCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = &self.key.0[..5];
        f.debug_struct("ExpresslaneCipher")
            .field("key", &key)
            .finish()
    }
}

/// Errors which can occur during decoding.
#[derive(Debug, thiserror::Error)]
pub enum ExpresslaneError {
    /// Creating new crypto failed
    #[error("Creating new crypto failed")]
    NewCipherFailed,

    /// Setting Aes256Gcm key failed
    #[error("Setting Aes256Gcm key failed")]
    SetKeyFailed,
}

type ExpresslaneResult<T> = Result<T, ExpresslaneError>;

/// Sliding window for replay protection
///
/// Tracks received packet counters to detect and prevent replay attacks
/// while handling out-of-order packet delivery typical in UDP.
#[derive(Debug, Clone, Default)]
struct ReplayWindow {
    /// Highest wire counter seen so far
    max_counter: u64,
    /// Bitmap tracking received packets within the window
    /// Bit N represents counter (max_counter - N)
    bitmap: u64,
}

impl ReplayWindow {
    /// Window size in packets (must be <= 64 for bitmap)
    const WINDOW_SIZE: u64 = 64;

    /// Check if a wire counter should be accepted and update window state
    ///
    /// Returns true if the packet is valid and should be processed.
    /// Returns false if it's a replay or too old.
    fn check_and_update(&mut self, wire_counter: u64) -> bool {
        // First packet ever received
        if self.max_counter == 0 && self.bitmap == 0 {
            self.max_counter = wire_counter;
            self.bitmap = 1; // Mark bit 0 as received
            return true;
        }

        // Packet is newer than current max - advance window
        if wire_counter > self.max_counter {
            let diff = wire_counter - self.max_counter;

            if diff < Self::WINDOW_SIZE {
                // Shift bitmap left by diff positions
                self.bitmap <<= diff;
            } else {
                // Packet is way ahead, reset the window
                self.bitmap = 0;
            }

            // Mark current position as received
            self.bitmap |= 1;
            self.max_counter = wire_counter;
            return true;
        }

        // Packet is within current window
        if wire_counter > self.max_counter.saturating_sub(Self::WINDOW_SIZE) {
            let bit_position = self.max_counter - wire_counter;
            let bit_mask = 1u64 << bit_position;

            // Check if we've already seen this counter
            if (self.bitmap & bit_mask) != 0 {
                return false; // Replay detected
            }

            // Mark as received
            self.bitmap |= bit_mask;
            return true;
        }

        // Packet is too old (outside window)
        false
    }
}

#[derive(Default)]
pub(crate) struct ExpresslaneData {
    pub(crate) version: ExpresslaneVersion,
    pub(crate) enabled: bool,
    // Counter value last send in the [`ExpresslaneConfig`] message
    pub(crate) config_counter: u64,
    /// Number of retransmissions done with the latest pending encoding request packet
    pub(crate) retransmit_count: u8,
    // Counter which is used in Expresslane wire packets (for sending)
    wire_counter: u64,
    // Replay protection window for received packets
    replay_window: ReplayWindow,
    // current key
    current_self: Option<ExpresslaneDataCipher>,
    current_peer: Option<ExpresslaneDataCipher>,
    // prev key
    next_self: Option<ExpresslaneDataCipher>,
    prev_peer: Option<ExpresslaneDataCipher>,
}

impl Debug for ExpresslaneData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Expresslane")
            .field("enabled", &self.enabled)
            .field("count", &self.config_counter)
            .field("self", &self.current_self)
            .field("peer", &self.current_peer)
            .finish()
    }
}

impl ExpresslaneData {
    /// Wire overhead in bytes
    const WIRE_OVERHEAD: usize = 40;

    pub(crate) fn is_ready(&self) -> bool {
        self.enabled && self.current_peer.is_some() && self.current_self.is_some()
    }

    pub(crate) fn self_key(&self) -> ExpresslaneKey {
        self.current_self
            .as_ref()
            .map(|a| a.key)
            .unwrap_or_default()
    }

    pub(crate) fn peer_key(&self) -> ExpresslaneKey {
        self.current_peer
            .as_ref()
            .map(|a| a.key)
            .unwrap_or_default()
    }

    pub(crate) fn update_next_self_key(&mut self, key: ExpresslaneKey) -> ExpresslaneResult<()> {
        let mut cipher =
            wolfssl::Aes256Gcm::new().map_err(|_| ExpresslaneError::NewCipherFailed)?;
        cipher
            .set_key(key.0)
            .map_err(|_| ExpresslaneError::SetKeyFailed)?;

        self.next_self = Some(ExpresslaneDataCipher { key, cipher });
        tracing::debug!("Updating expresslane next self keys: {:?}", self);
        Ok(())
    }

    pub(crate) fn update_self_key(&mut self) {
        self.current_self = self.next_self.take();
        tracing::debug!("Updating expresslane self keys: {:?}", self);
    }

    pub(crate) fn update_peer_key(&mut self, key: ExpresslaneKey) -> ExpresslaneResult<()> {
        let mut cipher =
            wolfssl::Aes256Gcm::new().map_err(|_| ExpresslaneError::NewCipherFailed)?;
        cipher
            .set_key(key.0)
            .map_err(|_| ExpresslaneError::SetKeyFailed)?;

        let current = Some(ExpresslaneDataCipher { key, cipher });
        self.prev_peer = std::mem::replace(&mut self.current_peer, current);

        tracing::debug!("Updating expresslane peer keys: {:?}", self);
        Ok(())
    }

    pub(crate) fn retransmit_wait_time(&self) -> Duration {
        const INITIAL_WAIT_TIME: Duration = Duration::from_millis(500);

        // To begin with, wait for INITIAL_WAIT_TIME.
        // Then, linearly increase the wait time with the number of retransmission attempted.
        INITIAL_WAIT_TIME * ((1 + self.retransmit_count) as u32)
    }

    pub(crate) fn try_from_wire(
        &mut self,
        buf: &mut BorrowedBytesMut,
        session_id: SessionId,
    ) -> FromWireResult<BytesMut> {
        if buf.len() < Self::WIRE_OVERHEAD {
            return Err(FromWireError::InsufficientData);
        };

        let wire_counter = buf.get_u64();

        // Check for replay attacks using sliding window
        if !self.replay_window.check_and_update(wire_counter) {
            return Err(FromWireError::ReplayedExpressData);
        }

        let mut auth_vec: [u8; 16] = [0; 16];
        auth_vec[..8].copy_from_slice(&session_id.0[..]);
        auth_vec[8..].copy_from_slice(&wire_counter.to_be_bytes()[..]);

        let mut iv = [0u8; 12];
        buf.copy_to_slice(&mut iv);
        let mut auth_tag = [0u8; 16];
        buf.copy_to_slice(&mut auth_tag);
        let data_len = buf.get_u16() as usize;
        let _reserved = buf.get_u16();

        if buf.len() < data_len {
            return Err(FromWireError::InsufficientData);
        }

        let data = buf.commit_and_split_to(data_len);

        let Some(current) = &mut self.current_peer else {
            tracing::error!("No key present packet");
            return Err(FromWireError::InvalidExpressData);
        };

        let plain_text = current
            .cipher
            .decrypt(iv, data.as_ref(), &auth_vec[..], &auth_tag)
            .map_err(|_| FromWireError::InvalidExpressData);

        let plain_text = match plain_text {
            Ok(p) => p,
            Err(e) => {
                if let Some(prev) = &mut self.prev_peer {
                    prev.cipher
                        .decrypt(iv, data.as_ref(), &auth_vec[..], &auth_tag)
                        .inspect_err(|e| tracing::error!("Prev key failed: {e:?}"))
                        .map_err(|_| e)?
                } else {
                    return Err(e);
                }
            }
        };

        Ok(plain_text)
    }

    pub(crate) fn append_to_wire(
        &mut self,
        buf: &mut BytesMut,
        session_id: SessionId,
        plain_text: &[u8],
        iv: [u8; 12],
    ) {
        debug_assert_le!(plain_text.len(), u16::MAX as usize);
        buf.reserve(Self::WIRE_OVERHEAD + plain_text.len());

        let Some(current) = &mut self.current_self else {
            tracing::error!("Skipping data packet");
            return;
        };

        self.wire_counter = self.wire_counter.wrapping_add(1);

        let mut auth_vec: [u8; 16] = [0; 16];
        auth_vec[..8].copy_from_slice(&session_id.0[..]);
        auth_vec[8..].copy_from_slice(&self.wire_counter.to_be_bytes()[..]);

        let (cipher_text, auth_tag) = current
            .cipher
            .encrypt(iv, plain_text.as_ref(), &auth_vec)
            .expect("Encrypt failed");

        buf.put_u64(self.wire_counter);
        buf.put(iv.as_ref());
        buf.put(auth_tag.as_ref());
        buf.put_u16(cipher_text.len() as u16);
        // Reserved
        buf.put_u16(0);

        buf.put(&cipher_text[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;

    #[test]
    fn expresslane_data_self_key() {
        let mut data = ExpresslaneData::default();
        let test_key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        data.update_next_self_key(test_key).unwrap();
        data.update_self_key();
        assert_eq!(data.self_key(), test_key);
    }

    #[test]
    fn expresslane_data_peer_key() {
        let mut data = ExpresslaneData::default();
        let test_key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        data.update_peer_key(test_key).unwrap();
        assert_eq!(data.peer_key(), test_key);
    }

    #[test]
    fn try_from_wire_insufficient_data() {
        let mut data = ExpresslaneData::default();
        let mut buf = ImmutableBytesMut::from(&[0u8; 39][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        let session_id = SessionId([1u8; 8]);

        assert!(matches!(
            data.try_from_wire(&mut buf, session_id).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn try_from_wire_no_key() {
        let mut data = ExpresslaneData::default();
        let mut test_data = [0u8; 50];
        test_data[36] = 0x00;
        test_data[37] = 0x0a;

        let mut buf = BytesMut::from(&test_data[..]);
        let mut borrowed_buf = crate::borrowed_bytesmut::BorrowedBytesMut::from(&mut buf);
        let session_id = SessionId([1u8; 8]);

        assert!(matches!(
            data.try_from_wire(&mut borrowed_buf, session_id)
                .err()
                .unwrap(),
            FromWireError::InvalidExpressData
        ));
    }

    #[test]
    fn try_from_wire_data_len_mismatch() {
        let mut data = ExpresslaneData::default();
        data.update_peer_key(ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]))
            .unwrap();

        let mut test_data = vec![0u8; 40];
        test_data[36] = 0x00;
        test_data[37] = 0x10;
        test_data.extend_from_slice(&[0u8; 5]);

        let mut buf = ImmutableBytesMut::from(test_data);
        let mut buf = buf.as_borrowed_bytesmut();
        let session_id = SessionId([1u8; 8]);

        assert!(matches!(
            data.try_from_wire(&mut buf, session_id).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn append_to_wire_no_key() {
        let mut data = ExpresslaneData::default();
        let mut buf = BytesMut::new();
        let session_id = SessionId([1u8; 8]);
        let plain_text = b"test data";
        let iv = [0u8; 12];

        data.append_to_wire(&mut buf, session_id, plain_text, iv);

        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn append_to_wire_with_key() {
        let mut data = ExpresslaneData::default();
        let test_key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        data.update_next_self_key(test_key).unwrap();
        data.update_self_key();

        let mut buf = BytesMut::new();
        let session_id = SessionId([1u8; 8]);
        let plain_text = b"test data";
        let iv = [0u8; 12];

        data.append_to_wire(&mut buf, session_id, plain_text, iv);

        // Should have wire overhead (40 bytes) + encrypted data length
        assert!(buf.len() >= ExpresslaneData::WIRE_OVERHEAD);

        // Check the structure: wire_counter (8) + iv (12) + auth_tag (16) + data_len (2) + reserved (2) + encrypted_data
        let wire_counter = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        assert_eq!(wire_counter, 1); // First packet should have wire_counter 1 (starts at 0, incremented before use)

        // Check IV is what we provided
        assert_eq!(&buf[8..20], &iv[..]);

        // Check data length field
        let data_len = u16::from_be_bytes([buf[36], buf[37]]) as usize;
        assert_eq!(data_len, plain_text.len()); // Encrypted data should be same length as plaintext for AES-GCM

        // Total length should be overhead + encrypted data length
        assert_eq!(buf.len(), ExpresslaneData::WIRE_OVERHEAD + data_len);
    }

    #[test]
    fn round_trip_encryption_decryption() {
        let mut sender_data = ExpresslaneData::default();
        let mut receiver_data = ExpresslaneData::default();

        let test_key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender_data.update_next_self_key(test_key).unwrap();
        sender_data.update_self_key();
        receiver_data.update_peer_key(test_key).unwrap();

        let session_id = SessionId([1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8]);
        let plain_text = b"Hello, ExpressLane!";
        let iv = [
            9u8, 10u8, 11u8, 12u8, 13u8, 14u8, 15u8, 16u8, 17u8, 18u8, 19u8, 20u8,
        ];

        // Encrypt
        let mut buf = BytesMut::new();
        sender_data.append_to_wire(&mut buf, session_id, plain_text, iv);

        assert!(!buf.is_empty());

        // Decrypt
        let mut borrowed_buf = crate::borrowed_bytesmut::BorrowedBytesMut::from(&mut buf);
        let decrypted = receiver_data
            .try_from_wire(&mut borrowed_buf, session_id)
            .unwrap();

        assert_eq!(decrypted.as_ref(), plain_text);
        assert!(borrowed_buf.is_empty(), "All data should be consumed");
    }

    #[test]
    fn wire_counter_increments_on_each_packet() {
        let mut data = ExpresslaneData::default();
        let test_key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        data.update_next_self_key(test_key).unwrap();
        data.update_self_key();

        let session_id = SessionId([1u8; 8]);
        let plain_text = b"test";
        let iv = [0u8; 12];

        // First packet
        let mut buf1 = BytesMut::new();
        data.append_to_wire(&mut buf1, session_id, plain_text, iv);
        let wire_counter1 = u64::from_be_bytes([
            buf1[0], buf1[1], buf1[2], buf1[3], buf1[4], buf1[5], buf1[6], buf1[7],
        ]);
        assert_eq!(wire_counter1, 1);

        // Second packet
        let mut buf2 = BytesMut::new();
        data.append_to_wire(&mut buf2, session_id, plain_text, iv);
        let wire_counter2 = u64::from_be_bytes([
            buf2[0], buf2[1], buf2[2], buf2[3], buf2[4], buf2[5], buf2[6], buf2[7],
        ]);
        assert_eq!(wire_counter2, 2);

        // Third packet
        let mut buf3 = BytesMut::new();
        data.append_to_wire(&mut buf3, session_id, plain_text, iv);
        let wire_counter3 = u64::from_be_bytes([
            buf3[0], buf3[1], buf3[2], buf3[3], buf3[4], buf3[5], buf3[6], buf3[7],
        ]);
        assert_eq!(wire_counter3, 3);
    }

    #[test]
    fn wire_counter_wrapping() {
        let mut data = ExpresslaneData::default();
        let test_key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        data.update_next_self_key(test_key).unwrap();
        data.update_self_key();

        // Set wire_counter close to max value
        data.wire_counter = u64::MAX - 1;

        let session_id = SessionId([1u8; 8]);
        let plain_text = b"test";
        let iv = [0u8; 12];

        // First packet should wrap from MAX-1 to MAX
        let mut buf1 = BytesMut::new();
        data.append_to_wire(&mut buf1, session_id, plain_text, iv);
        let wire_counter1 = u64::from_be_bytes([
            buf1[0], buf1[1], buf1[2], buf1[3], buf1[4], buf1[5], buf1[6], buf1[7],
        ]);
        assert_eq!(wire_counter1, u64::MAX);

        // Second packet should wrap from MAX to 0
        let mut buf2 = BytesMut::new();
        data.append_to_wire(&mut buf2, session_id, plain_text, iv);
        let wire_counter2 = u64::from_be_bytes([
            buf2[0], buf2[1], buf2[2], buf2[3], buf2[4], buf2[5], buf2[6], buf2[7],
        ]);
        assert_eq!(wire_counter2, 0);

        // Third packet should be 1
        let mut buf3 = BytesMut::new();
        data.append_to_wire(&mut buf3, session_id, plain_text, iv);
        let wire_counter3 = u64::from_be_bytes([
            buf3[0], buf3[1], buf3[2], buf3[3], buf3[4], buf3[5], buf3[6], buf3[7],
        ]);
        assert_eq!(wire_counter3, 1);
    }

    #[test]
    fn replay_window_accepts_first_packet() {
        let mut window = ReplayWindow::default();
        assert!(window.check_and_update(100));
        assert_eq!(window.max_counter, 100);
    }

    #[test]
    fn replay_window_detects_exact_replay() {
        let mut window = ReplayWindow::default();
        assert!(window.check_and_update(100));
        // Replaying the same counter should be rejected
        assert!(!window.check_and_update(100));
    }

    #[test]
    fn replay_window_accepts_newer_packets() {
        let mut window = ReplayWindow::default();
        assert!(window.check_and_update(100));
        assert!(window.check_and_update(101));
        assert!(window.check_and_update(102));
        assert_eq!(window.max_counter, 102);
    }

    #[test]
    fn replay_window_accepts_out_of_order_within_window() {
        let mut window = ReplayWindow::default();
        assert!(window.check_and_update(100));
        assert!(window.check_and_update(105));
        assert!(window.check_and_update(103)); // Out of order, but within window
        assert!(window.check_and_update(102)); // Out of order, but within window
        assert_eq!(window.max_counter, 105);
    }

    #[test]
    fn replay_window_rejects_replayed_out_of_order_packet() {
        let mut window = ReplayWindow::default();
        assert!(window.check_and_update(100));
        assert!(window.check_and_update(105));
        assert!(window.check_and_update(103));
        // Replaying 103 should be rejected
        assert!(!window.check_and_update(103));
    }

    #[test]
    fn replay_window_rejects_too_old_packets() {
        let mut window = ReplayWindow::default();
        assert!(window.check_and_update(100));
        assert!(window.check_and_update(200)); // Advance window by 100
        // Packet 100 is now outside the window (200 - 64 = 136)
        assert!(!window.check_and_update(100));
        assert!(!window.check_and_update(135));
        // But packets within window should work
        assert!(window.check_and_update(137));
    }

    #[test]
    fn replay_window_handles_large_jumps() {
        let mut window = ReplayWindow::default();
        assert!(window.check_and_update(100));
        // Jump way ahead (> window size)
        assert!(window.check_and_update(200));
        assert_eq!(window.max_counter, 200);
        // Old packets should be rejected
        assert!(!window.check_and_update(100));
    }

    #[test]
    fn replay_window_full_scenario() {
        let mut window = ReplayWindow::default();

        // Receive packets 1-10 in order
        for i in 1..=10 {
            assert!(window.check_and_update(i), "Failed to accept packet {}", i);
        }

        // Receive some out-of-order packets
        assert!(window.check_and_update(15));
        assert!(window.check_and_update(13));
        assert!(window.check_and_update(11));
        assert!(window.check_and_update(12));
        assert!(window.check_and_update(14));

        // Try to replay some packets
        assert!(!window.check_and_update(10));
        assert!(!window.check_and_update(13));
        assert!(!window.check_and_update(15));

        // Continue with new packets
        assert!(window.check_and_update(16));
        assert!(window.check_and_update(17));
    }

    #[test]
    fn replay_protection_end_to_end() {
        let mut sender = ExpresslaneData::default();
        let mut receiver = ExpresslaneData::default();

        let test_key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(test_key).unwrap();
        sender.update_self_key();
        receiver.update_peer_key(test_key).unwrap();

        let session_id = SessionId([1u8; 8]);
        let plain_text = b"Hello, ExpressLane!";
        let iv = [
            9u8, 10u8, 11u8, 12u8, 13u8, 14u8, 15u8, 16u8, 17u8, 18u8, 19u8, 20u8,
        ];

        // Send and receive packet 1
        let mut buf1 = BytesMut::new();
        sender.append_to_wire(&mut buf1, session_id, plain_text, iv);
        let buf1_clone = buf1.clone();

        let mut borrowed_buf1 = crate::borrowed_bytesmut::BorrowedBytesMut::from(&mut buf1);
        let decrypted1 = receiver
            .try_from_wire(&mut borrowed_buf1, session_id)
            .unwrap();
        assert_eq!(decrypted1.as_ref(), plain_text);

        // Try to replay packet 1 - should be rejected
        let mut buf1_replay = buf1_clone.clone();
        let mut borrowed_buf_replay =
            crate::borrowed_bytesmut::BorrowedBytesMut::from(&mut buf1_replay);
        let result = receiver.try_from_wire(&mut borrowed_buf_replay, session_id);
        assert!(matches!(
            result.err().unwrap(),
            FromWireError::ReplayedExpressData
        ));

        // Send and receive packet 2
        let mut buf2 = BytesMut::new();
        sender.append_to_wire(&mut buf2, session_id, plain_text, iv);
        let mut borrowed_buf2 = crate::borrowed_bytesmut::BorrowedBytesMut::from(&mut buf2);
        let decrypted2 = receiver
            .try_from_wire(&mut borrowed_buf2, session_id)
            .unwrap();
        assert_eq!(decrypted2.as_ref(), plain_text);

        // Try to replay packet 1 again - should still be rejected
        let mut buf1_replay2 = buf1_clone.clone();
        let mut borrowed_buf_replay2 =
            crate::borrowed_bytesmut::BorrowedBytesMut::from(&mut buf1_replay2);
        let result2 = receiver.try_from_wire(&mut borrowed_buf_replay2, session_id);
        assert!(matches!(
            result2.err().unwrap(),
            FromWireError::ReplayedExpressData
        ));
    }

    #[test]
    fn replay_protection_out_of_order_packets() {
        let mut sender = ExpresslaneData::default();
        let mut receiver = ExpresslaneData::default();

        let test_key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(test_key).unwrap();
        sender.update_self_key();
        receiver.update_peer_key(test_key).unwrap();

        let session_id = SessionId([1u8; 8]);
        let plain_text = b"Test data";
        let iv = [0u8; 12];

        // Generate 5 packets
        let mut packets = Vec::new();
        for _ in 0..5 {
            let mut buf = BytesMut::new();
            sender.append_to_wire(&mut buf, session_id, plain_text, iv);
            packets.push(buf);
        }

        // Receive packets out of order: 1, 3, 5, 2, 4
        let order = [0, 2, 4, 1, 3];
        for &idx in &order {
            let mut buf = packets[idx].clone();
            let mut borrowed_buf = crate::borrowed_bytesmut::BorrowedBytesMut::from(&mut buf);
            let result = receiver.try_from_wire(&mut borrowed_buf, session_id);
            assert!(
                result.is_ok(),
                "Failed to receive packet {} in out-of-order delivery",
                idx + 1
            );
        }

        // Try to replay packet 3 - should be rejected
        let mut buf = packets[2].clone();
        let mut borrowed_buf = crate::borrowed_bytesmut::BorrowedBytesMut::from(&mut buf);
        let result = receiver.try_from_wire(&mut borrowed_buf, session_id);
        assert!(matches!(
            result.err().unwrap(),
            FromWireError::ReplayedExpressData
        ));
    }
}
