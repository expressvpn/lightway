//! ExpressLane packet session: framing, AAD, key rotation, replay window.
//!
//! Every hot-path method takes `&self`, so a session can be driven from many
//! threads at once. That is the point of the crate: an offload engine runs the
//! data plane outside any connection-wide lock. The synchronisation is
//! deliberately fine-grained:
//!
//! - the wire counter is an atomic, the only TX serialisation point
//! - keys sit behind an `RwLock`, taken for read per packet and for write only
//!   on rotation, which is rare
//! - the replay window has its own mutex, taken twice on receive: `would_reject`
//!   before the AEAD, so an obvious replay costs no crypto, and `commit` after
//!   it. Splitting preview from commit is what keeps a forged counter from
//!   advancing the window and locking out real traffic - only a packet the
//!   AEAD has authenticated is ever recorded
//! - `has_valid_keys` is two atomic loads and must never take a lock, since
//!   the TX path calls it per packet

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use bitfield_struct::bitfield;
use bytes::{Buf, BufMut, BytesMut};

use crate::aead::ExpresslaneAead;
use crate::replay_window::ReplayWindow;
use crate::{ExpresslaneError, ExpresslaneKey, ExpresslaneResult, ExpresslaneVersion};

/// Flags field layout: |E|reserved|
#[bitfield(u16, order = Msb)]
struct Flags {
    encoded: bool,
    #[bits(15)]
    reserved: u16,
}

/// Build the AEAD associated data.
///
/// V1 binds 16 bytes; V2 additionally binds the flags. The length difference
/// is invisible on the wire and depends on a negotiated value, so getting it
/// wrong fails every packet with no diagnostic. Returns the buffer and its
/// significant length.
fn build_aad(
    version: ExpresslaneVersion,
    session_id: &[u8; 8],
    wire_counter: u64,
    flags: Flags,
) -> ([u8; 18], usize) {
    let mut buf = [0u8; 18];
    buf[..8].copy_from_slice(session_id);
    buf[8..16].copy_from_slice(&wire_counter.to_be_bytes());
    if version >= ExpresslaneVersion::Version2 {
        buf[16..].copy_from_slice(&u16::from(flags).to_be_bytes());
        (buf, 18)
    } else {
        (buf, 16)
    }
}

struct Keyed<A> {
    key: ExpresslaneKey,
    aead: A,
}

/// The four key slots: current and staged for TX, current and grace for RX.
struct Keys<A> {
    current_self: Option<Keyed<A>>,
    next_self: Option<Keyed<A>>,
    current_peer: Option<Keyed<A>>,
    prev_peer: Option<Keyed<A>>,
}

/// An ExpressLane packet session.
///
/// Frame layout, after the Lightway header and before the inside packet:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Counter (8 bytes)                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       IV (12 bytes)                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    AuthTag (16 bytes)                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        data length            |E|       RESERVED              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | ... length bytes of ciphertext
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct ExpresslaneSession<A: ExpresslaneAead> {
    version: AtomicU8,
    wire_counter: AtomicU64,
    packets_received: AtomicU64,
    replay: Mutex<ReplayWindow>,
    keys: RwLock<Keys<A>>,
    has_self: AtomicBool,
    has_peer: AtomicBool,
}

impl<A: ExpresslaneAead> ExpresslaneSession<A> {
    /// Bytes of framing added to every packet, excluding the Lightway header.
    pub const WIRE_OVERHEAD: usize = 40;

    /// How far behind the highest counter it has accepted a peer still admits
    /// a packet. A sender that reorders or batches beyond this span has its
    /// laggards dropped as replays, so it bounds TX batch depth.
    pub const REPLAY_WINDOW_SIZE: u64 = ReplayWindow::WINDOW_SIZE;

    /// Largest plaintext the 16-bit wire length field can describe.
    pub const MAX_PLAINTEXT: usize = u16::MAX as usize;

    /// Build an empty session. Keys are installed separately.
    pub fn new(version: ExpresslaneVersion) -> Self {
        Self {
            version: AtomicU8::new(version.into()),
            wire_counter: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            replay: Mutex::new(ReplayWindow::default()),
            keys: RwLock::new(Keys {
                current_self: None,
                next_self: None,
                current_peer: None,
                prev_peer: None,
            }),
            has_self: AtomicBool::new(false),
            has_peer: AtomicBool::new(false),
        }
    }

    /// The wire version currently in force.
    pub fn version(&self) -> ExpresslaneVersion {
        ExpresslaneVersion::from(self.version.load(Ordering::Relaxed))
    }

    /// Adopt a negotiated wire version.
    ///
    /// The version arrives from the peer after the session exists, and by then
    /// a key may already be staged. Rebuilding the session instead would drop
    /// that staged key along with the counters and the replay window, so the
    /// version is stored rather than fixed at construction.
    ///
    /// Only honoured before the first data packet: the version selects the AAD
    /// layout, so adopting a new one mid-stream would fail every packet already
    /// in flight. Once [`Self::packets_sent`] is non-zero the call is refused
    /// and the version left alone. Returns whether it was adopted.
    #[must_use]
    pub fn set_version(&self, version: ExpresslaneVersion) -> bool {
        if self.packets_sent() > 0 {
            return false;
        }
        self.version.store(version.into(), Ordering::Relaxed);
        true
    }

    fn keys_read(&self) -> std::sync::RwLockReadGuard<'_, Keys<A>> {
        self.keys.read().expect("expresslane keys poisoned")
    }

    fn keys_write(&self) -> std::sync::RwLockWriteGuard<'_, Keys<A>> {
        self.keys.write().expect("expresslane keys poisoned")
    }

    /// Stage the next TX key. Not used until [`Self::promote_self_key`], which
    /// the caller invokes once the peer has acknowledged it.
    pub fn update_next_self_key(&self, key: ExpresslaneKey) -> ExpresslaneResult<()> {
        let keyed = Keyed {
            key,
            aead: A::new(&key)?,
        };
        self.keys_write().next_self = Some(keyed);
        Ok(())
    }

    /// Promote the staged TX key.
    pub fn promote_self_key(&self) {
        let mut keys = self.keys_write();
        if let Some(next) = keys.next_self.take() {
            keys.current_self = Some(next);
            self.has_self.store(true, Ordering::Relaxed);
        }
    }

    /// Install a new RX key, retaining the previous one as a rotation grace so
    /// packets already in flight under the old key still decrypt.
    pub fn update_peer_key(&self, key: ExpresslaneKey) -> ExpresslaneResult<()> {
        let keyed = Keyed {
            key,
            aead: A::new(&key)?,
        };
        let mut keys = self.keys_write();
        keys.prev_peer = keys.current_peer.replace(keyed);
        self.has_peer.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// The current TX key, or the all-zero sentinel when unset.
    pub fn self_key(&self) -> ExpresslaneKey {
        self.keys_read()
            .current_self
            .as_ref()
            .map(|k| k.key)
            .unwrap_or(ExpresslaneKey::INVALID)
    }

    /// The current RX key, or the all-zero sentinel when unset.
    pub fn peer_key(&self) -> ExpresslaneKey {
        self.keys_read()
            .current_peer
            .as_ref()
            .map(|k| k.key)
            .unwrap_or(ExpresslaneKey::INVALID)
    }

    /// True when both directions have a key installed.
    ///
    /// Deliberately lock-free: the TX path calls this per packet, and taking
    /// the key lock here would make every outbound packet contend with the
    /// inbound worker.
    pub fn has_valid_keys(&self) -> bool {
        self.has_self.load(Ordering::Relaxed) && self.has_peer.load(Ordering::Relaxed)
    }

    /// Counters reserved for transmission.
    pub fn packets_sent(&self) -> u64 {
        self.wire_counter.load(Ordering::Relaxed)
    }

    /// Packets that authenticated and passed the replay window.
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Claim the next wire counter.
    ///
    /// Private: [`Self::append_to_wire`] is the only TX entry point and
    /// reserves its own counter, so a caller pairing this with an encrypt
    /// would burn two counters per packet.
    ///
    /// Under parallel TX, counters may reach the wire out of order, and a
    /// failed encrypt leaves a gap. Both are fine: the peer's replay window
    /// accepts out-of-order arrivals and gaps within its span.
    fn reserve_counter(&self) -> u64 {
        self.wire_counter
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    /// Encrypt `plaintext` and append a complete ExpressLane frame to `buf`.
    ///
    /// `iv` MUST be unique per packet under the current key; a CSPRNG is the
    /// expected source. The frame is appended only on success, so a failure
    /// leaves `buf` untouched.
    ///
    /// `plaintext` may be at most [`Self::MAX_PLAINTEXT`]; the wire length
    /// field is 16 bits and anything longer would frame as garbage.
    pub fn append_to_wire(
        &self,
        buf: &mut BytesMut,
        session_id: [u8; 8],
        plaintext: &[u8],
        iv: [u8; 12],
        is_encoded: bool,
    ) -> ExpresslaneResult<()> {
        if plaintext.len() > Self::MAX_PLAINTEXT {
            return Err(ExpresslaneError::PayloadTooLarge);
        }

        let flags = Flags::new().with_encoded(is_encoded);
        let counter = self.reserve_counter();
        let (aad_buf, aad_len) = build_aad(self.version(), &session_id, counter, flags);

        let (cipher_text, auth_tag) = {
            let keys = self.keys_read();
            let current = keys.current_self.as_ref().ok_or(ExpresslaneError::NoKey)?;
            current.aead.seal(iv, plaintext, &aad_buf[..aad_len])?
        };

        buf.reserve(Self::WIRE_OVERHEAD + cipher_text.len());
        buf.put_u64(counter);
        buf.put(iv.as_ref());
        buf.put(auth_tag.as_ref());
        buf.put_u16(cipher_text.len() as u16);
        buf.put_u16(flags.into());
        buf.put(&cipher_text[..]);
        Ok(())
    }

    /// Authenticate and decrypt one ExpressLane frame from `buf`.
    ///
    /// Returns the inside packet and whether it was inside-codec encoded.
    ///
    /// `buf` is advanced past the frame only on success, mirroring
    /// [`Self::append_to_wire`]: every error path leaves it byte-for-byte as
    /// it arrived. An offload engine can therefore hand a packet this session
    /// rejects - a foreign session id, a key it does not hold - straight back
    /// to the stack.
    pub fn try_from_wire(
        &self,
        buf: &mut BytesMut,
        session_id: [u8; 8],
    ) -> ExpresslaneResult<(BytesMut, bool)> {
        if buf.len() < Self::WIRE_OVERHEAD {
            return Err(ExpresslaneError::InsufficientData);
        }

        // A cursor over a borrowed slice: reading the header advances this
        // view, never `buf` itself.
        let mut header = &buf[..Self::WIRE_OVERHEAD];
        let wire_counter = header.get_u64();
        let mut iv = [0u8; 12];
        header.copy_to_slice(&mut iv);
        let mut auth_tag = [0u8; 16];
        header.copy_to_slice(&mut auth_tag);
        let data_len = header.get_u16() as usize;
        let flags = Flags::from(header.get_u16());
        let is_encoded = flags.encoded();

        let frame_len = Self::WIRE_OVERHEAD + data_len;
        if buf.len() < frame_len {
            return Err(ExpresslaneError::InsufficientData);
        }

        // Preview only. Committing before the AEAD has authenticated would let
        // a forged counter advance the window and lock out real traffic.
        if self
            .replay
            .lock()
            .expect("replay window poisoned")
            .would_reject(wire_counter)
        {
            return Err(ExpresslaneError::Replayed);
        }

        let (aad_buf, aad_len) = build_aad(self.version(), &session_id, wire_counter, flags);
        let aad = &aad_buf[..aad_len];
        // Borrowed, not split off: the prev_peer retry sees the original bytes
        // and a shared reference is one a backend cannot scribble on.
        let cipher_text = &buf[Self::WIRE_OVERHEAD..frame_len];

        let plain_text = {
            let keys = self.keys_read();
            let current = keys.current_peer.as_ref().ok_or(ExpresslaneError::NoKey)?;
            match current.aead.open(iv, cipher_text, aad, &auth_tag) {
                Ok(p) => p,
                Err(e) => match keys.prev_peer.as_ref() {
                    Some(prev) => prev.aead.open(iv, cipher_text, aad, &auth_tag)?,
                    None => return Err(e),
                },
            }
        };

        if !self
            .replay
            .lock()
            .expect("replay window poisoned")
            .commit(wire_counter)
        {
            return Err(ExpresslaneError::Replayed);
        }
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        buf.advance(frame_len);

        Ok((plain_text, is_encoded))
    }
}

#[cfg(all(test, feature = "wolfssl-backend"))]
mod tests {
    use super::*;
    use crate::{EXPRESSLANE_KEY_SIZE, WolfsslAead};

    const SID: [u8; 8] = [9; 8];

    fn keyed(v: ExpresslaneVersion) -> ExpresslaneSession<WolfsslAead> {
        let s = ExpresslaneSession::new(v);
        s.update_next_self_key(ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]))
            .unwrap();
        s.promote_self_key();
        s.update_peer_key(ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]))
            .unwrap();
        s
    }

    #[test]
    fn round_trip_v2() {
        let s = keyed(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::new();
        s.append_to_wire(&mut buf, SID, b"payload", [3u8; 12], true)
            .unwrap();
        assert_eq!(
            buf.len(),
            ExpresslaneSession::<WolfsslAead>::WIRE_OVERHEAD + 7
        );

        let (pt, encoded) = s.try_from_wire(&mut buf, SID).unwrap();
        assert_eq!(&pt[..], b"payload");
        assert!(encoded);
        assert_eq!(s.packets_sent(), 1);
        assert_eq!(s.packets_received(), 1);
    }

    #[test]
    fn append_without_self_key_errors_rather_than_silently_dropping() {
        let s: ExpresslaneSession<WolfsslAead> =
            ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::new();
        let err = s.append_to_wire(&mut buf, SID, b"x", [0u8; 12], false);
        assert!(matches!(err, Err(ExpresslaneError::NoKey)));
        assert!(buf.is_empty(), "nothing should be written on failure");
    }

    #[test]
    fn has_valid_keys_needs_both_directions() {
        let s: ExpresslaneSession<WolfsslAead> =
            ExpresslaneSession::new(ExpresslaneVersion::Version2);
        assert!(!s.has_valid_keys());
        s.update_next_self_key(ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]))
            .unwrap();
        assert!(!s.has_valid_keys(), "staged but not promoted");
        s.promote_self_key();
        assert!(!s.has_valid_keys(), "still no peer key");
        s.update_peer_key(ExpresslaneKey([2u8; EXPRESSLANE_KEY_SIZE]))
            .unwrap();
        assert!(s.has_valid_keys());
    }

    #[test]
    fn decrypt_falls_back_to_prev_peer_key_during_rotation() {
        let tx = keyed(ExpresslaneVersion::Version2);
        let rx = keyed(ExpresslaneVersion::Version2);

        let mut buf = BytesMut::new();
        tx.append_to_wire(&mut buf, SID, b"old-key", [4u8; 12], false)
            .unwrap();

        // Receiver rotates: the key that encrypted this packet becomes prev.
        rx.update_peer_key(ExpresslaneKey([2u8; EXPRESSLANE_KEY_SIZE]))
            .unwrap();

        let (pt, _) = rx
            .try_from_wire(&mut buf, SID)
            .expect("must fall back to prev_peer");
        assert_eq!(&pt[..], b"old-key");
    }

    #[test]
    fn tampered_flags_rejected() {
        let s = keyed(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::new();
        s.append_to_wire(&mut buf, SID, b"payload", [5u8; 12], false)
            .unwrap();
        // flags occupy the two bytes at offset 38
        buf[38] ^= 0x80;
        assert!(matches!(
            s.try_from_wire(&mut buf, SID),
            Err(ExpresslaneError::AuthFailed)
        ));
    }

    #[test]
    fn forged_counter_does_not_poison_the_window() {
        let tx = keyed(ExpresslaneVersion::Version2);
        let rx = keyed(ExpresslaneVersion::Version2);

        let mut forged = BytesMut::new();
        tx.append_to_wire(&mut forged, SID, b"nope", [6u8; 12], false)
            .unwrap();
        forged[0..8].copy_from_slice(&9_000_000u64.to_be_bytes());
        assert!(rx.try_from_wire(&mut forged, SID).is_err());

        // The genuine next packet still arrives.
        let mut good = BytesMut::new();
        tx.append_to_wire(&mut good, SID, b"yes", [7u8; 12], false)
            .unwrap();
        let (pt, _) = rx.try_from_wire(&mut good, SID).unwrap();
        assert_eq!(&pt[..], b"yes");
    }

    #[test]
    fn replayed_packet_rejected() {
        let tx = keyed(ExpresslaneVersion::Version2);
        let rx = keyed(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::new();
        tx.append_to_wire(&mut buf, SID, b"once", [8u8; 12], false)
            .unwrap();
        let copy = buf.clone();
        assert!(rx.try_from_wire(&mut buf, SID).is_ok());
        let mut again = copy;
        assert!(matches!(
            rx.try_from_wire(&mut again, SID),
            Err(ExpresslaneError::Replayed)
        ));
    }

    #[test]
    fn keys_read_back_after_install() {
        let s: ExpresslaneSession<WolfsslAead> =
            ExpresslaneSession::new(ExpresslaneVersion::Version2);
        assert!(s.self_key().is_invalid());
        assert!(s.peer_key().is_invalid());

        let tx = ExpresslaneKey([3u8; EXPRESSLANE_KEY_SIZE]);
        let rx = ExpresslaneKey([4u8; EXPRESSLANE_KEY_SIZE]);
        s.update_next_self_key(tx).unwrap();
        assert!(s.self_key().is_invalid(), "staged, not current");
        s.promote_self_key();
        s.update_peer_key(rx).unwrap();
        assert_eq!(s.self_key(), tx);
        assert_eq!(s.peer_key(), rx);
    }

    #[test]
    fn short_frame_rejected() {
        let s = keyed(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::from(&[0u8; 39][..]);
        assert!(matches!(
            s.try_from_wire(&mut buf, SID),
            Err(ExpresslaneError::InsufficientData)
        ));
    }

    /// A truncated payload: the header claims more ciphertext than arrived.
    #[test]
    fn truncated_payload_rejected() {
        let s = keyed(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::new();
        s.append_to_wire(&mut buf, SID, b"payload", [2u8; 12], false)
            .unwrap();
        buf.truncate(buf.len() - 3);
        assert!(matches!(
            s.try_from_wire(&mut buf, SID),
            Err(ExpresslaneError::InsufficientData)
        ));
    }

    #[test]
    fn decrypt_without_peer_key_reports_no_key() {
        let tx = keyed(ExpresslaneVersion::Version2);
        let rx: ExpresslaneSession<WolfsslAead> =
            ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::new();
        tx.append_to_wire(&mut buf, SID, b"payload", [2u8; 12], false)
            .unwrap();
        assert!(matches!(
            rx.try_from_wire(&mut buf, SID),
            Err(ExpresslaneError::NoKey)
        ));
    }

    /// V1 sender against a V2 receiver must fail: the AAD layouts differ, so
    /// authentication cannot match. Negotiation is what prevents this pairing.
    #[test]
    fn cross_version_decrypt_fails() {
        let tx = keyed(ExpresslaneVersion::Version1);
        let rx = keyed(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::new();
        tx.append_to_wire(&mut buf, SID, b"payload", [2u8; 12], false)
            .unwrap();
        assert!(matches!(
            rx.try_from_wire(&mut buf, SID),
            Err(ExpresslaneError::AuthFailed)
        ));
    }

    /// The version is negotiated after the session exists, and the client has
    /// a key staged by then. Adopting it must not disturb any other state.
    #[test]
    fn set_version_keeps_staged_key_and_counters() {
        let s: ExpresslaneSession<WolfsslAead> =
            ExpresslaneSession::new(ExpresslaneVersion::Unknown);
        let staged = ExpresslaneKey([5u8; EXPRESSLANE_KEY_SIZE]);
        s.update_next_self_key(staged).unwrap();
        s.update_peer_key(staged).unwrap();

        assert!(s.set_version(ExpresslaneVersion::Version2));
        assert_eq!(s.version(), ExpresslaneVersion::Version2);

        s.promote_self_key();
        assert_eq!(s.self_key(), staged, "staged key survived the version bump");
        assert!(s.has_valid_keys());

        let mut buf = BytesMut::new();
        s.append_to_wire(&mut buf, SID, b"after", [6u8; 12], false)
            .unwrap();
        let (pt, _) = s.try_from_wire(&mut buf, SID).unwrap();
        assert_eq!(&pt[..], b"after");
    }

    /// UDP reorders, so a run of frames must decrypt in any order and each
    /// still be rejected on a second showing.
    #[test]
    fn frames_decrypt_out_of_order_then_replay_is_rejected() {
        let tx = keyed(ExpresslaneVersion::Version2);
        let rx = keyed(ExpresslaneVersion::Version2);

        let frames: Vec<BytesMut> = (0..5u8)
            .map(|i| {
                let mut buf = BytesMut::new();
                tx.append_to_wire(&mut buf, SID, b"ordered", [i; 12], false)
                    .unwrap();
                assert_eq!(
                    u64::from_be_bytes(buf[0..8].try_into().unwrap()),
                    i as u64 + 1,
                    "counters increment by one per frame"
                );
                buf
            })
            .collect();

        for idx in [0, 2, 4, 1, 3] {
            let mut buf = frames[idx].clone();
            rx.try_from_wire(&mut buf, SID)
                .unwrap_or_else(|e| panic!("frame {idx} rejected out of order: {e:?}"));
        }
        assert_eq!(rx.packets_received(), 5);

        let mut replayed = frames[2].clone();
        assert!(matches!(
            rx.try_from_wire(&mut replayed, SID),
            Err(ExpresslaneError::Replayed)
        ));
    }

    #[test]
    fn wrong_session_id_rejected() {
        let tx = keyed(ExpresslaneVersion::Version2);
        let rx = keyed(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::new();
        tx.append_to_wire(&mut buf, SID, b"payload", [9u8; 12], false)
            .unwrap();
        assert!(rx.try_from_wire(&mut buf, [0xFF; 8]).is_err());
    }

    /// The AAD layout is chosen by the version, so a change once packets are
    /// on the wire would break every one of them. The guard is the API, not
    /// just the doc comment.
    #[test]
    fn set_version_refused_once_packets_are_sent() {
        let s = keyed(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::new();
        s.append_to_wire(&mut buf, SID, b"first", [1u8; 12], false)
            .unwrap();

        assert!(!s.set_version(ExpresslaneVersion::Version1));
        assert_eq!(
            s.version(),
            ExpresslaneVersion::Version2,
            "version unchanged"
        );
        // The frame already sent still decrypts, which is the point.
        assert!(s.try_from_wire(&mut buf, SID).is_ok());
    }

    /// The wire length field is 16 bits: a longer plaintext would truncate it
    /// and frame as garbage, so it must be refused rather than sealed.
    #[test]
    fn oversized_payload_rejected_before_encrypting() {
        let s = keyed(ExpresslaneVersion::Version2);
        let plaintext = vec![0u8; ExpresslaneSession::<WolfsslAead>::MAX_PLAINTEXT + 1];
        let mut buf = BytesMut::new();
        assert!(matches!(
            s.append_to_wire(&mut buf, SID, &plaintext, [1u8; 12], false),
            Err(ExpresslaneError::PayloadTooLarge)
        ));
        assert!(buf.is_empty(), "nothing written");
        assert_eq!(s.packets_sent(), 0, "no counter burned on a doomed packet");

        // The largest payload that does fit still round-trips.
        let plaintext = vec![7u8; ExpresslaneSession::<WolfsslAead>::MAX_PLAINTEXT];
        s.append_to_wire(&mut buf, SID, &plaintext, [2u8; 12], false)
            .unwrap();
        let (pt, _) = s.try_from_wire(&mut buf, SID).unwrap();
        assert_eq!(pt.len(), ExpresslaneSession::<WolfsslAead>::MAX_PLAINTEXT);
    }

    /// An offload engine that cannot decrypt a packet has to hand the original
    /// bytes back to the stack, so no error path may consume any of them.
    #[test]
    fn every_decrypt_failure_leaves_the_buffer_untouched() {
        let tx = keyed(ExpresslaneVersion::Version2);
        let mut frame = BytesMut::new();
        tx.append_to_wire(&mut frame, SID, b"passthrough", [3u8; 12], false)
            .unwrap();

        let no_key: ExpresslaneSession<WolfsslAead> =
            ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let wrong_key = keyed(ExpresslaneVersion::Version2);
        wrong_key
            .update_peer_key(ExpresslaneKey([0xEE; EXPRESSLANE_KEY_SIZE]))
            .unwrap();
        wrong_key
            .update_peer_key(ExpresslaneKey([0xEF; EXPRESSLANE_KEY_SIZE]))
            .unwrap();

        // NoKey, AuthFailed, InsufficientData (short header), InsufficientData
        // (truncated payload), and Replayed.
        let mut truncated = frame.clone();
        truncated.truncate(frame.len() - 1);
        let short = BytesMut::from(&frame[..ExpresslaneSession::<WolfsslAead>::WIRE_OVERHEAD - 1]);
        let replay_rx = keyed(ExpresslaneVersion::Version2);
        replay_rx.try_from_wire(&mut frame.clone(), SID).unwrap();

        for (name, rx, mut buf) in [
            ("no key", &no_key, frame.clone()),
            ("wrong key", &wrong_key, frame.clone()),
            ("short header", &no_key, short),
            ("truncated payload", &no_key, truncated),
            ("replayed", &replay_rx, frame.clone()),
        ] {
            let before = buf.clone();
            assert!(rx.try_from_wire(&mut buf, SID).is_err(), "{name}");
            assert_eq!(buf, before, "{name}: buffer was consumed");
        }
    }

    /// Trailing bytes belong to the caller: a frame followed by more data must
    /// consume exactly its own length.
    #[test]
    fn success_consumes_exactly_one_frame() {
        let tx = keyed(ExpresslaneVersion::Version2);
        let rx = keyed(ExpresslaneVersion::Version2);
        let mut buf = BytesMut::new();
        tx.append_to_wire(&mut buf, SID, b"one", [4u8; 12], false)
            .unwrap();
        buf.extend_from_slice(b"trailing");

        let (pt, _) = rx.try_from_wire(&mut buf, SID).unwrap();
        assert_eq!(&pt[..], b"one");
        assert_eq!(&buf[..], b"trailing");
    }

    #[test]
    fn v1_and_v2_aad_differ() {
        let v1 = keyed(ExpresslaneVersion::Version1);
        let v2 = keyed(ExpresslaneVersion::Version2);
        let mut a = BytesMut::new();
        let mut b = BytesMut::new();
        v1.append_to_wire(&mut a, SID, b"same", [8u8; 12], false)
            .unwrap();
        v2.append_to_wire(&mut b, SID, b"same", [8u8; 12], false)
            .unwrap();
        assert_ne!(a, b, "flags are bound into the AAD only on V2");
    }

    /// The reason every hot-path method takes `&self`: many threads encrypt on
    /// one session, every counter is unique, and a single-threaded receiver
    /// accepts all of them with no replay rejection.
    #[test]
    fn parallel_encrypt_yields_unique_counters_and_all_decrypt() {
        use std::sync::Arc;

        const THREADS: usize = 8;
        const PER_THREAD: usize = 200;

        let tx = Arc::new(keyed(ExpresslaneVersion::Version2));
        let mut frames = Vec::new();

        std::thread::scope(|s| {
            let handles: Vec<_> = (0..THREADS)
                .map(|t| {
                    let tx = tx.clone();
                    s.spawn(move || {
                        let mut out = Vec::with_capacity(PER_THREAD);
                        for i in 0..PER_THREAD {
                            let mut buf = BytesMut::new();
                            let iv = [(t * PER_THREAD + i) as u8; 12];
                            tx.append_to_wire(&mut buf, SID, b"parallel", iv, false)
                                .unwrap();
                            out.push(buf);
                        }
                        out
                    })
                })
                .collect();
            for h in handles {
                frames.extend(h.join().unwrap());
            }
        });

        assert_eq!(frames.len(), THREADS * PER_THREAD);
        assert_eq!(tx.packets_sent() as usize, THREADS * PER_THREAD);

        let mut counters: Vec<u64> = frames
            .iter()
            .map(|f| u64::from_be_bytes(f[0..8].try_into().unwrap()))
            .collect();
        counters.sort_unstable();
        counters.dedup();
        assert_eq!(
            counters.len(),
            THREADS * PER_THREAD,
            "every counter must be unique"
        );

        let rx = keyed(ExpresslaneVersion::Version2);
        for mut frame in frames {
            let (pt, _) = rx
                .try_from_wire(&mut frame, SID)
                .expect("every parallel frame must decrypt");
            assert_eq!(&pt[..], b"parallel");
        }
    }
}
