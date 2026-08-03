//! Session table and crypto. Deliberately free of I/O so it can be tested
//! exhaustively without a kernel, a TUN, or a socket.
//!
//! Everything here takes `&self`. The engine is `Sync`, so the control loop
//! and any number of packet threads share one `&Engine`: which threads read
//! which descriptor is process A's decision, and this type must not pre-empt
//! it. The session table is behind an `RwLock` taken for read per packet and
//! for write only when a key is pushed or a session dropped; every counter is
//! an atomic; each session's own hot paths are already lock-light.

use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::{BufMut, BytesMut};
use lightway_bpf_steering::{HEADER_LEN, MAGIC, is_expresslane_datagram};
use lightway_expresslane::{ExpresslaneSession, ExpresslaneVersion, WolfsslAead};

use crate::ipc::ControlMsg;

type Session = ExpresslaneSession<WolfsslAead>;

/// One session: its crypto, the versions it speaks, and its own counters.
struct Entry {
    session: Session,
    /// Emitted in the Lightway header of every datagram this session sends.
    /// The peer hard-rejects a version it did not negotiate, so this is the
    /// negotiated pair and never a constant.
    lightway_version: [u8; 2],
    sent_bytes: AtomicU64,
    received_bytes: AtomicU64,
    decrypt_failures: AtomicU64,
}

impl Entry {
    fn new(version: ExpresslaneVersion, lightway_version: [u8; 2]) -> Self {
        Self {
            session: Session::new(version),
            lightway_version,
            sent_bytes: AtomicU64::new(0),
            received_bytes: AtomicU64::new(0),
            decrypt_failures: AtomicU64::new(0),
        }
    }
}

/// The engine's session table and crypto.
pub struct Engine {
    sessions: RwLock<HashMap<[u8; 8], Entry>>,
    /// Datagrams handled for no session at all. Engine-wide because a refused
    /// datagram has no session to charge it to.
    refused: AtomicU64,
    active: AtomicBool,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// Build an engine holding no sessions.
    ///
    /// No version argument: versions are per session and arrive with the keys.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            refused: AtomicU64::new(0),
            active: AtomicBool::new(false),
        }
    }

    fn sessions_read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<[u8; 8], Entry>> {
        self.sessions.read().expect("session table poisoned")
    }

    fn sessions_write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<[u8; 8], Entry>> {
        self.sessions.write().expect("session table poisoned")
    }

    /// True when the inside path is steered here.
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Apply a control message. Returns a reply only for `StatsRequest`.
    pub fn apply(&self, msg: &ControlMsg) -> Option<ControlMsg> {
        match msg {
            ControlMsg::Attach => None,
            ControlMsg::PushKeys {
                session_id,
                version,
                lightway_version,
                self_key,
                peer_key,
            } => {
                // The callback fires whenever EITHER side's key changes, so a
                // half key can arrive; installing it would store garbage that
                // the next full push overwrites.
                if self_key.is_invalid() || peer_key.is_invalid() {
                    return None;
                }
                let version = ExpresslaneVersion::from(*version);
                let mut sessions = self.sessions_write();
                let entry = sessions
                    .entry(*session_id)
                    .or_insert_with(|| Entry::new(version, *lightway_version));
                entry.lightway_version = *lightway_version;
                if entry.session.version() != version && !entry.session.set_version(version) {
                    tracing::warn!(
                        session_id = ?session_id,
                        "version changed after traffic started, keeping the one in force"
                    );
                }
                // Re-pushing an unchanged key is normal - lightway-core
                // republishes on roam and on session-id change - and must be a
                // no-op. Reinstalling the peer key would move the current key
                // into the grace slot on top of the real previous one, so a
                // packet still in flight under that one would stop decrypting.
                if *self_key != entry.session.self_key() {
                    if entry.session.update_next_self_key(*self_key).is_ok() {
                        entry.session.promote_self_key();
                    } else {
                        tracing::warn!(session_id = ?session_id, "self-key install failed, keeping prior key");
                    }
                }
                if *peer_key != entry.session.peer_key()
                    && entry.session.update_peer_key(*peer_key).is_err()
                {
                    tracing::warn!(session_id = ?session_id, "peer-key install failed, keeping prior key");
                }
                None
            }
            ControlMsg::DropSession { session_id } => {
                self.sessions_write().remove(session_id);
                None
            }
            ControlMsg::SetActive { active } => {
                self.active.store(*active, Ordering::Relaxed);
                None
            }
            ControlMsg::StatsRequest { session_id } => {
                let refused = self.refused.load(Ordering::Relaxed);
                let sessions = self.sessions_read();
                Some(match sessions.get(session_id) {
                    // Absent is reported as absent, never as zeros: a caller
                    // differencing counters must be able to tell "no traffic"
                    // from "no such session".
                    None => ControlMsg::StatsReply {
                        session_id: *session_id,
                        sent: 0,
                        received: 0,
                        sent_bytes: 0,
                        received_bytes: 0,
                        decrypt_failures: 0,
                        refused,
                        known_session: false,
                    },
                    Some(entry) => ControlMsg::StatsReply {
                        session_id: *session_id,
                        sent: entry.session.packets_sent(),
                        received: entry.session.packets_received(),
                        sent_bytes: entry.sent_bytes.load(Ordering::Relaxed),
                        received_bytes: entry.received_bytes.load(Ordering::Relaxed),
                        decrypt_failures: entry.decrypt_failures.load(Ordering::Relaxed),
                        refused,
                        known_session: true,
                    },
                })
            }
            ControlMsg::StatsReply { .. } => None,
        }
    }

    /// Encrypt an inside packet into a complete outgoing datagram.
    ///
    /// `iv` must be unique per packet under the current key; a CSPRNG is the
    /// expected source.
    pub fn encrypt(
        &self,
        session_id: [u8; 8],
        inside_pkt: &[u8],
        iv: [u8; 12],
    ) -> Option<BytesMut> {
        let sessions = self.sessions_read();
        let entry = sessions.get(&session_id)?;
        if !entry.session.has_valid_keys() {
            return None;
        }

        let mut out =
            BytesMut::with_capacity(HEADER_LEN + Session::WIRE_OVERHEAD + inside_pkt.len());
        out.put_slice(&MAGIC);
        out.put_slice(&entry.lightway_version);
        out.put_u8(0); // aggressive_mode
        out.put_u8(1); // expresslane_data
        out.put_bytes(0, 2); // RESERVED
        out.put_slice(&session_id);

        entry
            .session
            .append_to_wire(&mut out, session_id, inside_pkt, iv, false)
            .ok()?;
        entry
            .sent_bytes
            .fetch_add(inside_pkt.len() as u64, Ordering::Relaxed);
        Some(out)
    }

    /// Decrypt an inbound datagram into its inside packet.
    ///
    /// Returns `None` and leaves `datagram` byte-for-byte unchanged when this
    /// engine cannot handle it, so the caller can hand it back to the stack.
    /// Every such datagram is counted - as `refused` when there was no session
    /// to charge it to, as that session's `decrypt_failures` when there was -
    /// so what the kernel steered here can be reconciled against what this
    /// engine did with it.
    pub fn decrypt(&self, datagram: &mut BytesMut) -> Option<BytesMut> {
        // The same classifier the outside BPF program applies, so a datagram
        // this refuses is one the kernel should not have steered here. The two
        // are held together by `header.rs`'s own test, not by the compiler.
        if datagram.len() < HEADER_LEN || !is_expresslane_datagram(datagram) {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&datagram[8..HEADER_LEN]);

        let sessions = self.sessions_read();
        let Some(entry) = sessions.get(&session_id) else {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        // Split the header off into its own handle so a failure below can be
        // undone by rejoining - try_from_wire itself never consumes on error.
        let header = datagram.split_to(HEADER_LEN);
        match entry.session.try_from_wire(datagram, session_id) {
            Ok((inside, _is_encoded)) => {
                entry
                    .received_bytes
                    .fetch_add(inside.len() as u64, Ordering::Relaxed);
                Some(inside)
            }
            Err(_) => {
                entry.decrypt_failures.fetch_add(1, Ordering::Relaxed);
                // Restore the datagram exactly as it arrived.
                let rest = std::mem::replace(datagram, header);
                datagram.unsplit(rest);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};

    const SID: [u8; 8] = [4; 8];
    const LW: [u8; 2] = [1, 3];

    fn push(engine: &Engine, key: ExpresslaneKey) {
        engine.apply(&ControlMsg::PushKeys {
            session_id: SID,
            version: 2,
            lightway_version: LW,
            self_key: key,
            peer_key: key,
        });
    }

    fn keyed_pair() -> (Engine, Engine) {
        let tx = Engine::new();
        let rx = Engine::new();
        let k = ExpresslaneKey([11; EXPRESSLANE_KEY_SIZE]);
        push(&tx, k);
        push(&rx, k);
        (tx, rx)
    }

    fn stats(engine: &Engine, session_id: [u8; 8]) -> ControlMsg {
        engine
            .apply(&ControlMsg::StatsRequest { session_id })
            .expect("StatsRequest must be answered")
    }

    #[test]
    fn a_packet_round_trips_between_two_engines() {
        let (tx, rx) = keyed_pair();
        let mut datagram = tx.encrypt(SID, b"inside packet", [1; 12]).expect("encrypt");

        // The Lightway header must mark this as ExpressLane so the kernel
        // steering picks it up on the far side.
        assert_eq!(&datagram[..2], b"He");
        assert_eq!(datagram[5], 1, "expresslane flag not set");
        assert_eq!(&datagram[8..16], &SID);

        let inside = rx.decrypt(&mut datagram).expect("decrypt");
        assert_eq!(&inside[..], b"inside packet");
    }

    /// Nothing in this crate depends on `lightway-core`, so a header-format
    /// change compiles clean here with no signal beyond a dead tunnel that
    /// looks like a network fault. Pin the hand-rolled header in `encrypt`
    /// against the real serializer, and against the exact classifier the BPF
    /// steering programs run.
    #[test]
    fn encrypted_header_matches_lightway_core_and_the_bpf_classifier() {
        let (tx, _) = keyed_pair();
        let datagram = tx.encrypt(SID, b"payload", [6; 12]).unwrap();

        assert!(is_expresslane_datagram(&datagram));

        let mut expected = BytesMut::new();
        lightway_core::Header {
            version: lightway_core::Version::MAXIMUM,
            aggressive_mode: false,
            expresslane_data: true,
            session: lightway_core::SessionId::from_const(SID),
        }
        .append_to_wire(&mut expected);
        assert_eq!(&datagram[..HEADER_LEN], &expected[..]);
    }

    /// The peer hard-rejects a header whose protocol version is not the one it
    /// negotiated, so the engine must emit what it was told, not a constant.
    #[test]
    fn the_header_carries_the_negotiated_lightway_version() {
        let engine = Engine::new();
        engine.apply(&ControlMsg::PushKeys {
            session_id: SID,
            version: 2,
            lightway_version: [1, 1],
            self_key: ExpresslaneKey([12; EXPRESSLANE_KEY_SIZE]),
            peer_key: ExpresslaneKey([12; EXPRESSLANE_KEY_SIZE]),
        });
        let datagram = engine.encrypt(SID, b"payload", [7; 12]).unwrap();
        assert_eq!(
            &datagram[2..4],
            &[1, 1],
            "the header must carry the negotiated version"
        );

        let mut expected = BytesMut::new();
        lightway_core::Header {
            version: lightway_core::Version::MINIMUM,
            aggressive_mode: false,
            expresslane_data: true,
            session: lightway_core::SessionId::from_const(SID),
        }
        .append_to_wire(&mut expected);
        assert_eq!(&datagram[..HEADER_LEN], &expected[..]);
    }

    /// The version selects the AAD length, and it is negotiated *after* the
    /// engine starts, so it has to arrive with the keys. A session built at
    /// the wrong version authenticates nothing and says nothing about why.
    #[test]
    fn the_version_arrives_with_the_keys_not_at_attach() {
        let k = ExpresslaneKey([13; EXPRESSLANE_KEY_SIZE]);
        let tx = Engine::new();
        let rx = Engine::new();
        // Attach carries no version at all; only PushKeys does.
        tx.apply(&ControlMsg::Attach);
        rx.apply(&ControlMsg::Attach);
        push(&tx, k);
        push(&rx, k);

        let mut datagram = tx.encrypt(SID, b"v2 payload", [8; 12]).unwrap();
        assert_eq!(
            &rx.decrypt(&mut datagram).expect("decrypt")[..],
            b"v2 payload",
            "the AAD length disagrees, so the version never reached the session"
        );

        // A V1 peer would build a different AAD over the same bytes.
        let v1 = Engine::new();
        v1.apply(&ControlMsg::PushKeys {
            session_id: SID,
            version: 1,
            lightway_version: LW,
            self_key: k,
            peer_key: k,
        });
        let mut datagram = tx.encrypt(SID, b"v2 payload", [10; 12]).unwrap();
        assert!(
            v1.decrypt(&mut datagram).is_none(),
            "a V1 session must not authenticate a V2 frame"
        );
    }

    /// The regression this crate must never reintroduce: lightway-core
    /// republishes *unchanged* keys on roam and on session-id change. Treating
    /// that as a rotation overwrites the grace key with a copy of the current
    /// one, and every packet still in flight under the real previous key stops
    /// decrypting - the ExpressLane degrade that was already root-caused once.
    #[test]
    fn republishing_unchanged_keys_keeps_the_rotation_grace_key() {
        let old = ExpresslaneKey([21; EXPRESSLANE_KEY_SIZE]);
        let new = ExpresslaneKey([22; EXPRESSLANE_KEY_SIZE]);

        let peer = Engine::new();
        push(&peer, old);
        let rx = Engine::new();
        push(&rx, old);

        // In flight under the old key when the rotation happens.
        let mut in_flight = peer.encrypt(SID, b"still in flight", [30; 12]).unwrap();

        // Rotate: old becomes the grace key.
        push(&rx, new);
        // Then a roam republishes the very same keys, twice for good measure.
        push(&rx, new);
        push(&rx, new);

        let inside = rx
            .decrypt(&mut in_flight)
            .expect("the rotation grace key was evicted by an unchanged re-push");
        assert_eq!(&inside[..], b"still in flight");

        // And the new key still works afterwards, from the same peer whose
        // counters and replay window carried across the rotation.
        push(&peer, new);
        let mut fresh = peer.encrypt(SID, b"after rotation", [31; 12]).unwrap();
        assert_eq!(&rx.decrypt(&mut fresh).unwrap()[..], b"after rotation");
    }

    #[test]
    fn an_unknown_session_leaves_the_datagram_untouched() {
        let (tx, _) = keyed_pair();
        let rx = Engine::new();
        let mut datagram = tx.encrypt(SID, b"payload", [2; 12]).unwrap();
        let before = datagram.clone();

        assert!(rx.decrypt(&mut datagram).is_none());
        assert_eq!(
            datagram, before,
            "a rejected datagram must be handed back byte-for-byte"
        );
    }

    /// The interesting restore path: a *known* session whose frame still gets
    /// rejected (here, a replay) drives `decrypt` through
    /// `split_to`/`try_from_wire`/`unsplit`, not the early-return checks. Only
    /// this path exercises the header-rejoin, so it is the one that must be
    /// checked against a full clone, not just the unknown-session shortcut.
    #[test]
    fn a_replayed_datagram_is_rejected_and_counted() {
        let (tx, rx) = keyed_pair();
        let datagram = tx.encrypt(SID, b"once", [3; 12]).unwrap();

        let mut first = datagram.clone();
        assert!(rx.decrypt(&mut first).is_some());
        let mut again = datagram;
        let before = again.clone();
        assert!(rx.decrypt(&mut again).is_none());
        assert_eq!(
            again, before,
            "a replayed datagram must be handed back byte-for-byte, header included"
        );

        let ControlMsg::StatsReply {
            received,
            decrypt_failures,
            refused,
            ..
        } = stats(&rx, SID)
        else {
            panic!("expected StatsReply")
        };
        assert_eq!(received, 1);
        assert_eq!(decrypt_failures, 1);
        assert_eq!(refused, 0, "a replay belongs to a session this engine has");
    }

    /// A datagram the kernel steered here and this engine would not touch has
    /// to appear somewhere, or the kernel's steering counters cannot be
    /// reconciled against the engine's and a misrouting reads as silence.
    #[test]
    fn refused_datagrams_are_counted_and_kept_apart_from_auth_failures() {
        let (tx, _) = keyed_pair();
        let rx = Engine::new();
        push(&rx, ExpresslaneKey([44; EXPRESSLANE_KEY_SIZE]));

        // Wrong session: nothing to charge it to.
        let mut foreign = tx.encrypt(SID, b"payload", [40; 12]).unwrap();
        foreign[8..16].copy_from_slice(&[0xEE; 8]);
        assert!(rx.decrypt(&mut foreign).is_none());

        // Not ExpressLane at all, and too short to classify.
        let mut plain = BytesMut::from(&[b'H', b'e', 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..]);
        assert!(rx.decrypt(&mut plain).is_none());
        let mut short = BytesMut::from(&b"He"[..]);
        assert!(rx.decrypt(&mut short).is_none());

        // The right session under the wrong key: an authentication failure.
        let mut mine = tx.encrypt(SID, b"payload", [41; 12]).unwrap();
        assert!(rx.decrypt(&mut mine).is_none());

        let ControlMsg::StatsReply {
            received,
            refused,
            decrypt_failures,
            ..
        } = stats(&rx, SID)
        else {
            panic!("expected StatsReply")
        };
        assert_eq!(received, 0);
        assert_eq!(refused, 3, "every refusal must be visible");
        assert_eq!(decrypt_failures, 1, "an auth failure is not a refusal");
    }

    /// Reporting zeros for a session the engine never had is the exact lie a
    /// per-session counter API cannot avoid; the reply says so explicitly.
    #[test]
    fn stats_answer_for_the_session_asked_about_not_for_the_table() {
        let (tx, rx) = keyed_pair();
        let mut datagram = tx.encrypt(SID, b"payload", [50; 12]).unwrap();
        rx.decrypt(&mut datagram).unwrap();

        let ControlMsg::StatsReply {
            session_id,
            known_session,
            received,
            received_bytes,
            ..
        } = stats(&rx, SID)
        else {
            panic!("expected StatsReply")
        };
        assert_eq!(session_id, SID, "the reply must name the session it is for");
        assert!(known_session);
        assert_eq!(received, 1);
        assert_eq!(received_bytes, b"payload".len() as u64);

        // A different session, on an engine that does hold one. Reporting the
        // table's emptiness rather than this session's absence is the bug.
        let other = [0x77; 8];
        let ControlMsg::StatsReply {
            session_id,
            known_session,
            ..
        } = stats(&rx, other)
        else {
            panic!("expected StatsReply")
        };
        assert_eq!(session_id, other);
        assert!(
            !known_session,
            "a session the engine does not hold must not be claimed"
        );
    }

    #[test]
    fn byte_counters_follow_the_inside_packets() {
        let (tx, rx) = keyed_pair();
        for payload in [&b"one"[..], &b"three!"[..]] {
            let mut datagram = tx.encrypt(SID, payload, [51; 12]).unwrap();
            rx.decrypt(&mut datagram).unwrap();
        }

        let ControlMsg::StatsReply {
            sent, sent_bytes, ..
        } = stats(&tx, SID)
        else {
            panic!("expected StatsReply")
        };
        assert_eq!(sent, 2);
        assert_eq!(sent_bytes, 9);

        let ControlMsg::StatsReply {
            received,
            received_bytes,
            ..
        } = stats(&rx, SID)
        else {
            panic!("expected StatsReply")
        };
        assert_eq!(received, 2);
        assert_eq!(received_bytes, 9);
    }

    #[test]
    fn dropping_a_session_forgets_its_keys() {
        let (tx, rx) = keyed_pair();
        let mut datagram = tx.encrypt(SID, b"payload", [4; 12]).unwrap();
        rx.apply(&ControlMsg::DropSession { session_id: SID });
        assert!(rx.decrypt(&mut datagram).is_none());

        let ControlMsg::StatsReply { known_session, .. } = stats(&rx, SID) else {
            panic!("expected StatsReply")
        };
        assert!(
            !known_session,
            "a dropped session must read as absent, not as zeros"
        );
    }

    #[test]
    fn the_active_flag_is_tracked() {
        let e = Engine::new();
        assert!(!e.active(), "must start inactive");
        e.apply(&ControlMsg::SetActive { active: true });
        assert!(e.active());
        e.apply(&ControlMsg::SetActive { active: false });
        assert!(!e.active());
    }

    #[test]
    fn encrypting_without_keys_yields_nothing() {
        let e = Engine::new();
        assert!(e.encrypt(SID, b"payload", [5; 12]).is_none());
    }

    /// The whole reason `apply` takes `&self`: process A gets to decide how
    /// many threads run the data plane, and it cannot decide that if the
    /// control loop holds the engine mutably for its whole lifetime.
    #[test]
    fn one_shared_engine_serves_control_and_packets_at_once() {
        let (tx, rx) = keyed_pair();
        let rx = &rx;
        let datagrams: Vec<BytesMut> = (0..64u8)
            .map(|i| tx.encrypt(SID, b"parallel", [i; 12]).unwrap())
            .collect();

        std::thread::scope(|s| {
            for chunk in datagrams.chunks(8) {
                let mut chunk: Vec<BytesMut> = chunk.to_vec();
                s.spawn(move || {
                    for d in chunk.iter_mut() {
                        assert_eq!(&rx.decrypt(d).expect("decrypt")[..], b"parallel");
                    }
                });
            }
            // Control traffic on the same shared reference, concurrently.
            s.spawn(move || {
                for _ in 0..64 {
                    assert!(matches!(
                        stats(rx, SID),
                        ControlMsg::StatsReply {
                            known_session: true,
                            ..
                        }
                    ));
                }
            });
        });

        let ControlMsg::StatsReply { received, .. } = stats(rx, SID) else {
            panic!("expected StatsReply")
        };
        assert_eq!(received, 64);
    }

    /// A datagram too short to hold a Lightway header must be rejected without
    /// panicking on the slice.
    #[test]
    fn a_truncated_datagram_is_rejected() {
        let (_, rx) = keyed_pair();
        let mut short = BytesMut::from(&b"He"[..]);
        assert!(rx.decrypt(&mut short).is_none());
    }
}
