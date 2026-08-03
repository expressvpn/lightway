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
use std::net::SocketAddr;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use bytes::{BufMut, BytesMut};
use lightway_bpf_steering::{
    EXPRESSLANE_FLAG_OFFSET, HEADER_LEN, MAGIC, SESSION_ID_OFFSET, is_expresslane_datagram,
};
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
    /// Where this session came in the order sessions were first seen. See
    /// [`Table::next_serial`].
    serial: u64,
    /// Packets and inside bytes this session really put on the wire, moved by
    /// [`Engine::count_sent`] and by nothing else.
    ///
    /// Not [`ExpresslaneSession::packets_sent`]: that is the wire counter,
    /// reserved *before* the AEAD, so a failed encrypt burns one and a failed
    /// send burns another. lightway-core degrades ExpressLane by comparing
    /// this against what the peer says it received, so counting a packet that
    /// never left is a degrade of a tunnel that is working.
    sent_packets: AtomicU64,
    sent_bytes: AtomicU64,
    received_bytes: AtomicU64,
    decrypt_failures: AtomicU64,
}

impl Entry {
    fn new(version: ExpresslaneVersion, lightway_version: [u8; 2], serial: u64) -> Self {
        Self {
            session: Session::new(version),
            lightway_version,
            serial,
            sent_packets: AtomicU64::new(0),
            sent_bytes: AtomicU64::new(0),
            received_bytes: AtomicU64::new(0),
            decrypt_failures: AtomicU64::new(0),
        }
    }
}

/// The session TX encrypts for, and where its datagrams go.
#[derive(Clone, Copy)]
struct Current {
    session_id: [u8; 8],
    peer: SocketAddr,
    /// The named session's [`Entry::serial`], so a push for an older one can be
    /// recognised as going backwards.
    serial: u64,
}

/// Everything one lock covers: the sessions and which of them TX uses.
///
/// They share a lock rather than having one each so that a packet costs a
/// single acquisition, and so that reading "which session" and reading that
/// session are one atomic step - between two locks a rotation could land, and
/// the packet would be encrypted under a session that was current a moment ago.
struct Table {
    by_id: HashMap<[u8; 8], Entry>,
    current: Option<Current>,
    /// Handed out in order as sessions are first seen, and never reused.
    ///
    /// It exists because `current` cannot be last-writer-wins: lightway-core
    /// republishes keys on roam and on session-id change, so a republish for
    /// the older of two live sessions would otherwise move `current` back onto
    /// a session that has been retired, and TX would encrypt under it.
    next_serial: u64,
}

/// Why the TX path threw an outbound packet away.
///
/// One reason per way a packet can be lost between the TUN and the wire; each
/// is reported once and then only counted, because the failures that matter
/// here are the ones that persist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxDrop {
    /// The engine has been told to stand down; the VPN process owns the inside
    /// path now.
    Inactive,
    /// No keys have arrived yet, or the session they named has been dropped.
    NoSession,
    /// The session would not encrypt it: no valid keys, or the frame would not
    /// build.
    Encrypt,
    /// The datagram could not be put on the wire.
    Send,
}

/// A datagram ready for the wire, and what to charge for it afterwards.
///
/// The session's counters do not move here. They move in
/// [`Engine::count_sent`], which the caller runs only once the socket has
/// really taken the datagram - see `Entry::sent_packets` for why a packet that
/// never left must not be counted as sent.
pub struct Outbound {
    /// The complete datagram, Lightway header included.
    pub datagram: BytesMut,
    /// Where it goes.
    pub peer: SocketAddr,
    session_id: [u8; 8],
    inside_len: usize,
}

/// The engine's session table and crypto.
pub struct Engine {
    sessions: RwLock<Table>,
    /// Datagrams handled for no session at all. Engine-wide because a refused
    /// datagram has no session to charge it to.
    refused: AtomicU64,
    /// Outbound packets dropped between the TUN and the wire, for any of the
    /// reasons in [`TxDrop`]. Engine-wide for the same reason `refused` is:
    /// most of them happen because there is no session to charge them to.
    tx_dropped: AtomicU64,
    /// One bit per [`TxDrop`] already reported, so the first of each kind gets
    /// a log line and a flood does not.
    tx_drop_reported: AtomicU8,
    /// Inside packets the engine decrypted and then could not deliver to the
    /// TUN. The RX mirror of `tx_dropped`, and engine-wide for the same
    /// reason: without it a device refusing writes is a tunnel that goes quiet
    /// with nothing to point at.
    rx_dropped: AtomicU64,
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
            sessions: RwLock::new(Table {
                by_id: HashMap::new(),
                current: None,
                next_serial: 0,
            }),
            refused: AtomicU64::new(0),
            tx_dropped: AtomicU64::new(0),
            tx_drop_reported: AtomicU8::new(0),
            rx_dropped: AtomicU64::new(0),
            active: AtomicBool::new(false),
        }
    }

    /// The session TX would encrypt for, and the address it would send to.
    ///
    /// Diagnostic only, and the packet path does not call it: choosing the
    /// session and encrypting for it have to be one locked step, which is what
    /// [`Engine::encrypt_current`] is. It stays public because the client
    /// binary's tests are a separate crate and this is how they check that a
    /// key push carried its peer address across the process boundary.
    pub fn current_session(&self) -> Option<([u8; 8], SocketAddr)> {
        self.sessions_read().current.map(|c| (c.session_id, c.peer))
    }

    fn sessions_read(&self) -> std::sync::RwLockReadGuard<'_, Table> {
        self.sessions.read().expect("session table poisoned")
    }

    fn sessions_write(&self) -> std::sync::RwLockWriteGuard<'_, Table> {
        self.sessions.write().expect("session table poisoned")
    }

    /// True when the inside path is steered here.
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Record an outbound packet the engine did not put on the wire.
    ///
    /// The first drop of each kind is logged; after that only the counter
    /// moves, which is what [`ControlMsg::StatsReply`]'s `tx_dropped` carries.
    /// Silence here is what "the tunnel went quiet with nothing to point at"
    /// is made of, so every path that discards a packet comes through here.
    pub fn count_tx_drop(&self, reason: TxDrop) {
        self.tx_dropped.fetch_add(1, Ordering::Relaxed);
        let bit = 1u8 << reason as u8;
        if self.tx_drop_reported.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
            tracing::warn!(?reason, "outbound packet dropped");
        }
    }

    /// Record an inside packet the engine decrypted but could not deliver.
    ///
    /// The RX counterpart of [`Engine::count_tx_drop`]: the kernel steered
    /// that datagram here, so nothing else was ever going to carry it.
    pub fn count_rx_drop(&self) {
        self.rx_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Charge a datagram the socket really took to the session that built it.
    ///
    /// Called after the send, never before: see `Entry::sent_packets`.
    pub fn count_sent(&self, out: &Outbound) {
        let sessions = self.sessions_read();
        // A rotation may have dropped the session between the encrypt and the
        // send. The packet still went, but there is nothing left to charge.
        let Some(entry) = sessions.by_id.get(&out.session_id) else {
            return;
        };
        entry.sent_packets.fetch_add(1, Ordering::Relaxed);
        entry
            .sent_bytes
            .fetch_add(out.inside_len as u64, Ordering::Relaxed);
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
                peer,
            } => {
                // The callback fires whenever EITHER side's key changes, so a
                // half key can arrive; installing it would store garbage that
                // the next full push overwrites.
                if self_key.is_invalid() || peer_key.is_invalid() {
                    return None;
                }
                let version = ExpresslaneVersion::from(*version);
                let mut sessions = self.sessions_write();
                let serial = sessions.next_serial;
                let entry = sessions
                    .by_id
                    .entry(*session_id)
                    .or_insert_with(|| Entry::new(version, *lightway_version, serial));
                let entry_serial = entry.serial;
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
                // A serial is consumed only by a session that was really new.
                if entry_serial == serial {
                    sessions.next_serial = serial + 1;
                }

                // Forwards or sideways only. `>=` rather than `>` because a
                // republish for the session already current is how a roam
                // delivers its new peer address, and that must land.
                match sessions.current {
                    Some(c) if entry_serial < c.serial => {
                        tracing::warn!(
                            session_id = ?session_id,
                            current = ?c.session_id,
                            "keys republished for a retired session, keeping the newer one"
                        );
                    }
                    _ => {
                        sessions.current = Some(Current {
                            session_id: *session_id,
                            peer: *peer,
                            serial: entry_serial,
                        })
                    }
                }
                None
            }
            ControlMsg::DropSession { session_id } => {
                let mut sessions = self.sessions_write();
                sessions.by_id.remove(session_id);
                // TX must never name a session the table no longer holds; both
                // live under one lock so there is no window where it could.
                if sessions
                    .current
                    .is_some_and(|c| c.session_id == *session_id)
                {
                    sessions.current = None;
                }
                None
            }
            ControlMsg::SetActive { active } => {
                self.active.store(*active, Ordering::Relaxed);
                None
            }
            ControlMsg::StatsRequest { session_id } => {
                let refused = self.refused.load(Ordering::Relaxed);
                let tx_dropped = self.tx_dropped.load(Ordering::Relaxed);
                let rx_dropped = self.rx_dropped.load(Ordering::Relaxed);
                let sessions = self.sessions_read();
                Some(match sessions.by_id.get(session_id) {
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
                        tx_dropped,
                        rx_dropped,
                        known_session: false,
                    },
                    Some(entry) => ControlMsg::StatsReply {
                        session_id: *session_id,
                        sent: entry.sent_packets.load(Ordering::Relaxed),
                        received: entry.session.packets_received(),
                        sent_bytes: entry.sent_bytes.load(Ordering::Relaxed),
                        received_bytes: entry.received_bytes.load(Ordering::Relaxed),
                        decrypt_failures: entry.decrypt_failures.load(Ordering::Relaxed),
                        refused,
                        tx_dropped,
                        rx_dropped,
                        known_session: true,
                    },
                })
            }
            ControlMsg::StatsReply { .. } => None,
        }
    }

    /// Encrypt an inside packet for whichever session is current, and say
    /// where it goes.
    ///
    /// This is what the packet path calls. Choosing the session and encrypting
    /// for it happen under one lock, so a rotation cannot land between the two
    /// and leave the packet encrypted under a session that has just been
    /// retired. Every `None` is counted; see [`Engine::count_tx_drop`].
    ///
    /// What comes back is not yet counted as sent. The caller sends it and
    /// then calls [`Engine::count_sent`], so a socket that refuses the
    /// datagram moves `tx_dropped` and nothing else.
    pub fn encrypt_current(&self, inside_pkt: &[u8], iv: [u8; 12]) -> Option<Outbound> {
        let sessions = self.sessions_read();
        let Some(current) = sessions.current else {
            self.count_tx_drop(TxDrop::NoSession);
            return None;
        };
        let datagram = self.encrypt_with(&sessions, current.session_id, inside_pkt, iv)?;
        Some(Outbound {
            datagram,
            peer: current.peer,
            session_id: current.session_id,
            inside_len: inside_pkt.len(),
        })
    }

    /// Encrypt an inside packet into a complete outgoing datagram.
    ///
    /// `iv` must be unique per packet under the current key; a CSPRNG is the
    /// expected source. A `None` is counted the same way `encrypt_current`'s
    /// is, so what went in can be reconciled against what went out however the
    /// caller reached it. Like `encrypt_current`, it counts nothing as sent.
    pub fn encrypt(
        &self,
        session_id: [u8; 8],
        inside_pkt: &[u8],
        iv: [u8; 12],
    ) -> Option<BytesMut> {
        let sessions = self.sessions_read();
        self.encrypt_with(&sessions, session_id, inside_pkt, iv)
    }

    fn encrypt_with(
        &self,
        sessions: &Table,
        session_id: [u8; 8],
        inside_pkt: &[u8],
        iv: [u8; 12],
    ) -> Option<BytesMut> {
        let Some(entry) = sessions.by_id.get(&session_id) else {
            self.count_tx_drop(TxDrop::NoSession);
            return None;
        };
        if !entry.session.has_valid_keys() {
            self.count_tx_drop(TxDrop::Encrypt);
            return None;
        }

        // Built through the constants the BPF classifier and `decrypt` read,
        // rather than byte by byte with comments for the offsets: this is a
        // copy of a header lightway-core owns, and the one thing that has to
        // stay true of it is where the ExpressLane flag sits.
        let mut header = [0u8; HEADER_LEN];
        header[..MAGIC.len()].copy_from_slice(&MAGIC);
        header[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&entry.lightway_version);
        header[EXPRESSLANE_FLAG_OFFSET] = 1;
        header[SESSION_ID_OFFSET..].copy_from_slice(&session_id);

        let mut out =
            BytesMut::with_capacity(HEADER_LEN + Session::WIRE_OVERHEAD + inside_pkt.len());
        out.put_slice(&header);

        if let Err(e) = entry
            .session
            .append_to_wire(&mut out, session_id, inside_pkt, iv, false)
        {
            // The counter says a packet was lost; only this says which of the
            // half-dozen ways it was, and a replay-window overflow needs a
            // different answer from a key that will not install.
            tracing::debug!(error = ?e, session_id = ?session_id, "encrypt failed");
            self.count_tx_drop(TxDrop::Encrypt);
            return None;
        }
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
        session_id.copy_from_slice(&datagram[SESSION_ID_OFFSET..HEADER_LEN]);

        let sessions = self.sessions_read();
        let Some(entry) = sessions.by_id.get(&session_id) else {
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
            Err(e) => {
                // The counter cannot tell a replay-window overflow from a key
                // that does not match, and those want opposite answers.
                tracing::debug!(error = ?e, session_id = ?session_id, "decrypt failed");
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
    use std::net::{IpAddr, Ipv4Addr};

    const SID: [u8; 8] = [4; 8];
    const LW: [u8; 2] = [1, 3];
    const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 443);

    fn push(engine: &Engine, key: ExpresslaneKey) {
        engine.apply(&ControlMsg::PushKeys {
            session_id: SID,
            version: 2,
            lightway_version: LW,
            self_key: key,
            peer_key: key,
            peer: PEER,
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

    fn tx_dropped(engine: &Engine, session_id: [u8; 8]) -> u64 {
        let ControlMsg::StatsReply { tx_dropped, .. } = stats(engine, session_id) else {
            panic!("expected StatsReply")
        };
        tx_dropped
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
            peer: PEER,
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
            peer: PEER,
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

    /// The hazard `Table::next_serial` exists for. lightway-core republishes
    /// keys on roam and on session-id change, so with two sessions still live a
    /// republish for the older one arrives *after* the newer one took over.
    /// Last-writer-wins would move TX back onto a session that has been retired
    /// and encrypt every outbound packet under it.
    #[test]
    fn a_republish_for_a_retired_session_does_not_move_tx_back_to_it() {
        const OLD: [u8; 8] = [1; 8];
        const NEW: [u8; 8] = [2; 8];
        let k = ExpresslaneKey([31; EXPRESSLANE_KEY_SIZE]);
        let engine = Engine::new();

        let push_to = |id: [u8; 8], peer: SocketAddr| {
            engine.apply(&ControlMsg::PushKeys {
                session_id: id,
                version: 2,
                lightway_version: LW,
                self_key: k,
                peer_key: k,
                peer,
            });
        };
        let old_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 1);
        let new_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 2);

        push_to(OLD, old_peer);
        push_to(NEW, new_peer);
        assert_eq!(engine.current_session(), Some((NEW, new_peer)));

        // The roam republish for the session that has already been superseded.
        push_to(OLD, old_peer);
        assert_eq!(
            engine.current_session(),
            Some((NEW, new_peer)),
            "TX was moved back onto a retired session"
        );

        // A republish for the session that *is* current still lands, because
        // that is how a roam delivers its new peer address.
        let roamed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)), 3);
        push_to(NEW, roamed);
        assert_eq!(engine.current_session(), Some((NEW, roamed)));

        // And a session created after it still takes over, so the guard is
        // ordering and not a latch.
        const NEWEST: [u8; 8] = [3; 8];
        push_to(NEWEST, old_peer);
        assert_eq!(engine.current_session(), Some((NEWEST, old_peer)));
    }

    /// Choosing the session and encrypting for it are one locked step, and the
    /// peer comes back with the datagram so no caller can pair one session's
    /// bytes with another's address.
    #[test]
    fn encrypt_current_uses_the_newest_session_and_its_peer() {
        let (tx, rx) = keyed_pair();
        let mut out = tx.encrypt_current(b"current", [60; 12]).expect("encrypt");
        assert_eq!(out.peer, PEER);
        assert_eq!(&rx.decrypt(&mut out.datagram).unwrap()[..], b"current");

        tx.apply(&ControlMsg::DropSession { session_id: SID });
        assert!(
            tx.encrypt_current(b"after the drop", [61; 12]).is_none(),
            "a dropped session must leave nothing current"
        );
    }

    /// The failure this whole counter exists to make visible: a data plane that
    /// silently stops carrying packets. Every way TX can lose one has to move
    /// it, or "the tunnel went quiet" has nothing behind it.
    #[test]
    fn every_outbound_packet_the_engine_loses_is_counted() {
        let engine = Engine::new();
        assert_eq!(tx_dropped(&engine, SID), 0);

        // No keys at all: nothing is current, and nothing to charge it to.
        assert!(engine.encrypt_current(b"no session", [70; 12]).is_none());
        assert_eq!(tx_dropped(&engine, SID), 1);

        // A session the engine does not hold, reached by session id.
        assert!(engine.encrypt(SID, b"unknown", [71; 12]).is_none());
        assert_eq!(tx_dropped(&engine, SID), 2);

        // And the reason the loop itself sees: told to stand down.
        engine.count_tx_drop(TxDrop::Inactive);
        assert_eq!(tx_dropped(&engine, SID), 3);

        // Counted engine-wide, so it survives having no session to report on.
        let ControlMsg::StatsReply { known_session, .. } = stats(&engine, SID) else {
            panic!("expected StatsReply")
        };
        assert!(!known_session, "the drops must not invent a session");
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
            let mut out = tx.encrypt_current(payload, [51; 12]).unwrap();
            rx.decrypt(&mut out.datagram).unwrap();
            tx.count_sent(&out);
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

    /// The overcount that biases lightway-core towards a degrade it has not
    /// earned. `sent` is weighed against what the peer says it received, so a
    /// packet the socket refused - or one the AEAD refused, which the session's
    /// own wire counter has already reserved a number for - must not be in it.
    /// A send failure belongs in `tx_dropped` and in exactly one of the two.
    #[test]
    fn a_packet_that_never_left_is_not_counted_as_sent() {
        let (tx, _) = keyed_pair();

        // Encrypted but not sent: the socket refused it, so the peer never saw
        // it and neither counter of a session's traffic may move.
        let refused = tx.encrypt_current(b"never left", [80; 12]).unwrap();
        tx.count_tx_drop(TxDrop::Send);

        let ControlMsg::StatsReply {
            sent,
            sent_bytes,
            tx_dropped,
            ..
        } = stats(&tx, SID)
        else {
            panic!("expected StatsReply")
        };
        assert_eq!(sent, 0, "a datagram the socket refused counted as sent");
        assert_eq!(sent_bytes, 0, "its bytes counted as sent too");
        assert_eq!(tx_dropped, 1, "and it has to be counted somewhere");

        // The same datagram, once it really goes, is counted exactly once.
        tx.count_sent(&refused);
        let ControlMsg::StatsReply {
            sent,
            sent_bytes,
            tx_dropped,
            ..
        } = stats(&tx, SID)
        else {
            panic!("expected StatsReply")
        };
        assert_eq!(sent, 1);
        assert_eq!(sent_bytes, b"never left".len() as u64);
        assert_eq!(tx_dropped, 1, "the earlier drop was counted twice");
    }

    /// A frame the session refuses burns a wire counter inside
    /// `lightway-expresslane`, which is why `sent` cannot be read from there.
    #[test]
    fn an_encrypt_that_fails_moves_no_sent_counter() {
        let engine = Engine::new();
        push(&engine, ExpresslaneKey([55; EXPRESSLANE_KEY_SIZE]));
        // Longer than the 16-bit wire length field, so `append_to_wire` fails
        // after the counter is reserved.
        let huge = vec![0u8; u16::MAX as usize + 1];
        assert!(engine.encrypt_current(&huge, [81; 12]).is_none());

        let ControlMsg::StatsReply {
            sent,
            sent_bytes,
            tx_dropped,
            ..
        } = stats(&engine, SID)
        else {
            panic!("expected StatsReply")
        };
        assert_eq!(sent, 0, "a packet that never framed counted as sent");
        assert_eq!(sent_bytes, 0);
        assert_eq!(tx_dropped, 1);
    }

    /// The RX mirror of `tx_dropped`. A TUN that will not take a decrypted
    /// packet is data loss on a path nothing else can carry, and without a
    /// counter it is indistinguishable from a peer that stopped sending.
    #[test]
    fn an_inside_packet_the_device_refuses_is_counted() {
        let (_, rx) = keyed_pair();
        let ControlMsg::StatsReply { rx_dropped, .. } = stats(&rx, SID) else {
            panic!("expected StatsReply")
        };
        assert_eq!(rx_dropped, 0);

        rx.count_rx_drop();
        let ControlMsg::StatsReply { rx_dropped, .. } = stats(&rx, SID) else {
            panic!("expected StatsReply")
        };
        assert_eq!(rx_dropped, 1);
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
