//! Control messages between the VPN process and the offload engine.
//!
//! Deliberately carries no packet-bearing variant: offloaded traffic goes
//! kernel-side through the BPF splits and must never cross this channel. If a
//! future change adds a variant with a payload, that is a design regression,
//! not a feature.
//!
//! # Where versions ride
//!
//! Neither version is known when the engine starts. `Attach` happens at
//! descriptor hand-over, which is before the handshake has negotiated
//! anything, so both the ExpressLane wire version and the Lightway protocol
//! version travel with [`ControlMsg::PushKeys`] - the message that already
//! fires once per session as soon as they are known, and again on every
//! rotation. A version carried on `Attach` would be structurally always
//! "not negotiated yet".

use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};

const TAG_ATTACH: u8 = 1;
const TAG_PUSH_KEYS: u8 = 2;
const TAG_DROP_SESSION: u8 = 3;
const TAG_SET_ACTIVE: u8 = 4;
const TAG_STATS_REQUEST: u8 = 5;
const TAG_STATS_REPLY: u8 = 6;

/// Bytes of length prefix in front of every message.
const LEN_PREFIX: usize = 4;

/// The longest message this protocol can encode, prefix included.
///
/// A stream reader accumulates until a message is complete, so without an
/// upper bound a peer that declared a huge length could make it buffer without
/// limit. [`ControlMsg::decode`] refuses any declared length above this as soon
/// as the prefix arrives, which keeps that buffer bounded by this constant.
pub const MAX_CONTROL_MSG_LEN: usize = ControlMsg::PushKeys {
    session_id: [0; 8],
    version: 0,
    lightway_version: [0; 2],
    self_key: ExpresslaneKey([0; EXPRESSLANE_KEY_SIZE]),
    peer_key: ExpresslaneKey([0; EXPRESSLANE_KEY_SIZE]),
}
.encoded_len();

/// Why a buffer could not be decoded.
#[derive(Debug, PartialEq, Eq)]
pub enum IpcError {
    /// The buffer holds only part of a message; read more and retry.
    Incomplete,
    /// The message tag is not one this build knows.
    BadTag(u8),
    /// The declared length does not match the variant's fixed size.
    BadLength,
}

/// A control message. No variant carries packet data, by design.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlMsg {
    /// Sent once by the VPN process together with the descriptors.
    ///
    /// Carries no fields on purpose: nothing is negotiated yet at hand-over
    /// time. See the module note on where versions ride.
    Attach,
    /// Install or replace both keys for a session, and the versions it speaks.
    ///
    /// Re-sending unchanged keys is expected - lightway-core republishes on
    /// roam and on session-id change - and the engine treats an unchanged key
    /// as a no-op so the rotation grace window survives.
    PushKeys {
        /// The session these keys belong to.
        session_id: [u8; 8],
        /// Negotiated ExpressLane wire version, as its byte encoding. It
        /// selects the AAD length, so a wrong value fails every packet with no
        /// diagnostic.
        version: u8,
        /// Negotiated Lightway protocol version, `[major, minor]`, as the peer
        /// expects to see it in the header of every datagram of this session.
        lightway_version: [u8; 2],
        /// Key this engine encrypts with.
        self_key: ExpresslaneKey,
        /// Key this engine decrypts with.
        peer_key: ExpresslaneKey,
    },
    /// Forget a session entirely.
    ///
    /// Its counters go with it: a [`ControlMsg::StatsRequest`] for a dropped
    /// session answers `known_session: false`, not zeros. A caller differencing
    /// counters across polls must treat that as "stop differencing", never as
    /// a decrease.
    DropSession {
        /// The session to forget.
        session_id: [u8; 8],
    },
    /// Flip the BPF steering flag; this is the whole DTLS fallback.
    SetActive {
        /// True routes the inside path here, false routes it to the VPN process.
        active: bool,
    },
    /// Ask for one session's counters.
    StatsRequest {
        /// The session to report on.
        session_id: [u8; 8],
    },
    /// Counters for one session, in reply.
    StatsReply {
        /// The session these counters describe, echoed from the request.
        session_id: [u8; 8],
        /// Packets this engine encrypted for this session.
        sent: u64,
        /// Packets this engine decrypted and accepted for this session.
        received: u64,
        /// Inside-packet bytes encrypted for this session. Wire bytes are this
        /// plus a fixed per-packet framing overhead.
        sent_bytes: u64,
        /// Inside-packet bytes decrypted and accepted for this session.
        received_bytes: u64,
        /// Datagrams for this session that failed AEAD or replay.
        decrypt_failures: u64,
        /// Datagrams the engine handled for no session at all: too short, not
        /// ExpressLane, or a session id it does not hold. Engine-wide, not
        /// per-session - a refused datagram has no session to charge it to.
        /// Without it the kernel's steering counters cannot be reconciled
        /// against the engine's.
        refused: u64,
        /// False when the engine has no such session - the caller must NOT
        /// treat that as zero traffic. This is the distinction
        /// `ExpresslaneMetrics::get_stats` in `lightway-core` cannot make,
        /// since it returns a plain counter struct.
        known_session: bool,
    },
}

const fn payload_len(msg: &ControlMsg) -> usize {
    match msg {
        ControlMsg::Attach => 1,
        ControlMsg::PushKeys { .. } => 1 + 8 + 1 + 2 + 2 * EXPRESSLANE_KEY_SIZE,
        ControlMsg::DropSession { .. } => 1 + 8,
        ControlMsg::SetActive { .. } => 1 + 1,
        ControlMsg::StatsRequest { .. } => 1 + 8,
        ControlMsg::StatsReply { .. } => 1 + 8 + 8 * 6 + 1,
    }
}

impl ControlMsg {
    /// How many bytes [`encode`](Self::encode) appends, length prefix included.
    pub const fn encoded_len(&self) -> usize {
        LEN_PREFIX + payload_len(self)
    }

    /// Append this message, length-prefixed, to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(payload_len(self) as u32).to_be_bytes());
        match self {
            ControlMsg::Attach => out.push(TAG_ATTACH),
            ControlMsg::PushKeys {
                session_id,
                version,
                lightway_version,
                self_key,
                peer_key,
            } => {
                out.push(TAG_PUSH_KEYS);
                out.extend_from_slice(session_id);
                out.push(*version);
                out.extend_from_slice(lightway_version);
                out.extend_from_slice(&self_key.0);
                out.extend_from_slice(&peer_key.0);
            }
            ControlMsg::DropSession { session_id } => {
                out.push(TAG_DROP_SESSION);
                out.extend_from_slice(session_id);
            }
            ControlMsg::SetActive { active } => {
                out.push(TAG_SET_ACTIVE);
                out.push(*active as u8);
            }
            ControlMsg::StatsRequest { session_id } => {
                out.push(TAG_STATS_REQUEST);
                out.extend_from_slice(session_id);
            }
            ControlMsg::StatsReply {
                session_id,
                sent,
                received,
                sent_bytes,
                received_bytes,
                decrypt_failures,
                refused,
                known_session,
            } => {
                out.push(TAG_STATS_REPLY);
                out.extend_from_slice(session_id);
                out.extend_from_slice(&sent.to_be_bytes());
                out.extend_from_slice(&received.to_be_bytes());
                out.extend_from_slice(&sent_bytes.to_be_bytes());
                out.extend_from_slice(&received_bytes.to_be_bytes());
                out.extend_from_slice(&decrypt_failures.to_be_bytes());
                out.extend_from_slice(&refused.to_be_bytes());
                out.push(*known_session as u8);
            }
        }
    }

    /// Decode one message, returning it and how many bytes it consumed.
    ///
    /// A length no variant can have is [`IpcError::BadLength`] straight away
    /// rather than [`IpcError::Incomplete`], so a caller accumulating a
    /// stream never buffers more than [`MAX_CONTROL_MSG_LEN`] waiting for a
    /// message that cannot arrive.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), IpcError> {
        if buf.len() < LEN_PREFIX {
            return Err(IpcError::Incomplete);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        // Tested against the bound before it is added to, so a declared length
        // near usize::MAX cannot overflow the sum.
        if len == 0 || len > MAX_CONTROL_MSG_LEN - LEN_PREFIX {
            return Err(IpcError::BadLength);
        }
        let total = LEN_PREFIX + len;
        if buf.len() < total {
            return Err(IpcError::Incomplete);
        }
        let body = &buf[4..total];

        let msg = match body[0] {
            TAG_ATTACH if len == 1 => ControlMsg::Attach,
            TAG_PUSH_KEYS if len == 1 + 8 + 1 + 2 + 2 * EXPRESSLANE_KEY_SIZE => {
                let mut session_id = [0u8; 8];
                session_id.copy_from_slice(&body[1..9]);
                let version = body[9];
                let lightway_version = [body[10], body[11]];
                let mut self_key = [0u8; EXPRESSLANE_KEY_SIZE];
                self_key.copy_from_slice(&body[12..12 + EXPRESSLANE_KEY_SIZE]);
                let mut peer_key = [0u8; EXPRESSLANE_KEY_SIZE];
                peer_key.copy_from_slice(&body[12 + EXPRESSLANE_KEY_SIZE..]);
                ControlMsg::PushKeys {
                    session_id,
                    version,
                    lightway_version,
                    self_key: ExpresslaneKey(self_key),
                    peer_key: ExpresslaneKey(peer_key),
                }
            }
            TAG_DROP_SESSION if len == 9 => {
                let mut session_id = [0u8; 8];
                session_id.copy_from_slice(&body[1..9]);
                ControlMsg::DropSession { session_id }
            }
            TAG_SET_ACTIVE if len == 2 => ControlMsg::SetActive {
                active: body[1] != 0,
            },
            TAG_STATS_REQUEST if len == 9 => {
                let mut session_id = [0u8; 8];
                session_id.copy_from_slice(&body[1..9]);
                ControlMsg::StatsRequest { session_id }
            }
            TAG_STATS_REPLY if len == 58 => {
                let mut session_id = [0u8; 8];
                session_id.copy_from_slice(&body[1..9]);
                let u64_at = |at: usize| {
                    u64::from_be_bytes(body[at..at + 8].try_into().expect("checked len"))
                };
                ControlMsg::StatsReply {
                    session_id,
                    sent: u64_at(9),
                    received: u64_at(17),
                    sent_bytes: u64_at(25),
                    received_bytes: u64_at(33),
                    decrypt_failures: u64_at(41),
                    refused: u64_at(49),
                    known_session: body[57] != 0,
                }
            }
            TAG_ATTACH | TAG_PUSH_KEYS | TAG_DROP_SESSION | TAG_SET_ACTIVE | TAG_STATS_REQUEST
            | TAG_STATS_REPLY => return Err(IpcError::BadLength),
            other => return Err(IpcError::BadTag(other)),
        };
        Ok((msg, total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};

    fn roundtrip(msg: ControlMsg) {
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        let (decoded, used) = ControlMsg::decode(&buf).expect("decode failed");
        assert_eq!(used, buf.len(), "decoder consumed the wrong length");
        assert_eq!(decoded, msg);
    }

    fn push_keys() -> ControlMsg {
        ControlMsg::PushKeys {
            session_id: [7; 8],
            version: 2,
            lightway_version: [1, 3],
            self_key: ExpresslaneKey([1; EXPRESSLANE_KEY_SIZE]),
            peer_key: ExpresslaneKey([2; EXPRESSLANE_KEY_SIZE]),
        }
    }

    fn stats_reply() -> ControlMsg {
        ControlMsg::StatsReply {
            session_id: [8; 8],
            sent: u64::MAX,
            received: 42,
            sent_bytes: 4242,
            received_bytes: 2424,
            decrypt_failures: 3,
            refused: 9,
            known_session: true,
        }
    }

    #[test]
    fn every_variant_round_trips() {
        roundtrip(ControlMsg::Attach);
        roundtrip(push_keys());
        roundtrip(ControlMsg::DropSession { session_id: [9; 8] });
        roundtrip(ControlMsg::SetActive { active: true });
        roundtrip(ControlMsg::SetActive { active: false });
        roundtrip(ControlMsg::StatsRequest { session_id: [5; 8] });
        roundtrip(stats_reply());
    }

    /// Every field of the two messages that carry more than one number must
    /// survive independently: a decoder reading the right length but the wrong
    /// offsets round-trips a uniform message perfectly and still corrupts a
    /// real one.
    #[test]
    fn multi_field_messages_keep_their_fields_apart() {
        let mut buf = Vec::new();
        push_keys().encode(&mut buf);
        let (decoded, _) = ControlMsg::decode(&buf).unwrap();
        let ControlMsg::PushKeys {
            session_id,
            version,
            lightway_version,
            self_key,
            peer_key,
        } = decoded
        else {
            panic!("expected PushKeys")
        };
        assert_eq!(session_id, [7; 8]);
        assert_eq!(version, 2);
        assert_eq!(lightway_version, [1, 3]);
        assert_eq!(self_key, ExpresslaneKey([1; EXPRESSLANE_KEY_SIZE]));
        assert_eq!(peer_key, ExpresslaneKey([2; EXPRESSLANE_KEY_SIZE]));

        let mut buf = Vec::new();
        stats_reply().encode(&mut buf);
        let (decoded, _) = ControlMsg::decode(&buf).unwrap();
        assert_eq!(decoded, stats_reply());
    }

    /// A decoder fed a prefix must ask for more rather than guess.
    #[test]
    fn truncated_input_is_incomplete_not_garbage() {
        let mut buf = Vec::new();
        push_keys().encode(&mut buf);

        for n in 0..buf.len() {
            assert!(
                matches!(ControlMsg::decode(&buf[..n]), Err(IpcError::Incomplete)),
                "prefix of {n} bytes should be Incomplete"
            );
        }
        assert!(ControlMsg::decode(&buf).is_ok());
    }

    #[test]
    fn two_messages_decode_in_sequence() {
        let mut buf = Vec::new();
        ControlMsg::StatsRequest { session_id: [1; 8] }.encode(&mut buf);
        ControlMsg::SetActive { active: true }.encode(&mut buf);

        let (first, used) = ControlMsg::decode(&buf).unwrap();
        assert_eq!(first, ControlMsg::StatsRequest { session_id: [1; 8] });
        let (second, _) = ControlMsg::decode(&buf[used..]).unwrap();
        assert_eq!(second, ControlMsg::SetActive { active: true });
    }

    /// `MAX_CONTROL_MSG_LEN` is what a stream reader sizes its buffer by, so
    /// every variant has to fit under it and `encoded_len` has to agree with
    /// what `encode` actually writes.
    #[test]
    fn no_variant_exceeds_the_accumulation_bound() {
        let all = [
            ControlMsg::Attach,
            push_keys(),
            ControlMsg::DropSession { session_id: [9; 8] },
            ControlMsg::SetActive { active: true },
            ControlMsg::StatsRequest { session_id: [5; 8] },
            stats_reply(),
        ];
        for msg in &all {
            let mut buf = Vec::new();
            msg.encode(&mut buf);
            assert_eq!(buf.len(), msg.encoded_len(), "encoded_len lies for {msg:?}");
            assert!(
                msg.encoded_len() <= MAX_CONTROL_MSG_LEN,
                "{msg:?} does not fit the bound readers size their buffers by"
            );
        }
    }

    /// The reason the bound exists: a peer declaring a length no variant can
    /// have must be refused at once, not waited on, or a reader accumulating a
    /// stream would grow its buffer to whatever the peer asked for.
    #[test]
    fn a_length_no_variant_can_have_is_rejected_rather_than_awaited() {
        let mut buf = (u32::MAX).to_be_bytes().to_vec();
        assert_eq!(ControlMsg::decode(&buf), Err(IpcError::BadLength));

        buf = ((MAX_CONTROL_MSG_LEN - LEN_PREFIX + 1) as u32)
            .to_be_bytes()
            .to_vec();
        buf.push(TAG_PUSH_KEYS);
        assert_eq!(
            ControlMsg::decode(&buf),
            Err(IpcError::BadLength),
            "one byte over the bound must not read as Incomplete"
        );
    }

    /// A known tag at a length that variant cannot have is a protocol error,
    /// not a short read: waiting for more bytes would stall the loop forever.
    #[test]
    fn a_known_tag_at_the_wrong_length_is_rejected() {
        // StatsRequest's tag at Attach's length.
        let buf = [0u8, 0, 0, 1, TAG_STATS_REQUEST];
        assert_eq!(ControlMsg::decode(&buf), Err(IpcError::BadLength));
    }

    #[test]
    fn unknown_tag_is_rejected() {
        // length 1, tag 0xEE
        let buf = [0u8, 0, 0, 1, 0xEE];
        assert!(matches!(
            ControlMsg::decode(&buf),
            Err(IpcError::BadTag(0xEE))
        ));
    }

    /// Key material must never reach a log through Debug.
    #[test]
    fn debug_does_not_leak_keys() {
        let msg = ControlMsg::PushKeys {
            session_id: [1; 8],
            version: 2,
            lightway_version: [1, 3],
            self_key: ExpresslaneKey([0xAB; EXPRESSLANE_KEY_SIZE]),
            peer_key: ExpresslaneKey([0xCD; EXPRESSLANE_KEY_SIZE]),
        };
        let rendered = format!("{msg:?}");
        assert!(!rendered.contains("171"), "key bytes leaked: {rendered}");
        assert!(!rendered.contains("ab"), "key bytes leaked: {rendered}");
    }
}
