//! Where the ExpressLane flag lives in a Lightway datagram.
//!
//! The outside BPF program hardcodes these offsets - the inside one reads no
//! header at all, it steers on a map entry. Nothing in lightway-core stops
//! someone reordering `Header`, and if that happens the classifier misroutes
//! silently and the tunnel fails looking like a network fault. The test below
//! is what turns that into a build failure instead.

/// Bytes of Lightway header preceding the payload.
pub const HEADER_LEN: usize = 16;

/// Offset of the `expresslane_data` flag within the header.
pub const EXPRESSLANE_FLAG_OFFSET: usize = 5;

/// Offset of the session id, which runs from here to the end of the header.
///
/// The BPF programs never read it - an engine that builds or parses a header
/// does, and the test below is what keeps that from being a guess.
pub const SESSION_ID_OFFSET: usize = 8;

/// The two magic bytes every Lightway datagram opens with.
pub const MAGIC: [u8; 2] = *b"He";

/// Classify a UDP payload exactly as the BPF program does.
///
/// Kept in lockstep with `outside.bpf.c` on purpose: the test below runs this
/// against real serialized headers, so a divergence between this and the
/// header layout fails the build.
pub fn is_expresslane_datagram(payload: &[u8]) -> bool {
    payload.len() > EXPRESSLANE_FLAG_OFFSET
        && payload[0] == MAGIC[0]
        && payload[1] == MAGIC[1]
        && payload[EXPRESSLANE_FLAG_OFFSET] != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use lightway_core::{Header, SessionId, Version};

    fn serialize(expresslane: bool) -> BytesMut {
        serialize_for(expresslane, SessionId::EMPTY)
    }

    fn serialize_for(expresslane: bool, session: SessionId) -> BytesMut {
        let hdr = Header {
            version: Version::MINIMUM,
            aggressive_mode: false,
            expresslane_data: expresslane,
            session,
        };
        let mut buf = BytesMut::new();
        hdr.append_to_wire(&mut buf);
        buf
    }

    /// The offsets the BPF programs hardcode must match what lightway-core
    /// actually serializes. If someone reorders `Header`, this fails.
    #[test]
    fn flag_offset_matches_the_real_header() {
        assert_eq!(Header::WIRE_SIZE, HEADER_LEN, "header grew or shrank");

        let on = serialize(true);
        let off = serialize(false);

        assert_eq!(&on[..2], &MAGIC, "magic moved");
        assert_ne!(on[EXPRESSLANE_FLAG_OFFSET], 0, "flag not at offset 5");
        assert_eq!(off[EXPRESSLANE_FLAG_OFFSET], 0, "flag not at offset 5");

        // Exactly one byte may differ between the two, and it must be ours.
        let differing: Vec<usize> = (0..HEADER_LEN).filter(|&i| on[i] != off[i]).collect();
        assert_eq!(differing, vec![EXPRESSLANE_FLAG_OFFSET]);
    }

    /// An engine building a header by hand puts the session id here, and
    /// `Engine::decrypt` reads the one it must answer for from the same place.
    /// A move would misroute every datagram with nothing to point at.
    #[test]
    fn session_id_offset_matches_the_real_header() {
        const SID: [u8; 8] = [0xA5, 1, 2, 3, 4, 5, 6, 0x5A];
        let buf = serialize_for(true, SessionId::from_const(SID));
        assert_eq!(&buf[SESSION_ID_OFFSET..HEADER_LEN], &SID);
    }

    #[test]
    fn classifier_agrees_with_the_header() {
        assert!(is_expresslane_datagram(&serialize(true)));
        assert!(!is_expresslane_datagram(&serialize(false)));
    }

    #[test]
    fn non_lightway_and_short_payloads_are_not_expresslane() {
        assert!(!is_expresslane_datagram(b""));
        assert!(!is_expresslane_datagram(b"He"));
        assert!(!is_expresslane_datagram(&[0xFF; 32]), "wrong magic");
    }
}
