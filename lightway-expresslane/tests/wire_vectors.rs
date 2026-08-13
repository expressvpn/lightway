//! Golden vectors. These bytes are the wire contract - if a change here is
//! required, it is a protocol change and needs a version bump, not a new
//! expected value.
//!
//! Shipped offload consumers and the `lightway-cffi` fork parse these frames
//! with their own code, so nothing here may be recomputed by the
//! implementation under test: the hex literals below were captured once from a
//! build known to interoperate and are now fixed. Reordering `build_aad`,
//! flipping the counter to little-endian or moving a header field changes
//! them, and each of those breaks a peer that has not been rebuilt.
#![cfg(feature = "wolfssl")]

use bytes::BytesMut;
use lightway_expresslane::{
    EXPRESSLANE_KEY_SIZE, ExpresslaneKey, ExpresslaneSession, ExpresslaneVersion, WolfsslAead,
};

const SID: [u8; 8] = [0xA1; 8];
const KEY: [u8; EXPRESSLANE_KEY_SIZE] = [0x5A; EXPRESSLANE_KEY_SIZE];
const IV: [u8; 12] = [0x2B; 12];
const PAYLOAD: &[u8] = b"expresslane golden vector payload";

/// The first counter of a fresh session, big-endian.
const COUNTER_1: &str = "0000000000000001";
/// `IV`, echoed verbatim into the frame.
const IV_HEX: &str = "2b2b2b2b2b2b2b2b2b2b2b2b";
/// `PAYLOAD.len()` (33) as the 16-bit length field, then flags with the
/// encoded bit set: the MSB of a big-endian u16.
const LEN_AND_ENCODED_FLAGS: &str = "00218000";

/// AES-256-GCM under `KEY`/`IV`: the keystream ignores the AAD, so every
/// vector below shares one ciphertext.
const CIPHERTEXT: &str = "1de0df19db6aa733e1f77938999b312f5310ecc610332f6a94234f38a17987cac8";

/// V1 binds session id and counter only.
const V1_TAG_ENCODED: &str = "f8cf6559479de62e9b6bf8cda32be127";
/// The same, with the encoded flag cleared: V1 leaves flags out of the AAD, so
/// the tag does not move. That is the hole V2 closes.
const V1_TAG_PLAIN: &str = "f8cf6559479de62e9b6bf8cda32be127";

/// V2 additionally binds the 2-byte flags field.
const V2_TAG_ENCODED: &str = "99729ab5a6261acd578ce423075905ed";
/// Differs from [`V2_TAG_ENCODED`] precisely because the flags are in the AAD.
const V2_TAG_PLAIN: &str = "2d5ee0b75c9d1319e0aed5f386808b97";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn session(v: ExpresslaneVersion) -> ExpresslaneSession<WolfsslAead> {
    let s = ExpresslaneSession::new(v);
    s.update_next_self_key(ExpresslaneKey(KEY)).unwrap();
    s.promote_self_key();
    s.update_peer_key(ExpresslaneKey(KEY)).unwrap();
    s
}

fn emit(v: ExpresslaneVersion, encoded: bool) -> BytesMut {
    let s = session(v);
    let mut buf = BytesMut::new();
    s.append_to_wire(&mut buf, SID, PAYLOAD, IV, encoded)
        .unwrap();
    buf
}

/// Same frame as [`emit`], produced through the zero-allocation path.
fn emit_into(v: ExpresslaneVersion, encoded: bool) -> Vec<u8> {
    let s = session(v);
    let counter = s.reserve_counter();
    let mut out = vec![0u8; 40 + PAYLOAD.len()];
    let n = s
        .encrypt_into(counter, SID, PAYLOAD, IV, encoded, &mut out)
        .unwrap();
    out.truncate(n);
    out
}

/// Every byte of a V1 frame, pinned.
#[test]
fn v1_golden_frame() {
    let buf = emit(ExpresslaneVersion::Version1, true);
    assert_eq!(hex(&buf[20..36]), V1_TAG_ENCODED, "auth tag");
    assert_eq!(hex(&buf[40..]), CIPHERTEXT, "ciphertext");
    assert_eq!(
        hex(&buf),
        format!("{COUNTER_1}{IV_HEX}{V1_TAG_ENCODED}{LEN_AND_ENCODED_FLAGS}{CIPHERTEXT}"),
        "whole frame"
    );
}

/// Every byte of a V2 frame, pinned. Same inputs as V1, different tag.
#[test]
fn v2_golden_frame() {
    let buf = emit(ExpresslaneVersion::Version2, true);
    assert_eq!(hex(&buf[20..36]), V2_TAG_ENCODED, "auth tag");
    assert_eq!(hex(&buf[40..]), CIPHERTEXT, "ciphertext");
    assert_eq!(
        hex(&buf),
        format!("{COUNTER_1}{IV_HEX}{V2_TAG_ENCODED}{LEN_AND_ENCODED_FLAGS}{CIPHERTEXT}"),
        "whole frame"
    );
}

/// The version difference, stated in bytes: clearing the encoded flag leaves a
/// V1 tag alone and changes a V2 one. Recomputing this from `build_aad` would
/// prove nothing, which is why both tags are literals.
#[test]
fn golden_tags_show_v2_binds_the_flags() {
    assert_eq!(
        hex(&emit(ExpresslaneVersion::Version1, false)[20..36]),
        V1_TAG_PLAIN
    );
    assert_eq!(
        hex(&emit(ExpresslaneVersion::Version2, false)[20..36]),
        V2_TAG_PLAIN
    );
    assert_eq!(V1_TAG_PLAIN, V1_TAG_ENCODED, "V1 does not bind flags");
    assert_ne!(V2_TAG_PLAIN, V2_TAG_ENCODED, "V2 binds flags");
}

#[test]
fn v2_layout_is_stable() {
    let buf = emit(ExpresslaneVersion::Version2, true);
    assert_eq!(buf.len(), 40 + PAYLOAD.len());
    assert_eq!(&buf[0..8], &1u64.to_be_bytes(), "counter starts at 1");
    assert_eq!(&buf[8..20], &IV, "iv is echoed verbatim");
    assert_eq!(
        u16::from_be_bytes([buf[36], buf[37]]) as usize,
        PAYLOAD.len(),
        "length field"
    );
    assert_eq!(
        u16::from_be_bytes([buf[38], buf[39]]),
        0x8000,
        "encoded flag is the MSB"
    );
}

#[test]
fn v1_and_v2_auth_tags_differ_but_ciphertexts_identical() {
    let v1 = emit(ExpresslaneVersion::Version1, true);
    let v2 = emit(ExpresslaneVersion::Version2, true);
    // Counter and IV are identical (both use same input)
    assert_eq!(&v1[0..20], &v2[0..20], "counter and IV are identical");
    // Auth tags differ because AAD length differs (V1: 16 bytes, V2: 18 bytes with flags)
    assert_ne!(
        &v1[20..36],
        &v2[20..36],
        "auth tags differ due to different AAD"
    );
    // Ciphertext length and flags are identical
    assert_eq!(
        &v1[36..40],
        &v2[36..40],
        "ciphertext length and flags are identical"
    );
    // Ciphertexts are identical (same plaintext, counter, and IV produce same AES-CTR output)
    assert_eq!(
        v1[40..],
        v2[40..],
        "ciphertext is identical (AES-CTR deterministic)"
    );
}

#[test]
fn each_version_round_trips_itself() {
    for v in [ExpresslaneVersion::Version1, ExpresslaneVersion::Version2] {
        let mut buf = emit(v, false);
        let rx = session(v);
        let (pt, encoded) = rx.try_from_wire(&mut buf, SID).unwrap();
        assert_eq!(&pt[..], PAYLOAD, "{v:?}");
        assert!(!encoded, "{v:?}");
    }
}

/// The pinned bytes must also come out of the zero-allocation entry point -
/// `encrypt_into` is not a separate implementation of the frame layout.
#[test]
fn v1_golden_frame_via_encrypt_into() {
    let buf = emit_into(ExpresslaneVersion::Version1, true);
    assert_eq!(
        hex(&buf),
        format!("{COUNTER_1}{IV_HEX}{V1_TAG_ENCODED}{LEN_AND_ENCODED_FLAGS}{CIPHERTEXT}"),
        "whole frame"
    );
}

#[test]
fn v2_golden_frame_via_encrypt_into() {
    let buf = emit_into(ExpresslaneVersion::Version2, true);
    assert_eq!(
        hex(&buf),
        format!("{COUNTER_1}{IV_HEX}{V2_TAG_ENCODED}{LEN_AND_ENCODED_FLAGS}{CIPHERTEXT}"),
        "whole frame"
    );
}

/// The same pinned bytes must be consumable by the zero-allocation entry
/// point on the receiving side.
#[test]
fn golden_frame_decrypts_via_decrypt_into() {
    for v in [ExpresslaneVersion::Version1, ExpresslaneVersion::Version2] {
        let buf = emit(v, true);
        let rx = session(v);
        let mut out = vec![0u8; PAYLOAD.len()];
        let (n, encoded) = rx.decrypt_into(SID, &buf, &mut out).unwrap();
        assert_eq!(&out[..n], PAYLOAD, "{v:?}");
        assert!(encoded, "{v:?}");
    }
}
