//! ExpressLane key material.

/// Size of an ExpressLane AES-256-GCM key in bytes.
pub const EXPRESSLANE_KEY_SIZE: usize = 32;

/// An ExpressLane AES-256-GCM key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExpresslaneKey(pub [u8; EXPRESSLANE_KEY_SIZE]);

impl ExpresslaneKey {
    /// The all-zero sentinel used before a real key has been negotiated.
    pub const INVALID: Self = ExpresslaneKey([0; EXPRESSLANE_KEY_SIZE]);

    /// True when this is the all-zero sentinel rather than real key material.
    pub fn is_invalid(&self) -> bool {
        self == &Self::INVALID
    }
}

impl From<[u8; EXPRESSLANE_KEY_SIZE]> for ExpresslaneKey {
    fn from(value: [u8; EXPRESSLANE_KEY_SIZE]) -> Self {
        ExpresslaneKey(value)
    }
}

impl std::fmt::Debug for ExpresslaneKey {
    /// Never prints key bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExpresslaneKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_key_is_invalid() {
        assert!(ExpresslaneKey::INVALID.is_invalid());
        assert!(!ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]).is_invalid());
    }

    #[test]
    fn debug_never_leaks_key_bytes() {
        let key = ExpresslaneKey([0xAB; EXPRESSLANE_KEY_SIZE]);
        assert_eq!(format!("{key:?}"), "ExpresslaneKey(<redacted>)");
    }
}
