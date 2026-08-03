//! Negotiated ExpressLane wire version.

/// ExpressLane wire version. Controls AAD length: `Version1` binds 16 bytes,
/// `Version2` additionally binds the 2-byte flags field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ExpresslaneVersion {
    /// Not yet negotiated
    #[default]
    Unknown = 0,
    /// Initial ExpressLane format
    Version1 = 1,
    /// Same wire layout as V1, but the flags field is bound into the AEAD AAD.
    /// Incompatible with V1 builds.
    Version2 = 2,
}

impl ExpresslaneVersion {
    /// Highest version this build supports.
    pub const MAX: Self = Self::Version2;
}

impl From<u8> for ExpresslaneVersion {
    /// A byte this build does not recognise becomes `Unknown`, which
    /// negotiation resolves to a supported version.
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Version1,
            2 => Self::Version2,
            _ => Self::Unknown,
        }
    }
}

impl From<ExpresslaneVersion> for u8 {
    fn from(value: ExpresslaneVersion) -> Self {
        value as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AAD length keys off `>= Version2`, so the ordering must hold.
    #[test]
    fn versions_order_by_wire_generation() {
        assert!(ExpresslaneVersion::Unknown < ExpresslaneVersion::Version1);
        assert!(ExpresslaneVersion::Version1 < ExpresslaneVersion::Version2);
        assert_eq!(ExpresslaneVersion::MAX, ExpresslaneVersion::Version2);
    }

    /// The version travels as one byte in the config frame, and an unknown
    /// byte must survive the round trip as `Unknown` rather than be rejected -
    /// that is what lets a newer peer negotiate down to us.
    #[test]
    fn wire_byte_round_trips_and_unknown_bytes_collapse() {
        for v in [
            ExpresslaneVersion::Unknown,
            ExpresslaneVersion::Version1,
            ExpresslaneVersion::Version2,
        ] {
            assert_eq!(ExpresslaneVersion::from(u8::from(v)), v);
        }
        assert_eq!(u8::from(ExpresslaneVersion::Version2), 2);
        assert_eq!(ExpresslaneVersion::from(3), ExpresslaneVersion::Unknown);
        assert_eq!(ExpresslaneVersion::from(255), ExpresslaneVersion::Unknown);
    }
}
