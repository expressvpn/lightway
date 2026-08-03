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
}
