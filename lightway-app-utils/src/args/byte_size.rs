use bytesize::ByteSize;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wrapper around [`ByteSize`] that serializes as a raw byte count (u64)
/// to avoid precision loss during serde round-trips.
///
/// `ByteSize`'s default human-readable serialization formats values using
/// base-10 units with limited precision (e.g., 8 MiB becomes "8.4 MB"),
/// which causes data loss when deserialized back.
#[derive(Copy, Clone)]
pub struct ExactByteSize(ByteSize);

impl ExactByteSize {
    /// Returns the byte count as a u64.
    pub fn as_u64(&self) -> u64 {
        self.0.as_u64()
    }

    /// Creates an `ExactByteSize` from a count of mebibytes.
    pub fn mib(count: u64) -> Self {
        Self(ByteSize::mib(count))
    }
}

impl Serialize for ExactByteSize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.as_u64().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ExactByteSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        ByteSize::deserialize(deserializer).map(ExactByteSize)
    }
}

impl std::fmt::Display for ExactByteSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for ExactByteSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ExactByteSize {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<ByteSize>().map(ExactByteSize)
    }
}
