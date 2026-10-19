//! Serde helpers for deserializing and serializing human-readable durations.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::Duration;

/// Deserializes an optional string into an optional Duration using human-readable format.
pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    opt.map(|s| humantime::parse_duration(&s).map_err(serde::de::Error::custom))
        .transpose()
}

/// Serializes a Duration into a human-readable string.
pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let formatted = humantime::format_duration(*duration).to_string();
    formatted.serialize(serializer)
}

/// Custom schema function for Duration fields using human-readable format.
pub fn custom_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let mut schema = String::json_schema(generator);
    schema.insert(
        "pattern".into(),
        "^([0-9]+(\\.[0-9]+)?(ns|us|ms|s|m|h|d|w|M) ?)+$".into(),
    );
    schema
}
