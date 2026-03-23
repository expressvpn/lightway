use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, ValueEnum, Debug, JsonSchema, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
/// Tracing log format type compatible with clap
pub enum ConfigFormat {
    /// A human-readable tab based config format
    Yaml,
    /// A config format to define type for fields in configure
    JsonSchema,
}
