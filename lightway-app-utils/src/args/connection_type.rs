use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use lightway_core::ConnectionType as LWConnectionType;

#[derive(Copy, Clone, ValueEnum, Debug, JsonSchema, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
/// [`lightway_core::ConnectionType`] wrapper compatible with clap
pub enum ConnectionType {
    /// UDP (Datagram)
    Udp,
    /// TCP (Stream)
    #[default]
    Tcp,
}

impl From<ConnectionType> for LWConnectionType {
    fn from(item: ConnectionType) -> LWConnectionType {
        match item {
            ConnectionType::Udp => LWConnectionType::Datagram,
            ConnectionType::Tcp => LWConnectionType::Stream,
        }
    }
}
