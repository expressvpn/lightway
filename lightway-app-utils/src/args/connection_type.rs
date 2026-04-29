use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use lightway_core::ConnectionType as LWConnectionType;

#[derive(
    Copy, Clone, PartialEq, Eq, ValueEnum, Debug, JsonSchema, Serialize, Deserialize, Default,
)]
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

impl ConnectionType {
    /// A helper function easier to use especially in mobile
    pub fn is_tcp(&self) -> bool {
        *self == ConnectionType::Tcp
    }
}

impl From<ConnectionType> for LWConnectionType {
    fn from(item: ConnectionType) -> LWConnectionType {
        match item {
            ConnectionType::Udp => LWConnectionType::Datagram,
            ConnectionType::Tcp => LWConnectionType::Stream,
        }
    }
}
