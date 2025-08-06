use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use lightway_core::ConnectionType as LWConnectionType;

#[derive(Copy, Clone, ValueEnum, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
/// [`lightway_core::ConnectionType`] wrapper compatible with clap and twelf
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
