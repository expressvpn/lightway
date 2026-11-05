use bytes::BytesMut;
use thiserror::Error;

use crate::{Header, PluginResult, plugin::PluginList};

#[derive(Debug)]
/// Packet structure used by application to inject outside packets into lightway-core
pub enum OutsidePacket<'pkt> {
    /// Opaque wire packet, before running plugin chain
    Wire(&'pkt mut BytesMut),
    /// Frame without a wire header, after running plugin chain. A
    /// transport without [`crate::TransportCaps::wire_header`] gets
    /// this variant.
    TcpFrame(&'pkt mut BytesMut),
    /// Frame with its parsed wire header, after running plugin chain.
    /// A transport with [`crate::TransportCaps::wire_header`] gets this
    /// variant.
    UdpFrame(&'pkt mut BytesMut, Header),
}

impl<'pkt> OutsidePacket<'pkt> {
    pub(crate) fn into_payload(self) -> Option<&'pkt mut BytesMut> {
        match self {
            Self::Wire(_) => None,
            Self::TcpFrame(buf) => Some(buf),
            Self::UdpFrame(buf, _hdr) => Some(buf),
        }
    }

    /// Returns the `Header` from the UDP OutsidePacket
    pub fn header(&self) -> Option<&Header> {
        match self {
            Self::UdpFrame(_buf, hdr) => Some(hdr),
            _ => None,
        }
    }

    pub(crate) fn apply_ingress_chain(
        self,
        plugins: &PluginList,
        wire_header: bool,
    ) -> Result<Self, OutsidePacketError> {
        match self {
            Self::Wire(buf) => {
                let buf = match plugins.do_ingress(buf) {
                    PluginResult::Accept => buf,
                    PluginResult::Drop => return Err(OutsidePacketError::PluginDrop),
                    PluginResult::DropWithReply(_) => return Err(OutsidePacketError::PluginDrop),
                    PluginResult::Error(e) => return Err(OutsidePacketError::PluginError(e)),
                };

                if !wire_header {
                    return Ok(Self::TcpFrame(buf));
                }
                let hdr = Header::try_from_wire(buf)
                    .map_err(|e| OutsidePacketError::BadWireHeader(e.into()))?;
                Ok(Self::UdpFrame(buf, hdr))
            }

            // Plugin chain already ran
            _ => Ok(self),
        }
    }
}

/// An error with [`OutsidePacket`]
#[derive(Debug, Error)]
pub enum OutsidePacketError {
    /// The UDP packet had an incorrect `wire::Header`
    #[error("Bad Wire Header: {0}")]
    BadWireHeader(Box<dyn std::error::Error + Sync + Send>),

    /// Plugin dropped the packet
    #[error("Plugin dropped outside packet")]
    PluginDrop,

    /// Plugin returned error
    #[error("Plugin Error: {0}")]
    PluginError(Box<dyn std::error::Error + Sync + Send>),
}
