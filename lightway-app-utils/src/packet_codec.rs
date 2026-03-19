use lightway_core::{PacketDecoderType, PacketEncoderType};

use bytes::BytesMut;
use tokio::sync::mpsc::UnboundedReceiver;

/// Factory to build [`PacketEncoderType`] and [`PacketDecoderType`] and its utilities
/// This will be used to build a new instance of [`PacketEncoderType`] and [`PacketDecoderType`] for every connection.
pub trait PacketCodecFactory {
    /// Build new instances of [`PacketEncoderType`] and [`PacketDecoderType`] and its utilities
    fn build(&self) -> PacketCodec;

    /// Returns the codec name for debugging purpose
    fn get_codec_name(&self) -> String;

    /// Sends shutdown signal to codec factory
    fn shutdown(&self) {}
}

/// Type for [`PacketCodecFactory`]
pub type PacketCodecFactoryType = Box<dyn PacketCodecFactory + Send + Sync>;

/// Packet codec and its utilities used by a Connection.
/// Returned by [`PacketCodecFactory::build`]
pub struct PacketCodec {
    /// Inside Packet Encoder
    pub encoder: PacketEncoderType,

    /// Inside Packet Decoder
    pub decoder: PacketDecoderType,

    /// Emits the encoded packets from the encoder
    pub encoded_pkt_receiver: UnboundedReceiver<BytesMut>,

    /// Emits the decoded packets from the receiver
    pub decoded_pkt_receiver: UnboundedReceiver<BytesMut>,
}
