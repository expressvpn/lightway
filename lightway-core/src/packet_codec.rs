use std::sync::{Arc, Weak};

use bytes::BytesMut;

/// PacketEncoder and PacketDecoder's trait function's return type
pub type PacketCodecResult<T> = std::result::Result<T, Box<dyn std::error::Error + Sync + Send>>;

/// PacketEncode trait. Accumulates inside packets and turn them to encoded packets
pub trait PacketEncoder {
    /// Store one inside packet into the PacketEncoder
    ///
    /// Returns a [`CodecStatus`].
    /// If the status is [`CodecStatus::ReadyToFlush`], encoded packets are ready to be retrieved.
    /// If the status is [`CodecStatus::SkipPacket`], the packet is skipped by the encoder and lightway
    /// may send it as a normal wire::Data packet.
    fn store(&self, data: &mut BytesMut) -> PacketCodecResult<CodecStatus>;

    /// Retrieve the encoded packets
    fn get_encoded_pkts(&self) -> PacketCodecResult<Vec<BytesMut>>;

    /// Get the encoding state
    ///
    /// The returned bool indicates whether encoding is enabled.
    fn get_encoding_state(&self) -> bool;

    /// Set the encoding status
    ///
    /// The param indicates whether encoding is enabled or disabled.
    fn set_encoding_state(&self, enabled: bool);

    /// Indicates whether the packets in the encoder should be retrieved.
    fn should_flush(&self) -> bool;
}

/// PacketDecoder trait to accumulate encoded packets and turn them to inside packets.
pub trait PacketDecoder {
    /// Store one encoded packet into the PacketDecoder
    ///
    /// Returns a [`CodecStatus`].
    /// If the status is [`CodecStatus::ReadyToFlush`], decoded inside packets are ready to be retrieved.
    /// If the status is [`CodecStatus::SkipPacket`], the packet should not be added to the decoder.
    /// and should be sent directly.
    fn store(&self, data: &mut BytesMut) -> PacketCodecResult<CodecStatus>;

    /// Retrieve the decoded inside packets
    fn get_decoded_pkts(&self) -> PacketCodecResult<Vec<BytesMut>>;
}

/// Indicates the status of [`PacketEncoder`] or [`PacketDecoder`] after storing the current packet
pub enum CodecStatus {
    /// Ready to flush
    ReadyToFlush,

    /// Not yet ready to flush
    #[allow(dead_code)]
    Pending,

    /// The codec does not accept this particular packet.
    /// The packet should be sent directly.
    #[allow(dead_code)]
    SkipPacket,
}

/// Type for [`PacketEncoder`]
pub type PacketEncoderType = Arc<dyn PacketEncoder + Send + Sync>;
/// Weak reference for [`PacketEncoder`]
pub type WeakPacketEncoderType = Weak<dyn PacketEncoder + Send + Sync>;

/// Type for [`PacketDecoder`]
pub type PacketDecoderType = Arc<dyn PacketDecoder + Send + Sync>;
/// Weak reference for [`PacketDecoder`]
pub type WeakPacketDecoderType = Weak<dyn PacketDecoder + Send + Sync>;

/// Factory to build [`PacketEncoderType`] and [`PacketDecoderType`]
/// This will be used to build a new instance of [`PacketEncoderType`] and [`PacketDecoderType`] for every connection.
pub trait PacketCodecFactory {
    /// Build a new instance of [`PacketEncoderType`] and [`PacketDecoderType`]
    fn build(&self) -> (PacketEncoderType, PacketDecoderType);

    /// Returns the codec name for debugging purpose
    fn get_codec_name(&self) -> String;
}

/// Type for [`PacketCodecFactory`]
pub type PacketCodecFactoryType = Box<dyn PacketCodecFactory + Send + Sync>;
