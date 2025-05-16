# Inside Packet Codec

Lightway core in UDP supports encoding the inside packets through the packet codec interface.

A codec consists of:
- An encoder that encodes the inside packets that are sent from the tunnel (i.e., before they are encrypted by WolfSSL).
- A decoder that decodes the inside packets that are to be sent to the tunnel (i.e., after they are decrypted by WolfSSL).

The codec is not necessarily used all the time; it is not required that all packets are encoded throughout the connection. 
1. The codec can decide whether the packet should be encoded based on its internal implementation.
2. The lightway-client can also decide to enable or disable the codec at any time when lightway is in the `CONNECTED` state by sending an [encoding request](#encoding-request) to the server.

Lightway-core accepts either encoded or non-encoded packets when its state is `CONNECTED`. Hence, the use of the codec never interrupts the lightway connection.

**N.B.:** The Inside Packet Codec is not supported by Lightway TCP.

## Packet Flow
The following describes the path the packet flows through when a codec is enabled and the packet is accepted by the codec:
### Inside to Outside
```
Tunnel -> Inside IO Loop -> Plugin -> Encoder -> Encoded Packet Handler Loop -> WolfSSL Encrypt -> ...
```
### Outside to Inside
```
... -> WolfSSL Decrypt -> Decoder -> Decoded Packet Handler Loop -> Plugin -> Tunnel
```

## Implementation

### Codec
A codec can be constructed by the `PacketEncoder` and `PacketDecoder` traits
```rust
/// [`PacketEncoder`] trait. Accumulates inside packets and turn them to encoded packets
pub trait PacketEncoder {
    /// Store one inside packet into the [`PacketEncoder`]
    ///
    /// Returns a [`CodecStatus`].
    /// If the status is [`CodecStatus::PacketAccepted`], the packet is accepted by the encoder.
    /// If the status is [`CodecStatus::SkipPacket`], the packet is skipped by the encoder and lightway
    /// may send it as a normal wire::Data packet.
    fn store(&self, data: &mut BytesMut) -> PacketCodecResult<CodecStatus>;

    /// Get the encoding state
    ///
    /// The returned bool indicates whether encoding is enabled.
    fn get_encoding_state(&self) -> bool;

    /// Set the encoding status
    ///
    /// The param indicates whether encoding is enabled or disabled.
    fn set_encoding_state(&self, enabled: bool);
}

/// [`PacketDecoder`] trait to accumulate encoded packets and turn them to inside packets.
pub trait PacketDecoder {
    /// Store one encoded packet into the [`PacketDecoder`]
    ///
    /// Returns a [`CodecStatus`].
    /// If the status is [`CodecStatus::PacketAccepted`], the packet is accepted by the encoder.
    /// If the status is [`CodecStatus::SkipPacket`], the packet should not be added to the decoder.
    /// and should be sent directly.
    fn store(&self, data: &mut BytesMut) -> PacketCodecResult<CodecStatus>;
}

/// Indicates the status of [`PacketEncoder`] or [`PacketDecoder`] after storing the current packet
pub enum CodecStatus {
    /// The codec accepted this packet.
    PacketAccepted,

    /// The codec does not accept this particular packet.
    /// The packet should be sent directly.
    #[allow(dead_code)]
    SkipPacket,
}
```
The encoder/decoder returns a `CodecStatus` enum with two variants: 
1. `PacketAccepted`: the packet is consumed by the encoder/decoder. The codec should send the packet to lightway-core again after it is encoded/decoded.
2. `SkipPacket`: the packet is rejected by the encoder/decoder. Lightway-core will send the packet normally as if there is no packet codec.

Whether the packet is accepted or skipped is defined by the encoder/decoder's implementation.

Additionally, an extra interface (`set_encoding_state()` function) exists for enabling/disabling the encoder. The encoder should always skip the packet 
if the encoding state is set to false. This interface is used by the [encoding request](#encoding-request) mechanism.

### Representation
To distinguish between encoded and non-encoded packets: encoded packets are wrapped as `EncodedData` or `EncodedDataFrag` inside wire frames, whereas 
non-encoded packets are wrapped as `Data` or `DataFrag` inside wire frames.

### Factory
The construction of the codec can be handled by implementing the `PacketCodecFactory` trait defined in lightway-app-utils:
```rust
/// Factory to build [`PacketEncoderType`] and [`PacketDecoderType`] and its utilities
/// This will be used to build a new instance of [`PacketEncoderType`] and [`PacketDecoderType`] for every connection.
pub trait PacketCodecFactory {
    /// Build new instances of [`PacketEncoderType`] and [`PacketDecoderType`] and its utilities
    fn build(&self) -> PacketCodec;

    /// Returns the codec name for debugging purpose
    fn get_codec_name(&self) -> String;
}

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
```

In the `build()` function, an mpsc channel should be initialized. The sender should be passed to the encoder/decoder. Encoded/decoded packets should 
be sent to the mpsc channel by passing the packets to the sender.

Lightway-client/lightway-server is responsible for listening to the receivers. Whenever a packet is received, it should be passed to lightway-core by 
invoking the `send_to_inside()` or `send_to_outside()` trait functions of `Connection`.

## Encoding Request
By default, when lightway changes state to `CONNECTED`, the packet encoder on the client and server are in the disabled state; all packets will be 
skipped by the encoder and sent as normal packets.

To enable encoding on both sides (client and server), the lightway client should send an encoding request to the server. The workflow of an encoding 
request looks like this:
1. The client sends an `EncodingRequest` inside a wire frame to the server.
2. If the server does not have the codec initialized, the `EncodingRequest` is ignored. Otherwise, the server enables the encoder and sends an 
`EncodingResponse` inside a wire frame to the client.
3. The client receives the `EncodingResponse` and enables the encoder.

### Retransmission
The encoding request and encoding response packets could be lost since the inside packet codec is only used with Lightway UDP. Hence, a retransmission 
mechanism is in place to ensure that the requests and responses can reach the peer.

Each new and unique encoding request from the client is incrementally assigned a unique integer id. Lightway server only commits and gives responses 
to encoding requests with its id higher or equal to the id of the most recently committed request.

The number of re-transmission is limited by a constant to avoid wasting network resources in case the server does not have encoding enabled. If the client
cannot receive a response after the maximum number of re-transmissions has been attempted, the request is considered as failed.