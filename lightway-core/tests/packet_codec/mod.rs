use lightway_app_utils::{PacketCodec, PacketCodecFactory};
use lightway_core::{CodecStatus, PacketCodecResult, PacketDecoder, PacketEncoder};

use bytes::BytesMut;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;

#[derive(Default)]
pub(crate) struct TestPacketCodecFactory {}

impl PacketCodecFactory for TestPacketCodecFactory {
    fn build(&self) -> PacketCodec {
        let (encoded_pkt_sender, encoded_pkt_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (decoded_pkt_sender, decoded_pkt_receiver) = tokio::sync::mpsc::unbounded_channel();

        let encoder = Arc::new(TestPacketEncoder::new(encoded_pkt_sender));
        let decoder = Arc::new(TestPacketDecoder::new(decoded_pkt_sender));

        PacketCodec {
            encoder,
            decoder,
            encoded_pkt_receiver,
            decoded_pkt_receiver,
        }
    }

    fn get_codec_name(&self) -> String {
        String::from("Test Packet Codec")
    }
}

#[derive(Clone)]
struct TestPacketEncoder {
    inner: Arc<Mutex<TestPacketEncoderInner>>,
}

struct TestPacketEncoderInner {
    codec_enabled: bool,
    encoded_pkt_sender: UnboundedSender<BytesMut>,
}

impl TestPacketEncoder {
    fn new(encoded_pkt_sender: UnboundedSender<BytesMut>) -> Self {
        TestPacketEncoder {
            inner: Arc::new(Mutex::new(TestPacketEncoderInner::new(encoded_pkt_sender))),
        }
    }
}

impl TestPacketEncoderInner {
    fn new(encoded_pkt_sender: UnboundedSender<BytesMut>) -> Self {
        TestPacketEncoderInner {
            codec_enabled: false,
            encoded_pkt_sender,
        }
    }
}

impl PacketEncoder for TestPacketEncoder {
    fn store(&self, data: &mut bytes::BytesMut) -> PacketCodecResult<CodecStatus> {
        let encoder = self
            .inner
            .lock()
            .expect("TestPacketEncoder inner lock in store()");

        if !encoder.codec_enabled {
            return Ok(CodecStatus::SkipPacket);
        }

        // Encoding: rotate left
        data.rotate_left(2);

        encoder
            .encoded_pkt_sender
            .send(data.clone())
            .expect("TestPacketEncoder send");
        Ok(CodecStatus::PacketAccepted)
    }

    fn set_encoding_state(&self, enabled: bool) {
        let mut encoder = self
            .inner
            .lock()
            .expect("TestPacketEncoder inner lock in set_encoding_state()");
        encoder.codec_enabled = enabled;
    }

    fn get_encoding_state(&self) -> bool {
        let encoder = self
            .inner
            .lock()
            .expect("TestPacketEncoder inner lock in get_encoding_state()");
        encoder.codec_enabled
    }
}

struct TestPacketDecoder {
    decoded_pkt_sender: Arc<Mutex<UnboundedSender<BytesMut>>>,
}

impl TestPacketDecoder {
    fn new(decoded_pkt_sender: UnboundedSender<BytesMut>) -> Self {
        TestPacketDecoder {
            decoded_pkt_sender: Arc::new(Mutex::new(decoded_pkt_sender)),
        }
    }
}

impl PacketDecoder for TestPacketDecoder {
    fn store(&self, data: &mut BytesMut) -> PacketCodecResult<CodecStatus> {
        let sender = self
            .decoded_pkt_sender
            .lock()
            .expect("TestPacketDecoder lock in store()");

        // Decoding: rotate right
        data.rotate_right(2);

        sender.send(data.clone()).expect("TestPacketDecoder send");

        Ok(CodecStatus::PacketAccepted)
    }
}
