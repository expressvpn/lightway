use std::sync::Arc;

use bytes::{Buf, BytesMut};
use delegate::delegate;
use more_asserts::*;

use wolfssl::IOCallbackResult;

use crate::{
    ConnectionType, OutsideIOSendCallbackArg, PluginResult, Version, plugin::PluginList, wire,
};

pub(crate) struct SendBuffer {
    data: BytesMut,
    total_capacity: usize,
    original_length: usize,
}

impl SendBuffer {
    pub(crate) fn new(mtu: usize) -> Self {
        let total_capacity = 2 * mtu;
        Self {
            // In tcp, there is no MTU restriction, so allocate twice the mtu.
            data: BytesMut::with_capacity(total_capacity),
            total_capacity,
            original_length: 0,
        }
    }

    delegate! {
        to self.data {
            fn is_empty(&self) -> bool;
            fn advance(&mut self, cnt: usize);
        }
    }

    /// Enqueue a new buffer to an empty `SendBuffer`.
    fn enqueue_buffer(&mut self, buf: &[u8]) {
        debug_assert_eq!(0, self.original_length);
        debug_assert!(self.data.is_empty());

        // Recover full capacity. Since the data buffer was originally
        // allocated with the required size this should just be
        // pointer/index fiddling to reset.
        self.data.reserve(self.data.capacity());
        self.data.extend_from_slice(buf);
        self.original_length = buf.len();
    }

    /// Apply plugins to the current buffer. This may change the size
    /// of the queued buffer but does not change the externally
    /// visible length.
    fn apply_egress_plugins(&mut self, plugins: &PluginList) -> PluginResult {
        plugins.do_egress(&mut self.data)
    }

    /// The length of the originally enqueued buffer.
    fn original_len(&self) -> usize {
        self.original_length
    }

    /// The current length, perhaps different to original length after
    /// `apply_egress_plugins`.
    fn actual_len(&self) -> usize {
        self.data.len()
    }

    /// The current actual bytes.
    fn as_bytes(&self) -> &[u8] {
        &self.data[..]
    }

    fn complete(&mut self) -> usize {
        self.data.clear();
        // Reclaim the buffer to get full capacity
        self.data.reserve(self.total_capacity);
        std::mem::take(&mut self.original_length)
    }
}

/// Adapt requirements of [`crate::Connection`] to those of the
/// [`wolfssl::IOCallbacks`] API.
pub(crate) struct WolfSSLIOAdapter {
    pub(crate) connection_type: ConnectionType,

    pub(crate) protocol_version: Version,

    pub(crate) outside_mtu: usize,

    /// [`ConnectionType::Datagram`] only: Send each datagram three
    /// times.
    pub(crate) aggressive_send: bool,

    /// Bytes received from outside, but not yet consumed
    pub(crate) recv_buf: BytesMut,

    /// In case of TCP, send can succeed even for partial data and the caller
    /// has to call send again with remaining data.
    /// But since we run the data through plugins, we cannot reliably let WolfSSL
    /// know about the remaining data to send.
    /// This buffer will be used to save the remaining data, to be sent in next call.
    pub(crate) send_buf: SendBuffer,

    /// Application provided object used to send data.
    pub(crate) io: OutsideIOSendCallbackArg,

    pub(crate) session_id: wire::SessionId,

    /// Plugins to act while egressing outside packet
    pub(crate) outside_plugins: Arc<PluginList>,
}

impl WolfSSLIOAdapter {
    pub(crate) fn set_session_id(&mut self, session_id: wire::SessionId) {
        self.session_id = session_id;
    }

    /// Force enable the IPv4 DF bit is set for all packets.
    pub(crate) fn enable_pmtud_probe(&self) {
        match self.io.enable_pmtud_probe() {
            Ok(_) => {}
            Err(err) => {
                // TODO: metric
                tracing::warn!(?err, "Failed to enable PMTUD probe");
            }
        }
    }

    /// Stop force enabling the IPv4 DF bit.
    pub(crate) fn disable_pmtud_probe(&self) {
        match self.io.disable_pmtud_probe() {
            Ok(_) => {}
            Err(err) => {
                // TODO: metric
                tracing::warn!(?err, "Failed to disable PMTUD probe");
            }
        }
    }

    fn udp_send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        // Prepend our `wire::Header` to the data we've been asked to
        // send.
        let h = wire::Header {
            version: self.protocol_version,
            aggressive_mode: false,
            session: self.session_id,
        };

        // Allocate max space
        let mut b = BytesMut::with_capacity(self.outside_mtu);
        h.append_to_wire(&mut b);
        b.extend_from_slice(buf);

        match self.outside_plugins.do_egress(&mut b) {
            PluginResult::Accept => {}
            PluginResult::Drop => {
                return IOCallbackResult::Ok(buf.len());
            }
            // Outside plugins cannot drop with reply
            PluginResult::DropWithReply(_) => {
                return IOCallbackResult::Ok(buf.len());
            }
            PluginResult::Error(e) => {
                use std::io::Error;
                return IOCallbackResult::Err(Error::other(e));
            }
        }

        // Send header + buf. If we are in aggressive mode we send it
        // a total of three times. On any send error we return
        // immediately without the remaining tries, otherwise we
        // return the result of the final attempt.

        if self.aggressive_send {
            match self.io.send(&b[..]) {
                IOCallbackResult::Ok(_) => {}
                wb @ IOCallbackResult::WouldBlock => return wb,
                err @ IOCallbackResult::Err(_) => return err,
            }

            match self.io.send(&b[..]) {
                IOCallbackResult::Ok(_) => {}
                wb @ IOCallbackResult::WouldBlock => return wb,
                err @ IOCallbackResult::Err(_) => return err,
            }
        }

        match self.io.send(&b[..]) {
            IOCallbackResult::Ok(n) => {
                // We've sent `n` bytes successfully out of
                // `wire::Header::WIRE_SIZE` + `b.len()` that we
                // tried to send.
                //
                // WolfSSL does not know about header, so return buf.len()
                if n > wire::Header::WIRE_SIZE {
                    IOCallbackResult::Ok(buf.len())
                } else {
                    // We didn't even manage to side the header, so we
                    // sent nothing from WolfSSL's point of view.
                    IOCallbackResult::Ok(0)
                }
            }
            wb @ IOCallbackResult::WouldBlock => wb,
            err @ IOCallbackResult::Err(_) => err,
        }
    }

    // In general, TCP send can succeed even for partial data and the caller
    // has to call send again with remaining data.
    // This api tries to hide the partial send behavior by buffering it.
    //
    // In brief, this api will store the remaining data in case of
    // partial send and returns `WouldBlock`. During the next call, it
    // then tries to send the previous remaining data
    //
    // See [`<repo>/lightway-core/README.md`] for more detailed explanation
    fn tcp_send(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        let send_buffer = &mut self.send_buf;

        if send_buffer.is_empty() {
            // Queue the new data.
            send_buffer.enqueue_buffer(buf);

            match send_buffer.apply_egress_plugins(&self.outside_plugins) {
                PluginResult::Accept => {}
                PluginResult::Drop => {
                    send_buffer.complete();
                    return IOCallbackResult::Ok(buf.len());
                }
                // Outside plugins cannot drop with reply
                PluginResult::DropWithReply(_) => {
                    send_buffer.complete();
                    return IOCallbackResult::Ok(buf.len());
                }
                PluginResult::Error(e) => {
                    use std::io::Error;
                    send_buffer.complete();
                    return IOCallbackResult::Err(Error::other(e));
                }
            }
        } else {
            // We have buffered data, so we have previously returned
            // `WouldBlock` and continue to send the remaining data.
            //
            // WolfSSL API says we will be called back with the same
            // data, possibly plus some extra (so the new `buf` we've
            // been given this time should have the original `buf`
            // from last time as a prefix).
            //
            // Continue to work through that original buffer until we
            // have sent all the corresponding bytes.
            debug_assert_le!(send_buffer.original_len(), buf.len());
        }

        match self.io.send(send_buffer.as_bytes()) {
            IOCallbackResult::Ok(n) if n == send_buffer.actual_len() => {
                // We've now sent everything we were originally
                // asked to, so signal completion of that original
                // `buf` (which after a previous `WouldBlock` may
                // only be a prefix of the current one).
                IOCallbackResult::Ok(send_buffer.complete())
            }
            IOCallbackResult::Ok(n) => {
                // There is more to send. Report
                // that we would block, eventually we will
                // completely succeed and will return the original
                // length via the path above.
                send_buffer.advance(n);
                IOCallbackResult::WouldBlock
            }
            wb @ IOCallbackResult::WouldBlock => wb,
            err @ IOCallbackResult::Err(_) => err,
        }
    }
}

impl wolfssl::IOCallbacks for WolfSSLIOAdapter {
    fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult<usize> {
        let pending_buf = &mut self.recv_buf;
        if pending_buf.is_empty() {
            return IOCallbackResult::WouldBlock;
        }

        let n = std::cmp::min(buf.len(), pending_buf.len());
        let mut pending_buf = pending_buf.split_to(n).freeze();
        pending_buf.copy_to_slice(&mut buf[..n]);
        debug_assert!(pending_buf.is_empty(), "Should have consumed everything");
        IOCallbackResult::Ok(n)
    }

    fn send(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        match self.connection_type {
            ConnectionType::Stream => self.tcp_send(buf),
            ConnectionType::Datagram => self.udp_send(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAX_OUTSIDE_MTU, OutsideIOSendCallback, Plugin, SessionId};
    use std::{
        collections::VecDeque,
        io::Error,
        sync::{Arc, Mutex},
    };
    use test_case::test_case;

    struct OneshotFakePlugin(Mutex<Option<PluginResult>>);

    impl OneshotFakePlugin {
        fn new(r: PluginResult) -> Box<Self> {
            Box::new(OneshotFakePlugin(Mutex::new(Some(r))))
        }
    }

    impl Plugin for OneshotFakePlugin {
        fn ingress(&self, _data: &mut BytesMut) -> PluginResult {
            std::unreachable!("Should not be testing ingress")
        }

        fn egress(&self, _data: &mut BytesMut) -> PluginResult {
            self.0.lock().unwrap().take().unwrap()
        }
    }

    struct FakeOutsideIOSend(Mutex<(VecDeque<IOCallbackResult<usize>>, Vec<u8>)>);

    impl FakeOutsideIOSend {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new((VecDeque::new(), Vec::new()))))
        }
        fn with_fakes(fakes: VecDeque<IOCallbackResult<usize>>) -> Arc<Self> {
            Arc::new(Self(Mutex::new((fakes, Vec::new()))))
        }
    }

    impl OutsideIOSendCallback for FakeOutsideIOSend {
        fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
            let (fakes, sent) = &mut *self.0.lock().unwrap();
            match fakes.pop_front() {
                Some(IOCallbackResult::Ok(n)) => {
                    assert_le!(n, buf.len());
                    sent.extend_from_slice(&buf[0..n]);
                    IOCallbackResult::Ok(n)
                }

                Some(x) => x,

                None => {
                    sent.extend_from_slice(buf);
                    IOCallbackResult::Ok(buf.len())
                }
            }
        }

        fn peer_addr(&self) -> std::net::SocketAddr {
            std::unreachable!("Should not be testing peer_addr");
        }
    }

    fn make_adapter(
        connection_type: ConnectionType,
        io: OutsideIOSendCallbackArg,
        outside_plugins: PluginList,
    ) -> WolfSSLIOAdapter {
        WolfSSLIOAdapter {
            connection_type,
            protocol_version: Version::MAXIMUM,
            aggressive_send: false,
            outside_mtu: MAX_OUTSIDE_MTU,
            recv_buf: Default::default(),
            send_buf: SendBuffer::new(MAX_OUTSIDE_MTU),
            io,
            session_id: SessionId::from_const(*b"\xde\xad\xbe\xef\xde\xad\xbe\xef"),
            outside_plugins: outside_plugins.into(),
        }
    }

    #[test_case(PluginResult::Accept => matches IOCallbackResult::Ok(n) if n == 3; "accept")]
    #[test_case(PluginResult::Drop => matches IOCallbackResult::Ok(n) if n == 3; "drop")]
    #[test_case(PluginResult::Error("ERR".into()) => matches IOCallbackResult::Err(e) if e.to_string() == "ERR"; "error")]
    fn udp_send_plugin(r: PluginResult) -> IOCallbackResult<usize> {
        let plugins: Vec<crate::PluginType> = vec![OneshotFakePlugin::new(r)];
        let plugins = PluginList::from(plugins);
        let a = make_adapter(ConnectionType::Datagram, FakeOutsideIOSend::new(), plugins);
        a.udp_send(b"abc")
    }

    // Reminder: `udp_send` adds a 16 byte [`wire::Header`].
    #[test_case(vec![] => matches(IOCallbackResult::Ok(n), v) if n == 9 && v == b"He\x01\x03\x00\x00\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xefabcdefghi"; "send all")]
    #[test_case(vec![IOCallbackResult::Ok(10)] => matches(IOCallbackResult::Ok(n), v) if n == 0 && v == b"He\x01\x03\x00\x00\x00\x00\xde\xad"; "less than header")]
    #[test_case(vec![IOCallbackResult::WouldBlock] => matches(IOCallbackResult::WouldBlock, v) if v.is_empty(); "would block")]
    #[test_case(vec![IOCallbackResult::Err(Error::other("ERR"))] => matches(IOCallbackResult::Err(e), v) if e.to_string() == "ERR" && v.is_empty(); "error")]
    fn udp_send_io(fakes: Vec<IOCallbackResult<usize>>) -> (IOCallbackResult<usize>, Vec<u8>) {
        let io = FakeOutsideIOSend::with_fakes(fakes.into());
        let a = make_adapter(ConnectionType::Datagram, io.clone(), Default::default());
        let r = a.udp_send(b"abcdefghi");

        let (fakes, sent) = &*io.0.lock().unwrap();
        assert!(fakes.is_empty());

        (r, sent.clone())
    }

    // Reminder: `udp_send` adds a 16 byte [`wire::Header`].
    #[test_case(vec![IOCallbackResult::WouldBlock] => matches(IOCallbackResult::WouldBlock, v) if v.is_empty(); "first would block")]
    #[test_case(vec![IOCallbackResult::Err(Error::other("ERR"))] => matches(IOCallbackResult::Err(e), v) if e.to_string() == "ERR" && v.is_empty(); "first error")]
    #[test_case(vec![IOCallbackResult::Ok(16+1), IOCallbackResult::WouldBlock] => matches(IOCallbackResult::WouldBlock, v) if v == b"He\x01\x03\x00\x00\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xefa"; "second would block")]
    #[test_case(vec![IOCallbackResult::Ok(16+1), IOCallbackResult::Err(Error::other("ERR"))] => matches(IOCallbackResult::Err(e), v) if e.to_string() == "ERR" && v == b"He\x01\x03\x00\x00\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xefa"; "second error")]
    #[test_case(vec![] => matches(IOCallbackResult::Ok(n), v) if n == 1 && v == b"He\x01\x03\x00\x00\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xefaHe\x01\x03\x00\x00\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xefaHe\x01\x03\x00\x00\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xefa"; "send all ok")]
    fn udp_send_io_aggressive(
        fakes: Vec<IOCallbackResult<usize>>,
    ) -> (IOCallbackResult<usize>, Vec<u8>) {
        let io = FakeOutsideIOSend::with_fakes(fakes.into());
        let mut a = make_adapter(ConnectionType::Datagram, io.clone(), Default::default());
        a.aggressive_send = true;

        let r = a.udp_send(b"a");

        let (fakes, sent) = &*io.0.lock().unwrap();
        assert!(fakes.is_empty());

        (r, sent.clone())
    }

    #[test_case(PluginResult::Accept => matches IOCallbackResult::Ok(n) if n == 3; "accept")]
    #[test_case(PluginResult::Drop => matches IOCallbackResult::Ok(n) if n == 3; "drop")]
    #[test_case(PluginResult::Error("ERR".into()) => matches IOCallbackResult::Err(e) if e.to_string() == "ERR"; "error")]
    fn tcp_send_plugin(r: PluginResult) -> IOCallbackResult<usize> {
        let plugins: Vec<crate::PluginType> = vec![OneshotFakePlugin::new(r)];
        let plugins = PluginList::from(plugins);
        let mut a = make_adapter(ConnectionType::Stream, FakeOutsideIOSend::new(), plugins);
        let r = a.tcp_send(b"abc");

        debug_assert!(a.send_buf.is_empty());

        r
    }

    #[test_case(vec![] => matches(IOCallbackResult::Ok(n), sent, buffered) if n == 9 && sent == b"abcdefghi" && buffered.is_empty(); "send all")]
    #[test_case(vec![IOCallbackResult::Ok(5)] => matches(IOCallbackResult::WouldBlock, sent, buffered) if sent == b"abcde" && buffered == b"fghi"; "partial send")]
    #[test_case(vec![IOCallbackResult::WouldBlock] => matches(IOCallbackResult::WouldBlock, sent, buffered) if sent.is_empty() && buffered == b"abcdefghi"; "would block")]
    #[test_case(vec![IOCallbackResult::Err(Error::other("ERR"))] => matches(IOCallbackResult::Err(e), sent, buffered) if e.to_string() == "ERR" && sent.is_empty() && buffered == b"abcdefghi"; "error")]
    fn tcp_send_io(
        fakes: Vec<IOCallbackResult<usize>>,
    ) -> (IOCallbackResult<usize>, Vec<u8>, Vec<u8>) {
        let io = FakeOutsideIOSend::with_fakes(fakes.into());
        let mut a = make_adapter(ConnectionType::Stream, io.clone(), Default::default());
        let r = a.tcp_send(b"abcdefghi");

        let (fakes, sent) = &*io.0.lock().unwrap();
        assert!(fakes.is_empty());

        (r, sent.clone(), a.send_buf.data.to_vec())
    }

    #[test_case(vec![IOCallbackResult::Ok(3), IOCallbackResult::Ok(4)] => matches(IOCallbackResult::WouldBlock, sent, buffered) if sent == b"abcdefg" && buffered == b"hi"; "partial resend")]
    #[test_case(vec![IOCallbackResult::Ok(3), IOCallbackResult::WouldBlock] => matches(IOCallbackResult::WouldBlock, sent, buffered) if sent == b"abc" && buffered == b"defghi"; "would block")]
    #[test_case(vec![IOCallbackResult::WouldBlock, IOCallbackResult::WouldBlock] => matches(IOCallbackResult::WouldBlock, sent, buffered) if sent.is_empty() && buffered == b"abcdefghi"; "still would block")]
    #[test_case(vec![IOCallbackResult::Ok(3), IOCallbackResult::Err(Error::other("ERR"))] => matches(IOCallbackResult::Err(e), sent, buffered) if e.to_string() == "ERR" && sent == b"abc" && buffered == b"defghi"; "error")]
    fn tcp_send_io_buffered(
        fakes: Vec<IOCallbackResult<usize>>,
    ) -> (IOCallbackResult<usize>, Vec<u8>, Vec<u8>) {
        let io = FakeOutsideIOSend::with_fakes(fakes.into());
        let mut a = make_adapter(ConnectionType::Stream, io.clone(), Default::default());
        let r = a.tcp_send(b"abcdefghi");
        assert!(matches!(r, IOCallbackResult::WouldBlock));

        let r = a.tcp_send(b"abcdefghi");

        let (fakes, sent) = &*io.0.lock().unwrap();
        assert!(fakes.is_empty());

        (r, sent.clone(), a.send_buf.data.to_vec())
    }

    #[test]
    fn send_buffer_enqueue() {
        let mut buf = SendBuffer::new(MAX_OUTSIDE_MTU);
        assert_eq!(buf.original_len(), 0);
        assert_eq!(buf.actual_len(), 0);

        buf.enqueue_buffer(b"ABCDEF");

        assert_eq!(buf.original_len(), 6);
        assert_eq!(buf.actual_len(), 6);
        assert_eq!(buf.as_bytes(), b"ABCDEF");
    }

    #[test]
    fn send_buffer_apply_egress_plugins() {
        let mut buf = SendBuffer::new(MAX_OUTSIDE_MTU);
        assert_eq!(buf.original_len(), 0);
        assert_eq!(buf.actual_len(), 0);

        buf.enqueue_buffer(b"ABCDEF");

        struct PaddingPlugin;

        impl PaddingPlugin {
            const PAD: &'static [u8] = b"GHI";
        }
        impl Plugin for PaddingPlugin {
            fn ingress(&self, _data: &mut BytesMut) -> PluginResult {
                std::unreachable!("Should not be testing ingress")
            }

            fn egress(&self, data: &mut BytesMut) -> PluginResult {
                data.extend_from_slice(Self::PAD);
                PluginResult::Accept
            }
        }

        let plugins: Vec<crate::PluginType> = vec![Box::new(PaddingPlugin)];
        let plugins = PluginList::from(plugins);

        buf.apply_egress_plugins(&plugins);
        assert_eq!(buf.original_len(), 6);
        assert_eq!(buf.actual_len(), 6 + PaddingPlugin::PAD.len());
        assert_eq!(buf.as_bytes(), b"ABCDEFGHI");
    }

    #[test]
    fn send_buffer_advance() {
        let mut buf = SendBuffer::new(MAX_OUTSIDE_MTU);
        assert_eq!(buf.original_len(), 0);
        assert_eq!(buf.actual_len(), 0);

        buf.enqueue_buffer(b"ABCDEF");

        assert_eq!(buf.original_len(), 6);
        assert_eq!(buf.actual_len(), 6);
        assert_eq!(buf.as_bytes(), b"ABCDEF");

        buf.advance(3);

        assert_eq!(buf.original_len(), 6);
        assert_eq!(buf.actual_len(), 3);
        assert_eq!(buf.as_bytes(), b"DEF");
        assert_lt!(buf.data.capacity(), buf.total_capacity);
    }

    #[test]
    fn send_buffer_complete() {
        let mut buf = SendBuffer::new(MAX_OUTSIDE_MTU);
        assert_eq!(buf.original_len(), 0);
        assert_eq!(buf.actual_len(), 0);

        buf.enqueue_buffer(b"ABCDEF");

        assert_eq!(buf.original_len(), 6);
        assert_eq!(buf.actual_len(), 6);
        assert_eq!(buf.as_bytes(), b"ABCDEF");

        buf.advance(3);

        let completed = buf.complete();
        assert_eq!(completed, 6);
        assert_eq!(buf.original_len(), 0);
        assert_eq!(buf.actual_len(), 0);
        assert_eq!(buf.data.capacity(), buf.total_capacity);
    }
}
