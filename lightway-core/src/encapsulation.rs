//! Encapsulation turns records into outside packets and outside
//! packets back into records. It owns the wire header and the outside
//! plugins.

use std::collections::VecDeque;
#[cfg(any(target_os = "linux", test))]
use std::num::NonZeroUsize;
use std::sync::Arc;

use bytes::{Buf, BytesMut};
use more_asserts::*;
use thiserror::Error;

use crate::tls::IOCallbackResult;

use crate::{
    ConnectionType, Header, OutsideIOSendCallbackArg, PluginResult, Version, plugin::PluginList,
    wire,
};

/// Per-connection UDP GSO coalescing buffer + batch state.
#[cfg(any(target_os = "linux", test))]
#[derive(Default)]
pub(crate) struct GsoBuffer {
    /// Coalescing buffer for the current GSO frame. Retained across
    /// batches — `clear()`ed on reset, never dropped — so the
    /// allocation is reused for the connection's lifetime. Starts
    /// (and stays, on connections that never coalesce) zero-capacity,
    /// costing only the `BytesMut` struct.
    buf: BytesMut,
    state: GsoBufferState,
}

/// State of the in-progress GSO batch.
#[cfg(any(target_os = "linux", test))]
#[derive(Default)]
enum GsoBufferState {
    /// Not coalescing — `udp_send` passes a single datagram straight
    /// to the socket (cf. a non-GSO skb, `gso_size == 0`).
    #[default]
    Passthrough,
    /// Batch open, awaiting the first segment; `gso_size` not yet
    /// established.
    Pending,
    /// First segment fixed `gso_size` and whether the batch carries
    /// expresslane records; later segments coalesce at this stride
    /// for `UDP_SEGMENT`.
    Coalescing(NonZeroUsize, bool),
}

#[cfg(any(target_os = "linux", test))]
impl GsoBuffer {
    /// Open a GSO batch. Reserves worst-case capacity on first call;
    /// subsequent calls are a no-op on the underlying allocation.
    pub(crate) fn open(&mut self) {
        debug_assert!(matches!(self.state, GsoBufferState::Passthrough));
        self.buf.reserve(crate::gso::MAX_GSO_FRAME_BYTES);
        self.state = GsoBufferState::Pending;
    }

    /// True iff a batch is open (state ≠ Passthrough). `udp_send`
    /// uses this to dispatch between coalescing and pass-through.
    pub(crate) fn is_batching(&self) -> bool {
        !matches!(self.state, GsoBufferState::Passthrough)
    }

    /// Append one encrypted segment to the frame — echoes `skb_put`.
    ///
    /// The first segment fixes `gso_size`; every later segment must
    /// be `<= gso_size`, a shorter one being the final datagram. A
    /// non-final segment shorter than `gso_size` would misalign the
    /// kernel's slicing.
    ///
    /// Every segment shares one header, so the first segment also
    /// fixes `expresslane` for the batch.
    pub(crate) fn put(&mut self, seg: &[u8], expresslane: bool) {
        match self.state {
            GsoBufferState::Passthrough => unreachable!("put before open"),
            GsoBufferState::Pending => {
                let Some(gso_size) = NonZeroUsize::new(seg.len()) else {
                    unreachable!("zero-length first GSO segment")
                };
                self.state = GsoBufferState::Coalescing(gso_size, expresslane);
            }
            GsoBufferState::Coalescing(gso_size, first) => {
                debug_assert!(seg.len() <= gso_size.get());
                debug_assert_eq!(first, expresslane);
            }
        }
        self.buf.extend_from_slice(seg);
    }

    /// The assembled frame, its `gso_size` for the `UDP_SEGMENT`
    /// sendmsg and its expresslane flag. `None` when nothing coalesced
    /// (Passthrough or Pending). This does not reset the buffer, so call
    /// `reset` after the send.
    pub(crate) fn frame(&self) -> Option<(&[u8], NonZeroUsize, bool)> {
        match self.state {
            GsoBufferState::Coalescing(gso_size, expresslane) => {
                Some((&self.buf[..], gso_size, expresslane))
            }
            _ => None,
        }
    }

    /// Clear the frame and return to `Passthrough`, keeping `buf`'s
    /// capacity.
    pub(crate) fn reset(&mut self) {
        self.buf.clear();
        self.state = GsoBufferState::Passthrough;
    }
}

/// Wraps records into outside packets and sends them on the outside IO.
pub(crate) struct Encapsulation {
    pub(crate) connection_type: ConnectionType,

    pub(crate) protocol_version: Version,

    pub(crate) outside_mtu: usize,

    /// [`ConnectionType::Stream`] only: outside packets that the
    /// outside IO did not take yet, in order. The head can be partly
    /// sent.
    pending: VecDeque<BytesMut>,

    /// [`ConnectionType::Datagram`] only: the buffer that each outside
    /// packet is built in, kept so that a send does not allocate.
    scratch: BytesMut,

    /// Per-connection UDP GSO coalescing buffer + batch state. On
    /// connections that never see GSO, this stays zero-capacity and
    /// costs only the `GsoBuffer` struct (no heap).
    #[cfg(target_os = "linux")]
    pub(crate) gso_buf: GsoBuffer,

    /// Application provided object used to send data.
    pub(crate) io: OutsideIOSendCallbackArg,

    pub(crate) session_id: wire::SessionId,

    /// Plugins to act while egressing outside packet
    pub(crate) outside_plugins: Arc<PluginList>,
}

impl Encapsulation {
    pub(crate) fn new(
        connection_type: ConnectionType,
        protocol_version: Version,
        outside_mtu: usize,
        io: OutsideIOSendCallbackArg,
        session_id: wire::SessionId,
        outside_plugins: Arc<PluginList>,
    ) -> Self {
        Self {
            connection_type,
            protocol_version,
            outside_mtu,
            pending: VecDeque::new(),
            scratch: BytesMut::new(),
            #[cfg(target_os = "linux")]
            gso_buf: GsoBuffer::default(),
            io,
            session_id,
            outside_plugins,
        }
    }

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

    pub(crate) fn udp_send(
        &mut self,
        buf: &[u8],
        expresslane_data: bool,
    ) -> IOCallbackResult<usize> {
        // GSO buffering: when a batch is open, coalesce the raw
        // post-encrypt, pre-`wire::Header` bytes; `udp_send_gso` will
        // later wrap each segment with `wire::Header` and flush via
        // `sendmsg(UDP_SEGMENT)`. Both DTLS and expresslane callers
        // hand us bytes in the same shape (post-encrypt, no header),
        // so this branch covers both.
        #[cfg(target_os = "linux")]
        if self.gso_buf.is_batching() {
            self.gso_buf.put(buf, expresslane_data);
            return IOCallbackResult::Ok(buf.len());
        }

        let mut b = std::mem::take(&mut self.scratch);
        b.clear();
        b.reserve(self.outside_mtu);
        let res = self.udp_send_in(&mut b, buf, expresslane_data);
        self.scratch = b;
        res
    }

    fn udp_send_in(
        &mut self,
        b: &mut BytesMut,
        buf: &[u8],
        expresslane_data: bool,
    ) -> IOCallbackResult<usize> {
        // Prepend our `wire::Header` to the data we've been asked to
        // send.
        let h = wire::Header {
            version: self.protocol_version,
            aggressive_mode: false,
            expresslane_data,
            session: self.session_id,
        };
        h.append_to_wire(b);
        b.extend_from_slice(buf);

        match self.outside_plugins.do_egress(b) {
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

        match self.io.send(&b[..]) {
            IOCallbackResult::Ok(n) => {
                // We've sent `n` bytes successfully out of
                // `wire::Header::WIRE_SIZE` + `b.len()` that we
                // tried to send.
                //
                // TLS library does not know about header, so return buf.len()
                if n > wire::Header::WIRE_SIZE {
                    IOCallbackResult::Ok(buf.len())
                } else {
                    // We didn't even manage to side the header, so we
                    // sent nothing from the TLS library's point of view.
                    IOCallbackResult::Ok(0)
                }
            }
            wb @ IOCallbackResult::WouldBlock => wb,
            err @ IOCallbackResult::Err(_) => err,
        }
    }

    /// Take the raw encrypted segments coalesced in `self.gso_buf`,
    /// wrap each with `wire::Header` (+ plugins), and send as one
    /// `sendmsg` with `UDP_SEGMENT`. The caller is responsible for
    /// calling `gso_buf.reset()` after this returns.
    ///
    /// Every segment but the last is `gso_size` long, so the frame
    /// holds `ceil(len / gso_size)` segments.
    ///
    /// When no outside plugins are configured, the encrypted payload
    /// is sent zero-copy: the kernel gathers a shared header buffer
    /// and slices of `tun_buf` via `iovec`, with no intermediate copy
    /// of the segment bytes.
    #[cfg(target_os = "linux")]
    pub(crate) fn udp_send_gso(&mut self) -> IOCallbackResult<usize> {
        use std::io::{Error, IoSlice};

        // No coalesced frame yet — caller's `gso.reset()` cleanup
        // path runs unconditionally, so this is also the safe exit
        // when nothing was buffered.
        let Some((tun_buf, tun_gso_size, expresslane_data)) = self.gso_buf.frame() else {
            return IOCallbackResult::Ok(0);
        };
        let tun_gso_size = tun_gso_size.get();
        let gso_segs = tun_buf.len().div_ceil(tun_gso_size);

        // Same Lightway header for every segment.
        let hdr = wire::Header {
            version: self.protocol_version,
            aggressive_mode: false,
            expresslane_data,
            session: self.session_id,
        };
        let mut hdr_buf = BytesMut::with_capacity(wire::Header::WIRE_SIZE);
        hdr.append_to_wire(&mut hdr_buf);

        // Fast path: no outside plugins. Segments are not mutated, so
        // we scatter-gather via iovec — shared header buffer plus
        // borrowed slices of `tun_buf`, zero payload copies.
        if self.outside_plugins.is_empty() {
            let stride = (wire::Header::WIRE_SIZE + tun_gso_size) as u16;
            let mut iovs: Vec<IoSlice<'_>> = Vec::with_capacity(gso_segs * 2);
            for i in 0..gso_segs {
                let start = i * tun_gso_size;
                let end = ((i + 1) * tun_gso_size).min(tun_buf.len());
                iovs.push(IoSlice::new(&hdr_buf[..]));
                iovs.push(IoSlice::new(&tun_buf[start..end]));
            }
            return self.io.send_gso(&iovs, stride);
        }

        // Plugin path: each segment is built into its own BytesMut so
        // plugins can freely mutate it. The Vec<BytesMut> outlives the
        // Vec<IoSlice> built from it, so the borrows are sound.
        let mut segs: Vec<BytesMut> = Vec::with_capacity(gso_segs);
        let mut wire_gso_size: Option<usize> = None;

        for i in 0..gso_segs {
            let start = i * tun_gso_size;
            let end = ((i + 1) * tun_gso_size).min(tun_buf.len());
            debug_assert_le!(start, end);

            let mut seg = BytesMut::with_capacity(self.outside_mtu);
            seg.extend_from_slice(&hdr_buf[..]);
            seg.extend_from_slice(&tun_buf[start..end]);

            match self.outside_plugins.do_egress(&mut seg) {
                PluginResult::Accept => {}
                PluginResult::Drop | PluginResult::DropWithReply(_) => continue,
                PluginResult::Error(e) => {
                    return IOCallbackResult::Err(Error::other(e));
                }
            }

            // UDP_SEGMENT requires every segment except the last to
            // have identical stride.
            let is_last = i == gso_segs - 1;
            match wire_gso_size {
                None => wire_gso_size = Some(seg.len()),
                Some(s) if !is_last && seg.len() != s => {
                    return IOCallbackResult::Err(Error::other(
                        "outside plugins produced non-uniform GSO segment size",
                    ));
                }
                Some(s) if is_last && seg.len() > s => {
                    return IOCallbackResult::Err(Error::other(
                        "outside plugins produced oversized trailing GSO segment",
                    ));
                }
                _ => {}
            }

            segs.push(seg);
        }

        // All segments dropped by plugins — nothing to put on the wire,
        // but report success for the inside bytes the caller handed us.
        if segs.is_empty() {
            return IOCallbackResult::Ok(tun_buf.len());
        }

        let stride = wire_gso_size.unwrap_or(0) as u16;
        let iovs: Vec<IoSlice<'_>> = segs.iter().map(|s| IoSlice::new(&s[..])).collect();
        self.io.send_gso(&iovs, stride)
    }

    /// Wrap one record into an outside packet and send it.
    ///
    /// On a datagram path, a packet that the outside IO cannot take
    /// is dropped. On a stream path, it waits in order until
    /// [`Encapsulation::flush`] sends it.
    pub(crate) fn send(&mut self, record: BytesMut) -> std::io::Result<()> {
        match self.connection_type {
            ConnectionType::Stream => self.tcp_send(record),
            ConnectionType::Datagram => match self.udp_send(&record, false) {
                IOCallbackResult::Ok(_) | IOCallbackResult::WouldBlock => Ok(()),
                IOCallbackResult::Err(e) => Err(e),
            },
        }
    }

    /// Whether outside packets wait for the outside IO. Only a stream
    /// path waits.
    pub(crate) fn is_blocked(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Replace the outside IO. Waiting packets are dropped, since a
    /// partly sent packet cannot continue on a new stream.
    pub(crate) fn set_outside_io(&mut self, io: OutsideIOSendCallbackArg) {
        self.io = io;
        self.pending.clear();
    }

    fn tcp_send(&mut self, mut packet: BytesMut) -> std::io::Result<()> {
        match self.outside_plugins.do_egress(&mut packet) {
            PluginResult::Accept => {}
            // Outside plugins cannot drop with reply
            PluginResult::Drop | PluginResult::DropWithReply(_) => return Ok(()),
            PluginResult::Error(e) => return Err(std::io::Error::other(e)),
        }
        self.pending.push_back(packet);
        self.flush()
    }

    /// Send the waiting outside packets, until the outside IO blocks.
    pub(crate) fn flush(&mut self) -> std::io::Result<()> {
        while let Some(head) = self.pending.front_mut() {
            match self.io.send(head) {
                IOCallbackResult::Ok(n) if n == head.len() => {
                    self.pending.pop_front();
                }
                IOCallbackResult::Ok(n) => {
                    head.advance(n);
                    return Ok(());
                }
                IOCallbackResult::WouldBlock => return Ok(()),
                IOCallbackResult::Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
/// Packet structure used by application to inject outside packets into lightway-core
pub enum OutsidePacket<'pkt> {
    /// Opaque wire packet, before running plugin chain
    Wire(&'pkt mut BytesMut, ConnectionType),
    /// Raw TCP frame, after running plugin chain
    TcpFrame(&'pkt mut BytesMut),
    /// Raw UDP frame, after running plugin chain
    UdpFrame(&'pkt mut BytesMut, Header),
}

impl<'pkt> OutsidePacket<'pkt> {
    pub(crate) fn into_payload(self) -> Option<&'pkt mut BytesMut> {
        match self {
            Self::Wire(_, _) => None,
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
    ) -> Result<Self, OutsidePacketError> {
        match self {
            Self::Wire(buf, conn_type) => {
                let buf = match plugins.do_ingress(buf) {
                    PluginResult::Accept => buf,
                    PluginResult::Drop => return Err(OutsidePacketError::PluginDrop),
                    PluginResult::DropWithReply(_) => return Err(OutsidePacketError::PluginDrop),
                    PluginResult::Error(e) => return Err(OutsidePacketError::PluginError(e)),
                };

                match conn_type {
                    ConnectionType::Stream => Ok(Self::TcpFrame(buf)),
                    ConnectionType::Datagram => {
                        let hdr = Header::try_from_wire(buf)
                            .map_err(|e| OutsidePacketError::BadWireHeader(e.into()))?;
                        Ok(Self::UdpFrame(buf, hdr))
                    }
                }
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

        fn send_gso(
            &self,
            _bufs: &[std::io::IoSlice<'_>],
            _gso_size: u16,
        ) -> IOCallbackResult<usize> {
            IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }

        fn peer_addr(&self) -> std::net::SocketAddr {
            std::unreachable!("Should not be testing peer_addr");
        }
    }

    fn make_encapsulation(
        connection_type: ConnectionType,
        io: OutsideIOSendCallbackArg,
        outside_plugins: PluginList,
    ) -> Encapsulation {
        Encapsulation::new(
            connection_type,
            Version::MAXIMUM,
            MAX_OUTSIDE_MTU,
            io,
            SessionId::from_const(*b"\xde\xad\xbe\xef\xde\xad\xbe\xef"),
            outside_plugins.into(),
        )
    }

    #[test_case(PluginResult::Accept => matches IOCallbackResult::Ok(n) if n == 3; "accept")]
    #[test_case(PluginResult::Drop => matches IOCallbackResult::Ok(n) if n == 3; "drop")]
    #[test_case(PluginResult::Error("ERR".into()) => matches IOCallbackResult::Err(e) if e.to_string() == "ERR"; "error")]
    fn udp_send_plugin(r: PluginResult) -> IOCallbackResult<usize> {
        let plugins: Vec<crate::PluginType> = vec![OneshotFakePlugin::new(r)];
        let plugins = PluginList::from(plugins);
        let mut a = make_encapsulation(ConnectionType::Datagram, FakeOutsideIOSend::new(), plugins);
        a.udp_send(b"abc", false)
    }

    // Reminder: `udp_send` adds a 16 byte [`wire::Header`].
    #[test_case(vec![] => matches(IOCallbackResult::Ok(n), v) if n == 9 && v == b"He\x01\x03\x00\x00\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xefabcdefghi"; "send all")]
    #[test_case(vec![IOCallbackResult::Ok(10)] => matches(IOCallbackResult::Ok(n), v) if n == 0 && v == b"He\x01\x03\x00\x00\x00\x00\xde\xad"; "less than header")]
    #[test_case(vec![IOCallbackResult::WouldBlock] => matches(IOCallbackResult::WouldBlock, v) if v.is_empty(); "would block")]
    #[test_case(vec![IOCallbackResult::Err(Error::other("ERR"))] => matches(IOCallbackResult::Err(e), v) if e.to_string() == "ERR" && v.is_empty(); "error")]
    fn udp_send_io(fakes: Vec<IOCallbackResult<usize>>) -> (IOCallbackResult<usize>, Vec<u8>) {
        let io = FakeOutsideIOSend::with_fakes(fakes.into());
        let mut a = make_encapsulation(ConnectionType::Datagram, io.clone(), Default::default());
        let r = a.udp_send(b"abcdefghi", false);

        let (fakes, sent) = &*io.0.lock().unwrap();
        assert!(fakes.is_empty());

        (r, sent.clone())
    }

    #[test_case(vec![IOCallbackResult::WouldBlock] => matches(Ok(()), v) if v.is_empty(); "would block")]
    #[test_case(vec![IOCallbackResult::Err(Error::other("ERR"))] => matches(Err(e), v) if e.to_string() == "ERR" && v.is_empty(); "error")]
    fn datagram_send_drops_a_blocked_packet(
        fakes: Vec<IOCallbackResult<usize>>,
    ) -> (std::io::Result<()>, Vec<u8>) {
        let io = FakeOutsideIOSend::with_fakes(fakes.into());
        let mut e = make_encapsulation(ConnectionType::Datagram, io.clone(), Default::default());
        let r = e.send(BytesMut::from(&b"abc"[..]));
        assert!(!e.is_blocked());

        let (fakes, sent) = &*io.0.lock().unwrap();
        assert!(fakes.is_empty());

        (r, sent.clone())
    }

    #[test_case(PluginResult::Accept => matches (Ok(()), v) if v == b"abc"; "accept")]
    #[test_case(PluginResult::Drop => matches (Ok(()), v) if v.is_empty(); "drop")]
    #[test_case(PluginResult::Error("ERR".into()) => matches (Err(e), v) if e.to_string() == "ERR" && v.is_empty(); "error")]
    fn stream_send_plugin(r: PluginResult) -> (std::io::Result<()>, Vec<u8>) {
        let plugins: Vec<crate::PluginType> = vec![OneshotFakePlugin::new(r)];
        let plugins = PluginList::from(plugins);
        let io = FakeOutsideIOSend::new();
        let mut e = make_encapsulation(ConnectionType::Stream, io.clone(), plugins);
        let r = e.send(BytesMut::from(&b"abc"[..]));
        assert!(!e.is_blocked());

        let sent = io.0.lock().unwrap().1.clone();
        (r, sent)
    }

    #[test_case(vec![] => matches (Ok(()), sent, waiting) if sent == b"abcdefghi" && waiting.is_empty(); "send all")]
    #[test_case(vec![IOCallbackResult::Ok(5)] => matches (Ok(()), sent, waiting) if sent == b"abcde" && waiting == b"fghi"; "partial send")]
    #[test_case(vec![IOCallbackResult::WouldBlock] => matches (Ok(()), sent, waiting) if sent.is_empty() && waiting == b"abcdefghi"; "would block")]
    #[test_case(vec![IOCallbackResult::Err(Error::other("ERR"))] => matches (Err(e), sent, waiting) if e.to_string() == "ERR" && sent.is_empty() && waiting == b"abcdefghi"; "error")]
    fn stream_send_io(
        fakes: Vec<IOCallbackResult<usize>>,
    ) -> (std::io::Result<()>, Vec<u8>, Vec<u8>) {
        let io = FakeOutsideIOSend::with_fakes(fakes.into());
        let mut e = make_encapsulation(ConnectionType::Stream, io.clone(), Default::default());
        let r = e.send(BytesMut::from(&b"abcdefghi"[..]));
        assert_eq!(e.is_blocked(), !e.pending.is_empty());

        let (fakes, sent) = &*io.0.lock().unwrap();
        assert!(fakes.is_empty());

        (
            r,
            sent.clone(),
            e.pending.iter().flatten().copied().collect(),
        )
    }

    #[test]
    fn stream_keeps_order_while_blocked() {
        let io = FakeOutsideIOSend::with_fakes(
            vec![IOCallbackResult::Ok(3), IOCallbackResult::WouldBlock].into(),
        );
        let mut e = make_encapsulation(ConnectionType::Stream, io.clone(), Default::default());
        e.send(BytesMut::from(&b"abcdefghi"[..])).unwrap();
        e.send(BytesMut::from(&b"jkl"[..])).unwrap();
        assert!(e.is_blocked());
        assert_eq!(io.0.lock().unwrap().1, b"abc");

        e.flush().unwrap();
        assert!(!e.is_blocked());
        assert_eq!(io.0.lock().unwrap().1, b"abcdefghijkl");
    }

    #[test]
    fn set_outside_io_drops_waiting_packets() {
        let io = FakeOutsideIOSend::with_fakes(vec![IOCallbackResult::Ok(3)].into());
        let mut e = make_encapsulation(ConnectionType::Stream, io, Default::default());
        e.send(BytesMut::from(&b"abcdefghi"[..])).unwrap();
        assert!(e.is_blocked());

        let io = FakeOutsideIOSend::new();
        e.set_outside_io(io.clone());
        assert!(!e.is_blocked());

        e.send(BytesMut::from(&b"jkl"[..])).unwrap();
        assert_eq!(io.0.lock().unwrap().1, b"jkl");
    }

    #[test]
    fn gso_default_is_passthrough() {
        let g = GsoBuffer::default();
        assert!(!g.is_batching());
        assert!(g.frame().is_none());
        assert_eq!(g.buf.capacity(), 0);
    }

    #[test]
    fn gso_open_transitions_to_pending() {
        let mut g = GsoBuffer::default();
        g.open();
        assert!(g.is_batching());
        assert!(g.frame().is_none());
        assert!(g.buf.capacity() >= crate::gso::MAX_GSO_FRAME_BYTES);
    }

    #[test]
    fn gso_put_fixes_stride() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[0xAB; 1280], false);

        let (bytes, stride, _) = g.frame().expect("Coalescing");
        assert_eq!(bytes.len(), 1280);
        assert_eq!(stride.get(), 1280);
        assert!(bytes.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn gso_put_appends_subsequent_segments() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[0xAA; 1280], false);
        g.put(&[0xBB; 1280], false);

        let (bytes, stride, _) = g.frame().expect("Coalescing");
        assert_eq!(bytes.len(), 2560);
        assert_eq!(stride.get(), 1280);
        assert!(bytes[..1280].iter().all(|&b| b == 0xAA));
        assert!(bytes[1280..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn gso_put_allows_shorter_trailing() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[0xAA; 1280], false);
        g.put(&[0xBB; 800], false);

        let (bytes, stride, _) = g.frame().expect("Coalescing");
        assert_eq!(bytes.len(), 1280 + 800);
        assert_eq!(stride.get(), 1280);
    }

    #[test]
    fn gso_reset_clears_state_keeps_capacity() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[0xAA; 1280], false);
        let cap_before = g.buf.capacity();
        g.reset();

        assert!(!g.is_batching());
        assert!(g.frame().is_none());
        assert_eq!(g.buf.len(), 0);
        assert_eq!(g.buf.capacity(), cap_before);
        assert!(g.buf.capacity() >= crate::gso::MAX_GSO_FRAME_BYTES);
    }

    #[test]
    fn gso_open_then_reset_then_open_reuses_buf() {
        let mut g = GsoBuffer::default();
        g.open();
        let cap_after_first_open = g.buf.capacity();
        g.put(&[0xAA; 1280], false);
        g.reset();

        g.open();
        assert_eq!(g.buf.capacity(), cap_after_first_open);
        assert!(g.is_batching());
    }

    #[test]
    #[should_panic(expected = "put before open")]
    fn gso_put_without_open_panics() {
        let mut g = GsoBuffer::default();
        g.put(&[0xAA; 1280], false);
    }

    #[test]
    #[should_panic(expected = "zero-length first GSO segment")]
    fn gso_put_zero_length_first_segment_panics() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[], false);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn gso_put_oversized_segment_debug_asserts() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[0xAA; 1280], false);
        g.put(&[0xBB; 1281], false);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn udp_send_gso_sends_every_segment_in_the_batch() {
        struct GsoCapture(Mutex<Vec<(Vec<u8>, u16)>>);

        impl OutsideIOSendCallback for GsoCapture {
            fn send(&self, _buf: &[u8]) -> IOCallbackResult<usize> {
                std::unreachable!("a batch sends only with GSO")
            }

            fn send_gso(
                &self,
                bufs: &[std::io::IoSlice<'_>],
                gso_size: u16,
            ) -> IOCallbackResult<usize> {
                let frame: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
                let n = frame.len();
                self.0.lock().unwrap().push((frame, gso_size));
                IOCallbackResult::Ok(n)
            }

            fn peer_addr(&self) -> std::net::SocketAddr {
                std::unreachable!("Should not be testing peer_addr");
            }
        }

        let io = Arc::new(GsoCapture(Mutex::new(Vec::new())));
        let mut e = make_encapsulation(ConnectionType::Datagram, io.clone(), Default::default());
        e.gso_buf.open();
        for seg in [&b"abcd"[..], b"efgh", b"ij"] {
            assert!(matches!(e.udp_send(seg, true), IOCallbackResult::Ok(_)));
        }
        assert!(matches!(e.udp_send_gso(), IOCallbackResult::Ok(_)));

        let mut hdr = BytesMut::new();
        wire::Header {
            version: Version::MAXIMUM,
            aggressive_mode: false,
            expresslane_data: true,
            session: e.session_id,
        }
        .append_to_wire(&mut hdr);
        let expected: Vec<u8> = [&b"abcd"[..], b"efgh", b"ij"]
            .iter()
            .flat_map(|seg| [&hdr[..], seg].concat())
            .collect();

        let sent = io.0.lock().unwrap();
        assert_eq!(
            *sent,
            vec![(expected, (wire::Header::WIRE_SIZE + 4) as u16)]
        );
    }
}
