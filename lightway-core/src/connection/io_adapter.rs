#[cfg(any(target_os = "linux", test))]
use std::num::NonZeroUsize;
use std::sync::Arc;

use bytes::{Buf, BytesMut};
use delegate::delegate;
use more_asserts::*;

use crate::tls::IOCallbackResult;

use crate::{
    ConnectionType, OutsideIOSendCallbackArg, PluginResult, Version, plugin::PluginList, wire,
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
    /// First segment fixed `gso_size`; later segments coalesce at
    /// this stride for `UDP_SEGMENT`.
    Coalescing(NonZeroUsize),
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
    pub(crate) fn put(&mut self, seg: &[u8]) {
        match self.state {
            GsoBufferState::Passthrough => unreachable!("put before open"),
            GsoBufferState::Pending => {
                let Some(gso_size) = NonZeroUsize::new(seg.len()) else {
                    unreachable!("zero-length first GSO segment")
                };
                self.state = GsoBufferState::Coalescing(gso_size);
            }
            GsoBufferState::Coalescing(gso_size) => {
                debug_assert!(seg.len() <= gso_size.get())
            }
        }
        self.buf.extend_from_slice(seg);
    }

    /// The assembled frame and its `gso_size` for the `UDP_SEGMENT`
    /// sendmsg, or `None` if nothing was coalesced (Passthrough or
    /// Pending). Does not reset — call `reset` after the send.
    pub(crate) fn frame(&self) -> Option<(&[u8], NonZeroUsize)> {
        match self.state {
            GsoBufferState::Coalescing(gso_size) => Some((&self.buf[..], gso_size)),
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

/// Flush GSO wire segments to the socket, splitting the batch into
/// multiple `sendmsg(UDP_SEGMENT)` calls when it exceeds the kernel's
/// single-send payload limit ([`crate::gso::MAX_GSO_SEND_BYTES`] — the
/// kernel builds one skb per send, bounded by the 64KiB maximum IP
/// datagram size, and rejects anything larger with `EMSGSIZE`).
///
/// `iovs` holds `entries_per_seg` gather entries per wire segment;
/// every segment is `stride` bytes except possibly a shorter final
/// one. Chunks split on segment boundaries, so the uniform-stride
/// requirement of `UDP_SEGMENT` holds within each call.
///
/// On a mid-batch failure the earlier chunks are already on the wire
/// and cannot be retried; the failure is surfaced for the caller's
/// log/metric and the remainder is dropped (datagram semantics — the
/// peer's transport recovers the loss).
#[cfg(target_os = "linux")]
fn send_gso_chunked(
    io: &OutsideIOSendCallbackArg,
    iovs: &[std::io::IoSlice<'_>],
    entries_per_seg: usize,
    stride: u16,
) -> IOCallbackResult<usize> {
    let segs_per_send = std::cmp::max(1, crate::gso::MAX_GSO_SEND_BYTES / stride.max(1) as usize);
    let entries_per_send = segs_per_send * entries_per_seg;

    if iovs.len() <= entries_per_send {
        return io.send_gso(iovs, stride);
    }

    let mut sent = 0;
    for chunk in iovs.chunks(entries_per_send) {
        match io.send_gso(chunk, stride) {
            IOCallbackResult::Ok(n) => sent += n,
            other => return other,
        }
    }
    IOCallbackResult::Ok(sent)
}

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

/// Adapt requirements of [`crate::Connection`] to those of the TLS/DTLS I/O API.
pub(crate) struct TlsIOAdapter {
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
    /// But since we run the data through plugins, we cannot reliably let the TLS layer
    /// know about the remaining data to send.
    /// This buffer will be used to save the remaining data, to be sent in next call.
    pub(crate) send_buf: SendBuffer,

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

impl TlsIOAdapter {
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
            self.gso_buf.put(buf);
            return IOCallbackResult::Ok(buf.len());
        }

        // Prepend our `wire::Header` to the data we've been asked to
        // send.
        let h = wire::Header {
            version: self.protocol_version,
            aggressive_mode: false,
            expresslane_data,
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
    /// When no outside plugins are configured, the encrypted payload
    /// is sent zero-copy: the kernel gathers a shared header buffer
    /// and slices of `tun_buf` via `iovec`, with no intermediate copy
    /// of the segment bytes.
    #[cfg(target_os = "linux")]
    pub(crate) fn udp_send_gso(
        &mut self,
        gso_segs: usize,
        expresslane_data: bool,
    ) -> IOCallbackResult<usize> {
        use std::io::{Error, IoSlice};

        // No coalesced frame yet — caller's `gso.reset()` cleanup
        // path runs unconditionally, so this is also the safe exit
        // when nothing was buffered.
        let Some((tun_buf, tun_gso_size)) = self.gso_buf.frame() else {
            return IOCallbackResult::Ok(0);
        };
        let tun_gso_size = tun_gso_size.get();

        if gso_segs == 0 {
            return IOCallbackResult::Ok(0);
        }

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
            return send_gso_chunked(&self.io, &iovs, 2, stride);
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
        send_gso_chunked(&self.io, &iovs, 1, stride)
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
            // TLS API says we will be called back with the same
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

impl crate::tls::IOCallbacks for TlsIOAdapter {
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
            ConnectionType::Datagram => self.udp_send(buf, false),
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

    /// Scripted results and the recorded `(total_bytes, gso_size)` of
    /// every `send_gso` call.
    #[cfg(target_os = "linux")]
    type FakeGsoState = (VecDeque<IOCallbackResult<usize>>, Vec<(usize, u16)>);

    /// Records every `send_gso` call as `(total_bytes, gso_size)`,
    /// optionally failing calls from a scripted queue first.
    #[cfg(target_os = "linux")]
    struct FakeGsoIOSend(Mutex<FakeGsoState>);

    #[cfg(target_os = "linux")]
    impl FakeGsoIOSend {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new((VecDeque::new(), Vec::new()))))
        }
        fn with_fakes(fakes: VecDeque<IOCallbackResult<usize>>) -> Arc<Self> {
            Arc::new(Self(Mutex::new((fakes, Vec::new()))))
        }
        fn calls(&self) -> Vec<(usize, u16)> {
            self.0.lock().unwrap().1.clone()
        }
    }

    #[cfg(target_os = "linux")]
    impl OutsideIOSendCallback for FakeGsoIOSend {
        fn send(&self, _buf: &[u8]) -> IOCallbackResult<usize> {
            std::unreachable!("Should not be testing send");
        }

        fn send_gso(
            &self,
            bufs: &[std::io::IoSlice<'_>],
            gso_size: u16,
        ) -> IOCallbackResult<usize> {
            let total: usize = bufs.iter().map(|b| b.len()).sum();
            let (fakes, calls) = &mut *self.0.lock().unwrap();
            calls.push((total, gso_size));
            match fakes.pop_front() {
                Some(r) => r,
                None => IOCallbackResult::Ok(total),
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
    ) -> TlsIOAdapter {
        TlsIOAdapter {
            connection_type,
            protocol_version: Version::MAXIMUM,
            aggressive_send: false,
            outside_mtu: MAX_OUTSIDE_MTU,
            recv_buf: Default::default(),
            send_buf: SendBuffer::new(MAX_OUTSIDE_MTU),
            io,
            session_id: SessionId::from_const(*b"\xde\xad\xbe\xef\xde\xad\xbe\xef"),
            outside_plugins: outside_plugins.into(),
            #[cfg(target_os = "linux")]
            gso_buf: GsoBuffer::default(),
        }
    }

    #[test_case(PluginResult::Accept => matches IOCallbackResult::Ok(n) if n == 3; "accept")]
    #[test_case(PluginResult::Drop => matches IOCallbackResult::Ok(n) if n == 3; "drop")]
    #[test_case(PluginResult::Error("ERR".into()) => matches IOCallbackResult::Err(e) if e.to_string() == "ERR"; "error")]
    fn udp_send_plugin(r: PluginResult) -> IOCallbackResult<usize> {
        let plugins: Vec<crate::PluginType> = vec![OneshotFakePlugin::new(r)];
        let plugins = PluginList::from(plugins);
        let mut a = make_adapter(ConnectionType::Datagram, FakeOutsideIOSend::new(), plugins);
        a.udp_send(b"abc", false)
    }

    // Reminder: `udp_send` adds a 16 byte [`wire::Header`].
    #[test_case(vec![] => matches(IOCallbackResult::Ok(n), v) if n == 9 && v == b"He\x01\x03\x00\x00\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xefabcdefghi"; "send all")]
    #[test_case(vec![IOCallbackResult::Ok(10)] => matches(IOCallbackResult::Ok(n), v) if n == 0 && v == b"He\x01\x03\x00\x00\x00\x00\xde\xad"; "less than header")]
    #[test_case(vec![IOCallbackResult::WouldBlock] => matches(IOCallbackResult::WouldBlock, v) if v.is_empty(); "would block")]
    #[test_case(vec![IOCallbackResult::Err(Error::other("ERR"))] => matches(IOCallbackResult::Err(e), v) if e.to_string() == "ERR" && v.is_empty(); "error")]
    fn udp_send_io(fakes: Vec<IOCallbackResult<usize>>) -> (IOCallbackResult<usize>, Vec<u8>) {
        let io = FakeOutsideIOSend::with_fakes(fakes.into());
        let mut a = make_adapter(ConnectionType::Datagram, io.clone(), Default::default());
        let r = a.udp_send(b"abcdefghi", false);

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

        let r = a.udp_send(b"a", false);

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
        g.put(&[0xAB; 1280]);

        let (bytes, stride) = g.frame().expect("Coalescing");
        assert_eq!(bytes.len(), 1280);
        assert_eq!(stride.get(), 1280);
        assert!(bytes.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn gso_put_appends_subsequent_segments() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[0xAA; 1280]);
        g.put(&[0xBB; 1280]);

        let (bytes, stride) = g.frame().expect("Coalescing");
        assert_eq!(bytes.len(), 2560);
        assert_eq!(stride.get(), 1280);
        assert!(bytes[..1280].iter().all(|&b| b == 0xAA));
        assert!(bytes[1280..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn gso_put_allows_shorter_trailing() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[0xAA; 1280]);
        g.put(&[0xBB; 800]);

        let (bytes, stride) = g.frame().expect("Coalescing");
        assert_eq!(bytes.len(), 1280 + 800);
        assert_eq!(stride.get(), 1280);
    }

    #[test]
    fn gso_reset_clears_state_keeps_capacity() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[0xAA; 1280]);
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
        g.put(&[0xAA; 1280]);
        g.reset();

        g.open();
        assert_eq!(g.buf.capacity(), cap_after_first_open);
        assert!(g.is_batching());
    }

    #[test]
    #[should_panic(expected = "put before open")]
    fn gso_put_without_open_panics() {
        let mut g = GsoBuffer::default();
        g.put(&[0xAA; 1280]);
    }

    #[test]
    #[should_panic(expected = "zero-length first GSO segment")]
    fn gso_put_zero_length_first_segment_panics() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn gso_put_oversized_segment_debug_asserts() {
        let mut g = GsoBuffer::default();
        g.open();
        g.put(&[0xAA; 1280]);
        g.put(&[0xBB; 1281]);
    }

    /// A batch that fits within the kernel's single-send limit goes
    /// out as exactly one `send_gso` call.
    #[test]
    #[cfg(target_os = "linux")]
    fn gso_flush_under_limit_single_send() {
        let io = FakeGsoIOSend::new();
        let seg = vec![0xAA; 1350];
        let iovs: Vec<std::io::IoSlice<'_>> =
            (0..10).map(|_| std::io::IoSlice::new(&seg)).collect();
        let arg: OutsideIOSendCallbackArg = io.clone();

        let r = send_gso_chunked(&arg, &iovs, 1, 1350);
        assert!(matches!(r, IOCallbackResult::Ok(n) if n == 10 * 1350));
        assert_eq!(io.calls(), vec![(10 * 1350, 1350)]);
    }

    /// The failing case from the field: a full 65535-byte TSO
    /// aggregate at MTU 1350 becomes 50 wire segments of 1350 bytes
    /// (header included) — 67500 bytes total, over the 64KiB skb
    /// limit. The flush must split so every `sendmsg` payload stays
    /// within `MAX_GSO_SEND_BYTES` and no bytes are lost.
    #[test]
    #[cfg(target_os = "linux")]
    fn gso_flush_over_limit_splits_on_segment_boundary() {
        const STRIDE: usize = 1350;
        const SEGS: usize = 50;

        let io = FakeGsoIOSend::new();
        let seg = vec![0xAA; STRIDE];
        let iovs: Vec<std::io::IoSlice<'_>> =
            (0..SEGS).map(|_| std::io::IoSlice::new(&seg)).collect();
        let arg: OutsideIOSendCallbackArg = io.clone();

        let r = send_gso_chunked(&arg, &iovs, 1, STRIDE as u16);
        assert!(matches!(r, IOCallbackResult::Ok(n) if n == SEGS * STRIDE));

        let calls = io.calls();
        let segs_per_send = crate::gso::MAX_GSO_SEND_BYTES / STRIDE; // 48
        assert_eq!(
            calls,
            vec![
                (segs_per_send * STRIDE, STRIDE as u16),
                ((SEGS - segs_per_send) * STRIDE, STRIDE as u16)
            ]
        );
        for (total, _) in calls {
            assert_le!(total, crate::gso::MAX_GSO_SEND_BYTES);
        }
    }

    /// Chunk boundaries must fall on whole segments even when each
    /// segment is scattered over multiple iovec entries (the
    /// zero-copy path uses 2 per segment: shared header + payload).
    #[test]
    #[cfg(target_os = "linux")]
    fn gso_flush_split_respects_entries_per_seg() {
        const HDR: usize = 16;
        const PAYLOAD: usize = 1334;
        const STRIDE: usize = HDR + PAYLOAD; // 1350
        const SEGS: usize = 50;

        let io = FakeGsoIOSend::new();
        let hdr = vec![0xBB; HDR];
        let payload = vec![0xAA; PAYLOAD];
        let mut iovs: Vec<std::io::IoSlice<'_>> = Vec::with_capacity(SEGS * 2);
        for _ in 0..SEGS {
            iovs.push(std::io::IoSlice::new(&hdr));
            iovs.push(std::io::IoSlice::new(&payload));
        }
        let arg: OutsideIOSendCallbackArg = io.clone();

        let r = send_gso_chunked(&arg, &iovs, 2, STRIDE as u16);
        assert!(matches!(r, IOCallbackResult::Ok(n) if n == SEGS * STRIDE));

        // Every chunk's byte count is a whole multiple of the stride
        // (all segments here are full-sized), within the send limit.
        let calls = io.calls();
        assert_eq!(calls.len(), 2);
        for (total, _) in calls {
            assert_eq!(total % STRIDE, 0, "chunk split mid-segment");
            assert_le!(total, crate::gso::MAX_GSO_SEND_BYTES);
        }
    }

    /// A failure after the first chunk is surfaced to the caller —
    /// the already-sent chunks cannot be retried, the rest is dropped.
    #[test]
    #[cfg(target_os = "linux")]
    fn gso_flush_mid_batch_error_is_surfaced() {
        const STRIDE: usize = 1350;
        const SEGS: usize = 50;

        let io = FakeGsoIOSend::with_fakes(
            vec![
                IOCallbackResult::Ok(48 * STRIDE),
                IOCallbackResult::Err(Error::other("EMSGSIZE")),
            ]
            .into(),
        );
        let seg = vec![0xAA; STRIDE];
        let iovs: Vec<std::io::IoSlice<'_>> =
            (0..SEGS).map(|_| std::io::IoSlice::new(&seg)).collect();
        let arg: OutsideIOSendCallbackArg = io.clone();

        let r = send_gso_chunked(&arg, &iovs, 1, STRIDE as u16);
        assert!(matches!(r, IOCallbackResult::Err(e) if e.to_string() == "EMSGSIZE"));
        assert_eq!(io.calls().len(), 2);
    }
}
