use std::io::IoSlice;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use super::{OutsideIO, OutsideSocket};
use anyhow::Result;
use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use lightway_core::{
    IOCallbackResult, MAX_OUTSIDE_MTU, OutsideIOSendCallback, OutsideIOSendCallbackArg,
    PluginResult, PluginType,
};

/// The outside IO of a stream whose setup left plugins that only work on
/// that stream, such as a layer negotiated while connecting it. It runs them
/// over the bytes of the stream's own outside IO, so they sit beneath the
/// connection's outside plugins, nearest the wire.
///
/// Only for a stream: a send the stream takes in part is kept and finished
/// on the next send, and a receive is whatever bytes arrived, not a packet.
/// Plugins over a datagram socket would need running once per datagram.
///
/// The first plugin is the outermost, as in a `PluginFactoryList`.
pub struct StreamPluginIo {
    inner: Arc<dyn OutsideIO>,
    plugins: Arc<[PluginType]>,
    send: Arc<PluginSend>,
}

impl StreamPluginIo {
    pub fn new(inner: Arc<dyn OutsideIO>, plugins: Vec<PluginType>) -> Self {
        let plugins: Arc<[PluginType]> = plugins.into();
        let send = Arc::new(PluginSend::new(
            inner.clone().into_io_send_callback(),
            plugins.clone(),
        ));
        Self {
            inner,
            plugins,
            send,
        }
    }
}

#[async_trait]
impl OutsideIO for StreamPluginIo {
    fn set_send_buffer_size(&self, size: usize) -> Result<()> {
        self.inner.set_send_buffer_size(size)
    }

    fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        self.inner.set_recv_buffer_size(size)
    }

    fn send_buffer_size(&self) -> Result<usize> {
        self.inner.send_buffer_size()
    }

    fn recv_buffer_size(&self) -> Result<usize> {
        self.inner.recv_buffer_size()
    }

    async fn poll(&self, interest: tokio::io::Interest) -> Result<tokio::io::Ready> {
        self.inner.poll(interest).await
    }

    fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize> {
        let start = buf.len();
        match self.inner.recv_buf(buf) {
            IOCallbackResult::Ok(_) => {}
            other => return other,
        }

        let mut data = buf.split_off(start);
        for plugin in self.plugins.iter() {
            match plugin.ingress(&mut data) {
                PluginResult::Accept => {}
                // A stream cannot skip bytes, so as in Lightway's own stream
                // receive, a drop is an error. A plugin short of a whole frame
                // accepts with nothing yet instead.
                PluginResult::Drop | PluginResult::DropWithReply(_) => {
                    return IOCallbackResult::Err(std::io::Error::other(
                        "Outside plugin dropped stream data",
                    ));
                }
                PluginResult::Error(e) => {
                    return IOCallbackResult::Err(std::io::Error::other(e));
                }
            }
        }
        let n = data.len();
        buf.unsplit(data);
        IOCallbackResult::Ok(n)
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg {
        self.send.clone()
    }

    fn peer_addr(&self) -> SocketAddr {
        self.inner.peer_addr()
    }

    #[cfg(apple)]
    fn reconnect(&self) {
        self.inner.reconnect()
    }

    #[cfg(windows)]
    fn pin_egress_interface(&self, if_index: u32) {
        self.inner.pin_egress_interface(if_index)
    }

    fn socket(&self) -> Option<OutsideSocket> {
        self.inner.socket()
    }

    fn required_outside_mtu(&self) -> Option<usize> {
        self.inner.required_outside_mtu()
    }

    fn empty_first_key_share(&self) -> bool {
        self.inner.empty_first_key_share()
    }
}

/// Sends through the plugins, keeping what the stream has not taken yet.
///
/// Like Lightway's own TCP send: the plugins run once per buffer, and a
/// partial send reports `WouldBlock` until the rest goes. Lightway then
/// calls again with the same bytes first, which are not run through the
/// plugins again.
struct PluginSend {
    inner: OutsideIOSendCallbackArg,
    plugins: Arc<[PluginType]>,
    pending: Mutex<Pending>,
}

#[derive(Default)]
struct Pending {
    data: BytesMut,
    original_len: usize,
}

impl PluginSend {
    fn new(inner: OutsideIOSendCallbackArg, plugins: Arc<[PluginType]>) -> Self {
        Self {
            inner,
            plugins,
            pending: Mutex::default(),
        }
    }
}

impl OutsideIOSendCallback for PluginSend {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        let mut guard = self.pending.lock().unwrap();
        let pending = &mut *guard;

        if pending.data.is_empty() {
            // Reuse the buffer. Plugins may grow the data in place, only as
            // far as its capacity, so leave them room as Lightway's TCP send
            // does.
            pending.data.clear();
            pending.data.reserve(2 * buf.len().max(MAX_OUTSIDE_MTU));
            pending.data.extend_from_slice(buf);
            for plugin in self.plugins.iter().rev() {
                match plugin.egress(&mut pending.data) {
                    PluginResult::Accept => {}
                    PluginResult::Drop | PluginResult::DropWithReply(_) => {
                        pending.data.clear();
                        return IOCallbackResult::Ok(buf.len());
                    }
                    PluginResult::Error(e) => {
                        pending.data.clear();
                        return IOCallbackResult::Err(std::io::Error::other(e));
                    }
                }
            }
            if pending.data.is_empty() {
                return IOCallbackResult::Ok(buf.len());
            }
            pending.original_len = buf.len();
        }

        match self.inner.send(&pending.data) {
            IOCallbackResult::Ok(n) if n == pending.data.len() => {
                pending.data.clear();
                IOCallbackResult::Ok(std::mem::take(&mut pending.original_len))
            }
            IOCallbackResult::Ok(n) => {
                pending.data.advance(n);
                IOCallbackResult::WouldBlock
            }
            other => other,
        }
    }

    fn send_gso(&self, _bufs: &[IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    fn peer_addr(&self) -> SocketAddr {
        self.inner.peer_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use lightway_core::Plugin;

    /// Wraps each egress buffer in its tag and strips it on ingress, so the
    /// order plugins ran in shows in the bytes.
    struct TagPlugin(&'static str);

    impl Plugin for TagPlugin {
        fn ingress(&self, data: &mut BytesMut) -> PluginResult {
            let tag = self.0.as_bytes();
            if !data.starts_with(tag) || !data.ends_with(tag) {
                return PluginResult::Error(anyhow::anyhow!("no {} tag", self.0).into());
            }
            let inner = data[tag.len()..data.len() - tag.len()].to_vec();
            *data = BytesMut::from(&inner[..]);
            PluginResult::Accept
        }

        fn egress(&self, data: &mut BytesMut) -> PluginResult {
            let mut tagged = BytesMut::from(self.0.as_bytes());
            tagged.extend_from_slice(data);
            tagged.extend_from_slice(self.0.as_bytes());
            *data = tagged;
            PluginResult::Accept
        }
    }

    /// Drops everything.
    struct DropPlugin;

    impl Plugin for DropPlugin {
        fn ingress(&self, _data: &mut BytesMut) -> PluginResult {
            PluginResult::Drop
        }

        fn egress(&self, _data: &mut BytesMut) -> PluginResult {
            PluginResult::Drop
        }
    }

    /// Appends its tag without reallocating, failing if the buffer has no
    /// room for it.
    struct InPlaceTagPlugin(&'static str);

    impl Plugin for InPlaceTagPlugin {
        fn ingress(&self, _data: &mut BytesMut) -> PluginResult {
            PluginResult::Accept
        }

        fn egress(&self, data: &mut BytesMut) -> PluginResult {
            let tag = self.0.as_bytes();
            if data.capacity() - data.len() < tag.len() {
                return PluginResult::Error(anyhow::anyhow!("no room for {}", self.0).into());
            }
            data.extend_from_slice(tag);
            PluginResult::Accept
        }
    }

    fn plugins(list: Vec<PluginType>) -> Arc<[PluginType]> {
        list.into()
    }

    fn tags(outer_first: &[&'static str]) -> Arc<[PluginType]> {
        plugins(
            outer_first
                .iter()
                .map(|tag| Box::new(TagPlugin(tag)) as PluginType)
                .collect(),
        )
    }

    /// Takes at most `limit` bytes per call and records them.
    struct Wire {
        limit: Mutex<usize>,
        sent: Mutex<Vec<u8>>,
    }

    impl Wire {
        fn new(limit: usize) -> Arc<Self> {
            Arc::new(Self {
                limit: Mutex::new(limit),
                sent: Mutex::default(),
            })
        }

        fn sent(&self) -> Vec<u8> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl OutsideIOSendCallback for Wire {
        fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
            let limit = *self.limit.lock().unwrap();
            if limit == 0 {
                return IOCallbackResult::WouldBlock;
            }
            let n = buf.len().min(limit);
            self.sent.lock().unwrap().extend_from_slice(&buf[..n]);
            IOCallbackResult::Ok(n)
        }

        fn send_gso(&self, _bufs: &[IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
            IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }

        fn peer_addr(&self) -> SocketAddr {
            "127.0.0.1:9".parse().unwrap()
        }
    }

    #[test]
    fn send_runs_plugins_innermost_first() {
        let wire = Wire::new(usize::MAX);
        let send = PluginSend::new(wire.clone(), tags(&["outer", "inner"]));

        assert!(matches!(send.send(b"data"), IOCallbackResult::Ok(4)));
        assert_eq!(wire.sent(), b"outerinnerdatainnerouter");
    }

    #[test]
    fn partial_send_resumes_without_rerunning_plugins() {
        let wire = Wire::new(5);
        let send = PluginSend::new(wire.clone(), tags(&["tag"]));

        assert!(matches!(send.send(b"data"), IOCallbackResult::WouldBlock));
        *wire.limit.lock().unwrap() = 0;
        assert!(matches!(send.send(b"data"), IOCallbackResult::WouldBlock));
        *wire.limit.lock().unwrap() = usize::MAX;
        // Lightway resends the same bytes, perhaps with more after them.
        assert!(matches!(send.send(b"datamore"), IOCallbackResult::Ok(4)));
        assert_eq!(wire.sent(), b"tagdatatag");

        assert!(matches!(send.send(b"more"), IOCallbackResult::Ok(4)));
        assert_eq!(wire.sent(), b"tagdatatagtagmoretag");
    }

    #[test]
    fn send_leaves_plugins_room_to_grow_in_place() {
        let wire = Wire::new(usize::MAX);
        let send = PluginSend::new(
            wire.clone(),
            plugins(vec![Box::new(InPlaceTagPlugin("tag"))]),
        );

        assert!(matches!(send.send(b"data"), IOCallbackResult::Ok(4)));
        assert_eq!(wire.sent(), b"datatag");

        let full = vec![b'x'; MAX_OUTSIDE_MTU];
        assert!(matches!(send.send(&full), IOCallbackResult::Ok(n) if n == full.len()));
    }

    #[test]
    fn send_held_back_by_a_plugin_is_complete() {
        let wire = Wire::new(usize::MAX);
        let send = PluginSend::new(wire.clone(), plugins(vec![Box::new(DropPlugin)]));

        assert!(matches!(send.send(b"data"), IOCallbackResult::Ok(4)));
        assert!(wire.sent().is_empty());
    }

    async fn connected_pair() -> (Arc<dyn OutsideIO>, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let tcp = super::super::Tcp::new(
            addr,
            Some(client.unwrap()),
            #[cfg(all(linux, not(feature = "mobile")))]
            0,
        )
        .await
        .unwrap();
        (Arc::new(tcp), server.unwrap().0)
    }

    async fn recv(io: &StreamPluginIo) -> IOCallbackResult<usize> {
        let mut buf = BytesMut::with_capacity(64);
        io.poll(tokio::io::Interest::READABLE).await.unwrap();
        match io.recv_buf(&mut buf) {
            IOCallbackResult::Ok(n) => {
                assert_eq!(n, buf.len());
                assert_eq!(&buf[..], b"data");
                IOCallbackResult::Ok(n)
            }
            other => other,
        }
    }

    #[tokio::test]
    async fn recv_runs_plugins_outermost_first() {
        use tokio::io::AsyncWriteExt;

        let (inner, mut peer) = connected_pair().await;
        let io = StreamPluginIo::new(
            inner,
            vec![Box::new(TagPlugin("outer")), Box::new(TagPlugin("inner"))],
        );

        peer.write_all(b"outerinnerdatainnerouter").await.unwrap();
        assert!(matches!(recv(&io).await, IOCallbackResult::Ok(4)));
    }

    #[tokio::test]
    async fn recv_dropped_by_a_plugin_is_an_error() {
        use tokio::io::AsyncWriteExt;

        let (inner, mut peer) = connected_pair().await;
        let io = StreamPluginIo::new(inner, vec![Box::new(DropPlugin)]);

        peer.write_all(b"data").await.unwrap();
        assert!(matches!(recv(&io).await, IOCallbackResult::Err(_)));
    }

    /// Keeps every byte for later, like a layer short of a whole frame.
    struct HoldPlugin;

    impl Plugin for HoldPlugin {
        fn ingress(&self, data: &mut BytesMut) -> PluginResult {
            data.clear();
            PluginResult::Accept
        }

        fn egress(&self, _data: &mut BytesMut) -> PluginResult {
            PluginResult::Accept
        }
    }

    #[tokio::test]
    async fn recv_held_back_by_a_plugin_is_empty() {
        use tokio::io::AsyncWriteExt;

        let (inner, mut peer) = connected_pair().await;
        let io = StreamPluginIo::new(inner, vec![Box::new(HoldPlugin)]);

        peer.write_all(b"data").await.unwrap();
        let mut buf = BytesMut::with_capacity(64);
        io.poll(tokio::io::Interest::READABLE).await.unwrap();
        assert!(matches!(io.recv_buf(&mut buf), IOCallbackResult::Ok(0)));
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn sends_reach_the_stream() {
        use tokio::io::AsyncReadExt;

        let (inner, mut peer) = connected_pair().await;
        let io = Arc::new(StreamPluginIo::new(inner, vec![Box::new(TagPlugin("tag"))]));
        let peer_addr = io.peer_addr();
        let send = io.into_io_send_callback();

        assert_eq!(send.peer_addr(), peer_addr);
        assert!(matches!(send.send(b"data"), IOCallbackResult::Ok(4)));
        let mut got = [0; 10];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"tagdatatag");
    }
}
