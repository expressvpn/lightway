pub(crate) mod datagram;
pub(crate) mod tcp;
pub(crate) mod udp;

pub(crate) use datagram::DatagramServer;
pub(crate) use tcp::TcpServer;
pub(crate) use udp::UdpIo;

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use lightway_core::{
    IOCallbackResult, MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU, OutsideIOSendCallbackArg,
};
use std::net::SocketAddr;

#[async_trait]
pub(crate) trait Server {
    async fn run(&mut self) -> Result<()>;
}

/// Where one received wire packet came from.
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
    /// Address the packet was received from.
    ///
    /// The server routes by this address before it consults the session
    /// id, so this is the demultiplex key. It must be unique per client
    /// and stable for the life of a connection. Two clients that report
    /// one address collide: the server delivers the second client's
    /// packets to the first connection, where decryption fails. A
    /// transport that demultiplexes for itself must synthesize a
    /// unique, stable address per client.
    pub peer: SocketAddr,

    /// Local address the packet was received on.
    pub local: SocketAddr,
}

/// Application provided outside IO.
///
/// The server owns the receive loop and all of the dispatch: parsing the
/// wire header, routing to a connection, and delivering. An implementation
/// supplies only the transport.
///
/// Pass it as `ServerConnectionMode::DatagramIo`. Datagram transports
/// only: `TcpServer` is accept-based and does not fit the shared loop.
#[async_trait]
pub trait OutsideIO: Send {
    /// Receive one wire packet into `buf`. The implementation clears `buf`
    /// and reserves [`lightway_core::MAX_OUTSIDE_MTU`] before it receives.
    ///
    /// Return `WouldBlock` only after awaiting readiness. The server loop
    /// retries immediately, so a `WouldBlock` that awaited nothing burns a
    /// core without making progress.
    ///
    /// The loop charges tokio's cooperative budget per datagram received,
    /// so an implementation that receives through a manual readiness API
    /// does not have to.
    async fn recv(&mut self, buf: &mut BytesMut) -> IOCallbackResult<RecvMeta>;

    /// Receive up to [`lightway_core::MAX_IO_BATCH_SIZE`] packets,
    /// appending one [`RecvMeta`] to `metas` per buffer filled, in the
    /// same order. `metas` arrives empty, and `metas.len()` is the count.
    ///
    /// Implementations must only wait when no packet is available. When
    /// packets are already queued they return what is ready without
    /// waiting, so batching adds no latency.
    ///
    /// The `WouldBlock` rule on [`Self::recv`] applies here too. Override
    /// when the transport has a batch receive syscall; the default reads a
    /// single packet.
    async fn recv_many(
        &mut self,
        bufs: &mut [BytesMut; MAX_IO_BATCH_SIZE],
        metas: &mut Vec<RecvMeta>,
    ) -> IOCallbackResult<()> {
        bufs[0].clear();
        bufs[0].reserve(MAX_OUTSIDE_MTU);
        match self.recv(&mut bufs[0]).await {
            IOCallbackResult::Ok(meta) => {
                metas.push(meta);
                IOCallbackResult::Ok(())
            }
            IOCallbackResult::WouldBlock => IOCallbackResult::WouldBlock,
            IOCallbackResult::Err(err) => IOCallbackResult::Err(err),
        }
    }

    /// Build the send callback for a connection being created.
    ///
    /// Called once per connection, with the metadata of the packet that
    /// caused the connection to be created.
    ///
    /// When a peer roams, the server calls `set_peer_addr` on this
    /// callback to redirect sends. A transport that routes internally
    /// can keep the default no-op; the server keys its connection map
    /// from its own record, not from this callback.
    fn send_callback(&self, meta: &RecvMeta) -> OutsideIOSendCallbackArg;

    /// Send an already-encoded frame to a peer that has no connection.
    /// Failures are expected to be ignored: there is no connection to
    /// report them against.
    fn send_unconnected(&self, meta: &RecvMeta, buf: &[u8]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 5000);
    const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 27690);

    /// Implements only the required methods, so the defaults are what
    /// the tests below observe.
    struct MinimalIO;

    #[async_trait]
    impl OutsideIO for MinimalIO {
        async fn recv(&mut self, buf: &mut BytesMut) -> IOCallbackResult<RecvMeta> {
            buf.extend_from_slice(b"one packet");
            IOCallbackResult::Ok(RecvMeta {
                peer: PEER,
                local: LOCAL,
            })
        }

        fn send_callback(&self, _meta: &RecvMeta) -> OutsideIOSendCallbackArg {
            unimplemented!("not needed for default-method tests")
        }

        fn send_unconnected(&self, _meta: &RecvMeta, _buf: &[u8]) {
            unimplemented!("not needed for default-method tests")
        }
    }

    #[tokio::test]
    async fn default_recv_many_reads_one_packet() {
        let mut io = MinimalIO;
        let mut bufs: [BytesMut; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BytesMut::with_capacity(MAX_OUTSIDE_MTU));
        let mut metas = Vec::new();

        assert!(matches!(
            io.recv_many(&mut bufs, &mut metas).await,
            IOCallbackResult::Ok(())
        ));
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].peer, PEER);
        assert_eq!(&bufs[0][..], b"one packet");
    }
}
