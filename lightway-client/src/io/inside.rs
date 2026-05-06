pub mod tun;

use anyhow::Result;
use bytes::BytesMut;
use std::sync::Arc;
pub use tun::Tun;

use async_trait::async_trait;
#[cfg(linux)]
use lightway_app_utils::TunOffloadBuffers;
use lightway_core::{
    IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg, InsideIpConfig,
};

use crate::ConnectionState;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
/// Trait for InsideIORecv
/// This will be used client app to fetch inside packets
pub trait InsideIORecv<ExtAppState: Send + Sync>: Send + Sync {
    async fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize>;

    /// Receive multiple packets into caller-owned buffers. `buffers` is
    /// scratch reused across calls; each `Tun` impl uses only the part it
    /// needs. `bufs` entries must be pre-sized to MTU; populated entries
    /// are truncated to each packet's length on return.
    ///
    /// Returns the number of packets written.
    ///
    /// Linux and client only.
    #[cfg(linux)]
    async fn recv_multiple_buf(
        &self,
        tun_buffer: &mut TunOffloadBuffers,
        bufs: &mut [BytesMut],
    ) -> IOCallbackResult<usize>;

    fn try_send(&self, pkt: BytesMut, ip_config: Option<InsideIpConfig>) -> Result<usize>;

    /// MTU of the underlying interface.
    fn mtu(&self) -> usize;

    /// Returns whether the underlying TUN reports UDP/TCP GSO support.
    #[cfg(linux)]
    fn gso(&self) -> (bool, bool);

    fn into_io_send_callback(
        self: Arc<Self>,
    ) -> InsideIOSendCallbackArg<ConnectionState<ExtAppState>>;
}

/// Trait for InsideIO
///
/// This is a super trait which includes both InsideIORecv and InsideIOSendCallback
/// A default blanket implementation is provided, so users has to only implement
/// InsideIORecv and InsideIOSendCallback in their data structures.
pub trait InsideIO<ExtAppState: Send + Sync = ()>:
    InsideIORecv<ExtAppState> + InsideIOSendCallback<ConnectionState<ExtAppState>>
{
}

/// Default blanket implementation for InsideIO
impl<
    ExtAppState: Send + Sync,
    U: Send
        + Sync
        + Sized
        + InsideIOSendCallback<ConnectionState<ExtAppState>>
        + InsideIORecv<ExtAppState>,
> InsideIO<ExtAppState> for U
{
}

/// A wrapper for receive buffers for the inside (TUN) read path.
/// Allocated once at task startup and reused across every
/// [`recv`](Self::recv) call so the hot loop never allocates.
///
/// Construct with [`new`](Self::new) for the single-packet path
/// (non-Linux, or Linux with TUN offload disabled). On Linux, construct
/// with [`new_batched`](Self::new_batched) when [`InsideIORecv::gso`]
/// reports UDP or TCP GSO support — that mode also holds the additional
/// scratch space tun-rs needs to split kernel GRO super-packets into
/// individual IP packets.
pub struct InsideRecvBuf {
    bufs: Vec<BytesMut>,
    mtu: usize,
    #[cfg(linux)]
    multi_buffers: Option<TunOffloadBuffers>,
}

impl InsideRecvBuf {
    /// Single-packet recv mode. Use on non-Linux platforms, or on Linux
    /// when TUN offload is disabled at runtime.
    pub fn new(mtu: usize) -> Self {
        Self {
            bufs: vec![BytesMut::zeroed(mtu)],
            mtu,
            #[cfg(linux)]
            multi_buffers: None,
        }
    }

    /// Batched recv mode for `count` GRO-segmented packets. Caller must
    /// verify TUN offload is actually enabled via [`InsideIORecv::gso`]
    /// before constructing in this mode.
    #[cfg(linux)]
    pub fn new_batched(mtu: usize, count: usize) -> Self {
        Self {
            bufs: (0..count).map(|_| BytesMut::zeroed(mtu)).collect(),
            mtu,
            multi_buffers: Some(TunOffloadBuffers::new(count)),
        }
    }

    /// Drop the populated contents of the first `count` scratch buffers
    /// and resize MTU capacity in each.
    pub fn reset(&mut self, count: usize) {
        for b in self.bufs.iter_mut().take(count) {
            b.clear();
            b.resize(self.mtu, 0);
        }
    }

    /// Recv one or more inside packets. Returns how packets it received and slice of populated
    /// `BytesMut`s, each truncated to its packet's length.
    ///
    /// Caller must invoke [`reset`](Self::reset) after processing each batch
    /// so the buffers are at MTU length on the next call. Initial state from
    /// [`new`](Self::new) / [`new_batched`](Self::new_batched) already satisfies
    /// the invariant.
    pub async fn recv<ExtAppState, R>(
        &mut self,
        io: &R,
    ) -> IOCallbackResult<(usize, &mut [BytesMut])>
    where
        ExtAppState: Send + Sync,
        R: InsideIORecv<ExtAppState> + ?Sized,
    {
        #[cfg(linux)]
        if let Some(buffers) = self.multi_buffers.as_mut() {
            return match io.recv_multiple_buf(buffers, &mut self.bufs).await {
                IOCallbackResult::Ok(n) => IOCallbackResult::Ok((n, &mut self.bufs[..n])),
                IOCallbackResult::WouldBlock => IOCallbackResult::WouldBlock,
                IOCallbackResult::Err(e) => IOCallbackResult::Err(e),
            };
        }
        match io.recv_buf(&mut self.bufs[0]).await {
            IOCallbackResult::Ok(_n) => IOCallbackResult::Ok((1, &mut self.bufs[..1])),
            IOCallbackResult::WouldBlock => IOCallbackResult::WouldBlock,
            IOCallbackResult::Err(e) => IOCallbackResult::Err(e),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_MTU: usize = 1500;

    #[test]
    fn new_allocates_one_mtu_sized_buffer() {
        let buf = InsideRecvBuf::new(TEST_MTU);
        assert_eq!(buf.bufs.len(), 1);
        assert_eq!(buf.bufs[0].len(), TEST_MTU);
        assert_eq!(buf.mtu, TEST_MTU);
        #[cfg(linux)]
        assert!(buf.multi_buffers.is_none());
    }

    #[cfg(linux)]
    #[test]
    fn new_batched_allocates_count_mtu_sized_buffers() {
        let buf = InsideRecvBuf::new_batched(TEST_MTU, 8);
        assert_eq!(buf.bufs.len(), 8);
        for b in &buf.bufs {
            assert_eq!(b.len(), TEST_MTU);
        }
        assert!(buf.multi_buffers.is_some());
    }

    #[test]
    fn reset_restores_truncated_buffer_to_mtu() {
        let mut buf = InsideRecvBuf::new(TEST_MTU);
        buf.bufs[0].truncate(40);
        buf.reset(1);
        assert_eq!(buf.bufs[0].len(), TEST_MTU);
    }

    #[cfg(linux)]
    #[test]
    fn reset_only_touches_first_count_buffers() {
        let mut buf = InsideRecvBuf::new_batched(TEST_MTU, 4);
        for b in &mut buf.bufs {
            b.truncate(10);
        }
        buf.reset(2);
        assert_eq!(buf.bufs[0].len(), TEST_MTU);
        assert_eq!(buf.bufs[1].len(), TEST_MTU);
        assert_eq!(buf.bufs[2].len(), 10);
        assert_eq!(buf.bufs[3].len(), 10);
    }

    #[tokio::test]
    async fn recv_single_path_returns_one_truncated_buffer() {
        let mut mock = MockInsideIORecv::<()>::new();
        mock.expect_recv_buf().times(1).returning(|buf| {
            buf.truncate(64);
            IOCallbackResult::Ok(64)
        });
        let mut buf = InsideRecvBuf::new(TEST_MTU);
        let IOCallbackResult::Ok((n, slice)) = buf.recv::<(), _>(&mock).await else {
            panic!("expected Ok");
        };
        assert_eq!(n, 1);
        assert_eq!(slice.len(), 1);
        assert_eq!(slice[0].len(), 64);
    }

    #[tokio::test]
    async fn recv_single_path_propagates_would_block() {
        let mut mock = MockInsideIORecv::<()>::new();
        mock.expect_recv_buf()
            .times(1)
            .returning(|_| IOCallbackResult::WouldBlock);
        let mut buf = InsideRecvBuf::new(TEST_MTU);
        assert!(matches!(
            buf.recv::<(), _>(&mock).await,
            IOCallbackResult::WouldBlock
        ));
    }

    #[tokio::test]
    async fn recv_single_path_propagates_err() {
        let mut mock = MockInsideIORecv::<()>::new();
        mock.expect_recv_buf()
            .times(1)
            .returning(|_| IOCallbackResult::Err(std::io::Error::other("boom")));
        let mut buf = InsideRecvBuf::new(TEST_MTU);
        assert!(matches!(
            buf.recv::<(), _>(&mock).await,
            IOCallbackResult::Err(_)
        ));
    }

    #[cfg(linux)]
    #[tokio::test]
    async fn recv_batched_path_returns_first_n_populated_buffers() {
        let mut mock = MockInsideIORecv::<()>::new();
        mock.expect_recv_multiple_buf()
            .times(1)
            .returning(|_tun_buffer, bufs| {
                bufs[0].truncate(40);
                bufs[1].truncate(80);
                bufs[2].truncate(120);
                IOCallbackResult::Ok(3)
            });
        let mut buf = InsideRecvBuf::new_batched(TEST_MTU, 8);
        let IOCallbackResult::Ok((n, slice)) = buf.recv::<(), _>(&mock).await else {
            panic!("expected Ok");
        };
        assert_eq!(n, 3);
        assert_eq!(slice.len(), 3);
        assert_eq!(slice[0].len(), 40);
        assert_eq!(slice[1].len(), 80);
        assert_eq!(slice[2].len(), 120);
    }

    #[cfg(linux)]
    #[tokio::test]
    async fn recv_batched_path_does_not_call_recv_buf() {
        let mut mock = MockInsideIORecv::<()>::new();
        mock.expect_recv_buf().times(0);
        mock.expect_recv_multiple_buf()
            .times(1)
            .returning(|_, bufs| {
                bufs[0].truncate(10);
                IOCallbackResult::Ok(1)
            });
        let mut buf = InsideRecvBuf::new_batched(TEST_MTU, 4);
        let _ = buf.recv::<(), _>(&mock).await;
    }

    #[cfg(linux)]
    #[tokio::test]
    async fn recv_batched_path_propagates_would_block() {
        let mut mock = MockInsideIORecv::<()>::new();
        mock.expect_recv_multiple_buf()
            .times(1)
            .returning(|_, _| IOCallbackResult::WouldBlock);
        let mut buf = InsideRecvBuf::new_batched(TEST_MTU, 8);
        assert!(matches!(
            buf.recv::<(), _>(&mock).await,
            IOCallbackResult::WouldBlock
        ));
    }

    #[cfg(linux)]
    #[tokio::test]
    async fn recv_batched_path_propagates_err() {
        let mut mock = MockInsideIORecv::<()>::new();
        mock.expect_recv_multiple_buf()
            .times(1)
            .returning(|_, _| IOCallbackResult::Err(std::io::Error::other("boom")));
        let mut buf = InsideRecvBuf::new_batched(TEST_MTU, 8);
        assert!(matches!(
            buf.recv::<(), _>(&mock).await,
            IOCallbackResult::Err(_)
        ));
    }
}
