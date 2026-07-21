//! Scoped batching of outgoing UDP datagrams.
//!
//! While a batch window ([`SendBatchGuard`]) is open, per-connection send
//! callbacks enqueue datagrams here instead of issuing one `sendmsg` each.
//! Dropping the guard flushes the queue — with `sendmmsg` on Linux, or a
//! `sendmsg` loop on other platforms.

use bytes::Bytes;
use lightway_core::MAX_IO_BATCH_SIZE;
use socket2::SockAddr;
use std::sync::{Arc, Mutex};

use crate::metrics;

/// One queued datagram. Destination and pktinfo are captured at push time
/// since they are per-connection state.
struct QueuedDatagram {
    peer: SockAddr,
    pktinfo: Option<libc::in_pktinfo>,
    data: Bytes,
}

/// Shared queue for batching outgoing datagrams on the server socket.
///
/// `None` means no batch window is open: senders take the direct
/// `sendmsg` path. `Some` means a window is open: senders push and the
/// guard flushes on drop. The mutex makes check-and-push atomic against
/// take-and-flush so a datagram can never be stranded in a queue nobody
/// will flush, even on a multi-threaded runtime.
pub(crate) struct SendQueue {
    sock: Arc<tokio::net::UdpSocket>,
    queue: Mutex<Option<Vec<QueuedDatagram>>>,
}

impl SendQueue {
    pub(crate) fn new(sock: Arc<tokio::net::UdpSocket>) -> Arc<Self> {
        Arc::new(Self {
            sock,
            queue: Mutex::new(None),
        })
    }

    /// Push a datagram if a batch window is open. Returns false if no
    /// window is open — the caller must send directly.
    pub(crate) fn try_enqueue(
        &self,
        peer: SockAddr,
        pktinfo: Option<libc::in_pktinfo>,
        data: &[u8],
    ) -> bool {
        let mut queue = self.queue.lock().unwrap();
        match queue.as_mut() {
            Some(q) => {
                q.push(QueuedDatagram {
                    peer,
                    pktinfo,
                    data: Bytes::copy_from_slice(data),
                });
                true
            }
            None => false,
        }
    }

    /// Open a batch window. Sends arriving via [`Self::try_enqueue`] are
    /// queued until the batch is flushed via [`SendBatchGuard::flush`]
    /// (or the guard is dropped, which flushes best-effort).
    ///
    /// Only one window may be open at a time (there is a single inside-IO
    /// loop); opening a second discards the first window's queue reference,
    /// so callers must not nest.
    pub(crate) fn begin_batch(self: &Arc<Self>) -> SendBatchGuard {
        let mut queue = self.queue.lock().unwrap();
        debug_assert!(queue.is_none(), "nested send batch windows");
        *queue = Some(Vec::with_capacity(MAX_IO_BATCH_SIZE));
        SendBatchGuard {
            queue: Arc::clone(self),
        }
    }
}

/// Closes the batch window opened by [`SendQueue::begin_batch`].
///
/// The window contains no await points, so the guard is short-lived by
/// construction. The batched loop consumes it with [`Self::flush`],
/// which waits for socket writability instead of dropping when the
/// send buffer fills; dropping the guard without flushing falls back
/// to a synchronous best-effort flush so queued datagrams can never
/// be stranded.
pub(crate) struct SendBatchGuard {
    queue: Arc<SendQueue>,
}

impl SendBatchGuard {
    /// Close the window and send everything queued while it was open,
    /// treating a full socket buffer as backpressure: wait until the
    /// socket is writable again and continue where the previous
    /// attempt stopped. Only hard IO errors drop the remainder. Sends
    /// arriving while the flush is in progress take the direct path.
    pub(crate) async fn flush(self) {
        let msgs = self.queue.queue.lock().unwrap().take();
        let Some(msgs) = msgs else { return };
        // Windows that queued nothing are not recorded: zero-size
        // samples would drag down the batch-size histogram that the
        // batching A/B comparison reads.
        if !msgs.is_empty() {
            metrics::udp_send_batch_flush(msgs.len());
            flush_retrying(&self.queue.sock, &msgs).await;
        }
    }
}

impl Drop for SendBatchGuard {
    fn drop(&mut self) {
        // Fallback for paths that exit without calling flush(), which
        // takes the queue and leaves None here.
        let msgs = self.queue.queue.lock().unwrap().take();
        let Some(msgs) = msgs else { return };
        metrics::udp_send_batch_missed_flush();
        if !msgs.is_empty() {
            metrics::udp_send_batch_flush(msgs.len());
            flush_best_effort(&self.queue.sock, &msgs);
        }
    }
}

/// Send all `msgs` with a single `sendmmsg`, carrying per-message
/// destination and pktinfo control data. The kernel caps one call at
/// `UIO_MAXIOV` (1024) messages and may accept fewer than requested;
/// callers resume from the first unsent message. Returns the number
/// of messages the kernel accepted.
///
/// The pointer-carrying arrays are rebuilt per call rather than kept
/// across retries: `iovec`/`mmsghdr` are `!Send`, so holding them
/// across an await point would make the flush future `!Send`.
#[cfg(linux)]
#[allow(unsafe_code)]
fn sendmmsg_all(
    sock: &Arc<tokio::net::UdpSocket>,
    msgs: &[QueuedDatagram],
) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd;

    const CMSG_SIZE: usize = super::cmsg::Message::space::<libc::in_pktinfo>();

    // Both vectors are filled to their final length before any element
    // pointers are taken below, so those pointers stay valid.
    let mut iovecs: Vec<libc::iovec> = msgs
        .iter()
        .map(|m| libc::iovec {
            // The kernel only reads through this pointer on send.
            iov_base: m.data.as_ptr() as *mut libc::c_void,
            iov_len: m.data.len(),
        })
        .collect();
    let mut cmsgs: Vec<super::cmsg::BufferMut<CMSG_SIZE>> =
        std::iter::repeat_with(super::cmsg::BufferMut::zeroed)
            .take(msgs.len())
            .collect();

    let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(msgs.len());
    for (i, m) in msgs.iter().enumerate() {
        // SAFETY: a zeroed mmsghdr is valid (null pointers + zero lengths).
        let mut hdr = unsafe { std::mem::zeroed::<libc::mmsghdr>() };
        hdr.msg_hdr.msg_iov = &mut iovecs[i];
        hdr.msg_hdr.msg_iovlen = 1;
        hdr.msg_hdr.msg_name = m.peer.as_ptr() as *mut libc::c_void;
        hdr.msg_hdr.msg_namelen = m.peer.len();
        if let Some(pi) = m.pktinfo {
            let cmsg = &mut cmsgs[i];
            // The buffer is sized for exactly one in_pktinfo, so this
            // only fails if that invariant is broken; fall back to
            // sending without pktinfo rather than dropping the packet.
            if cmsg
                .builder()
                .fill_next(libc::SOL_IP, libc::IP_PKTINFO, pi)
                .is_ok()
            {
                hdr.msg_hdr.msg_control = cmsg.as_mut_slice().as_mut_ptr() as *mut libc::c_void;
                hdr.msg_hdr.msg_controllen = CMSG_SIZE as _;
            }
        }
        hdrs.push(hdr);
    }

    // SAFETY: hdrs/iovecs/cmsgs and the queued datagrams they point
    // into outlive the syscall; the kernel does not write through any
    // of these pointers on send.
    let n = unsafe {
        libc::sendmmsg(
            sock.as_ref().as_raw_fd(),
            hdrs.as_mut_ptr(),
            hdrs.len() as _,
            0,
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Flush queued datagrams with as few `sendmmsg` syscalls as possible,
/// waiting for the socket to become writable again whenever the send
/// buffer fills (counted in `udp_send_batch_blocked`). A partial send
/// continues from the first unsent message. A hard IO error drops only
/// the datagram that caused it (counted in `udp_send_batch_dropped`);
/// the rest of the queue is still flushed.
#[cfg(linux)]
async fn flush_retrying(sock: &Arc<tokio::net::UdpSocket>, msgs: &[QueuedDatagram]) {
    use tokio::io::Interest;

    let mut sent_total = 0usize;
    while sent_total < msgs.len() {
        let result = sock
            .async_io(Interest::WRITABLE, || {
                sendmmsg_all(sock, &msgs[sent_total..]).inspect_err(|err| {
                    if matches!(err.kind(), std::io::ErrorKind::WouldBlock) {
                        metrics::udp_send_batch_blocked();
                    }
                })
            })
            .await;
        match result {
            Ok(n) => sent_total += n,
            Err(err) => {
                // sendmmsg fails on the first message of the remainder,
                // so skip that datagram alone and keep flushing.
                tracing::warn!("sendmmsg flush failed: {err}");
                metrics::udp_send_batch_dropped(1);
                sent_total += 1;
            }
        }
    }
}

/// Single-attempt variant used by the guard's `Drop` fallback: on
/// `WouldBlock`, a hard error or a partial send the remainder is
/// dropped and counted in `udp_send_batch_dropped`.
#[cfg(linux)]
fn flush_best_effort(sock: &Arc<tokio::net::UdpSocket>, msgs: &[QueuedDatagram]) {
    use tokio::io::Interest;

    match sock.try_io(Interest::WRITABLE, || sendmmsg_all(sock, msgs)) {
        Ok(n) if n == msgs.len() => {}
        Ok(n) => metrics::udp_send_batch_dropped(msgs.len() - n),
        Err(err) => {
            if !matches!(err.kind(), std::io::ErrorKind::WouldBlock) {
                tracing::warn!("sendmmsg flush failed: {err}");
            }
            metrics::udp_send_batch_dropped(msgs.len());
        }
    }
}

/// Non-Linux fallback: no batch-send syscall, send one `sendmsg` per
/// datagram, waiting for writability whenever the socket blocks.
#[cfg(not(linux))]
async fn flush_retrying(sock: &Arc<tokio::net::UdpSocket>, msgs: &[QueuedDatagram]) {
    use lightway_core::IOCallbackResult;
    use std::io::IoSlice;

    let mut dropped = 0usize;
    for (i, m) in msgs.iter().enumerate() {
        loop {
            match super::send_to_socket(sock, &[IoSlice::new(&m.data)], &m.peer, m.pktinfo, None) {
                IOCallbackResult::Ok(_) => break,
                IOCallbackResult::WouldBlock => {
                    metrics::udp_send_batch_blocked();
                    if let Err(err) = sock.writable().await {
                        tracing::warn!("await socket writable failed: {err}");
                        metrics::udp_send_batch_dropped(dropped + msgs.len() - i);
                        return;
                    }
                }
                IOCallbackResult::Err(err) => {
                    dropped += 1;
                    tracing::warn!("send flush failed: {err}");
                    break;
                }
            }
        }
    }
    if dropped > 0 {
        metrics::udp_send_batch_dropped(dropped);
    }
}

/// Non-Linux single-attempt variant used by the guard's `Drop`
/// fallback.
#[cfg(not(linux))]
fn flush_best_effort(sock: &Arc<tokio::net::UdpSocket>, msgs: &[QueuedDatagram]) {
    use lightway_core::IOCallbackResult;
    use std::io::IoSlice;

    let mut dropped = 0usize;
    for m in msgs {
        match super::send_to_socket(sock, &[IoSlice::new(&m.data)], &m.peer, m.pktinfo, None) {
            IOCallbackResult::Ok(_) => {}
            IOCallbackResult::WouldBlock => dropped += 1,
            IOCallbackResult::Err(err) => {
                dropped += 1;
                tracing::warn!("send flush failed: {err}");
            }
        }
    }
    if dropped > 0 {
        metrics::udp_send_batch_dropped(dropped);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightway_core::MAX_IO_BATCH_SIZE;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    async fn socket_pair() -> (
        Arc<tokio::net::UdpSocket>,
        tokio::net::UdpSocket,
        SocketAddr,
    ) {
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.writable().await.unwrap();
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        (Arc::new(sender), receiver, receiver_addr)
    }

    async fn recv_one(receiver: &tokio::net::UdpSocket) -> Vec<u8> {
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(2), receiver.recv(&mut buf))
            .await
            .expect("timed out waiting for flushed datagram")
            .unwrap();
        buf.truncate(n);
        buf
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn enqueue_without_open_window_returns_false() {
        let (sender, _receiver, receiver_addr) = socket_pair().await;
        let queue = SendQueue::new(sender);
        assert!(!queue.try_enqueue(receiver_addr.into(), None, b"direct"));
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn guard_drop_flushes_queued_datagrams_in_order() {
        let (sender, receiver, receiver_addr) = socket_pair().await;
        let queue = SendQueue::new(sender);

        let guard = queue.begin_batch();
        for payload in [b"one".as_slice(), b"two", b"three"] {
            assert!(queue.try_enqueue(receiver_addr.into(), None, payload));
        }
        drop(guard);

        assert_eq!(recv_one(&receiver).await, b"one");
        assert_eq!(recv_one(&receiver).await, b"two");
        assert_eq!(recv_one(&receiver).await, b"three");
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn window_closes_after_flush() {
        let (sender, _receiver, receiver_addr) = socket_pair().await;
        let queue = SendQueue::new(sender);

        queue.begin_batch().flush().await;
        assert!(!queue.try_enqueue(receiver_addr.into(), None, b"late"));
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn flush_sends_batches_larger_than_max_io_batch_size() {
        let (sender, receiver, receiver_addr) = socket_pair().await;
        let queue = SendQueue::new(sender);

        let total = MAX_IO_BATCH_SIZE + 5;
        let guard = queue.begin_batch();
        for i in 0..total {
            let payload = format!("pkt-{i}");
            assert!(queue.try_enqueue(receiver_addr.into(), None, payload.as_bytes()));
        }
        guard.flush().await;

        for i in 0..total {
            assert_eq!(recv_one(&receiver).await, format!("pkt-{i}").into_bytes());
        }
    }

    /// Mirrors the reply_pktinfo the server echoes in production:
    /// source-address selection only, no interface override.
    #[cfg(linux)]
    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn flush_carries_per_message_pktinfo() {
        let (sender, receiver, receiver_addr) = socket_pair().await;
        let queue = SendQueue::new(sender);

        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };

        let guard = queue.begin_batch();
        assert!(queue.try_enqueue(receiver_addr.into(), Some(pktinfo), b"with-pktinfo"));
        guard.flush().await;

        assert_eq!(recv_one(&receiver).await, b"with-pktinfo");
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn udp_socket_send_queues_inside_window_and_sends_direct_outside() {
        use super::super::UdpSocket;
        use lightway_core::OutsideIOSendCallback;
        use std::sync::RwLock;

        let (sender, receiver, receiver_addr) = socket_pair().await;
        let queue = SendQueue::new(sender.clone());

        let cb = UdpSocket {
            sock: sender,
            peer_addr: RwLock::new((receiver_addr, receiver_addr.into())),
            reply_pktinfo: None,
            send_queue: Some(queue.clone()),
        };

        // Outside a window: direct send, arrives immediately.
        cb.send(b"direct");
        assert_eq!(recv_one(&receiver).await, b"direct");

        // Inside a window: held until the guard flushes.
        let guard = queue.begin_batch();
        cb.send(b"queued");
        let mut probe = vec![0u8; 64];
        assert!(
            receiver.try_recv(&mut probe).is_err(),
            "datagram must be held in the queue until flush"
        );
        drop(guard);
        assert_eq!(recv_one(&receiver).await, b"queued");
    }
}
