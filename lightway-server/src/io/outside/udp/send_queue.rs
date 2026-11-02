//! Scoped batching of outgoing UDP datagrams.
//!
//! While a batch window ([`SendBatchGuard`]) is open, per-connection send
//! callbacks enqueue datagrams here instead of issuing one `sendmsg` each.
//! Closing the window flushes the queue — with `sendmmsg` on Linux, or a
//! `sendmsg` loop on other platforms.

use bytes::Bytes;
use lightway_core::MAX_IO_BATCH_SIZE;
use socket2::SockAddr;
use std::cell::RefCell;
use std::sync::Arc;

use crate::metrics;

/// One queued datagram. Destination and pktinfo are captured at push time
/// since they are per-connection state.
struct QueuedDatagram {
    peer: SockAddr,
    pktinfo: Option<libc::in_pktinfo>,
    data: Bytes,
}

/// The datagrams in a batch window. `owner` is the queue of the first
/// datagram. Sends for any other queue take the direct path.
struct Batch {
    owner: Arc<BatchSendSocket>,
    msgs: Vec<QueuedDatagram>,
}

/// The batch window of one thread.
enum Window {
    Closed,
    /// Open with no datagram yet, so the window allocates nothing.
    Open,
    /// Open and bound to the queue of its first datagram.
    Bound(Batch),
}

thread_local! {
    static WINDOW: RefCell<Window> = const { RefCell::new(Window::Closed) };
}

fn take_window() -> Window {
    WINDOW.replace(Window::Closed)
}

/// The server socket, with batch send on.
///
/// When no batch window is open on the calling thread, senders take the
/// direct `sendmsg` path. When a window is open, senders push and the
/// guard flushes. Only the thread that opens a window pushes to it or
/// flushes it. Thus no window keeps a datagram that no thread flushes.
pub(crate) struct BatchSendSocket {
    sock: Arc<tokio::net::UdpSocket>,
}

impl BatchSendSocket {
    pub(crate) fn new(sock: Arc<tokio::net::UdpSocket>) -> Arc<Self> {
        Arc::new(Self { sock })
    }

    /// Push a datagram if a batch window is open. Returns false if no
    /// window is open — the caller must send directly.
    pub(crate) fn try_enqueue(
        self: &Arc<Self>,
        peer: SockAddr,
        pktinfo: Option<libc::in_pktinfo>,
        data: &[u8],
    ) -> bool {
        WINDOW.with_borrow_mut(|window| {
            if let Window::Open = window {
                *window = Window::Bound(Batch {
                    owner: Arc::clone(self),
                    msgs: Vec::with_capacity(MAX_IO_BATCH_SIZE),
                });
            }
            let Window::Bound(batch) = window else {
                return false;
            };
            if !Arc::ptr_eq(&batch.owner, self) {
                return false;
            }
            batch.msgs.push(QueuedDatagram {
                peer,
                pktinfo,
                data: Bytes::copy_from_slice(data),
            });
            true
        })
    }
}

/// Call `f` for each item inside one batch window on this thread, then
/// flush the window. `f` is synchronous, so no caller can hold the window
/// across an await point. `f` drops before the flush, so the values that
/// it owns do not live while the flush waits for the socket.
pub(crate) async fn for_each_in_batch<T>(items: impl IntoIterator<Item = T>, f: impl FnMut(T)) {
    let guard = begin_batch();
    items.into_iter().for_each(f);
    // Windows that queued nothing are not recorded: zero-size samples
    // would drag down the batch-size histogram that the batching A/B
    // comparison reads.
    if let Some(batch) = guard.close() {
        batch.flush().await;
    }
}

/// Open a batch window. Sends arriving via
/// [`BatchSendSocket::try_enqueue`] are queued until the window is
/// closed via [`SendBatchGuard::close`] (or the guard is dropped, which
/// flushes best-effort).
///
/// Only one window may be open at a time on a thread; opening a second
/// discards the first window, so callers must not nest.
fn begin_batch() -> SendBatchGuard {
    let previous = WINDOW.replace(Window::Open);
    debug_assert!(
        matches!(previous, Window::Closed),
        "nested send batch windows"
    );
    SendBatchGuard
}

/// Closes the batch window opened by [`begin_batch`].
///
/// The window contains no await points, so the guard is short-lived by
/// construction. [`for_each_in_batch`] consumes it with [`Self::close`]
/// on the thread that opened it, and only then awaits the flush;
/// dropping the guard without closing falls back to a synchronous
/// best-effort flush so queued datagrams can never be stranded.
struct SendBatchGuard;

impl SendBatchGuard {
    /// Close the window and return its batch, or `None` if it queued
    /// nothing. This is synchronous, so the window closes on the thread
    /// that opened it.
    fn close(self) -> Option<Batch> {
        std::mem::forget(self);
        match take_window() {
            Window::Bound(batch) => Some(batch),
            _ => None,
        }
    }
}

impl Batch {
    /// Send everything in the batch, treating a full socket buffer as
    /// backpressure: wait until the socket is writable again and
    /// continue where the previous attempt stopped. Only hard IO errors
    /// drop the remainder. Sends arriving while the flush is in progress
    /// take the direct path.
    async fn flush(self) {
        metrics::udp_send_batch_flush(self.msgs.len());
        flush_retrying(&self.owner.sock, &self.msgs).await;
    }
}

impl Drop for SendBatchGuard {
    fn drop(&mut self) {
        // Fallback for paths that exit without calling close(), which
        // forgets the guard.
        let window = take_window();
        if let Window::Closed = window {
            return;
        }
        metrics::udp_send_batch_missed_flush();
        if let Window::Bound(Batch { owner, msgs }) = window {
            metrics::udp_send_batch_flush(msgs.len());
            flush_best_effort(&owner.sock, &msgs);
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
    use std::cell::Cell;
    use std::net::SocketAddr;
    use std::rc::Rc;
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

    /// Records whether it drops while the batch window is open.
    struct WindowProbe {
        queue: Arc<BatchSendSocket>,
        peer: SocketAddr,
        dropped_in_window: Rc<Cell<bool>>,
    }

    impl Drop for WindowProbe {
        fn drop(&mut self) {
            let in_window = self.queue.try_enqueue(self.peer.into(), None, b"probe");
            self.dropped_in_window.set(in_window);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn for_each_in_batch_drops_f_before_the_flush() {
        let (sender, _receiver, receiver_addr) = socket_pair().await;
        let dropped_in_window = Rc::new(Cell::new(false));
        let probe = WindowProbe {
            queue: BatchSendSocket::new(sender),
            peer: receiver_addr,
            dropped_in_window: dropped_in_window.clone(),
        };

        for_each_in_batch([b"pkt".as_slice()], move |payload| {
            assert!(probe.queue.try_enqueue(probe.peer.into(), None, payload));
        })
        .await;

        assert!(
            dropped_in_window.get(),
            "f must drop before the flush closes the window"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn enqueue_without_open_window_returns_false() {
        let (sender, _receiver, receiver_addr) = socket_pair().await;
        let queue = BatchSendSocket::new(sender);
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
        let queue = BatchSendSocket::new(sender);

        let guard = begin_batch();
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
        let queue = BatchSendSocket::new(sender);

        assert!(begin_batch().close().is_none());
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
        let queue = BatchSendSocket::new(sender);

        let total = MAX_IO_BATCH_SIZE + 5;
        let guard = begin_batch();
        for i in 0..total {
            let payload = format!("pkt-{i}");
            assert!(queue.try_enqueue(receiver_addr.into(), None, payload.as_bytes()));
        }
        guard.close().unwrap().flush().await;

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
        let queue = BatchSendSocket::new(sender);

        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };

        let guard = begin_batch();
        assert!(queue.try_enqueue(receiver_addr.into(), Some(pktinfo), b"with-pktinfo"));
        guard.close().unwrap().flush().await;

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
        let queue = BatchSendSocket::new(sender.clone());

        let cb = UdpSocket {
            sock: sender,
            peer_addr: RwLock::new((receiver_addr, receiver_addr.into())),
            reply_pktinfo: None,
            batch_send_socket: Some(queue.clone()),
        };

        // Outside a window: direct send, arrives immediately.
        cb.send(b"direct");
        assert_eq!(recv_one(&receiver).await, b"direct");

        // Inside a window: held until the guard flushes.
        let guard = begin_batch();
        cb.send(b"queued");
        let mut probe = vec![0u8; 64];
        assert!(
            receiver.try_recv(&mut probe).is_err(),
            "datagram must be held in the queue until flush"
        );
        drop(guard);
        assert_eq!(recv_one(&receiver).await, b"queued");
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn window_queues_only_sends_from_its_own_thread() {
        let (sender, _receiver, receiver_addr) = socket_pair().await;
        let queue = BatchSendSocket::new(sender);

        let guard = begin_batch();
        let other = queue.clone();
        let queued_by_other_thread =
            std::thread::spawn(move || other.try_enqueue(receiver_addr.into(), None, b"other"))
                .join()
                .unwrap();
        assert!(!queued_by_other_thread);
        assert!(queue.try_enqueue(receiver_addr.into(), None, b"own"));
        guard.close().unwrap().flush().await;
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn window_queues_only_sends_for_the_first_queue() {
        let (first, _first_receiver, receiver_addr) = socket_pair().await;
        let (second, _second_receiver, _) = socket_pair().await;
        let first = BatchSendSocket::new(first);
        let second = BatchSendSocket::new(second);

        let guard = begin_batch();
        assert!(first.try_enqueue(receiver_addr.into(), None, b"first"));
        assert!(!second.try_enqueue(receiver_addr.into(), None, b"second"));
        guard.close().unwrap().flush().await;
    }
}
