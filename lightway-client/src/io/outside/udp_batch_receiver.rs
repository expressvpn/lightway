#![cfg(batch_receive)]

use anyhow::Result;
use bytes::BytesMut;
use lightway_core::MAX_OUTSIDE_MTU;
use rtrb::{PopError, RingBuffer};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{error, info};

pub(crate) struct BatchReceiver {
    recv_ready: Arc<Semaphore>,
    recv_consumer: Mutex<rtrb::Consumer<BytesMut>>,
    io_error: Arc<Mutex<Option<io::Error>>>,
    _drop_guard: DropGuard,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum BatchReceiverConsumerError {
    #[error("Empty ring buffer: {0}")]
    EmptyBuffer(#[from] PopError),
    #[error("Semaphore is closed by the task: {0}")]
    SemaphoreClosed(#[from] io::Error),
}

const MAX_BUFFER_SIZE: usize = 1024;
impl BatchReceiver {
    pub fn new(sock: Arc<UdpSocket>) -> Self {
        let recv_ready = Arc::new(Semaphore::new(0));
        let (recv_producer, recv_consumer) = RingBuffer::new(MAX_BUFFER_SIZE);
        let cancellation_token = CancellationToken::new();
        let io_error = Arc::new(Mutex::new(None));
        tokio::task::spawn(handle_udp_recv(
            sock.clone(),
            recv_producer,
            recv_ready.clone(),
            cancellation_token.clone(),
            io_error.clone(),
        ));
        Self {
            recv_ready,
            recv_consumer: Mutex::new(recv_consumer),
            io_error,
            _drop_guard: cancellation_token.drop_guard(),
        }
    }

    pub async fn recv_queue_ready(&self) -> Result<()> {
        // Using a semaphore so bursts are counted correctly: each
        // received packet adds exactly one permit, and each readable() consumes one.
        self.recv_ready
            .acquire()
            .await
            .map_err(|e| anyhow::anyhow!("recv_ready semaphore closed: {e}"))?
            .forget(); // consume the permit without dropping it back
        Ok(())
    }

    pub fn pop_recv_consumer(&self) -> std::result::Result<BytesMut, BatchReceiverConsumerError> {
        if !self.recv_ready.is_closed() {
            self.recv_consumer
                .lock()
                .unwrap()
                .pop()
                .map_err(|e| e.into())
        } else {
            let io_err = self
                .io_error
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| io::Error::other("batch receiver task closed unexpectedly"));
            Err(io_err.into())
        }
    }
}

/// Check whether the platform supports batch receiving via `recvmsg_x`.
#[cfg(apple)]
pub(crate) fn is_batch_receive_available() -> bool {
    apple::is_batch_receive_available()
}

/// Maximum number of messages to send/receive in a single syscall.
const BATCH_SIZE: usize = 32;

/// Platform-specific batch receive syscall.
trait BatchRecvSyscall {
    /// Receive up to `msg_count` packets from `fd` into `recv_bufs`.
    /// Returns the number of packets actually received.
    fn recv_multiple(
        fd: libc::c_int,
        recv_bufs: &mut [BytesMut; BATCH_SIZE],
        msg_count: usize,
    ) -> io::Result<usize>;
}
/// Tokio task: receives packets from the socket using the platform-specific
/// batch syscall and pushes them into the rx ring buffer.
pub(crate) async fn handle_udp_recv(
    sock: Arc<UdpSocket>,
    mut rx_queue: rtrb::Producer<BytesMut>,
    rx_ready: Arc<Semaphore>,
    cancel: CancellationToken,
    io_error: Arc<Mutex<Option<io::Error>>>,
) {
    let mut recv_bufs: [BytesMut; BATCH_SIZE] =
        std::array::from_fn(|_| BytesMut::with_capacity(MAX_OUTSIDE_MTU));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Batch receiver shutting down");
                return;
            }
            ready = sock.readable() => {
                if let Err(e) = ready {
                    error!("Batch receive task failed on readable: {e}");
                    rx_ready.close();
                    io_error.lock().unwrap().replace(e);
                    return;
                }
                let msg_count = rx_queue.slots().min(BATCH_SIZE);
                if msg_count == 0 {
                    // The ring buffer is full. We must yield here because
                    // the socket is still readable (data in the kernel buffer),
                    // so `readable()` would return immediately on the next
                    // iteration — creating a busy spin that starves the
                    // consumer task and prevents it from draining the buffer.
                    tokio::task::yield_now().await;
                    continue;
                }

                // Retry if we received Interrupted
                let recv_count = loop {
                    match sock.try_io(tokio::io::Interest::READABLE, || {
                        // TODO: Make this a trait so that other platforms can use the same interface
                        apple::recv_multiple(sock.as_raw_fd(), &mut recv_bufs, msg_count)
                    }) {
                        Ok(n) => break n,
                        // try_io may return WouldBlock even if the socket isn't actually
                        // readable. Break with 0 to wait for another readable event emitted.
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break 0,
                        // Interrupted means the syscall was interrupted by a signal and can be
                        // retried immediately without waiting for another readable event.
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            error!("Batch receive task failed: {e}");
                            rx_ready.close();
                            io_error.lock().unwrap().replace(e);
                            return;
                        }
                    }
                };

                if recv_count > 0 {
                    let chunk = rx_queue
                        .write_chunk_uninit(recv_count)
                        .expect("slots() guaranteed enough space");
                    let pushed = chunk.fill_from_iter((0..recv_count).map(|i| {
                        std::mem::replace(&mut recv_bufs[i], BytesMut::with_capacity(MAX_OUTSIDE_MTU))
                    }));
                    rx_ready.add_permits(pushed);
                }
            }
        }
    }
}

#[cfg(apple)]
mod apple {
    use crate::io::outside::udp_batch_receiver::BATCH_SIZE;
    use bytes::BytesMut;
    use lightway_core::MAX_OUTSIDE_MTU;
    use std::sync::LazyLock;
    use std::{io, mem};

    /// Whether the `recvmsg_x` syscall is available on the running OS.
    ///
    /// The symbol is a private Apple API that may not exist on all macOS/iOS
    /// versions, so we probe for it with `dlsym(RTLD_DEFAULT, …)` once.
    static RECVMSG_X_AVAILABLE: LazyLock<bool> = LazyLock::new(|| symbol_exists(c"recvmsg_x"));

    /// Probe whether a C symbol is available in the current process via `dlsym`.
    ///
    /// Returns `true` if `dlsym(RTLD_DEFAULT, name)` finds the symbol.
    #[allow(unsafe_code)]
    pub(crate) fn symbol_exists(name: &std::ffi::CStr) -> bool {
        // SAFETY: `dlsym` with `RTLD_DEFAULT` searches all loaded libraries for
        // the symbol. Passing a valid C string is safe; the returned pointer is
        // only used for a null check and never dereferenced.
        // Ref: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dlsym.3.html
        unsafe { !libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()).is_null() }
    }

    pub fn is_batch_receive_available() -> bool {
        *RECVMSG_X_AVAILABLE
    }

    // Ref: https://github.com/apple-oss-distributions/xnu/blob/rel/xnu-10063/bsd/sys/socket.h
    #[repr(C)]
    #[allow(non_camel_case_types)]
    pub(crate) struct msghdr_x {
        pub msg_name: *mut libc::c_void,
        pub msg_namelen: libc::socklen_t,
        pub msg_iov: *mut libc::iovec,
        pub msg_iovlen: libc::c_int,
        pub msg_control: *mut libc::c_void,
        pub msg_controllen: libc::socklen_t,
        pub msg_flags: libc::c_int,
        pub msg_datalen: usize,
    }

    #[allow(unsafe_code)]
    unsafe extern "C" {
        fn recvmsg_x(
            s: libc::c_int,
            msgp: *const msghdr_x,
            cnt: libc::c_uint,
            flags: libc::c_int,
        ) -> isize;
    }

    /// Receive packets from the socket using the `recvmsg_x` batch syscall.
    /// Fills `recv_bufs` with up to `msg_count` messages and returns the number received.
    #[allow(unsafe_code)]
    pub(crate) fn recv_multiple(
        fd: libc::c_int,
        recv_bufs: &mut [BytesMut; BATCH_SIZE],
        msg_count: usize,
    ) -> io::Result<usize> {
        // SAFETY: zeroed iovec is valid (null pointer + zero length).
        let mut iovecs = unsafe { mem::zeroed::<[libc::iovec; BATCH_SIZE]>() };
        // SAFETY: zeroed msghdr_x is valid (null pointers + zero lengths).
        let mut hdrs = unsafe { mem::zeroed::<[msghdr_x; BATCH_SIZE]>() };
        for i in 0..msg_count {
            iovecs[i].iov_base =
                recv_bufs[i].spare_capacity_mut().as_mut_ptr() as *mut libc::c_void;
            iovecs[i].iov_len = MAX_OUTSIDE_MTU;
            hdrs[i].msg_iov = &mut iovecs[i];
            hdrs[i].msg_iovlen = 1;
        }

        // SAFETY: hdrs and iovecs are valid for msg_count entries, fd is a valid and borrowed socket.
        let n = unsafe { recvmsg_x(fd, hdrs.as_mut_ptr(), msg_count as _, 0) };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let count = n as usize;
        for i in 0..count {
            let len = hdrs[i].msg_datalen;
            // SAFETY: For recvmsg_x(), the size of the data received is given by the field msg_datalen,
            // and we have early returned already if we have received no packets from the kernel.
            unsafe {
                recv_bufs[i].set_len(len);
            }
        }

        Ok(count)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn dlsym_finds_known_symbol() {
            // `recvmsg` is a standard POSIX symbol that must exist on any Apple platform.
            assert!(symbol_exists(c"recvmsg"));
        }

        #[test]
        fn dlsym_returns_false_for_nonexistent_symbol() {
            assert!(!symbol_exists(c"definitely_should_not_exist_bruh"));
        }

        #[test]
        fn recvmsg_x_available_is_true() {
            // On macOS, recvmsg_x should be available as it ships with the OS kernel.
            assert!(*RECVMSG_X_AVAILABLE);
        }
    }
}

#[cfg(test)]
#[serial_test::serial]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    async fn make_socket_pair() -> (UdpSocket, Arc<UdpSocket>) {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .connect(receiver.local_addr().unwrap())
            .await
            .unwrap();
        (sender, Arc::new(receiver))
    }

    #[tokio::test]
    async fn single_packet_received() {
        let (sender, receiver) = make_socket_pair().await;
        let batch = BatchReceiver::new(receiver);

        sender.send(b"hello").await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), batch.recv_queue_ready())
            .await
            .unwrap()
            .unwrap();
        let pkt = batch.pop_recv_consumer().unwrap();
        assert_eq!(&pkt[..], b"hello");
    }

    #[tokio::test]
    async fn multiple_packets_received_in_order() {
        let (sender, receiver) = make_socket_pair().await;
        let batch = BatchReceiver::new(receiver);

        for i in 0..10u8 {
            sender.send(&[i]).await.unwrap();
        }

        for i in 0..10u8 {
            tokio::time::timeout(Duration::from_secs(2), batch.recv_queue_ready())
                .await
                .unwrap()
                .unwrap();
            let pkt = batch.pop_recv_consumer().unwrap();
            assert_eq!(pkt[0], i);
        }
    }

    #[tokio::test]
    async fn pop_on_empty_returns_error() {
        let (_sender, receiver) = make_socket_pair().await;
        let batch = BatchReceiver::new(receiver);
        assert!(matches!(
            batch.pop_recv_consumer(),
            Err(BatchReceiverConsumerError::EmptyBuffer(_))
        ));
    }

    #[tokio::test]
    async fn ring_buffer_full_no_data_loss() {
        let (sender, receiver) = make_socket_pair().await;
        let batch = BatchReceiver::new(receiver);

        // Fill the ring buffer to capacity.
        for i in 0..MAX_BUFFER_SIZE as u32 {
            sender.send(&i.to_le_bytes()).await.unwrap();
        }

        // Drain and verify every packet arrived in order.
        for i in 0..MAX_BUFFER_SIZE as u32 {
            tokio::time::timeout(Duration::from_secs(5), batch.recv_queue_ready())
                .await
                .unwrap()
                .unwrap();
            let pkt = batch.pop_recv_consumer().unwrap();
            assert_eq!(
                u32::from_le_bytes(pkt[..4].try_into().unwrap()),
                i,
                "packet {i} out of order"
            );
        }
    }

    #[tokio::test]
    async fn packets_after_drain() {
        let (sender, receiver) = make_socket_pair().await;
        let batch = BatchReceiver::new(receiver);

        // First burst.
        sender.send(b"first").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), batch.recv_queue_ready())
            .await
            .unwrap()
            .unwrap();
        let pkt = batch.pop_recv_consumer().unwrap();
        assert_eq!(&pkt[..], b"first");

        // Second burst after draining.
        sender.send(b"second").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), batch.recv_queue_ready())
            .await
            .unwrap()
            .unwrap();
        let pkt = batch.pop_recv_consumer().unwrap();
        assert_eq!(&pkt[..], b"second");
    }

    #[tokio::test]
    async fn closed_sender_socket_propagates_error() {
        let (sender, receiver) = make_socket_pair().await;
        let batch = BatchReceiver::new(receiver);

        // Send one packet, then drop the sender.
        sender.send(b"bye").await.unwrap();
        drop(sender);

        // The already-queued packet should still be readable.
        tokio::time::timeout(Duration::from_secs(2), batch.recv_queue_ready())
            .await
            .unwrap()
            .unwrap();
        let pkt = batch.pop_recv_consumer().unwrap();
        assert_eq!(&pkt[..], b"bye");
    }

    #[tokio::test]
    async fn pop_after_semaphore_closed_returns_semaphore_closed() {
        let (_sender, receiver) = make_socket_pair().await;
        let batch = BatchReceiver::new(receiver);

        // Manually close the semaphore to simulate the recv task dying with an IO error.
        batch.recv_ready.close();
        batch
            .io_error
            .lock()
            .unwrap()
            .replace(io::Error::other("simulated IO failure"));

        assert!(matches!(
            batch.pop_recv_consumer(),
            Err(BatchReceiverConsumerError::SemaphoreClosed(_))
        ));
    }

    // ---- Direct handle_udp_recv tests ----

    /// Helper: spawn handle_udp_recv with our own ring buffer and semaphore.
    #[allow(clippy::type_complexity)]
    fn spawn_handle_udp_recv(
        sock: Arc<UdpSocket>,
        buffer_size: usize,
    ) -> (
        rtrb::Consumer<BytesMut>,
        Arc<Semaphore>,
        CancellationToken,
        Arc<Mutex<Option<io::Error>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let rx_ready = Arc::new(Semaphore::new(0));
        let (producer, consumer) = RingBuffer::new(buffer_size);
        let cancel = CancellationToken::new();
        let io_error = Arc::new(Mutex::new(None));
        let handle = tokio::task::spawn(handle_udp_recv(
            sock,
            producer,
            rx_ready.clone(),
            cancel.clone(),
            io_error.clone(),
        ));
        (consumer, rx_ready, cancel, io_error, handle)
    }

    #[tokio::test]
    async fn handle_recv_cancellation_stops_task() {
        let (_sender, receiver) = make_socket_pair().await;
        let (_, _, cancel, _, handle) = spawn_handle_udp_recv(receiver, MAX_BUFFER_SIZE);

        cancel.cancel();

        // Task should exit promptly.
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task did not finish in time")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn handle_recv_pushes_packets_and_adds_permits() {
        let (sender, receiver) = make_socket_pair().await;
        let (mut consumer, rx_ready, cancel, _, _handle) =
            spawn_handle_udp_recv(receiver, MAX_BUFFER_SIZE);

        sender.send(b"pkt1").await.unwrap();
        sender.send(b"pkt2").await.unwrap();

        // Wait for both permits.
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(2), rx_ready.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }

        let p1 = consumer.pop().unwrap();
        let p2 = consumer.pop().unwrap();
        assert_eq!(&p1[..], b"pkt1");
        assert_eq!(&p2[..], b"pkt2");

        cancel.cancel();
    }

    // TODO: Add handle_recv error path test once recv_multiple is behind a trait,
    // allowing injection of fatal IO errors. Closing the raw fd doesn't wake
    // tokio's event loop, so the task stays blocked on readable() indefinitely.
}
