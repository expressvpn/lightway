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

/// Maximum number of messages to send/receive in a single syscall.
const BATCH_SIZE: usize = 32;

/// Tokio task: receives packets from the socket via `recvmsg_x` and pushes them
/// into the rx ring buffer.
async fn handle_udp_recv(
    sock: Arc<UdpSocket>,
    mut rx_queue: rtrb::Producer<BytesMut>,
    rx_ready: Arc<Semaphore>,
    cancel: CancellationToken,
    io_error: Arc<Mutex<Option<io::Error>>>,
) {
    let mut recv_bufs = [[0u8; MAX_OUTSIDE_MTU]; BATCH_SIZE];

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
                    continue;
                }

                // Retry if we received Interrupted
                let recv_count = loop {
                    match sock.try_io(tokio::io::Interest::READABLE, || {
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
                        BytesMut::from(&recv_bufs[i][..])
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
    use lightway_core::MAX_OUTSIDE_MTU;
    use std::{io, mem};

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
        recv_bufs: &mut [[u8; MAX_OUTSIDE_MTU]; BATCH_SIZE],
        msg_count: usize,
    ) -> io::Result<usize> {
        // SAFETY: zeroed iovec is valid (null pointer + zero length).
        let mut iovecs = unsafe { mem::zeroed::<[libc::iovec; BATCH_SIZE]>() };
        // SAFETY: zeroed msghdr_x is valid (null pointers + zero lengths).
        let mut hdrs = unsafe { mem::zeroed::<[msghdr_x; BATCH_SIZE]>() };
        for i in 0..msg_count {
            iovecs[i].iov_base = recv_bufs[i].as_mut_ptr() as *mut libc::c_void;
            iovecs[i].iov_len = MAX_OUTSIDE_MTU;
            hdrs[i].msg_iov = &mut iovecs[i];
            hdrs[i].msg_iovlen = 1;
        }

        // SAFETY: hdrs and iovecs are valid for msg_count entries, fd is a valid and borrowed socket.
        let n = unsafe { recvmsg_x(fd, hdrs.as_mut_ptr(), msg_count as _, 0) };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(n as usize)
    }
}
