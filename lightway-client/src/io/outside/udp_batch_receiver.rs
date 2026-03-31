#![cfg(batch_receive)]

use anyhow::Result;
use bytes::BytesMut;
use rtrb::RingBuffer;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio_util::sync::{CancellationToken, DropGuard};

pub(crate) struct BatchReceiver {
    recv_ready: Arc<Semaphore>,
    recv_consumer: Mutex<rtrb::Consumer<BytesMut>>,
    _drop_guard: DropGuard,
}

const MAX_BUFFER_SIZE: usize = 1024;
impl BatchReceiver {
    pub fn new(sock: Arc<UdpSocket>) -> Self {
        let recv_ready = Arc::new(Semaphore::new(0));
        let (recv_producer, recv_consumer) = RingBuffer::new(MAX_BUFFER_SIZE);
        let cancellation_token = CancellationToken::new();
        let io_error = Arc::new(Mutex::new(None));
        Self {
            recv_ready,
            recv_consumer: Mutex::new(recv_consumer),
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
}

/// Maximum number of messages to send/receive in a single syscall.
const BATCH_SIZE: usize = 32;

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
