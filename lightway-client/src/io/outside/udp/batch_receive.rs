#![cfg(batch_receive)]

use bytes::BytesMut;
use lightway_core::MAX_IO_BATCH_SIZE;
use std::io;

/// Platform-specific batch receive syscall.
trait BatchRecvSyscall {
    /// Receive up to `msg_count` packets from `fd` into `recv_bufs`.
    /// Returns the number of packets actually received.
    fn recv_multiple(
        fd: libc::c_int,
        recv_bufs: &mut [BytesMut; MAX_IO_BATCH_SIZE],
        msg_count: usize,
    ) -> io::Result<usize>;
}

#[cfg(apple)]
type PlatformBatchRecv = apple::RecvmsgX;

#[cfg(any(linux, android))]
type PlatformBatchRecv = linux::Recvmmsg;

pub(crate) fn recv_multiple(
    fd: libc::c_int,
    recv_bufs: &mut [BytesMut; MAX_IO_BATCH_SIZE],
    max_batch_size: usize,
) -> io::Result<usize> {
    let max_batch_size = max_batch_size.min(MAX_IO_BATCH_SIZE);
    PlatformBatchRecv::recv_multiple(fd, recv_bufs, max_batch_size)
}

/// Batched GRO receive (Linux): one `recvmmsg` fills up to
/// `max_batch_size` datagrams, and for each we parse the per-message
/// `UDP_GRO` control message so a datagram the kernel coalesced is
/// reported with its segment size in `gro_sizes[i]` (`None` when the
/// kernel did not coalesce that message — e.g. an old kernel or a
/// server that sends zero-checksum UDP). Returns the datagram count.
///
/// This replaces one `recvmsg` per datagram on the download path with
/// one syscall per batch, independent of whether the kernel coalesces.
#[cfg(linux)]
pub(crate) fn recv_multiple_gro(
    fd: libc::c_int,
    recv_bufs: &mut [BytesMut; MAX_IO_BATCH_SIZE],
    gro_sizes: &mut [Option<u16>; MAX_IO_BATCH_SIZE],
    max_batch_size: usize,
) -> io::Result<usize> {
    linux::recv_multiple_gro(fd, recv_bufs, gro_sizes, max_batch_size.min(MAX_IO_BATCH_SIZE))
}

#[cfg(apple)]
mod apple {
    use bytes::BytesMut;
    use lightway_app_utils::recvmsg_x::{msghdr_x, recvmsg_x};
    use lightway_core::MAX_IO_BATCH_SIZE;
    use std::{io, mem};

    pub(crate) struct RecvmsgX;

    impl super::BatchRecvSyscall for RecvmsgX {
        /// Receive packets from the socket using the `recvmsg_x` batch syscall.
        /// Fills `recv_bufs` with up to `msg_count` messages and returns the number received.
        #[allow(unsafe_code)]
        fn recv_multiple(
            fd: libc::c_int,
            recv_bufs: &mut [BytesMut; MAX_IO_BATCH_SIZE],
            msg_count: usize,
        ) -> io::Result<usize> {
            // SAFETY: zeroed iovec is valid (null pointer + zero length).
            let mut iovecs = unsafe { mem::zeroed::<[libc::iovec; MAX_IO_BATCH_SIZE]>() };
            // SAFETY: zeroed msghdr_x is valid (null pointers + zero lengths).
            let mut hdrs = unsafe { mem::zeroed::<[msghdr_x; MAX_IO_BATCH_SIZE]>() };
            for i in 0..msg_count {
                // Advertise only the buffer's spare capacity to the kernel so
                // it can never write past the allocation; oversized datagrams
                // are truncated, matching the non-batch recv path.
                let spare = recv_bufs[i].spare_capacity_mut();
                let iovec = &mut iovecs[i];
                let hdr = &mut hdrs[i];
                iovec.iov_base = spare.as_mut_ptr() as *mut libc::c_void;
                iovec.iov_len = spare.len();
                hdr.msg_iov = iovec;
                hdr.msg_iovlen = 1;
            }

            // SAFETY: hdrs and iovecs are valid for msg_count entries, fd is a valid and borrowed socket.
            let n = unsafe { recvmsg_x(fd, hdrs.as_mut_ptr(), msg_count as _, 0) };

            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            let count = n as usize;
            // Should not happen, but just to play it safe
            if count > msg_count {
                return Err(io::Error::other(
                    "recvmsg_x returned more packets than requested",
                ));
            }
            // Note: current XNU does not set MSG_TRUNC in the per-message
            // msg_flags of recvmsg_x (only MSG_CTRUNC is reported there), so
            // this count stays zero on Apple platforms today. The check is
            // kept in case the kernel gains support.
            let mut truncated = 0usize;
            for i in 0..count {
                let hdr = &hdrs[i];
                // For recvmsg_x(), the size of the data received is given by the field msg_datalen.
                let len = hdr.msg_datalen;
                let recv_buf = &mut recv_bufs[i];
                let new_len = recv_buf.len() + len;
                // SAFETY: the kernel wrote `len` bytes into the spare capacity
                // advertised via the iovec, which was bounded by that spare
                // capacity, so `new_len <= capacity()`.
                unsafe {
                    recv_buf.set_len(new_len);
                }
                if hdr.msg_flags & libc::MSG_TRUNC != 0 {
                    truncated += 1;
                }
            }
            if truncated > 0 {
                tracing::warn!(
                    "{truncated} datagram(s) truncated to receive buffer capacity; \
                     the configured outside_mtu may be too small"
                );
            }

            Ok(count)
        }
    }
}

#[cfg(any(linux, android))]
mod linux {
    use bytes::BytesMut;
    use lightway_core::MAX_IO_BATCH_SIZE;
    use std::{io, mem};

    /// Per-message control buffer for one `UDP_GRO` cmsg, aligned for
    /// `cmsghdr` as the `CMSG_*` macros require. Stack-allocated and
    /// reused per call — no heap traffic on the receive hot path.
    #[cfg(linux)]
    #[repr(C, align(16))]
    struct GroControl([u8; lightway_app_utils::cmsg::Message::space::<libc::c_int>()]);

    /// One `recvmmsg` with per-message `UDP_GRO` control parsing.
    #[cfg(linux)]
    #[allow(unsafe_code)]
    pub(crate) fn recv_multiple_gro(
        fd: libc::c_int,
        recv_bufs: &mut [BytesMut; MAX_IO_BATCH_SIZE],
        gro_sizes: &mut [Option<u16>; MAX_IO_BATCH_SIZE],
        msg_count: usize,
    ) -> io::Result<usize> {
        use lightway_app_utils::cmsg;

        const CTRL_LEN: usize = cmsg::Message::space::<libc::c_int>();

        // SAFETY: a zeroed iovec is valid (null pointer + zero length).
        let mut iovecs = unsafe { mem::zeroed::<[libc::iovec; MAX_IO_BATCH_SIZE]>() };
        // SAFETY: a zeroed mmsghdr is valid (null pointers + zero lengths).
        let mut hdrs = unsafe { mem::zeroed::<[libc::mmsghdr; MAX_IO_BATCH_SIZE]>() };
        // Aligned, zeroed control area per message (see `GroControl`).
        let mut ctrls: [GroControl; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| GroControl([0u8; CTRL_LEN]));

        for i in 0..msg_count {
            // Advertise only the buffer's spare capacity so the kernel
            // can never write past the allocation; oversized datagrams
            // are truncated, matching the non-batch recv path.
            let spare = recv_bufs[i].spare_capacity_mut();
            iovecs[i].iov_base = spare.as_mut_ptr() as *mut libc::c_void;
            iovecs[i].iov_len = spare.len();
            hdrs[i].msg_hdr.msg_iov = &mut iovecs[i];
            hdrs[i].msg_hdr.msg_iovlen = 1;
            hdrs[i].msg_hdr.msg_control = ctrls[i].0.as_mut_ptr() as *mut libc::c_void;
            hdrs[i].msg_hdr.msg_controllen = CTRL_LEN as _;
        }

        // SAFETY: hdrs/iovecs/ctrls are valid for msg_count entries and
        // outlive the call; fd is a valid borrowed socket.
        let n = unsafe {
            libc::recvmmsg(
                fd,
                hdrs.as_mut_ptr(),
                msg_count as _,
                0,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let count = (n as usize).min(msg_count);
        let mut truncated = 0usize;
        for i in 0..count {
            let len = hdrs[i].msg_len as usize;
            let recv_buf = &mut recv_bufs[i];
            let new_len = recv_buf.len() + len;
            // SAFETY: the kernel wrote `len` bytes into the spare
            // capacity advertised via the iovec, bounded by it, so
            // `new_len <= capacity()`.
            unsafe {
                recv_buf.set_len(new_len);
            }

            // Parse the per-message control area for a UDP_GRO segment
            // size. `msg_controllen` is what the kernel actually wrote.
            let controllen = hdrs[i].msg_hdr.msg_controllen as usize;
            gro_sizes[i] = if controllen == 0 {
                None
            } else {
                cmsg::first_udp_gro_segment(&ctrls[i].0[..controllen])
            };

            if hdrs[i].msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                truncated += 1;
            }
        }
        if truncated > 0 {
            tracing::warn!(
                "{truncated} datagram(s) truncated to receive buffer capacity; \
                 the configured outside_mtu may be too small"
            );
        }

        Ok(count)
    }

    pub(crate) struct Recvmmsg;

    impl super::BatchRecvSyscall for Recvmmsg {
        /// Receive packets from the socket using the `recvmmsg` batch syscall.
        /// Fills `recv_bufs` with up to `msg_count` messages and returns the number received.
        #[allow(unsafe_code)]
        fn recv_multiple(
            fd: libc::c_int,
            recv_bufs: &mut [BytesMut; MAX_IO_BATCH_SIZE],
            msg_count: usize,
        ) -> io::Result<usize> {
            // SAFETY: zeroed iovec is valid (null pointer + zero length).
            let mut iovecs = unsafe { mem::zeroed::<[libc::iovec; MAX_IO_BATCH_SIZE]>() };
            // SAFETY: zeroed mmsghdr is valid (null pointers + zero lengths).
            let mut hdrs = unsafe { mem::zeroed::<[libc::mmsghdr; MAX_IO_BATCH_SIZE]>() };
            for i in 0..msg_count {
                // Advertise only the buffer's spare capacity to the kernel so
                // it can never write past the allocation; oversized datagrams
                // are truncated, matching the non-batch recv path.
                let spare = recv_bufs[i].spare_capacity_mut();
                let iovec = &mut iovecs[i];
                let hdr = &mut hdrs[i];
                iovec.iov_base = spare.as_mut_ptr() as *mut libc::c_void;
                iovec.iov_len = spare.len();
                hdr.msg_hdr.msg_iov = iovec;
                hdr.msg_hdr.msg_iovlen = 1;
            }

            // SAFETY: hdrs and iovecs are valid for msg_count entries, fd is a valid and borrowed socket.
            let n = unsafe {
                libc::recvmmsg(
                    fd,
                    hdrs.as_mut_ptr(),
                    msg_count as _,
                    0,
                    std::ptr::null_mut(),
                )
            };

            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            let count = n as usize;
            // Should not happen, but just to play it safe
            if count > msg_count {
                return Err(io::Error::other(
                    "recvmmsg returned more packets than requested",
                ));
            }
            let mut truncated = 0usize;
            for i in 0..count {
                let hdr = &hdrs[i];
                // recvmmsg sets msg_len to the number of bytes received per message.
                let len = hdr.msg_len as usize;
                let recv_buf = &mut recv_bufs[i];
                let new_len = recv_buf.len() + len;
                // SAFETY: the kernel wrote `len` bytes into the spare capacity
                // advertised via the iovec, which was bounded by that spare
                // capacity, so `new_len <= capacity()`.
                unsafe {
                    recv_buf.set_len(new_len);
                }
                if hdr.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                    truncated += 1;
                }
            }
            if truncated > 0 {
                tracing::warn!(
                    "{truncated} datagram(s) truncated to receive buffer capacity; \
                     the configured outside_mtu may be too small"
                );
            }

            Ok(count)
        }
    }
}

#[cfg(test)]
#[serial_test::serial]
mod tests {
    use super::*;
    use lightway_core::MAX_OUTSIDE_MTU;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    async fn make_socket_pair() -> (UdpSocket, UdpSocket) {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .connect(receiver.local_addr().unwrap())
            .await
            .unwrap();
        (sender, receiver)
    }

    #[tokio::test]
    async fn recv_multiple_single_packet() {
        let (sender, receiver) = make_socket_pair().await;

        sender.send(b"hello").await.unwrap();

        let mut bufs: [BytesMut; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BytesMut::with_capacity(MAX_OUTSIDE_MTU));

        tokio::time::timeout(Duration::from_secs(2), receiver.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&receiver);
        let count = PlatformBatchRecv::recv_multiple(fd, &mut bufs, MAX_IO_BATCH_SIZE).unwrap();
        assert!(count >= 1);
        assert_eq!(&bufs[0][..], b"hello");
    }

    #[tokio::test]
    async fn recv_multiple_truncates_datagram_larger_than_buffer_capacity() {
        let (sender, receiver) = make_socket_pair().await;

        // A datagram larger than the buffer's capacity (e.g. a configured
        // outside_mtu smaller than the received packet) must be truncated by
        // the kernel rather than written past the allocation
        const SMALL_CAPACITY: usize = 16;
        let payload = [0xa5u8; SMALL_CAPACITY * 4];
        sender.send(&payload).await.unwrap();

        let mut bufs: [BytesMut; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BytesMut::with_capacity(SMALL_CAPACITY));
        let capacity = bufs[0].capacity();

        tokio::time::timeout(Duration::from_secs(2), receiver.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&receiver);
        let count = PlatformBatchRecv::recv_multiple(fd, &mut bufs, MAX_IO_BATCH_SIZE).unwrap();
        assert_eq!(count, 1);
        assert_eq!(bufs[0].len(), capacity);
        assert_eq!(&bufs[0][..], &payload[..capacity]);
    }

    /// Linux/Android only: current XNU never copies MSG_TRUNC into
    /// recvmsg_x's per-message msg_flags, so the warning cannot fire on
    /// Apple platforms.
    #[cfg(any(linux, android))]
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn recv_multiple_warns_when_datagrams_are_truncated() {
        let (sender, receiver) = make_socket_pair().await;

        const SMALL_CAPACITY: usize = 16;
        let mut bufs: [BytesMut; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BytesMut::with_capacity(SMALL_CAPACITY));
        let capacity = bufs[0].capacity();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&receiver);

        // A datagram that fits must not produce a truncation warning.
        sender.send(&vec![0u8; capacity / 2]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), receiver.readable())
            .await
            .unwrap()
            .unwrap();
        let count = PlatformBatchRecv::recv_multiple(fd, &mut bufs, MAX_IO_BATCH_SIZE).unwrap();
        assert_eq!(count, 1);
        assert!(
            !logs_contain("truncated"),
            "no warning expected for a datagram that fits",
        );

        for buf in &mut bufs {
            buf.clear();
        }

        // A datagram larger than the buffer capacity must produce a single
        // truncation warning for the batch. Use a fresh socket pair: the raw
        // recv above bypassed tokio, leaving the first receiver's readiness
        // cached, so another readable().await on it would not actually wait
        // for this datagram to arrive.
        let (sender, receiver) = make_socket_pair().await;
        let fd = std::os::fd::AsRawFd::as_raw_fd(&receiver);
        sender.send(&vec![0xa5u8; capacity * 4]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), receiver.readable())
            .await
            .unwrap()
            .unwrap();
        let count = PlatformBatchRecv::recv_multiple(fd, &mut bufs, MAX_IO_BATCH_SIZE).unwrap();
        assert_eq!(count, 1);
        logs_assert(|lines: &[&str]| {
            match lines
                .iter()
                .inspect(|f| eprintln!("{}", f))
                .filter(|line| line.contains("WARN") && line.contains("truncated"))
                .count()
            {
                1 => Ok(()),
                n => Err(format!("expected exactly one truncation warning, got {n}")),
            }
        });
    }

    #[tokio::test]
    async fn recv_multiple_multiple_packets() {
        let (sender, receiver) = make_socket_pair().await;

        for i in 0..10u8 {
            sender.send(&[i]).await.unwrap();
        }

        // Give packets time to arrive in kernel buffer.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut bufs: [BytesMut; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BytesMut::with_capacity(MAX_OUTSIDE_MTU));

        tokio::time::timeout(Duration::from_secs(2), receiver.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&receiver);
        let count = PlatformBatchRecv::recv_multiple(fd, &mut bufs, MAX_IO_BATCH_SIZE).unwrap();
        assert!(count >= 1);
        // Verify received packets are in order.
        for (i, b) in bufs.iter().enumerate().take(count) {
            assert_eq!(b[0], i as u8);
        }
    }
}
