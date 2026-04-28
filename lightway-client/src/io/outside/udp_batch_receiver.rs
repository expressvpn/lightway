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

/// Check whether the platform supports batch receiving via `recvmsg_x`.
#[cfg(apple)]
pub(crate) fn is_batch_receive_available() -> bool {
    apple::is_batch_receive_available()
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

#[cfg(apple)]
mod apple {
    use bytes::BytesMut;
    use lightway_core::{MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU};
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
            // Should not happen, but just to play it safe
            if count > msg_count {
                return Err(io::Error::other(
                    "recvmsg_x returned more packets than requested",
                ));
            }
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

#[cfg(any(linux, android))]
mod linux {
    use bytes::BytesMut;
    use lightway_core::{MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU};
    use std::{io, mem};

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
                iovecs[i].iov_base =
                    recv_bufs[i].spare_capacity_mut().as_mut_ptr() as *mut libc::c_void;
                iovecs[i].iov_len = MAX_OUTSIDE_MTU;
                hdrs[i].msg_hdr.msg_iov = &mut iovecs[i];
                hdrs[i].msg_hdr.msg_iovlen = 1;
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
            for i in 0..count {
                let len = hdrs[i].msg_len as usize;
                // SAFETY: recvmmsg sets msg_len to the number of bytes received per message,
                // and we have early returned already if we have received no packets from the kernel.
                unsafe {
                    recv_bufs[i].set_len(len);
                }
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
