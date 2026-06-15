//! Platform-specific batch UDP receive syscalls for Lightway Server
//!
//! - [`recv_multiple_with_metadata`] — fuller API for sockets that need to
//!   demultiplex incoming packets by source address and/or read per-packet
//!   control messages (e.g. `IP_PKTINFO` on a server socket bound to
//!   `0.0.0.0`). Fills source address and a caller-provided control buffer in
//!   addition to the data.

use crate::io::outside::udp::cmsg;
use crate::io::outside::udp::cmsg::LibcControlLen;
use bytes::BytesMut;
use lightway_core::MAX_IO_BATCH_SIZE;
use std::io;
use std::net::SocketAddr;

/// Platform-specific batch receive syscall.
trait ServerBatchRecvSyscall {
    /// Receive up to `msg_count` packets from `fd` into `slots`, filling
    /// per-packet peer address and control (cmsg) data alongside the payload.
    /// Returns the number of packets actually received.
    fn recv_multiple_with_metadata<const CONTROL_SIZE: usize>(
        fd: libc::c_int,
        slots: &mut [BatchRecvSlot<CONTROL_SIZE>; MAX_IO_BATCH_SIZE],
        msg_count: usize,
    ) -> io::Result<usize>;
}

/// Per-slot state for a batched UDP receive that also captures the source
/// address and any control messages (cmsg) the kernel returns.
///
/// Construct once with [`BatchRecvSlot::new`] and reuse across calls by
/// invoking [`BatchRecvSlot::reset`] between batches.
pub struct BatchRecvSlot<const CONTROL_SIZE: usize> {
    /// Data buffer for the packet payload.
    ///
    /// Spare capacity should be at least [`lightway_core::MAX_OUTSIDE_MTU`]
    /// before each batch call. The syscall advertises at most the spare capacity
    /// to the kernel, so an undersized buffer results in truncated datagrams
    /// rather than an out-of-bounds write. The syscall sets the length to the
    /// number of bytes actually received.
    pub buf: BytesMut,
    /// Control message buffer.
    ///
    /// Caller supplies the capacity needed for the cmsg types they care about
    /// (e.g. `CMSG_SPACE(sizeof(in_pktinfo))`). The syscall sets the length to
    /// the number of bytes of cmsg data the kernel wrote.
    pub control: Option<cmsg::Buffer<CONTROL_SIZE>>,
    /// Out: Control message buffer length
    pub control_length: Option<LibcControlLen>,
    /// Out: source-address storage written by the kernel. `SockAddrStorage`
    /// is `#[repr(transparent)]` over `libc::sockaddr_storage`, so it can be
    /// handed to a raw recvmsg-style syscall and afterwards decoded via
    /// [`BatchRecvSlot::take_peer_addr`].
    peer_addr_storage: socket2::SockAddrStorage,
    /// Buffer length for the source address. Pre-filled with
    /// [`socket2::SockAddrStorage::size_of`] when we call reset() so the kernel
    /// knows how much room it has; the syscall replaces it with the actual
    /// number of bytes it wrote (typically `sizeof(sockaddr_in)` for IPv4 or
    /// `sizeof(sockaddr_in6)` for IPv6).
    peer_addr_len: libc::socklen_t,
    /// Out: `true` if the kernel set `MSG_TRUNC` in `msg_flags` for this
    /// packet, meaning the datagram was larger than the buffer we supplied and
    /// the tail was discarded. Callers should treat the payload as incomplete.
    ///
    /// Note: on Apple platforms this stays `false` — current XNU does not set
    /// `MSG_TRUNC` in the per-message `msg_flags` of `recvmsg_x` (only
    /// `MSG_CTRUNC` is reported there).
    pub truncated: bool,
}

impl<const CONTROL_SIZE: usize> BatchRecvSlot<CONTROL_SIZE> {
    /// Create a slot with data spare-capacity of [`lightway_core::MAX_OUTSIDE_MTU`]
    /// and a control buffer of `control_capacity` bytes.
    pub fn new() -> Self {
        let peer_addr_storage = socket2::SockAddrStorage::zeroed();
        let peer_addr_len = peer_addr_storage.size_of();
        Self {
            buf: BytesMut::with_capacity(lightway_core::MAX_OUTSIDE_MTU),
            control: if CONTROL_SIZE > 0 {
                Some(cmsg::Buffer::<CONTROL_SIZE>::new())
            } else {
                None
            },
            control_length: None,
            peer_addr_storage,
            peer_addr_len,
            truncated: false,
        }
    }

    /// Reset the slot for a new batch receive without releasing any
    /// allocations: clears the buffer length (preserving capacity) and restores
    /// the source-address length bound so the kernel knows how much room the
    /// storage has. The address storage itself is not touched here — it is left
    /// zeroed by [`take_peer_addr`](Self::take_peer_addr) and overwritten by the
    /// kernel on the next receive.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.buf.reserve(lightway_core::MAX_OUTSIDE_MTU);
        if let Some(control) = &mut self.control {
            control.reset();
        }
        self.control_length = None;
        self.peer_addr_len = self.peer_addr_storage.size_of();
        self.truncated = false;
    }

    /// Convert the slot's source-address storage into a [`SocketAddr`], taking
    /// the stored address (the slot's storage is left zeroed afterwards).
    ///
    /// Returns `None` if the address family is not `AF_INET` or `AF_INET6`,
    /// which should not happen for a UDP/IP socket.
    pub fn take_peer_addr(&mut self) -> Option<SocketAddr> {
        // `SockAddr::new` consumes the storage by value, so move the
        // kernel-populated bytes out of the slot (leaving a zeroed storage in
        // their place) rather than copying them. The length is what the
        // syscall returned for this packet (typically `sizeof(sockaddr_in)`
        // for IPv4 or `sizeof(sockaddr_in6)` for IPv6).
        let storage = std::mem::replace(
            &mut self.peer_addr_storage,
            socket2::SockAddrStorage::zeroed(),
        );
        // SAFETY: `storage` holds the source address the kernel wrote and
        // `peer_addr_len` is the length the syscall reported for it.
        #[allow(unsafe_code)]
        unsafe {
            socket2::SockAddr::new(storage, self.peer_addr_len).as_socket()
        }
    }
}

#[cfg(macos)]
type PlatformBatchRecv = apple::RecvmsgX;

#[cfg(linux)]
type PlatformBatchRecv = linux::Recvmmsg;

/// Receive up to `max_batch_size` packets from `fd` into `slots`, filling each
/// slot's peer address and control buffer in addition to the data buffer.
///
/// Returns the number of packets received. On `Ok(n)`, for every `i < n`:
/// - `slots[i].buf.len()` is set to the bytes received,
/// - `slots[i].control.len()` is set to the cmsg bytes received,
/// - `slots[i].peer_addr_storage` holds the source address (use
///   [`BatchRecvSlot::take_peer_addr`] to decode).
///
/// Callers must call [`BatchRecvSlot::reset`] on each slot before invoking this
/// again, otherwise the data and control lengths from the previous call leak
/// into the new one.
pub(crate) fn recv_multiple_with_metadata<const CONTROL_SIZE: usize>(
    fd: libc::c_int,
    slots: &mut [BatchRecvSlot<CONTROL_SIZE>; MAX_IO_BATCH_SIZE],
    max_batch_size: usize,
) -> io::Result<usize> {
    let max_batch_size = max_batch_size.min(MAX_IO_BATCH_SIZE);
    PlatformBatchRecv::recv_multiple_with_metadata(fd, slots, max_batch_size)
}

#[cfg(macos)]
mod apple {
    use crate::io::outside::udp::cmsg::LibcControlLen;
    use lightway_app_utils::recvmsg_x::{msghdr_x, recvmsg_x};
    use lightway_core::{MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU};
    use std::{io, mem};

    pub(crate) struct RecvmsgX;

    impl super::ServerBatchRecvSyscall for RecvmsgX {
        /// Receive packets with peer-address and control (cmsg) metadata using
        /// the `recvmsg_x` batch syscall.
        #[allow(unsafe_code)]
        fn recv_multiple_with_metadata<const CONTROL_SIZE: usize>(
            fd: libc::c_int,
            slots: &mut [super::BatchRecvSlot<CONTROL_SIZE>; MAX_IO_BATCH_SIZE],
            msg_count: usize,
        ) -> io::Result<usize> {
            // SAFETY: zeroed iovec are valid (null pointers + zero lengths).
            let mut iovecs = unsafe { mem::zeroed::<[libc::iovec; MAX_IO_BATCH_SIZE]>() };
            // SAFETY: zeroed msghdr_x is valid (null pointers + zero lengths).
            let mut hdrs = unsafe { mem::zeroed::<[msghdr_x; MAX_IO_BATCH_SIZE]>() };
            for (i, slot) in slots.iter_mut().take(msg_count).enumerate() {
                let spare = slot.buf.spare_capacity_mut();
                debug_assert!(
                    spare.len() >= MAX_OUTSIDE_MTU,
                    "slot {i}: buf spare capacity ({}) < MAX_OUTSIDE_MTU ({MAX_OUTSIDE_MTU})",
                    spare.len(),
                );

                let iovec = &mut iovecs[i];
                let hdr = &mut hdrs[i];
                // Bound the iovec by the spare capacity actually available so
                // the kernel can never write past the allocation, even if a
                // caller violates the spare-capacity contract above.
                iovec.iov_base = spare.as_mut_ptr() as *mut libc::c_void;
                iovec.iov_len = spare.len().min(MAX_OUTSIDE_MTU);
                hdr.msg_iov = iovec;
                hdr.msg_iovlen = 1;

                hdr.msg_name = &mut slot.peer_addr_storage as *mut socket2::SockAddrStorage
                    as *mut libc::c_void;
                hdr.msg_namelen = slot.peer_addr_len;

                if let Some(control) = &mut slot.control {
                    hdr.msg_control = control.as_mut().as_mut_ptr() as *mut libc::c_void;
                    hdr.msg_controllen = control.capacity() as LibcControlLen;
                }
            }

            // SAFETY: hdrs/iovecs and the per-slot storage referenced by their
            // pointers remain valid for the duration of the syscall; `slots`
            // is borrowed mutably for the whole call.
            let n = unsafe { recvmsg_x(fd, hdrs.as_mut_ptr(), msg_count as _, 0) };

            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            let count = n as usize;
            if count > msg_count {
                return Err(io::Error::other(
                    "recvmsg_x returned more packets than requested",
                ));
            }
            for (slot, hdr) in slots.iter_mut().take(count).zip(hdrs) {
                // For recvmsg_x(), the size of the data received is given by the field msg_datalen.
                let len = hdr.msg_datalen;
                let new_len = slot.buf.len() + len;
                // SAFETY: the kernel wrote `len` bytes into the spare capacity
                // advertised via the iovec, which was bounded by that spare
                // capacity, so `new_len <= capacity()`.
                unsafe {
                    slot.buf.set_len(new_len);
                }
                slot.peer_addr_len = hdr.msg_namelen;
                if slot.control.is_some() {
                    slot.control_length = Some(hdr.msg_controllen);
                }
                // Note: current XNU does not set MSG_TRUNC in the per-message
                // msg_flags of recvmsg_x (only MSG_CTRUNC is reported there),
                // so this stays false today. The check is kept in case the
                // kernel gains support.
                slot.truncated = hdr.msg_flags & libc::MSG_TRUNC != 0;
            }

            Ok(count)
        }
    }
}

#[cfg(linux)]
mod linux {
    use crate::io::outside::udp::cmsg::LibcControlLen;
    use lightway_core::{MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU};
    use std::{io, mem};

    pub(crate) struct Recvmmsg;

    impl super::ServerBatchRecvSyscall for Recvmmsg {
        /// Receive packets with peer-address and control (cmsg) metadata using
        /// the `recvmmsg` batch syscall.
        #[allow(unsafe_code)]
        fn recv_multiple_with_metadata<const CONTROL_SIZE: usize>(
            fd: libc::c_int,
            slots: &mut [super::BatchRecvSlot<CONTROL_SIZE>; MAX_IO_BATCH_SIZE],
            msg_count: usize,
        ) -> io::Result<usize> {
            // SAFETY: zeroed iovec are valid (null pointers + zero lengths).
            let mut iovecs = unsafe { mem::zeroed::<[libc::iovec; MAX_IO_BATCH_SIZE]>() };
            // SAFETY: zeroed hdrs are valid (null pointers + zero lengths).
            let mut hdrs = unsafe { mem::zeroed::<[libc::mmsghdr; MAX_IO_BATCH_SIZE]>() };
            for (i, slot) in slots.iter_mut().take(msg_count).enumerate() {
                let spare = slot.buf.spare_capacity_mut();
                debug_assert!(
                    spare.len() >= MAX_OUTSIDE_MTU,
                    "slot {i}: buf spare capacity ({}) < MAX_OUTSIDE_MTU ({MAX_OUTSIDE_MTU})",
                    spare.len(),
                );

                let iovec = &mut iovecs[i];
                let hdr = &mut hdrs[i];
                // Bound the iovec by the spare capacity actually available so
                // the kernel can never write past the allocation, even if a
                // caller violates the spare-capacity contract above.
                iovec.iov_base = spare.as_mut_ptr() as *mut libc::c_void;
                iovec.iov_len = spare.len().min(MAX_OUTSIDE_MTU);
                hdr.msg_hdr.msg_iov = iovec;
                hdr.msg_hdr.msg_iovlen = 1;

                hdr.msg_hdr.msg_name = &mut slot.peer_addr_storage as *mut socket2::SockAddrStorage
                    as *mut libc::c_void;
                hdr.msg_hdr.msg_namelen = slot.peer_addr_len;

                if let Some(control) = &mut slot.control {
                    hdr.msg_hdr.msg_control = control.as_mut().as_mut_ptr() as *mut libc::c_void;
                    hdr.msg_hdr.msg_controllen = control.capacity() as LibcControlLen;
                }
            }

            // SAFETY: hdrs/iovecs and the per-slot storage referenced by their
            // pointers remain valid for the duration of the syscall; `slots`
            // is borrowed mutably for the whole call.
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
            if count > msg_count {
                return Err(io::Error::other(
                    "recvmmsg returned more packets than requested",
                ));
            }
            for (slot, hdr) in slots.iter_mut().take(count).zip(hdrs) {
                // recvmmsg sets msg_len to the number of bytes received per message.
                let len = hdr.msg_len as usize;
                let new_len = slot.buf.len() + len;
                // SAFETY: the kernel wrote `len` bytes into the spare capacity
                // advertised via the iovec, which was bounded by that spare
                // capacity, so `new_len <= capacity()`.
                unsafe {
                    slot.buf.set_len(new_len);
                }
                slot.peer_addr_len = hdr.msg_hdr.msg_namelen;
                if slot.control.is_some() {
                    slot.control_length = Some(hdr.msg_hdr.msg_controllen);
                }
                slot.truncated = hdr.msg_hdr.msg_flags & libc::MSG_TRUNC != 0;
            }

            Ok(count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    #[test]
    fn reset_returns_slot_to_fresh_state() {
        const CONTROL_CAP: usize = 64;
        let mut slot: BatchRecvSlot<CONTROL_CAP> = BatchRecvSlot::new();

        let initial_buf_cap = slot.buf.capacity();
        let initial_peer_addr_len = slot.peer_addr_len;
        let initial_control_cap = slot
            .control
            .as_ref()
            .expect("CONTROL_CAP > 0 should allocate a control buffer")
            .capacity();

        // Dirty every output field as a kernel write would. The address
        // storage itself is owned by `take_peer_addr` (see its own test), so
        // `reset` only has to restore the length bound here.
        slot.buf.extend_from_slice(b"junk payload");
        slot.control_length = Some(32);
        slot.truncated = true;
        slot.peer_addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        slot.reset();

        assert_eq!(slot.buf.len(), 0, "reset must clear buf len");
        assert_eq!(
            slot.buf.capacity(),
            initial_buf_cap,
            "reset must preserve buf capacity",
        );
        let control = slot.control.as_ref().expect("control buffer still present");
        assert_eq!(
            control.capacity(),
            initial_control_cap,
            "reset must preserve control capacity",
        );
        assert!(
            slot.control_length.is_none(),
            "reset must clear control_length",
        );
        assert_eq!(
            slot.peer_addr_len, initial_peer_addr_len,
            "reset must restore peer_addr_len to the storage bound",
        );
        assert!(!slot.truncated, "reset must clear the truncated flag");
    }

    #[test]
    fn take_peer_addr_consumes_the_stored_address() {
        const CONTROL_CAP: usize = 64;
        let mut slot: BatchRecvSlot<CONTROL_CAP> = BatchRecvSlot::new();

        // Simulate a kernel write of an IPv4 source address.
        slot.peer_addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        #[allow(unsafe_code)]
        // SAFETY: `SockAddrStorage` is `#[repr(transparent)]` over
        // `sockaddr_storage`, large enough for any sockaddr. Setting
        // `ss_family = AF_INET` makes `take_peer_addr` decode it as an IPv4
        // socket address (with zero bytes for ip/port).
        unsafe {
            let storage = slot.peer_addr_storage.view_as::<libc::sockaddr_storage>();
            storage.ss_family = libc::AF_INET as _;
        }

        assert!(
            slot.take_peer_addr().is_some(),
            "first take must decode the kernel-written AF_INET address",
        );
        assert!(
            slot.take_peer_addr().is_none(),
            "take_peer_addr must leave the storage zeroed (AF_UNSPEC -> None)",
        );
    }

    #[test]
    fn reset_with_zero_control_capacity_keeps_control_none() {
        let mut slot: BatchRecvSlot<0> = BatchRecvSlot::new();
        assert!(
            slot.control.is_none(),
            "CONTROL_SIZE == 0 must not allocate a control buffer",
        );

        slot.buf.extend_from_slice(b"junk");
        slot.control_length = Some(8);
        slot.reset();

        assert_eq!(slot.buf.len(), 0);
        assert!(
            slot.control.is_none(),
            "reset must not allocate a control buffer when CONTROL_SIZE == 0",
        );
        assert!(slot.control_length.is_none());
    }

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
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn recv_multiple_with_metadata_single_packet() {
        let (sender, receiver) = make_socket_pair().await;

        sender.send(b"hello").await.unwrap();

        // No cmsg sockopt enabled on this connected socket, so zero control capacity.
        let mut slots: [BatchRecvSlot<0>; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BatchRecvSlot::new());

        tokio::time::timeout(Duration::from_secs(2), receiver.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&receiver);
        let count =
            PlatformBatchRecv::recv_multiple_with_metadata(fd, &mut slots, MAX_IO_BATCH_SIZE)
                .unwrap();
        assert!(count >= 1);
        assert_eq!(&slots[0].buf[..], b"hello");
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn recv_multiple_with_metadata_truncates_oversized_datagram() {
        let (sender, receiver) = make_socket_pair().await;

        // A datagram larger than MAX_OUTSIDE_MTU must be truncated to the
        // iovec we advertised and never written past the buffer's allocation.
        // On Linux it is additionally reported via the truncated flag.
        let payload = vec![0xa5u8; lightway_core::MAX_OUTSIDE_MTU + 500];
        sender.send(&payload).await.unwrap();

        let mut slots: [BatchRecvSlot<0>; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BatchRecvSlot::new());

        tokio::time::timeout(Duration::from_secs(2), receiver.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&receiver);
        let count =
            PlatformBatchRecv::recv_multiple_with_metadata(fd, &mut slots, MAX_IO_BATCH_SIZE)
                .unwrap();
        assert_eq!(count, 1);

        let slot = &slots[0];
        assert_eq!(slot.buf.len(), lightway_core::MAX_OUTSIDE_MTU);
        assert_eq!(&slot.buf[..], &payload[..lightway_core::MAX_OUTSIDE_MTU]);
        // recvmsg_x on Apple platforms does not report MSG_TRUNC in the
        // per-message msg_flags, so the truncated flag can only be asserted
        // where recvmmsg provides it.
        #[cfg(linux)]
        assert!(
            slot.truncated,
            "MSG_TRUNC must be reported for oversized datagrams",
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn recv_multiple_with_metadata_populates_peer_addr() {
        // Unconnected server-side socket: accepts from any peer.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let sender_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sender_a.local_addr().unwrap();
        let addr_b = sender_b.local_addr().unwrap();

        // Use a non-zero control capacity so we can verify reset() preserves
        // control-buffer capacity even though this test doesn't enable any
        // cmsg sockopt on the server.
        const CONTROL_CAP: usize = 64;
        let mut slots: [BatchRecvSlot<CONTROL_CAP>; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BatchRecvSlot::new());

        let storage_size_of = slots[0].peer_addr_storage.size_of();
        for (i, slot) in slots.iter().enumerate() {
            assert_eq!(slot.buf.len(), 0, "slot {i}: fresh buf must be empty");
            assert!(
                slot.buf.capacity() >= lightway_core::MAX_OUTSIDE_MTU,
                "slot {i}: buf cap {} < MAX_OUTSIDE_MTU",
                slot.buf.capacity(),
            );
            assert_eq!(slot.peer_addr_len, storage_size_of);
        }

        sender_a.send_to(b"alpha", server_addr).await.unwrap();
        sender_b.send_to(b"bravo", server_addr).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        tokio::time::timeout(Duration::from_secs(2), server.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&server);
        let count =
            PlatformBatchRecv::recv_multiple_with_metadata(fd, &mut slots, MAX_IO_BATCH_SIZE)
                .unwrap();
        assert!(count >= 1);

        // recvmmsg/recvmsg_x ordering across distinct peers isn't guaranteed,
        // so check that both senders appear among the received slots.
        let received: Vec<(std::net::SocketAddr, Vec<u8>)> = slots[..count]
            .iter_mut()
            .map(|s| (s.take_peer_addr().expect("AF_INET peer"), s.buf.to_vec()))
            .collect();
        assert!(
            received.contains(&(addr_a, b"alpha".to_vec())),
            "missing alpha from {addr_a}: got {received:?}",
        );
        assert!(
            received.contains(&(addr_b, b"bravo".to_vec())),
            "missing bravo from {addr_b}: got {received:?}",
        );

        let expected_v4_addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        for (i, slot) in slots[..count].iter().enumerate() {
            assert_eq!(slot.buf.len(), 5, "slot {i}: payload was 5 bytes");
            assert_eq!(
                slot.peer_addr_len, expected_v4_addrlen,
                "slot {i}: AF_INET peer_addr_len should be sizeof(sockaddr_in)",
            );
        }

        // Reset all slots and verify they're back to a clean "ready for next
        // batch" state without releasing the underlying allocations.
        let buf_caps_before: Vec<usize> = slots.iter().map(|s| s.buf.capacity()).collect();
        for slot in &mut slots {
            slot.reset();
        }
        for (i, slot) in slots.iter_mut().enumerate() {
            assert_eq!(slot.buf.len(), 0, "slot {i}: reset must clear buf len");
            assert_eq!(
                slot.buf.capacity(),
                buf_caps_before[i],
                "slot {i}: reset must preserve buf capacity",
            );
            assert_eq!(
                slot.peer_addr_len, storage_size_of,
                "slot {i}: reset must restore peer_addr_len to the buffer bound",
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn recv_multiple_with_metadata_populates_control_length() {
        // Unconnected server socket with IP_PKTINFO enabled so the kernel
        // writes a cmsg into our control buffer for each received packet.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        lightway_app_utils::sockopt::socket_enable_pktinfo(&server).unwrap();

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"pktinfo", server_addr).await.unwrap();

        const CONTROL_CAP: usize = cmsg::Message::space::<libc::in_pktinfo>();
        let mut slots: [BatchRecvSlot<CONTROL_CAP>; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BatchRecvSlot::new());

        // Sanity: a fresh slot has no control_length until the syscall writes one.
        assert!(slots[0].control_length.is_none());

        tokio::time::timeout(Duration::from_secs(2), server.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&server);
        let count =
            PlatformBatchRecv::recv_multiple_with_metadata(fd, &mut slots, MAX_IO_BATCH_SIZE)
                .unwrap();
        assert!(count >= 1);

        let slot = &slots[0];
        assert_eq!(&slot.buf[..], b"pktinfo");

        let control_len = slot
            .control_length
            .expect("control_length should be Some after recv with cmsg enabled");
        assert!(
            (control_len as usize) >= std::mem::size_of::<libc::cmsghdr>(),
            "control_length ({control_len}) too small to hold a cmsghdr",
        );
        assert!(
            (control_len as usize) <= CONTROL_CAP,
            "control_length ({control_len}) exceeded control capacity ({CONTROL_CAP})",
        );
    }
}
