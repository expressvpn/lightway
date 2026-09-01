//! Platform-specific batch UDP receive syscalls for Lightway Server
//!
//! - [`recv_multiple_with_metadata`] — fuller API for sockets that need to
//!   demultiplex incoming packets by source address and/or read per-packet
//!   control messages (e.g. `IP_PKTINFO` on a server socket bound to
//!   `0.0.0.0`). Fills source address and a caller-provided control buffer in
//!   addition to the data.

use bytes::BytesMut;
use lightway_app_utils::cmsg;
use lightway_app_utils::cmsg::LibcControlLen;
use lightway_core::{MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU};
use std::io;
use std::net::SocketAddr;

const CONTROL_SIZE: usize = super::PKTINFO_CONTROL_SIZE;

/// Per-packet metadata for a batched UDP receive: the source address and
/// any control messages (cmsg) the kernel returns.
///
/// The payload buffers are supplied by the caller, one per slot, so a
/// receive can read straight into buffers the caller already owns.
///
/// Construct once with [`BatchRecvSlot::new`] and reuse across calls: the
/// receive call re-advertises the control buffer and the address length on
/// every packet it fills.
pub(crate) struct BatchRecvSlot {
    /// Control message buffer. The receive call sets `control_length` to the
    /// number of cmsg bytes the kernel wrote.
    control: cmsg::Buffer<CONTROL_SIZE>,
    /// Out: Control message buffer length
    control_length: Option<LibcControlLen>,
    /// Out: source-address storage written by the kernel. `SockAddrStorage`
    /// is `#[repr(transparent)]` over `libc::sockaddr_storage`, so it can be
    /// handed to a raw recvmsg-style syscall and afterwards decoded via
    /// [`BatchRecvSlot::take_peer_addr`].
    peer_addr_storage: socket2::SockAddrStorage,
    /// Buffer length for the source address. The receive call pre-fills it
    /// from [`socket2::SockAddrStorage::size_of`] so the kernel knows how
    /// much room it has, then the syscall replaces it with the number of
    /// bytes it wrote.
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

impl BatchRecvSlot {
    /// Create a slot with a control buffer of [`CONTROL_SIZE`] bytes.
    pub(crate) fn new() -> Self {
        let peer_addr_storage = socket2::SockAddrStorage::zeroed();
        let peer_addr_len = peer_addr_storage.size_of();
        Self {
            control: cmsg::Buffer::new(),
            control_length: None,
            peer_addr_storage,
            peer_addr_len,
            truncated: false,
        }
    }

    /// Iterate the control messages the kernel wrote for this packet.
    ///
    /// `None` until a receive has filled the slot.
    pub(crate) fn control_messages(&mut self) -> Option<cmsg::Iter<'_>> {
        let len = self.control_length?;
        // SAFETY: the receive call set `control_length` to the number of
        // bytes the kernel wrote into `control`.
        #[allow(unsafe_code)]
        Some(unsafe { self.control.iter(len) })
    }

    /// Convert the slot's source-address storage into a [`SocketAddr`], taking
    /// the stored address (the slot's storage is left zeroed afterwards).
    ///
    /// Returns `None` if the address family is not `AF_INET` or `AF_INET6`,
    /// which should not happen for a UDP/IP socket.
    pub(crate) fn take_peer_addr(&mut self) -> Option<SocketAddr> {
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
use apple::recv_multiple as platform_recv;
#[cfg(linux)]
use linux::recv_multiple as platform_recv;

/// Receive up to [`MAX_IO_BATCH_SIZE`] packets from `fd` into `bufs`, filling
/// the matching slot's peer address and control buffer for each.
///
/// Returns the number of packets received. On `Ok(n)`, for every `i < n`:
/// - `bufs[i].len()` is set to the bytes received,
/// - `slots[i].control_length` is set to the cmsg bytes received,
/// - `slots[i].peer_addr_storage` holds the source address (use
///   [`BatchRecvSlot::take_peer_addr`] to decode).
///
/// Every buffer and slot is prepared here, so a caller can hand the same
/// arrays back on the next call without touching them.
pub(crate) fn recv_multiple_with_metadata(
    fd: libc::c_int,
    bufs: &mut [BytesMut; MAX_IO_BATCH_SIZE],
    slots: &mut [BatchRecvSlot; MAX_IO_BATCH_SIZE],
) -> io::Result<usize> {
    for (buf, slot) in bufs.iter_mut().zip(slots.iter_mut()) {
        // Prepare here rather than trusting the caller. `clear` alone is not
        // enough: parsing advances the offset, so `reserve` is what returns
        // the full spare capacity the iovec advertises.
        buf.clear();
        buf.reserve(MAX_OUTSIDE_MTU);
        slot.control_length = None;
        slot.peer_addr_len = slot.peer_addr_storage.size_of();
        slot.truncated = false;
    }
    platform_recv(fd, bufs, slots)
}

#[cfg(macos)]
mod apple {
    use lightway_app_utils::cmsg::LibcControlLen;
    use lightway_app_utils::recvmsg_x::{msghdr_x, recvmsg_x};
    use lightway_core::{MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU};
    use std::{io, mem};

    /// Receive packets with peer-address and control (cmsg) metadata using
    /// the batch syscall. Buffers and slots arrive prepared by the caller.
    #[allow(unsafe_code)]
    pub(crate) fn recv_multiple(
        fd: libc::c_int,
        bufs: &mut [bytes::BytesMut; MAX_IO_BATCH_SIZE],
        slots: &mut [super::BatchRecvSlot; MAX_IO_BATCH_SIZE],
    ) -> io::Result<usize> {
        // SAFETY: zeroed iovec are valid (null pointers + zero lengths).
        let mut iovecs = unsafe { mem::zeroed::<[libc::iovec; MAX_IO_BATCH_SIZE]>() };
        // SAFETY: zeroed msghdr_x is valid (null pointers + zero lengths).
        let mut hdrs = unsafe { mem::zeroed::<[msghdr_x; MAX_IO_BATCH_SIZE]>() };
        for (i, (slot, buf)) in slots.iter_mut().zip(bufs.iter_mut()).enumerate() {
            let spare = buf.spare_capacity_mut();

            let iovec = &mut iovecs[i];
            let hdr = &mut hdrs[i];
            iovec.iov_base = spare.as_mut_ptr() as *mut libc::c_void;
            // Bound by the spare capacity actually behind the pointer, so the
            // kernel cannot write past the allocation whatever was reserved.
            iovec.iov_len = spare.len().min(MAX_OUTSIDE_MTU);
            hdr.msg_iov = iovec;
            hdr.msg_iovlen = 1;

            hdr.msg_name =
                &mut slot.peer_addr_storage as *mut socket2::SockAddrStorage as *mut libc::c_void;
            hdr.msg_namelen = slot.peer_addr_len;

            hdr.msg_control = slot.control.spare_capacity_mut().as_mut_ptr() as *mut libc::c_void;
            hdr.msg_controllen = super::CONTROL_SIZE as LibcControlLen;
        }

        // SAFETY: hdrs/iovecs and the per-slot storage referenced by their
        // pointers remain valid for the duration of the syscall; `slots`
        // is borrowed mutably for the whole call.
        let n = unsafe { recvmsg_x(fd, hdrs.as_mut_ptr(), MAX_IO_BATCH_SIZE as _, 0) };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let count = n as usize;
        if count > MAX_IO_BATCH_SIZE {
            return Err(io::Error::other(
                "recvmsg_x returned more packets than requested",
            ));
        }
        for ((slot, buf), hdr) in slots.iter_mut().zip(bufs.iter_mut()).take(count).zip(hdrs) {
            // For recvmsg_x(), the size of the data received is given by the field msg_datalen.
            let len = hdr.msg_datalen;
            // SAFETY: the caller cleared the buffer and the kernel wrote
            // `len` bytes into the spare capacity advertised via the
            // iovec, which was bounded by that spare capacity, so
            // `len <= capacity()`.
            unsafe {
                buf.set_len(len);
            }
            slot.peer_addr_len = hdr.msg_namelen;
            slot.control_length = Some(hdr.msg_controllen);
            // Current XNU does not set MSG_TRUNC in the per-message msg_flags
            // of recvmsg_x (only MSG_CTRUNC is reported there), so this stays
            // false today. Read it anyway, in case the kernel gains support.
            slot.truncated = hdr.msg_flags & libc::MSG_TRUNC != 0;
        }

        Ok(count)
    }
}

#[cfg(linux)]
mod linux {
    use lightway_app_utils::cmsg::LibcControlLen;
    use lightway_core::{MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU};
    use std::{io, mem};

    /// Receive packets with peer-address and control (cmsg) metadata using
    /// the batch syscall. Buffers and slots arrive prepared by the caller.
    #[allow(unsafe_code)]
    pub(crate) fn recv_multiple(
        fd: libc::c_int,
        bufs: &mut [bytes::BytesMut; MAX_IO_BATCH_SIZE],
        slots: &mut [super::BatchRecvSlot; MAX_IO_BATCH_SIZE],
    ) -> io::Result<usize> {
        // SAFETY: zeroed iovec are valid (null pointers + zero lengths).
        let mut iovecs = unsafe { mem::zeroed::<[libc::iovec; MAX_IO_BATCH_SIZE]>() };
        // SAFETY: zeroed hdrs are valid (null pointers + zero lengths).
        let mut hdrs = unsafe { mem::zeroed::<[libc::mmsghdr; MAX_IO_BATCH_SIZE]>() };
        for (i, (slot, buf)) in slots.iter_mut().zip(bufs.iter_mut()).enumerate() {
            let spare = buf.spare_capacity_mut();

            let iovec = &mut iovecs[i];
            let hdr = &mut hdrs[i];
            iovec.iov_base = spare.as_mut_ptr() as *mut libc::c_void;
            // Bound by the spare capacity actually behind the pointer, so the
            // kernel cannot write past the allocation whatever was reserved.
            iovec.iov_len = spare.len().min(MAX_OUTSIDE_MTU);
            hdr.msg_hdr.msg_iov = iovec;
            hdr.msg_hdr.msg_iovlen = 1;

            hdr.msg_hdr.msg_name =
                &mut slot.peer_addr_storage as *mut socket2::SockAddrStorage as *mut libc::c_void;
            hdr.msg_hdr.msg_namelen = slot.peer_addr_len;

            hdr.msg_hdr.msg_control =
                slot.control.spare_capacity_mut().as_mut_ptr() as *mut libc::c_void;
            hdr.msg_hdr.msg_controllen = super::CONTROL_SIZE as LibcControlLen;
        }

        // SAFETY: hdrs/iovecs and the per-slot storage referenced by their
        // pointers remain valid for the duration of the syscall; `slots`
        // is borrowed mutably for the whole call.
        let n = unsafe {
            libc::recvmmsg(
                fd,
                hdrs.as_mut_ptr(),
                MAX_IO_BATCH_SIZE as _,
                0,
                std::ptr::null_mut(),
            )
        };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let count = n as usize;
        if count > MAX_IO_BATCH_SIZE {
            return Err(io::Error::other(
                "recvmmsg returned more packets than requested",
            ));
        }
        for ((slot, buf), hdr) in slots.iter_mut().zip(bufs.iter_mut()).take(count).zip(hdrs) {
            // recvmmsg sets msg_len to the number of bytes received per message.
            let len = hdr.msg_len as usize;
            // SAFETY: the caller cleared the buffer and the kernel wrote
            // `len` bytes into the spare capacity advertised via the
            // iovec, which was bounded by that spare capacity, so
            // `len <= capacity()`.
            unsafe {
                buf.set_len(len);
            }
            slot.peer_addr_len = hdr.msg_hdr.msg_namelen;
            slot.control_length = Some(hdr.msg_hdr.msg_controllen);
            slot.truncated = hdr.msg_hdr.msg_flags & libc::MSG_TRUNC != 0;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    /// The receive call clears and reserves each buffer itself, so these
    /// start empty.
    fn fresh_bufs() -> [BytesMut; MAX_IO_BATCH_SIZE] {
        std::array::from_fn(|_| BytesMut::new())
    }

    #[test]
    fn take_peer_addr_consumes_the_stored_address() {
        let mut slot: BatchRecvSlot = BatchRecvSlot::new();

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
        let mut slots: [BatchRecvSlot; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BatchRecvSlot::new());
        let mut bufs = fresh_bufs();

        tokio::time::timeout(Duration::from_secs(2), receiver.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&receiver);
        let count = recv_multiple_with_metadata(fd, &mut bufs, &mut slots).unwrap();
        assert!(count >= 1);
        assert_eq!(&bufs[0][..], b"hello");
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

        let mut slots: [BatchRecvSlot; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BatchRecvSlot::new());
        let mut bufs = fresh_bufs();

        tokio::time::timeout(Duration::from_secs(2), receiver.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&receiver);
        let count = recv_multiple_with_metadata(fd, &mut bufs, &mut slots).unwrap();
        assert_eq!(count, 1);

        assert_eq!(bufs[0].len(), lightway_core::MAX_OUTSIDE_MTU);
        assert_eq!(&bufs[0][..], &payload[..lightway_core::MAX_OUTSIDE_MTU]);
        // recvmsg_x on Apple platforms does not report MSG_TRUNC in the
        // per-message msg_flags, so the truncated flag can only be asserted
        // where recvmmsg provides it.
        #[cfg(linux)]
        assert!(
            slots[0].truncated,
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

        let mut slots: [BatchRecvSlot; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BatchRecvSlot::new());
        let mut bufs = fresh_bufs();

        sender_a.send_to(b"alpha", server_addr).await.unwrap();
        sender_b.send_to(b"bravo", server_addr).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        tokio::time::timeout(Duration::from_secs(2), server.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&server);
        let count = recv_multiple_with_metadata(fd, &mut bufs, &mut slots).unwrap();
        assert!(count >= 1);

        // recvmmsg/recvmsg_x ordering across distinct peers isn't guaranteed,
        // so check that both senders appear among the received slots.
        let received: Vec<(std::net::SocketAddr, Vec<u8>)> = slots[..count]
            .iter_mut()
            .zip(bufs[..count].iter())
            .map(|(s, b)| (s.take_peer_addr().expect("AF_INET peer"), b.to_vec()))
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
            assert_eq!(bufs[i].len(), 5, "slot {i}: payload was 5 bytes");
            assert_eq!(
                slot.peer_addr_len, expected_v4_addrlen,
                "slot {i}: AF_INET peer_addr_len should be sizeof(sockaddr_in)",
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

        let mut slots: [BatchRecvSlot; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BatchRecvSlot::new());
        let mut bufs = fresh_bufs();

        // Sanity: a fresh slot has no control_length until the syscall writes one.
        assert!(slots[0].control_length.is_none());

        tokio::time::timeout(Duration::from_secs(2), server.readable())
            .await
            .unwrap()
            .unwrap();

        let fd = std::os::fd::AsRawFd::as_raw_fd(&server);
        let count = recv_multiple_with_metadata(fd, &mut bufs, &mut slots).unwrap();
        assert!(count >= 1);

        let slot = &slots[0];
        assert_eq!(&bufs[0][..], b"pktinfo");

        let control_len = slot
            .control_length
            .expect("control_length should be Some after recv with cmsg enabled");
        assert!(
            (control_len as usize) >= std::mem::size_of::<libc::cmsghdr>(),
            "control_length ({control_len}) too small to hold a cmsghdr",
        );
        assert!(
            (control_len as usize) <= CONTROL_SIZE,
            "control_length ({control_len}) exceeded the control buffer",
        );
    }
}
