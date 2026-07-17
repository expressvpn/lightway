//! Encapsulates the control message apis used with `recvmsg(2)` and
//! `sendmsg(2)`.
#![allow(unsafe_code)]

use bytes::BytesMut;

/// The libc type of `msghdr::msg_controllen` on this platform.
#[cfg(target_vendor = "apple")]
pub type LibcControlLen = libc::socklen_t;

/// The libc type of `msghdr::msg_controllen` on this platform.
#[cfg(all(not(target_vendor = "apple"), target_env = "musl"))]
pub type LibcControlLen = libc::socklen_t;

/// The libc type of `msghdr::msg_controllen` on this platform.
#[cfg(all(not(target_vendor = "apple"), not(target_env = "musl")))]
pub type LibcControlLen = libc::size_t;

/// A buffer suitable for receiving control messages with `recvmsg(2)`.
pub struct Buffer<const N: usize>(BytesMut);

impl<const N: usize> Buffer<N> {
    /// A new buffer with capacity for `N` bytes of control messages.
    pub fn new() -> Self {
        Self(BytesMut::with_capacity(N))
    }

    /// The spare capacity of the buffer, to be passed to `recvmsg(2)`
    /// as `msg_control`.
    pub fn spare_capacity_mut(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        self.0.spare_capacity_mut()
    }

    /// Total capacity of the buffer.
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Reset the buffer for reuse in a subsequent `recvmsg(2)` call.
    pub fn reset(&mut self) {
        self.0.clear();
        self.0.reserve(N);
    }

    /// Iterate over the control messages the kernel wrote.
    ///
    /// # Safety
    ///
    /// `control_len` must have been set to the number of bytes of the
    /// buffer which have been initialized.
    pub unsafe fn iter(&mut self, control_len: LibcControlLen) -> Iter<'_, N> {
        // SAFETY: The outer function here has enforced this requirement already
        unsafe {
            // `LibcControlLen` is `size_t` on glibc but `socklen_t` on
            // apple/musl, so the cast is a no-op on some targets only.
            #[cfg_attr(target_os = "linux", allow(clippy::unnecessary_cast))]
            self.0.set_len(control_len as usize);
        }
        // Build a `msghdr` so we can use the `CMSG_*` functionality in
        // libc. We will only use the `CMSG_*` macros which only use
        // the `msg_control*` fields.
        // SAFETY: We're initializing an msghdr struct with zeroed memory, which is safe
        // as all fields will be explicitly set below before use
        let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
        msghdr.msg_name = std::ptr::null_mut();
        msghdr.msg_namelen = 0;
        msghdr.msg_iov = std::ptr::null_mut();
        msghdr.msg_iovlen = 0;
        msghdr.msg_control = self.0.as_ptr() as *mut _;
        msghdr.msg_controllen = control_len;
        msghdr.msg_flags = 0;
        // SAFETY: We constructed a sufficiently valid `msghdr` above.
        // `msg_control[..msg_controllen]` are valid initialized bytes
        // per the safety requirements for calling this method.
        let cursor = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
        Iter {
            msghdr,
            cursor,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<const N: usize> Default for Buffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A control message received from the kernel.
pub enum Message<'a> {
    /// An `IP_PKTINFO` message.
    IpPktinfo(&'a libc::in_pktinfo),
    /// A `UDP_GRO` message carrying the size of each coalesced
    /// segment in a GRO aggregate delivered by `recvmsg(2)`.
    #[cfg(target_os = "linux")]
    UdpGroSegments(u16),
    /// Any other control message.
    Unknown(#[allow(dead_code)] &'a libc::cmsghdr),
}

impl Message<'_> {
    /// The number of bytes of control buffer space (including padding)
    /// required to hold a message with a payload of type `T`. See
    /// `CMSG_SPACE(3)`.
    pub const fn space<T>() -> usize {
        // SAFETY: CMSG_SPACE is always safe
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<T>() as libc::c_uint) as usize }
    }
}

/// Iterator over the control messages in a [`Buffer`].
pub struct Iter<'a, const N: usize> {
    msghdr: libc::msghdr,
    cursor: *const libc::cmsghdr,
    // `msghdr` contains a raw pointer into the owning `Buffer` and
    // `cursor` is within that buffer. Ensure it remains live longer
    // than this iterator.
    _phantom: std::marker::PhantomData<&'a Buffer<N>>,
}

impl<'a, const N: usize> Iterator for Iter<'a, N> {
    type Item = Message<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.is_null() {
            None
        } else {
            // SAFETY: `cursor` is set by either `CMSG_FIRSTHDR` or
            // `CMSGNXTHDR`, we dealt with the null case above.
            let item = unsafe { &*self.cursor };

            // SAFETY: `msghdr` was constructed as a sufficiently
            // valid `msghdr` by `Buffer::iter()`. `cursor` is valid
            // since it came from a prior `CMSG_FIRSTHDR` or
            // `CMSG_NXTHDR`.
            self.cursor = unsafe { libc::CMSG_NXTHDR(&self.msghdr, self.cursor) };

            #[cfg(target_vendor = "apple")]
            let (cmsg_level, cmsg_type) = (libc::IPPROTO_IP, libc::IP_PKTINFO);
            #[cfg(not(target_vendor = "apple"))]
            let (cmsg_level, cmsg_type) = (libc::SOL_IP, libc::IP_PKTINFO);

            if item.cmsg_level == cmsg_level && item.cmsg_type == cmsg_type {
                // SAFETY: `item` is a valid `cmsghdr` from a
                // prior call to `CMSG_FIRSTHDR` or `CMSG_NXTHDR`.
                let data = unsafe { libc::CMSG_DATA(item) as *const libc::in_pktinfo };
                // SAFETY: we constructed `data` above
                let pi = unsafe { &*data };
                return Some(Message::IpPktinfo(pi));
            }

            #[cfg(target_os = "linux")]
            if item.cmsg_level == libc::SOL_UDP && item.cmsg_type == libc::UDP_GRO {
                // The kernel writes the segment size as a C int
                // (`udp_cmsg_recv`); the value is a `gso_size` and so
                // always fits a u16.
                // SAFETY: `item` is a valid `cmsghdr` from a prior
                // call to `CMSG_FIRSTHDR` or `CMSG_NXTHDR`.
                let data = unsafe { libc::CMSG_DATA(item) as *const libc::c_int };
                // SAFETY: `CMSG_DATA` is aligned for a `cmsghdr`,
                // which is at least the alignment of `c_int`.
                let gro_size = unsafe { *data };
                return Some(Message::UdpGroSegments(gro_size as u16));
            }

            Some(Message::Unknown(item))
        }
    }
}

/// A buffer for building control messages to pass to `sendmsg(2)`.
#[repr(C, align(16))] // Must be suitably aligned for a `libc::cmsghdr`.
pub struct BufferMut<const N: usize>([u8; N]);

impl<const N: usize> BufferMut<N> {
    /// A new zero-initialized buffer.
    pub fn zeroed() -> Self {
        Self([0; N])
    }

    /// A builder to fill the buffer with control messages.
    ///
    /// # Safety
    ///
    /// From <https://man7.org/linux/man-pages/man3/cmsg.3.html>:
    /// The provided buffer should be zero-initialized to ensure the
    /// correct operation of CMSG_NXTHDR().
    ///
    /// Since `BufferMut::zeroed()` is the only constructor this must
    /// be the case.
    ///
    /// Note that this is not mentioned in
    /// <https://pubs.opengroup.org/onlinepubs/9699919799.2018edition/basedefs/sys_socket.h.html>.
    pub fn builder(&mut self) -> BufferBuilder<'_, N> {
        // Build a `msghdr` so we can use the `CMSG_*` functionality in
        // libc. We will only use the `CMSG_*` macros which only use
        // the `msg_control*` fields.
        // SAFETY: We're initializing an msghdr struct with zeroed memory, which is safe
        // as all fields will be explicitly set below before use
        let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
        msghdr.msg_name = std::ptr::null_mut();
        msghdr.msg_namelen = 0;
        msghdr.msg_iov = std::ptr::null_mut();
        msghdr.msg_iovlen = 0;
        msghdr.msg_control = self.0.as_mut_ptr() as *mut _;
        msghdr.msg_controllen = self.0.len() as LibcControlLen;
        msghdr.msg_flags = 0;
        // SAFETY: We constructed a sufficiently valid `msghdr` above.
        // `msg_control[..msg_controllen]` are valid initialized bytes
        // per the safety requirements for calling this method.
        let cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };

        BufferBuilder {
            msghdr,
            cmsghdr,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<const N: usize> AsRef<[u8]> for BufferMut<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Sequentially fills a [`BufferMut`] with control messages.
pub struct BufferBuilder<'a, const N: usize> {
    msghdr: libc::msghdr,
    cmsghdr: *mut libc::cmsghdr,
    // `msghdr` contains a raw pointer into the owning `Buffer` and
    // `cursor` is within that buffer. Ensure it remains live longer
    // than this iterator.
    _phantom: std::marker::PhantomData<&'a mut Buffer<N>>,
}

impl<const N: usize> BufferBuilder<'_, N> {
    /// Append a control message with the given level, type and payload.
    ///
    /// Fails if the buffer has insufficient space remaining.
    pub fn fill_next<T>(
        &mut self,
        cmsg_level: libc::c_int,
        cmsg_type: libc::c_int,
        data: T,
    ) -> std::io::Result<()> {
        // Our use of `CMSG_FIRSTHDR` to get a validly aligned pointer
        // to a `cmsghdr` assumes that `cmsghdr` requires no more
        // alignment than `BufferMut`.
        const { assert!(std::mem::align_of::<libc::cmsghdr>() <= std::mem::align_of::<BufferMut<N>>()) };
        // Our use of `CMSG_DATA` to get a validly aligned pointer to
        // `T` requires that `T` requires no more alignment than
        // `cmsghdr`.
        const { assert!(std::mem::align_of::<T>() <= std::mem::align_of::<libc::cmsghdr>()) };

        if self.cmsghdr.is_null() {
            return Err(std::io::Error::other(
                "cmsg buffer: insufficient space for next header",
            ));
        }

        let data_size = std::mem::size_of::<T>();

        // SAFETY: `CMSG_LEN` is always safe
        let cmsg_len = unsafe { libc::CMSG_LEN(data_size as libc::c_uint) as LibcControlLen };
        // SAFETY:
        //
        // The pointer is valid. It was produced by a previous call to
        // either `CMSG_FIRSTHDR` or `CMSG_NXTHDR`. Both of which
        // check for bounds compared with the length in `msghdr` and
        // return NULL if there is not enough space. We checked for
        // NULL above.
        //
        // The pointer is correctly aligned for a `cmsghdr`:
        // - For the initial iteration `CMSG_FIRSTHDR` maintains the
        //   alignment of the underlying `BufferMut`, which we
        //   asserted above is at least that of a `cmsghdr`.
        // - For subsequent iterations `CMSG_NXTHDR` takes alignment
        //   into consideration and returns a pointer correctly aligned
        //   for a `cmsghdr`.
        // SAFETY: We're initializing a cmsghdr struct with zeroed memory, which is safe
        // as all fields will be explicitly set below before use
        let mut cmsghdr: libc::cmsghdr = unsafe { std::mem::zeroed() };
        cmsghdr.cmsg_len = cmsg_len;
        cmsghdr.cmsg_level = cmsg_level;
        cmsghdr.cmsg_type = cmsg_type;
        // SAFETY: self.cmsghdr is a valid pointer from CMSG_FIRSTHDR/CMSG_NXTHDR
        // (verified non-null above), and is correctly aligned for cmsghdr (see comments above)
        unsafe {
            self.cmsghdr.write(cmsghdr);
        }

        // SAFETY: `self.cmsghdr` is a valid `cmsghdr` from a prior
        // call to `CMSG_FIRSTHDR` or `CMSG_NXTHDR`, see full argument
        // above.
        let cmsg_data = unsafe { libc::CMSG_DATA(self.cmsghdr) };

        // This type case is necessary for macOS build
        #[allow(clippy::unnecessary_cast)]
        // Check that we have sufficient space remaining. `CMSG_DATA`
        // does not do this.
        let max = self.msghdr.msg_control as usize + self.msghdr.msg_controllen as usize;
        let end = cmsg_data as usize + data_size;

        if end > max {
            return Err(std::io::Error::other(
                "cmsg buffer: insufficient space for data",
            ));
        }

        let cmsg_data = cmsg_data as *mut T;
        // SAFETY:
        //
        // `CMSG_DATA` always returns a valid pointer given a valid
        // `cmsghdr`, which we gave it.
        //
        // We validated there was enough room for a `T` above.
        //
        // `CMSG_DATA` returns a pointer validly aligned for a
        // `cmsghdr`. We asserted above that `T` does not have a
        // stricter alignment requirement.
        unsafe { cmsg_data.write(data) };

        // SAFETY: `self.cmsghdr` is a valid `cmsghdr` from a prior
        // call to `CMSG_FIRSTHDR` or `CMSG_NXTHDR`. If the result is
        // NULL this will be checked on the next call to `fill_next`.
        self.cmsghdr = unsafe { libc::CMSG_NXTHDR(&self.msghdr, self.cmsghdr) };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code, clippy::undocumented_unsafe_blocks)]

    use super::*;

    #[test]
    fn success_single_pktinfo() {
        const SIZE: usize = Message::space::<libc::in_pktinfo>();
        let mut cmsg = BufferMut::<SIZE>::zeroed();
        let mut builder = cmsg.builder();
        builder
            .fill_next(
                0,
                0,
                libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr { s_addr: 0 },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                },
            )
            .unwrap();
    }

    /// Round-trip: a control buffer built with `SOL_UDP`/`UDP_GRO`
    /// parses back as `Message::UdpGroSegments` with the same size.
    #[test]
    #[cfg(target_os = "linux")]
    fn parse_udp_gro_cmsg() {
        const SIZE: usize = Message::space::<libc::c_int>();
        let mut out = BufferMut::<SIZE>::zeroed();
        out.builder()
            .fill_next(libc::SOL_UDP, libc::UDP_GRO, 1350 as libc::c_int)
            .unwrap();

        // Copy the built control bytes into a receive-side Buffer.
        let mut buf = Buffer::<SIZE>::new();
        for (dst, src) in buf.spare_capacity_mut().iter_mut().zip(out.as_ref()) {
            dst.write(*src);
        }

        // SAFETY: all SIZE bytes were initialized by the copy above.
        let mut iter = unsafe { buf.iter(SIZE as LibcControlLen) };
        assert!(matches!(iter.next(), Some(Message::UdpGroSegments(1350))));
        assert!(iter.next().is_none());
    }

    #[test]
    fn fill_empty_buffer() {
        let mut cmsg = BufferMut::<0>::zeroed();
        let mut builder = cmsg.builder();
        let err = builder.fill_next(0, 0, 0).unwrap_err();
        assert!(matches!(err.kind(), std::io::ErrorKind::Other));
        assert!(
            err.to_string()
                .contains("cmsg buffer: insufficient space for next header")
        );
    }

    #[test]
    fn not_enough_room_for_first_header() {
        let mut cmsg = BufferMut::<4>::zeroed();
        assert!(cmsg.0.len() < std::mem::size_of::<libc::cmsghdr>());

        let mut builder = cmsg.builder();
        let err = builder.fill_next(0, 0, 0).unwrap_err();
        assert!(matches!(err.kind(), std::io::ErrorKind::Other));
        assert!(
            err.to_string()
                .contains("cmsg buffer: insufficient space for next header")
        );
    }

    #[test]
    fn not_enough_room_for_next_header() {
        const SIZE: usize = Message::space::<libc::in_pktinfo>();
        let mut cmsg = BufferMut::<SIZE>::zeroed();

        let mut builder = cmsg.builder();

        builder
            .fill_next(
                0,
                0,
                libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr { s_addr: 0 },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                },
            )
            .unwrap();
        let err = builder.fill_next(0, 0, 0).unwrap_err();
        assert!(matches!(err.kind(), std::io::ErrorKind::Other));
        assert!(
            err.to_string()
                .contains("cmsg buffer: insufficient space for next header")
        );
    }

    #[test]
    fn not_enough_room_for_data() {
        // NOTE: Message::space adds padding, which can confound things here.
        const SIZE: usize =
            std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<libc::in_pktinfo>() - 1;
        let mut cmsg = BufferMut::<SIZE>::zeroed();
        assert!(cmsg.0.len() > std::mem::size_of::<libc::cmsghdr>());
        assert!(cmsg.0.len() < Message::space::<libc::in_pktinfo>());

        let mut builder = cmsg.builder();
        let err = builder
            .fill_next(
                0,
                0,
                libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr { s_addr: 0 },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                },
            )
            .unwrap_err();
        assert!(matches!(err.kind(), std::io::ErrorKind::Other));
        assert!(
            err.to_string()
                .contains("cmsg buffer: insufficient space for data")
        );
    }
}
