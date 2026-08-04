//! Encapsulates the control message apis used with `recvmsg(2)` and
//! `sendmsg(2)`.
#![allow(unsafe_code)]
// Low-level control-message plumbing; the public items are self-describing
// by name and covered by the module doc, so individual doc comments would
// add noise without value.
#![allow(missing_docs)]

#[cfg(target_vendor = "apple")]
pub type LibcControlLen = libc::socklen_t;

#[cfg(all(not(target_vendor = "apple"), target_env = "musl"))]
pub type LibcControlLen = libc::socklen_t;

#[cfg(all(not(target_vendor = "apple"), not(target_env = "musl")))]
pub type LibcControlLen = libc::size_t;

#[repr(C, align(16))] // Must be suitably aligned for a `libc::cmsghdr`.
pub struct Buffer<const N: usize>([std::mem::MaybeUninit<u8>; N]);

impl<const N: usize> Buffer<N> {
    pub fn new() -> Self {
        const {
            assert!(std::mem::align_of::<libc::cmsghdr>() <= 16);
        }
        Self([std::mem::MaybeUninit::uninit(); N])
    }

    pub fn spare_capacity_mut(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        &mut self.0
    }

    pub fn capacity(&self) -> usize {
        N
    }

    pub fn reset(&mut self) {}

    /// Iterate over the control messages the kernel wrote.
    ///
    /// # Safety
    ///
    /// `control_len` must have been set to the number of bytes of the
    /// buffer which have been initialized.
    pub unsafe fn iter(&mut self, control_len: LibcControlLen) -> Iter<'_> {
        // `LibcControlLen` is `size_t` on glibc but `socklen_t` on
        // apple/musl, so the cast is a no-op on some targets only.
        #[allow(clippy::unnecessary_cast)]
        let control_len = control_len as usize;
        assert!(
            control_len <= N,
            "control_len ({control_len}) exceeds control buffer capacity ({N})"
        );

        // SAFETY: the caller guarantees the kernel initialized the first
        // `control_len` bytes, and `MaybeUninit<u8>` has the same layout as
        // `u8`.
        let control =
            unsafe { std::slice::from_raw_parts(self.0.as_ptr() as *const u8, control_len) };

        iter_control(control)
    }
}

impl<const N: usize> Default for Buffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

pub enum Message<'a> {
    IpPktinfo(&'a libc::in_pktinfo),
    #[cfg(linux)]
    UdpGroSegment(libc::c_int),
    Unknown(#[allow(dead_code)] &'a libc::cmsghdr),
}

impl Message<'_> {
    pub const fn space<T>() -> usize {
        // SAFETY: CMSG_SPACE is always safe
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<T>() as libc::c_uint) as usize }
    }
}

pub fn iter_control(control: &[u8]) -> Iter<'_> {
    // Not a `debug_assert!`: `Iter::next` turns the `CMSG_*` pointers into
    // `&libc::cmsghdr`, and a misaligned reference is UB. Keeping the check
    // in release turns that into a clean panic, at the cost of one
    // predictable branch per `recvmsg`.
    assert!(
        control.is_empty()
            || control
                .as_ptr()
                .align_offset(std::mem::align_of::<libc::cmsghdr>())
                == 0,
        "control buffer must be aligned for cmsghdr"
    );

    // Build a `msghdr` referencing `control` purely so the `CMSG_*`
    // macros can walk it — they read only `msg_control`/`msg_controllen`.
    // SAFETY: a zeroed msghdr is valid; the two fields we use are set
    // below and the buffer is never written through this pointer.
    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_control = control.as_ptr() as *mut _;
    msghdr.msg_controllen = control.len() as LibcControlLen;

    // SAFETY: `msghdr` is valid and `control` is initialized for its
    // full length.
    let cursor = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
    Iter {
        msghdr,
        cursor,
        _phantom: std::marker::PhantomData,
    }
}

#[cfg(linux)]
pub fn first_udp_gro_segment(control: &[u8]) -> Option<u16> {
    iter_control(control).find_map(|m| match m {
        Message::UdpGroSegment(seg) => Some(seg as u16),
        _ => None,
    })
}

pub struct Iter<'a> {
    msghdr: libc::msghdr,
    cursor: *const libc::cmsghdr,
    // `msghdr` contains a raw pointer into the underlying control
    // region and `cursor` is within that region. Ensure it remains
    // live longer than this iterator.
    _phantom: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = Message<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.is_null() {
            None
        } else {
            // SAFETY: `cursor` is set by either `CMSG_FIRSTHDR` or
            // `CMSGNXTHDR`, we dealt with the null case above.
            let item = unsafe { &*self.cursor };

            // SAFETY: `msghdr` was constructed as a sufficiently
            // valid `msghdr` by `iter_control()`. `cursor` is valid
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

            #[cfg(linux)]
            if item.cmsg_level == libc::SOL_UDP && item.cmsg_type == libc::UDP_GRO {
                // SAFETY: `item` is a valid `cmsghdr` from a prior call
                // to `CMSG_FIRSTHDR` or `CMSG_NXTHDR`.
                let data = unsafe { libc::CMSG_DATA(item) as *const libc::c_int };
                // SAFETY: a `UDP_GRO` cmsg carries a `c_int` and
                // `CMSG_DATA` returns a pointer aligned for it within the
                // cmsg.
                let seg = unsafe { *data };
                return Some(Message::UdpGroSegment(seg));
            }

            Some(Message::Unknown(item))
        }
    }
}

#[repr(C, align(16))] // Must be suitably aligned for a `libc::cmsghdr`.
pub struct BufferMut<const N: usize>([u8; N]);

impl<const N: usize> BufferMut<N> {
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

    /// Mutable view of the raw buffer, for passing to `msg_control` in
    /// syscalls that need a mutable pointer.
    #[cfg(linux)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for BufferMut<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct BufferBuilder<'a, const N: usize> {
    msghdr: libc::msghdr,
    cmsghdr: *mut libc::cmsghdr,
    // `msghdr` contains a raw pointer into the owning `Buffer` and
    // `cursor` is within that buffer. Ensure it remains live longer
    // than this iterator.
    _phantom: std::marker::PhantomData<&'a mut Buffer<N>>,
}

impl<const N: usize> BufferBuilder<'_, N> {
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
    fn buffers_are_aligned_for_cmsghdr() {
        let cmsghdr_align = std::mem::align_of::<libc::cmsghdr>();
        assert!(std::mem::align_of::<Buffer<64>>() >= cmsghdr_align);
        assert!(std::mem::align_of::<BufferMut<64>>() >= cmsghdr_align);

        let mut buf = Buffer::<64>::new();
        assert_eq!(
            buf.spare_capacity_mut()
                .as_ptr()
                .align_offset(cmsghdr_align),
            0,
        );
        assert_eq!(buf.capacity(), 64);
    }

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

    /// `first_udp_gro_segment` extracts the segment size from a raw
    /// (aligned) control buffer built with `SOL_UDP`/`UDP_GRO`, and
    /// returns `None` when no such message is present.
    #[test]
    #[cfg(target_os = "linux")]
    fn first_udp_gro_segment_parses_raw_control() {
        const SIZE: usize = Message::space::<libc::c_int>();
        let mut out = BufferMut::<SIZE>::zeroed();
        out.builder()
            .fill_next(libc::SOL_UDP, libc::UDP_GRO, 1400 as libc::c_int)
            .unwrap();
        // BufferMut is `#[repr(align(16))]`, so `as_ref()` is aligned.
        assert_eq!(first_udp_gro_segment(out.as_ref()), Some(1400));

        // A buffer with an unrelated (pktinfo) message yields None.
        const PSIZE: usize = Message::space::<libc::in_pktinfo>();
        let mut other = BufferMut::<PSIZE>::zeroed();
        other
            .builder()
            .fill_next(
                libc::SOL_IP,
                libc::IP_PKTINFO,
                libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr { s_addr: 0 },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                },
            )
            .unwrap();
        assert_eq!(first_udp_gro_segment(other.as_ref()), None);

        assert_eq!(first_udp_gro_segment(&[]), None);
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
