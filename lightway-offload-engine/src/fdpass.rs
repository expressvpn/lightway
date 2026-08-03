//! Descriptor passing over a unix socket.
//!
//! This is the userspace analogue of the kernel driver's
//! `set_offload_socket(fd)`: the VPN process creates the TUN queue and the
//! reuseport socket, then hands them here. The receiving process gets its own
//! descriptors referring to the same open files.
//!
//! # Framing on a stream socket
//!
//! `SOCK_STREAM` carries bytes, not messages, and ancillary data binds to the
//! *first byte* of the data it was sent with. [`send_with_fds`] issues one
//! `sendmsg`, and the kernel refuses to glue a descriptor-bearing message onto
//! bytes from an earlier one, so a reader whose buffer is at least as large as
//! the whole message gets the descriptors together with it. A reader with a
//! smaller buffer gets them with only a *prefix*: the descriptors and the rest
//! of the message are then separated, and the caller must keep accumulating
//! into the same logical message. Size the receive buffer for the largest
//! message the protocol defines and this cannot happen; [`recv_with_fds`]
//! rejects the read outright when it sees the signature of that split.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Most descriptors one message may carry. The engine needs two - a TUN queue
/// and a socket - and the margin costs nothing.
pub const MAX_FDS: usize = 4;

const FD_SIZE: usize = mem::size_of::<RawFd>();
const MAX_FD_BYTES: usize = MAX_FDS * FD_SIZE;

/// Control buffer size, taken from libc's own `CMSG_SPACE` rather than guessed.
const CMSG_BUF_LEN: usize = cmsg_space(MAX_FD_BYTES);

/// Where the descriptor array starts inside a `SCM_RIGHTS` control message.
const CMSG_DATA_OFFSET: usize = cmsg_len(0);

const fn cmsg_space(payload: usize) -> usize {
    // SAFETY: CMSG_SPACE is arithmetic over its argument. It reads no memory
    // and has no preconditions; the `unsafe` is libc's blanket `f!` marking.
    (unsafe { libc::CMSG_SPACE(payload as u32) }) as usize
}

const fn cmsg_len(payload: usize) -> usize {
    // SAFETY: CMSG_LEN is arithmetic over its argument, as above.
    (unsafe { libc::CMSG_LEN(payload as u32) }) as usize
}

// The buffer must hold a header plus MAX_FDS descriptors, and `CMSG_DATA`
// (`cmsg + 1`) must land on the same byte as `CMSG_LEN(0)`, which is what the
// offset arithmetic below assumes. Both hold on every Linux target; assert it
// so a future one cannot break it silently.
const _: () = assert!(CMSG_BUF_LEN >= CMSG_DATA_OFFSET + MAX_FD_BYTES);
const _: () = assert!(CMSG_DATA_OFFSET == mem::size_of::<libc::cmsghdr>());
const _: () = assert!(mem::align_of::<usize>() >= mem::align_of::<libc::cmsghdr>());

/// A control buffer with the alignment `cmsghdr` needs.
///
/// A bare `[u8; N]` is only byte-aligned. `CMSG_ALIGN` rounds to
/// `size_of::<usize>()` and the kernel reads `cmsg_len` as a word, so the
/// buffer has to start on a word boundary. The zero-length `usize` array
/// contributes no bytes and only raises the alignment.
#[repr(C)]
struct CmsgBuf {
    _align: [usize; 0],
    bytes: [u8; CMSG_BUF_LEN],
}

impl CmsgBuf {
    fn new() -> Self {
        Self {
            _align: [],
            bytes: [0u8; CMSG_BUF_LEN],
        }
    }
}

/// Send `payload` together with `fds`.
///
/// `fds` are duplicated into the receiving process; the caller keeps
/// ownership of its own copies and may close them afterwards.
///
/// `payload` must not be empty: a zero-length stream send transfers nothing at
/// all, so the descriptors would be dropped on the floor. The socket is
/// expected to be blocking - see the module note on framing for what a caller
/// must do about partial reads on the far side.
pub fn send_with_fds(sock: &UnixStream, payload: &[u8], fds: &[RawFd]) -> io::Result<()> {
    if fds.len() > MAX_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many descriptors",
        ));
    }
    if payload.is_empty() {
        // A zero-length send carries no ancillary data on some kernels and
        // reads as EOF on the far side. Refuse rather than silently no-op.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload must not be empty",
        ));
    }

    let mut cmsg_buf = CmsgBuf::new();
    let mut controllen = 0usize;

    if !fds.is_empty() {
        let fd_bytes = fds.len() * FD_SIZE;

        let mut hdr: libc::cmsghdr =
            // SAFETY: cmsghdr is integer fields only, so all-zero is a valid
            // value; zeroing is also how musl's `__pad1` gets a defined value.
            unsafe { mem::zeroed() };
        hdr.cmsg_len = cmsg_len(fd_bytes) as _;
        hdr.cmsg_level = libc::SOL_SOCKET;
        hdr.cmsg_type = libc::SCM_RIGHTS;

        let hdr_at = cmsg_buf.bytes.as_mut_ptr().cast::<libc::cmsghdr>();
        // SAFETY: `bytes` is the first field of a word-aligned CmsgBuf, so
        // `hdr_at` meets cmsghdr's alignment, and CMSG_BUF_LEN is at least
        // size_of::<cmsghdr>() bytes of writable space (asserted above).
        unsafe { hdr_at.write(hdr) };

        // Descriptors go in byte-wise through safe slice writes. That keeps
        // one provenance chain over the buffer and assumes nothing about
        // CMSG_DATA being RawFd-aligned.
        for (i, fd) in fds.iter().enumerate() {
            let at = CMSG_DATA_OFFSET + i * FD_SIZE;
            cmsg_buf.bytes[at..at + FD_SIZE].copy_from_slice(&fd.to_ne_bytes());
        }

        controllen = cmsg_space(fd_bytes);
    }

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr =
        // SAFETY: msghdr is pointers and integers; all-zero is the "nothing
        // set" state, and every field this call needs is assigned below.
        unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if controllen != 0 {
        msg.msg_control = cmsg_buf.bytes.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = controllen as _;
    }

    let sent = loop {
        // SAFETY: `msg` describes `payload` and `cmsg_buf`, both alive for the
        // call. msg_controllen is CMSG_SPACE(fd_bytes) <= CMSG_BUF_LEN and
        // covers exactly the one well-formed cmsghdr written above.
        // MSG_NOSIGNAL turns a dead peer into EPIPE instead of a signal.
        let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if n >= 0 {
            break n as usize;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
        // EINTR means nothing was sent, so resending the whole message - the
        // descriptors included - is correct rather than duplicating them.
    };

    if sent == 0 {
        // An AF_UNIX stream sendmsg never reports zero for a non-empty payload:
        // it transfers at least one byte, blocks, or fails. If one ever did, we
        // could not tell whether the ancillary data crossed - it rides with the
        // first byte - and resending the payload alone would silently drop the
        // descriptors. Refuse rather than guess.
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "socket accepted no bytes; descriptor delivery is indeterminate",
        ));
    }
    if sent < payload.len() {
        // A short sendmsg has already handed the ancillary data over with the
        // first byte. Failing here would leave the peer holding a truncated
        // message forever, so finish the write instead.
        send_all(sock.as_raw_fd(), &payload[sent..])?;
    }
    Ok(())
}

/// Write the tail of a partially sent payload. No ancillary data is involved:
/// it went out with the first byte.
fn send_all(fd: RawFd, mut rest: &[u8]) -> io::Result<()> {
    while !rest.is_empty() {
        // SAFETY: `rest` is a live slice of `rest.len()` bytes and `fd` is
        // borrowed from a UnixStream alive in the caller.
        let n = unsafe {
            libc::send(
                fd,
                rest.as_ptr().cast::<libc::c_void>(),
                rest.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "socket accepted no bytes",
            ));
        }
        rest = &rest[n as usize..];
    }
    Ok(())
}

/// Receive one message, appending any descriptors to `fds_out` in send order.
///
/// Returns the number of payload bytes read. `Ok(0)` means end of file - the
/// peer closed its end - and nothing else: the call blocks rather than return
/// early, [`send_with_fds`] refuses to send an empty payload, and an empty
/// `buf` is rejected outright.
///
/// `fds_out` is left untouched unless the whole receive succeeds. On any error
/// path the descriptors that did arrive are closed rather than handed back,
/// because a partial set is worse than none.
///
/// Read the module note on framing before choosing the size of `buf`: a read
/// that both carries descriptors and fills `buf` completely is rejected, since
/// it cannot be distinguished from a message split away from its descriptors.
pub fn recv_with_fds(
    sock: &UnixStream,
    buf: &mut [u8],
    fds_out: &mut Vec<OwnedFd>,
) -> io::Result<usize> {
    if buf.is_empty() {
        // recvmsg with nowhere to put the data returns 0, which the caller
        // would read as end of file.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "receive buffer must not be empty",
        ));
    }

    let mut cmsg_buf = CmsgBuf::new();
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr =
        // SAFETY: msghdr is pointers and integers; all-zero is the "nothing
        // set" state, and every field this call needs is assigned below.
        unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.bytes.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = CMSG_BUF_LEN as _;

    let got = loop {
        // SAFETY: `msg` describes `buf` and `cmsg_buf`, both alive across the
        // call. MSG_CMSG_CLOEXEC closes the received descriptors on exec, so a
        // forked child cannot inherit the tunnel's socket.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 {
            break n as usize;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    };

    // Collected locally so that an error return drops - and therefore closes -
    // whatever did arrive, instead of leaving the caller a partial set.
    let mut received: Vec<OwnedFd> = Vec::new();

    // SAFETY: `msg` is initialised and msg_control points at cmsg_buf, which
    // the kernel filled with msg_controllen bytes of well-formed headers.
    let mut hdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !hdr.is_null() {
        // SAFETY: CMSG_FIRSTHDR and CMSG_NXTHDR only ever return a pointer to
        // a header the kernel wrote inside cmsg_buf, which is word-aligned.
        let cmsg = unsafe { hdr.read() };

        if cmsg.cmsg_level == libc::SOL_SOCKET && cmsg.cmsg_type == libc::SCM_RIGHTS {
            // `cmsg_len` is the kernel's word for how much it attached, and
            // neither CMSG_FIRSTHDR nor CMSG_NXTHDR checks it against the buffer
            // we handed over - the first only checks that one header fits.
            // A correct kernel cannot overstate it (put_cmsg truncates and sets
            // MSG_CTRUNC), but clamping to what physically remains between this
            // header and the end of cmsg_buf makes the read below in bounds by
            // construction instead of by trust.
            let hdr_offset = (hdr as usize).saturating_sub(msg.msg_control as usize);
            let room = CMSG_BUF_LEN.saturating_sub(hdr_offset + CMSG_DATA_OFFSET);
            let declared = (cmsg.cmsg_len as usize).saturating_sub(CMSG_DATA_OFFSET);
            let count = declared.min(room) / FD_SIZE;

            // SAFETY: CMSG_DATA is pointer arithmetic one header past `hdr`.
            let data = unsafe { libc::CMSG_DATA(hdr) };
            // SAFETY: `count * FD_SIZE` is clamped above to the bytes remaining
            // in cmsg_buf after this header, so the range lies inside the
            // buffer; the kernel filled it with descriptor numbers. cmsg_buf
            // outlives this borrow and no other path touches it meanwhile.
            let raw = unsafe { std::slice::from_raw_parts(data.cast_const(), count * FD_SIZE) };

            for chunk in raw.chunks_exact(FD_SIZE) {
                let fd = RawFd::from_ne_bytes(chunk.try_into().expect("chunks_exact yields 4"));
                // SAFETY: the kernel installed `fd` in this process's table for
                // this message and nothing else owns it, so OwnedFd may close it.
                received.push(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }

        // SAFETY: `hdr` is a header the kernel wrote and `msg` still describes
        // the buffer holding it; CMSG_NXTHDR bounds-checks against
        // msg_controllen and returns null at the end.
        hdr = unsafe { libc::CMSG_NXTHDR(&msg, hdr) };
    }

    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ancillary data truncated; descriptors were lost",
        ));
    }
    if !received.is_empty() && got == buf.len() {
        // Descriptors plus a completely full buffer is the signature of a
        // message split from its own ancillary data: on SOCK_STREAM the
        // descriptors ride with the first byte, so the caller would hold them
        // alongside a prefix that fails to decode, and drop them when it gave
        // up. Silent descriptor loss dressed as a network fault is the worst
        // thing this function could do, so refuse the pair instead. A buffer
        // sized to the largest message the protocol defines never trips this.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptors arrived with a buffer-filling read; \
             the message may be split from them - enlarge the receive buffer",
        ));
    }
    if got == 0 {
        if !received.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "descriptors arrived without a payload byte",
            ));
        }
        return Ok(0);
    }

    fds_out.append(&mut received);
    Ok(got)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// The buffer-sizing claim, end to end: a full load of MAX_FDS must arrive
    /// intact, with no MSG_CTRUNC. An undersized or misaligned control buffer
    /// loses descriptors here. (The const assertions at the top of the module
    /// cover the arithmetic itself; a run-time re-derivation of CMSG_BUF_LEN
    /// from CMSG_SPACE would only restate its own definition.)
    #[test]
    fn a_full_load_of_descriptors_arrives_untruncated() {
        let (a, b) = UnixStream::pair().unwrap();
        let pipes: Vec<_> = (0..MAX_FDS).map(|_| std::io::pipe().unwrap()).collect();
        let raw: Vec<RawFd> = pipes.iter().map(|(rx, _)| rx.as_raw_fd()).collect();

        send_with_fds(&a, b"x", &raw).unwrap();
        drop(pipes);

        let mut buf = [0u8; 8];
        let mut fds = Vec::new();
        assert_eq!(recv_with_fds(&b, &mut buf, &mut fds).unwrap(), 1);
        assert_eq!(fds.len(), MAX_FDS, "descriptors were lost in transit");
    }

    #[test]
    fn more_than_max_fds_is_rejected_before_the_syscall() {
        let (a, _b) = UnixStream::pair().unwrap();
        let (rx, _tx) = std::io::pipe().unwrap();
        let too_many = vec![rx.as_raw_fd(); MAX_FDS + 1];
        let err = send_with_fds(&a, b"x", &too_many).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn an_empty_payload_is_rejected() {
        let (a, _b) = UnixStream::pair().unwrap();
        let err = send_with_fds(&a, b"", &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// The dangerous half of the same rule: a zero-length stream send transfers
    /// nothing at all, so accepting this would drop the descriptors on the floor.
    #[test]
    fn descriptors_with_an_empty_payload_are_rejected() {
        let (a, b) = UnixStream::pair().unwrap();
        let (rx, _tx) = std::io::pipe().unwrap();
        let err = send_with_fds(&a, b"", &[rx.as_raw_fd()]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Nothing crossed, so the peer sees an empty socket, not a stray fd.
        drop(a);
        let mut buf = [0u8; 16];
        let mut fds = Vec::new();
        assert_eq!(recv_with_fds(&b, &mut buf, &mut fds).unwrap(), 0);
        assert!(fds.is_empty());
    }

    #[test]
    fn send_all_writes_every_byte_of_the_tail() {
        let (a, b) = UnixStream::pair().unwrap();
        send_all(a.as_raw_fd(), b"abcdef").unwrap();
        drop(a);

        let mut got = Vec::new();
        let mut reader = &b;
        std::io::Read::read_to_end(&mut reader, &mut got).unwrap();
        assert_eq!(got, b"abcdef");
    }

    /// Descriptors arriving with a buffer-filling read cannot be told apart
    /// from a message split away from them, so the pair must be refused rather
    /// than handed over to be silently dropped.
    #[test]
    fn descriptors_with_a_buffer_filling_read_are_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        let (rx, _tx) = std::io::pipe().unwrap();
        send_with_fds(&a, b"0123456789", &[rx.as_raw_fd()]).unwrap();

        // Deliberately too small: the fds ride with the first byte only.
        let mut buf = [0u8; 4];
        let mut fds = Vec::new();
        let err = recv_with_fds(&b, &mut buf, &mut fds).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(fds.is_empty(), "a doomed descriptor was handed back");
    }

    /// The same guard must not fire on the normal case: descriptors with a
    /// message that leaves room to spare are fine.
    #[test]
    fn descriptors_with_a_short_read_are_accepted() {
        let (a, b) = UnixStream::pair().unwrap();
        let (rx, _tx) = std::io::pipe().unwrap();
        send_with_fds(&a, b"0123456789", &[rx.as_raw_fd()]).unwrap();

        let mut buf = [0u8; 11];
        let mut fds = Vec::new();
        assert_eq!(recv_with_fds(&b, &mut buf, &mut fds).unwrap(), 10);
        assert_eq!(fds.len(), 1);
    }

    /// Zero must mean end of file and only end of file.
    #[test]
    fn a_closed_peer_reads_as_end_of_file() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        let mut buf = [0u8; 16];
        let mut fds = Vec::new();
        assert_eq!(recv_with_fds(&b, &mut buf, &mut fds).unwrap(), 0);
        assert!(fds.is_empty());
    }

    #[test]
    fn an_empty_receive_buffer_is_rejected_rather_than_read_as_eof() {
        let (a, b) = UnixStream::pair().unwrap();
        send_with_fds(&a, b"hello", &[]).unwrap();
        let mut fds = Vec::new();
        let err = recv_with_fds(&b, &mut [], &mut fds).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
