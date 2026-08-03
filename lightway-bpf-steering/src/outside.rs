//! The outside split: two UDP sockets in one `SO_REUSEPORT` group, with a BPF
//! program choosing between them per datagram.
//!
//! The control socket binds first and defines the group; the engine socket
//! binds the address the control socket ended up with. Both therefore share a
//! source port, so a datagram the engine sends reaches the peer as part of the
//! same flow and no roam is signalled.

use std::io;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::skel::{OpenSkel as _, SkelBuilder as _};
use libbpf_rs::{MapCore as _, MapFlags, OpenObject};
use socket2::{Domain, Protocol, Socket, Type};

use crate::load::{load_error, read_counters};

// The skeleton is machine-generated and does not carry the SAFETY comments
// this crate demands of code it writes itself.
#[allow(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block
)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/outside.skel.rs"));
}

use skel::{OutsideSkel, OutsideSkelBuilder};

/// Sockarray index of the control-plane socket, as `outside.bpf.c` has it.
const IDX_CONTROL: u32 = 0;
/// Sockarray index of the engine socket, as `outside.bpf.c` has it.
const IDX_ENGINE: u32 = 1;
/// Buckets in `outside_counts`: control, engine, selection failed.
const COUNT_BUCKETS: usize = 3;

/// A reuseport pair with ExpressLane datagrams steered to `engine`.
///
/// Neither socket may be `connect`ed. A connected UDP socket is found by the
/// four-tuple half of `udp4_lib_lookup2`, which returns it directly and only
/// consults the reuseport group for a socket with no fixed peer
/// (`net/ipv4/udp.c:442-460`); the program is then never called and the split
/// is silently off. Today's client leaves both unconnected and sends with
/// `send_to` - that is a requirement of this type, not a coincidence.
///
/// The fds are public, but must be *cloned* out rather than moved out: the
/// skeleton lives in this struct, and dropping it detaches the program. See
/// [`clone_control`](Self::clone_control).
///
/// ```no_run
/// # use lightway_bpf_steering::OutsideSplit;
/// let split = OutsideSplit::bind("127.0.0.1:0".parse().unwrap())?;
///
/// // Hand duplicates to whatever does the I/O; `split` stays alive here, so
/// // the program stays attached.
/// let engine = split.clone_engine()?;
/// engine.set_nonblocking(true)?;
/// let control = split.clone_control()?;
/// control.set_nonblocking(true)?;
///
/// // And the split is still usable afterwards.
/// let [_control, _engine, failed] = split.counts()?;
/// assert_eq!(failed, 0);
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct OutsideSplit {
    /// Receives everything that is not an ExpressLane data packet.
    pub control: UdpSocket,
    /// Receives ExpressLane data packets only.
    pub engine: UdpSocket,
    skel: OutsideSkel<'static>,
}

/// A UDP socket in the reuseport group at `addr`.
fn reuseport_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    // Must be set before bind for the group to form.
    sock.set_reuse_port(true)?;
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

impl OutsideSplit {
    /// Bind both sockets and attach the splitter.
    ///
    /// Pass port 0 to let the kernel choose; the engine socket then binds the
    /// port the control socket was given, so both share one address and the
    /// peer sees a single flow.
    ///
    /// Loading BPF needs `CAP_BPF` and `CAP_NET_ADMIN`. Without them this
    /// fails with [`io::ErrorKind::PermissionDenied`], distinctly from a
    /// program the kernel loaded but rejected.
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let control = reuseport_socket(addr)?;
        // Bind the engine to the port the kernel just handed the control
        // socket, so both share one address and form a reuseport group. Both
        // must be bound before the sockarray will accept them: the kernel
        // requires a socket to already have a reuseport group, and refuses
        // the update with EINVAL otherwise (reuseport_array.c:220).
        let engine = reuseport_socket(control.local_addr()?)?;

        // `OutsideSkel` borrows the storage its object lives in, so keeping a
        // skeleton around means that storage must really be `'static`. Leaking
        // one pointer-sized box buys that outright, instead of a struct that
        // borrows from itself and stays sound only while nobody reorders its
        // fields. The skeleton's own drop still closes the `bpf_object`; what
        // leaks is the empty shell, once per `bind`.
        let slot: &'static mut MaybeUninit<OpenObject> = Box::leak(Box::new(MaybeUninit::uninit()));

        let skel = OutsideSkelBuilder::default()
            .open(slot)
            .and_then(|open| open.load())
            .map_err(load_error)?;

        for (idx, fd) in [
            (IDX_CONTROL, control.as_raw_fd()),
            (IDX_ENGINE, engine.as_raw_fd()),
        ] {
            skel.maps
                .socks
                .update(
                    &idx.to_ne_bytes(),
                    &(fd as u64).to_ne_bytes(),
                    MapFlags::ANY,
                )
                .map_err(io::Error::other)?;
        }

        // setsockopt wants a *pointer* to the fd, so the fd needs somewhere to
        // live: `as_raw_fd()` yields a value, not a place.
        let prog_fd: libc::c_int = skel.progs.lw_split.as_fd().as_raw_fd();

        // SAFETY: `control` outlives the attachment - it is moved into the
        // returned struct alongside the skeleton that owns the program - and
        // setsockopt reads exactly `size_of::<c_int>()` bytes from `&prog_fd`,
        // which lives across the call.
        let rc = unsafe {
            libc::setsockopt(
                control.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_REUSEPORT_EBPF,
                std::ptr::from_ref(&prog_fd).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            control,
            engine,
            skel,
        })
    }

    /// The address both sockets share.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.control.local_addr()
    }

    /// A duplicate of the control socket, for a caller that must own one.
    ///
    /// Moving [`control`](Self::control) out is not possible and should not
    /// be: this struct owns the skeleton, and dropping it closes the
    /// `bpf_object` and so detaches the program the reuseport group steers by.
    /// The split has to outlive the sockets it feeds, so the fd is duplicated
    /// and the split kept.
    ///
    /// `dup(2)` gives another handle on the *same* socket, not a third member
    /// of the group, so the copy receives exactly what the program steered
    /// here. Call [`UdpSocket::set_nonblocking`] on it before
    /// `tokio::net::UdpSocket::from_std`, which requires a socket already in
    /// nonblocking mode.
    pub fn clone_control(&self) -> io::Result<UdpSocket> {
        self.control.try_clone()
    }

    /// A duplicate of the engine socket. See [`clone_control`](Self::clone_control).
    pub fn clone_engine(&self) -> io::Result<UdpSocket> {
        self.engine.try_clone()
    }

    /// Kernel-side ground truth: `[to_control, to_engine, selection_failed]`.
    ///
    /// The kernel counts what `bpf_sk_select_reuseport` did, not what the
    /// classifier wanted. The third bucket is the disagreement: the helper
    /// refused the chosen index - an empty sockarray slot, say - and delivery
    /// fell back to the kernel's own hash. Anything but zero there means the
    /// split was not in force for that many datagrams.
    pub fn counts(&self) -> io::Result<[u64; COUNT_BUCKETS]> {
        read_counters(&self.skel.maps.outside_counts)
    }
}
