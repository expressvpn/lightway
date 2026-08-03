//! The inside split: a multiqueue TUN whose queue is chosen by a BPF program
//! reading a single "is ExpressLane active" flag.
//!
//! Steering is an *egress* decision. The kernel runs the program in
//! `tun_select_queue` on its way out of the device (`tun.c:560`), so it picks
//! which fd a packet the stack transmits surfaces on. Packets written *into* a
//! queue fd go the other way, into the stack, and are not steered at all.
//!
//! Both queues must be attached before any of this takes effect:
//! `netdev_core_pick_tx` only calls `ndo_select_queue` while
//! `real_num_tx_queues != 1`, and `tun_attach` raises that as queues join
//! (`tun.c:844`).

use std::fs::{File, OpenOptions};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::OpenOptionsExt as _;

use libbpf_rs::skel::{OpenSkel as _, SkelBuilder as _};
use libbpf_rs::{MapCore as _, MapFlags, OpenObject};

use crate::load::{load_error, read_counters};

// The skeleton is machine-generated and does not carry the SAFETY comments
// this crate demands of code it writes itself.
#[allow(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block
)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/inside.skel.rs"));
}

use skel::{InsideSkel, InsideSkelBuilder};

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;

/// `_IOW('T', 202, int)` - `if_tun.h:34`.
const TUNSETIFF: libc::Ioctl = 0x4004_54ca_u32 as libc::Ioctl;
/// `_IOR('T', 224, int)` - `if_tun.h:60`.
const TUNSETSTEERINGEBPF: libc::Ioctl = 0x8004_54e0_u32 as libc::Ioctl;

/// Queue index the program returns for the control plane, as `inside.bpf.c`
/// has it. Doubles as its bucket in `inside_counts`, and is the order the two
/// queues are attached in: the first `TUNSETIFF` is queue 0.
const QUEUE_CONTROL: usize = 0;
/// Queue index the program returns for the engine, as `inside.bpf.c` has it.
/// Doubles as its bucket in `inside_counts`.
const QUEUE_ENGINE: usize = 1;
/// Buckets in `inside_counts`, one per queue index.
const COUNT_BUCKETS: usize = QUEUE_ENGINE + 1;

// `inside.bpf.c` hardcodes the same two values, and `inside_counts` there is
// two entries wide. Renumbering one side only would read a bucket the map does
// not have, which looks like a counter stuck at zero rather than a mistake.
const _: () = assert!(QUEUE_CONTROL == 0 && QUEUE_ENGINE == 1);

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IF_NAMESIZE],
    flags: libc::c_short,
    _pad: [u8; 22],
}

// `struct ifreq` is a 16-byte name plus a 24-byte union (`ifru_map` is the
// widest member) and the kernel copies all 40 bytes out of userspace. A short
// struct here would have it read past the end of this one.
const _: () = assert!(size_of::<IfReq>() == 40);

/// A two-queue TUN with a BPF steering program attached.
///
/// Both queue fds are opened `O_NONBLOCK`, so a read on an idle queue returns
/// [`io::ErrorKind::WouldBlock`] rather than parking (`tun.c:2041` reads
/// `f_flags` per call).
/// The fds are public, but must be *cloned* out rather than moved out: the
/// skeleton lives in this struct, and dropping it detaches the program. See
/// [`clone_control_queue`](Self::clone_control_queue).
///
/// ```no_run
/// # use lightway_bpf_steering::InsideSplit;
/// let split = InsideSplit::create("lwsteer%d")?;
///
/// // Hand duplicates to whatever does the I/O; `split` stays alive here, so
/// // the device and its program stay alive with it.
/// let engine = split.clone_engine_queue()?;
/// let control = split.clone_control_queue()?;
///
/// // And the split is still the whole control plane afterwards.
/// split.set_offload_active(true)?;
/// let [_control, _engine] = split.counts()?;
/// # drop((engine, control));
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct InsideSplit {
    /// Queue 0 - carries inside packets while ExpressLane is not active.
    pub control_queue: File,
    /// Queue 1 - carries every inside packet once ExpressLane is active.
    pub engine_queue: File,
    name: String,
    skel: InsideSkel<'static>,
}

/// Open `/dev/net/tun` and join `name` as one more queue, creating the device
/// if this is the first.
///
/// Returns the fd and the name the kernel settled on, which is not `name`
/// whenever that carries a `%d`.
fn attach_queue(name: &str) -> io::Result<(File, String)> {
    if name.is_empty() || name.len() >= libc::IF_NAMESIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name must be 1..IFNAMSIZ-1 bytes",
        ));
    }

    let tun = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/net/tun")?;

    let mut req = IfReq {
        name: [0; libc::IF_NAMESIZE],
        flags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
        _pad: [0; 22],
    };
    for (dst, b) in req.name.iter_mut().zip(name.as_bytes()) {
        *dst = *b as libc::c_char;
    }

    // SAFETY: `req` is a correctly sized `ifreq` (asserted above) and lives
    // across the call; the fd is open and owned by `tun`.
    let rc = unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &raw mut req) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // The kernel writes back the name it actually used, which is the only way
    // to learn what a "%d" pattern became. Everything downstream - the second
    // queue, `if_index` - has to use that and not what was asked for.
    let actual: Vec<u8> = req
        .name
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    let actual =
        String::from_utf8(actual).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok((tun, actual))
}

impl InsideSplit {
    /// Create a two-queue TUN named `name` and attach the steering program.
    ///
    /// The device is not persistent: it disappears when both queue fds close.
    /// It comes up with no address and the flag clear, so the control queue
    /// owns the inside path until something says otherwise.
    ///
    /// Needs `CAP_NET_ADMIN` for the device and `CAP_BPF` for the program;
    /// without either this fails with [`io::ErrorKind::PermissionDenied`],
    /// distinctly from a program the kernel loaded but rejected.
    pub fn create(name: &str) -> io::Result<Self> {
        // Order matters, and it is the reason the second queue is attached
        // last. `netdev_core_pick_tx` consults the steering callback only
        // while `real_num_tx_queues != 1`, which `tun_attach` raises as the
        // second queue joins (`tun.c:844`). Attaching both queues first would
        // open a window - however brief - in which the device is multiqueue
        // with no program, and the kernel steers by its own flow hash
        // (`tun_automq_select_queue`); a packet in that window could surface
        // on either fd. Attaching one queue, then the program, then the
        // second closes it outright: until the second queue exists the
        // callback is skipped entirely, and `tun_set_ebpf` is happy with a
        // single attached fd.
        let (control_queue, name) = attach_queue(name)?;

        // `InsideSkel` borrows the storage its object lives in, so keeping a
        // skeleton around means that storage must really be `'static`. Leaking
        // one pointer-sized box buys that outright, instead of a struct that
        // borrows from itself and stays sound only while nobody reorders its
        // fields. The skeleton's own drop still closes the `bpf_object`; what
        // leaks is the empty shell, once per `create`.
        let slot: &'static mut MaybeUninit<OpenObject> = Box::leak(Box::new(MaybeUninit::uninit()));

        let skel = InsideSkelBuilder::default()
            .open(slot)
            .and_then(|open| open.load())
            .map_err(load_error)?;

        // The ioctl wants a *pointer* to the fd, so the fd needs somewhere to
        // live: `as_raw_fd()` yields a value, not a place. `lw_steer` is
        // `SEC("socket")` because `tun_set_ebpf` demands
        // `BPF_PROG_TYPE_SOCKET_FILTER` (`tun.c:3017`) - anything else is
        // EINVAL here. `Skel::attach` does not attach socket programs, so
        // this ioctl is the whole attachment.
        let prog_fd: libc::c_int = skel.progs.lw_steer.as_fd().as_raw_fd();

        // SAFETY: the ioctl copies one `int` out of the pointer, and `prog_fd`
        // is a local that outlives the call. Both fds are open: `prog_fd`
        // names a program the skeleton owns, and `control_queue` owns its own.
        // Steering is per device rather than per queue, so setting it on this
        // fd covers the queue attached after it.
        let rc = unsafe {
            libc::ioctl(
                control_queue.as_raw_fd(),
                TUNSETSTEERINGEBPF,
                std::ptr::from_ref(&prog_fd),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        // Join the device the first open settled on, never the pattern that
        // was asked for: "lwsteer%d" twice would be two devices, not two
        // queues.
        let (engine_queue, _) = attach_queue(&name)?;

        let this = Self {
            control_queue,
            engine_queue,
            name,
            skel,
        };
        // A fresh array map reads zero, but say so anyway: the state the
        // device starts in is part of the contract, not an accident.
        this.set_offload_active(false)?;
        Ok(this)
    }

    /// Point the inside path at the engine queue, or back at the control
    /// queue. This single map write is the entire DTLS fallback.
    pub fn set_offload_active(&self, active: bool) -> io::Result<()> {
        self.skel
            .maps
            .offload_active
            .update(
                &0u32.to_ne_bytes(),
                &u32::from(active).to_ne_bytes(),
                MapFlags::ANY,
            )
            .map_err(io::Error::other)
    }

    /// Steering *decisions*: `[chose_control_queue, chose_engine_queue]`.
    ///
    /// Read this as what the program asked for, not as where the packet went.
    /// The program bumps the bucket and returns the index; the kernel then
    /// delivers to `tfiles[ret % numqueues]` (`tun.c:558`), and BPF cannot see
    /// `numqueues`. So if the engine reader closes its queue while the flag is
    /// still set, `numqueues` drops to 1, the engine bucket keeps climbing and
    /// every packet lands on queue 0 instead.
    ///
    /// Anything built on these - `--require-offload`, say - therefore has to
    /// treat them as intent and corroborate delivery some other way, e.g. with
    /// the engine's own receive counters.
    pub fn counts(&self) -> io::Result<[u64; COUNT_BUCKETS]> {
        read_counters(&self.skel.maps.inside_counts)
    }

    /// A duplicate of the control queue's fd, for a caller that must own one.
    ///
    /// Moving [`control_queue`](Self::control_queue) out is not possible and
    /// should not be: this struct owns the skeleton and both queue fds, and
    /// dropping it detaches the program and takes the device down with it.
    /// The split has to outlive the queues it feeds, so the fd is duplicated
    /// and the split kept.
    ///
    /// `dup(2)` gives another handle on the *same* `tun_file`, not a third
    /// queue: the copy reads what the kernel steered to queue 0, and does not
    /// change `numqueues`. It shares the `O_NONBLOCK` that
    /// [`create`](Self::create) set, which is what
    /// `tokio::io::unix::AsyncFd` wants; a `std::net`-style
    /// `set_nonblocking(true)` has no equivalent here.
    pub fn clone_control_queue(&self) -> io::Result<File> {
        self.control_queue.try_clone()
    }

    /// A duplicate of the engine queue's fd.
    /// See [`clone_control_queue`](Self::clone_control_queue).
    pub fn clone_engine_queue(&self) -> io::Result<File> {
        self.engine_queue.try_clone()
    }

    /// The device's interface index.
    pub fn if_index(&self) -> io::Result<u32> {
        let cname = std::ffi::CString::new(self.name.as_str())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: `cname` is a valid NUL-terminated string living across the
        // call, which is all `if_nametoindex` reads.
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name is copied into a fixed 16-byte field; anything that would not
    /// fit with its NUL has to be refused rather than silently truncated onto
    /// some other device.
    #[test]
    fn an_oversized_name_is_rejected_before_any_fd_is_opened() {
        for name in ["", "sixteen_char_nam", "much_too_long_for_ifnamsiz"] {
            let e = attach_queue(name).expect_err("name should have been refused");
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "for {name:?}");
        }
    }
}
