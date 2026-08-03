//! eBPF packet steering for an out-of-process ExpressLane offload engine.
//!
//! Two programs, one per direction. Outside, a `SK_REUSEPORT` program reads
//! three bytes of the Lightway header - the two magic bytes and the
//! ExpressLane flag - and picks between two sockets in a reuseport group.
//! Inside, a `SOCKET_FILTER` program attached with
//! `TUNSETSTEERINGEBPF` reads a one-entry map and picks between two queues of
//! a multiqueue TUN.
//!
//! This is the userspace counterpart of what `kp_lwt` does with `encap_rcv`,
//! one layer up: the kernel decides, so the control-plane process never sees
//! an offloaded packet at all.
//!
//! The two `counts()` are not symmetric, and code reading both must not treat
//! them as one metric: outside counts *outcomes* - `[control, engine, failed]`,
//! what `bpf_sk_select_reuseport` actually did - while inside counts
//! *decisions* - `[control, engine]`, what the program asked for, before the
//! kernel's `% numqueues`.
#![cfg(target_os = "linux")]
#![warn(missing_docs)]

mod header;
mod outside;

pub use header::{
    EXPRESSLANE_FLAG_OFFSET, HEADER_LEN, MAGIC, SESSION_ID_OFFSET, is_expresslane_datagram,
};
pub use outside::OutsideSplit;
