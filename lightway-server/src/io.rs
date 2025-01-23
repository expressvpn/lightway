pub(crate) mod inside;
pub(crate) mod outside;

mod ffi;
mod tx;

use std::{
    os::fd::{AsRawFd, OwnedFd, RawFd},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Context as _, Result};
use io_uring::{
    cqueue::Entry as CEntry,
    opcode,
    squeue::Entry as SEntry,
    types::{Fd, Fixed},
    Builder, IoUring, SubmissionQueue, Submitter,
};

use ffi::{iovec, msghdr};
pub use tx::TxQueue;

/// Convenience function to handle errors in a uring result codes
/// (which are negative errno codes).
fn io_uring_res(res: i32) -> std::io::Result<i32> {
    if res < 0 {
        Err(std::io::Error::from_raw_os_error(-res))
    } else {
        Ok(res)
    }
}

/// An I/O source pushing requests to a uring instance
pub(crate) trait UringIoSource: Send {
    /// Return the raw file descriptor. This will be registered as an
    /// fd with the ring, allowing the use of io_uring::types::Fixed.
    fn as_raw_fd(&self) -> RawFd;

    /// Push the initial set of requests to `sq`.
    fn push_initial_ops(&mut self, sq: &mut io_uring::SubmissionQueue) -> Result<()>;

    /// Complete an rx request
    fn complete_rx(
        &mut self,
        sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
        idx: u32,
    ) -> Result<()>;

    /// Complete a tx request
    fn complete_tx(
        &mut self,
        sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
        idx: u32,
    ) -> Result<()>;
}

pub(crate) enum OutsideIoSource {
    Udp(outside::udp::UdpServer),
    Tcp(outside::tcp::TcpServer),
}

// Avoiding `dyn`amic dispatch is a small performance win.
impl UringIoSource for OutsideIoSource {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            OutsideIoSource::Udp(udp) => udp.as_raw_fd(),
            OutsideIoSource::Tcp(tcp) => tcp.as_raw_fd(),
        }
    }

    fn push_initial_ops(&mut self, sq: &mut io_uring::SubmissionQueue) -> Result<()> {
        match self {
            OutsideIoSource::Udp(udp) => udp.push_initial_ops(sq),
            OutsideIoSource::Tcp(tcp) => tcp.push_initial_ops(sq),
        }
    }

    fn complete_rx(
        &mut self,
        sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
        idx: u32,
    ) -> Result<()> {
        match self {
            OutsideIoSource::Udp(udp) => udp.complete_rx(sq, cqe, idx),
            OutsideIoSource::Tcp(tcp) => tcp.complete_rx(sq, cqe, idx),
        }
    }

    fn complete_tx(
        &mut self,
        sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
        idx: u32,
    ) -> Result<()> {
        match self {
            OutsideIoSource::Udp(udp) => udp.complete_tx(sq, cqe, idx),
            OutsideIoSource::Tcp(tcp) => tcp.complete_tx(sq, cqe, idx),
        }
    }
}

pub(crate) struct Loop {
    ring: IoUring,

    tx: Arc<Mutex<TxQueue>>,

    cancel_buf: u8,

    outside: OutsideIoSource,
    inside: inside::tun::Tun,
}

impl Loop {
    /// Use for outside IO requests, `self.outside.as_raw_fd` will be registered in this slot.
    const FIXED_OUTSIDE_FD: Fixed = Fixed(0);
    /// Use for inside IO requests, `self.inside.as_raw_fd` will be registered in this slot.
    const FIXED_INSIDE_FD: Fixed = Fixed(1);

    /// Masks the bits used by `*_USER_DATA_BASE`
    const USER_DATA_TYPE_MASK: u64 = 0xe000_0000_0000_0000;

    /// Indexes in this range will result in a call to `self.outside.complete_rx`
    const OUTSIDE_RX_USER_DATA_BASE: u64 = 0xc000_0000_0000_0000;
    /// Indexes in this range will result in a call to `self.outside.complete_tx`
    const OUTSIDE_TX_USER_DATA_BASE: u64 = 0x8000_0000_0000_0000;

    /// Indexes in this range will result in a call to `self.inside.complete_rx`
    const INSIDE_RX_USER_DATA_BASE: u64 = 0x4000_0000_0000_0000;
    /// Indexes in this range will result in a call to `self.inside.complete_tx`
    const INSIDE_TX_USER_DATA_BASE: u64 = 0x2000_0000_0000_0000;

    /// Indexes in this range are used by `Loop` itself.
    const CONTROL_USER_DATA_BASE: u64 = 0x0000_0000_0000_0000;

    /// A read request on the cancellation fd (used to exit the io loop)
    const CANCEL_USER_DATA: u64 = Self::CONTROL_USER_DATA_BASE + 1;

    /// Return user data for a particular outside rx index.
    fn outside_rx_user_data(idx: u32) -> u64 {
        Self::OUTSIDE_RX_USER_DATA_BASE + (idx as u64)
    }

    /// Return user data for a particular inside rx index.
    fn inside_rx_user_data(idx: u32) -> u64 {
        Self::INSIDE_RX_USER_DATA_BASE + (idx as u64)
    }

    /// Return user data for a particular inside tx index.
    fn inside_tx_user_data(idx: u32) -> u64 {
        Self::INSIDE_TX_USER_DATA_BASE + (idx as u64)
    }

    /// Return user data for a particular outside tx index.
    fn outside_tx_user_data(idx: u32) -> u64 {
        Self::OUTSIDE_TX_USER_DATA_BASE + (idx as u64)
    }

    pub(crate) fn new(
        ring_size: usize,
        sqpoll_idle_time: Duration,
        tx: Arc<Mutex<TxQueue>>,
        outside: OutsideIoSource,
        inside: inside::tun::Tun,
    ) -> Result<Self> {
        tracing::info!(ring_size, "creating IoUring");
        let mut builder: Builder<SEntry, CEntry> = IoUring::builder();

        builder.dontfork();

        if sqpoll_idle_time.as_millis() > 0 {
            let idle_time: u32 = sqpoll_idle_time
                .as_millis()
                .try_into()
                .with_context(|| "invalid sqpoll idle time")?;
            // This setting makes CPU go 100% when there is continuous traffic
            builder.setup_sqpoll(idle_time); // Needs 5.13
        }

        let ring = builder
            .build(ring_size as u32)
            .inspect_err(|e| tracing::error!("iouring setup failed: {e}"))?;

        Ok(Self {
            ring,
            tx,
            cancel_buf: 0,
            outside,
            inside,
        })
    }

    pub(crate) fn run(mut self, cancel: OwnedFd) -> Result<()> {
        let (submitter, mut sq, mut cq) = self.ring.split();

        submitter.register_files(&[self.outside.as_raw_fd(), self.inside.as_raw_fd()])?;

        let sqe = opcode::Read::new(
            Fd(cancel.as_raw_fd()),
            &mut self.cancel_buf as *mut _,
            std::mem::size_of_val(&self.cancel_buf) as _,
        )
        .build()
        .user_data(Self::CANCEL_USER_DATA);

        #[allow(unsafe_code)]
        // SAFETY: The buffer is owned by `self.cancel_buf` and `self` is owned
        unsafe {
            sq.push(&sqe)?
        };

        self.outside.push_initial_ops(&mut sq)?;
        self.inside.push_initial_ops(&mut sq)?;
        sq.sync();

        loop {
            let _ = submitter.submit_and_wait(1)?;

            cq.sync();

            for cqe in &mut cq {
                let user_data = cqe.user_data();

                match user_data & Self::USER_DATA_TYPE_MASK {
                    Self::CONTROL_USER_DATA_BASE => {
                        match user_data - Self::CONTROL_USER_DATA_BASE {
                            Self::CANCEL_USER_DATA => {
                                let res = cqe.result();
                                tracing::debug!(?res, "Uring cancelled");
                                return Ok(());
                            }
                            idx => {
                                return Err(anyhow!(
                                    "Unknown control data {user_data:016x} => {idx:016x}"
                                ))
                            }
                        }
                    }
                    Self::OUTSIDE_RX_USER_DATA_BASE => {
                        self.outside.complete_rx(
                            &mut sq,
                            cqe,
                            (user_data - Self::OUTSIDE_RX_USER_DATA_BASE) as u32,
                        )?;
                    }
                    Self::OUTSIDE_TX_USER_DATA_BASE => {
                        self.outside.complete_tx(
                            &mut sq,
                            cqe,
                            (user_data - Self::OUTSIDE_TX_USER_DATA_BASE) as u32,
                        )?;
                    }

                    Self::INSIDE_RX_USER_DATA_BASE => {
                        self.inside.complete_rx(
                            &mut sq,
                            cqe,
                            (user_data - Self::INSIDE_RX_USER_DATA_BASE) as u32,
                        )?;
                    }
                    Self::INSIDE_TX_USER_DATA_BASE => {
                        self.inside.complete_tx(
                            &mut sq,
                            cqe,
                            (user_data - Self::INSIDE_TX_USER_DATA_BASE) as u32,
                        )?;
                    }

                    _ => unreachable!(),
                }

                self.tx.lock().unwrap().drain(&submitter, &mut sq)?;
            }
        }
    }
}
