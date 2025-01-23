//! TxQueue, helper/queue for UringIoSource tx implementations
//!
//! Uses uring indexes:
//!
//! Loop::outside_rx_user_data:
//!  - None
//!
//! Loop::outside_tx_user_data:
//!  - 0..TxQueue::state.len()

use std::collections::VecDeque;

use anyhow::{Context as _, Result};
use bytes::Bytes;
use io_uring::squeue::Entry as SEntry;

use super::{
    ffi::{iovec, msghdr},
    io_uring_res,
    outside::udp::cmsg,
    Loop, SubmissionQueue, Submitter,
};

pub(super) struct TxState {
    pub buf: Option<Bytes>,
    pub addr: libc::sockaddr_storage,
    pub addr_len: libc::socklen_t,
    pub control: cmsg::BufferMut<{ Self::CONTROL_SIZE }>,
    pub iov: [iovec; 1],
    pub msghdr: msghdr,
}

impl TxState {
    const CONTROL_SIZE: usize = cmsg::Message::space::<libc::in_pktinfo>();
    fn new() -> Self {
        #[allow(unsafe_code)]
        Self {
            buf: None,
            // SAFETY: All zeroes is a valid sockaddr
            addr: unsafe { std::mem::zeroed() },
            addr_len: 0,
            control: cmsg::BufferMut::zeroed(),

            // SAFETY: All zeroes is a valid iov
            iov: [unsafe { std::mem::zeroed() }],
            // SAFETY: All zeroes is a valid msghdr
            msghdr: unsafe { std::mem::zeroed() },
        }
    }
}

pub struct TxQueue {
    sqe_ring: VecDeque<SEntry>,
    slots: Vec<u32>,
    state: Vec<TxState>,
}

impl TxQueue {
    pub fn new(nr_slots: u32) -> Self {
        tracing::info!("TxQueue with {nr_slots} slots");
        let sqe_ring = VecDeque::with_capacity(nr_slots as usize);
        let (slots, state) = (0..nr_slots).map(|nr| (nr, TxState::new())).unzip();

        Self {
            sqe_ring,
            slots,
            state,
        }
    }

    /// Reserve a slot, the returned value should be passed to
    /// `push_*_slot` after setting up the state and constructing an
    /// sqe.
    pub(super) fn take_slot(&mut self) -> Option<(u32, &mut TxState)> {
        let slot = self.slots.pop()?;
        let state = &mut self.state[slot as usize];
        Some((slot, state))
    }

    #[allow(unsafe_code)]
    /// Push an inside request entry to the tx queue.
    ///
    /// Callers are responsible for calling `::complete` when the
    /// request completes to free the slot.
    ///
    /// # Safety:
    ///
    /// - idx must have been previously obtained from `take_slot`
    /// - sqe must meet the safety requirements <https://docs.rs/io-uring/latest/io_uring/squeue/struct.SubmissionQueue.html#method.push>
    ///
    /// Any sqe userdata will be overwritten
    pub(super) unsafe fn push_inside_slot(&mut self, idx: u32, sqe: SEntry) {
        let sqe = sqe.user_data(Loop::inside_tx_user_data(idx));
        self.sqe_ring.push_back(sqe);
    }

    #[allow(unsafe_code)]
    /// Push an outside request entry to the tx queue.
    ///
    /// Callers are responsible for calling `::complete` when the
    /// request completes to free the slot.
    ///
    /// # Safety:
    ///
    /// - idx must have been previously obtained from `take_slot`
    /// - sqe must meet the safety requirements <https://docs.rs/io-uring/latest/io_uring/squeue/struct.SubmissionQueue.html#method.push>
    ///
    /// Any sqe userdata will be overwritten
    pub(super) unsafe fn push_outside_slot(&mut self, idx: u32, sqe: SEntry) {
        let sqe = sqe.user_data(Loop::outside_tx_user_data(idx));
        self.sqe_ring.push_back(sqe);
    }

    #[allow(unsafe_code)]
    /// Push an arbitrary entry to the tx queue. Does not consume a slot.
    ///
    /// Callers are responsible for completion and should not call
    /// `::complete`.
    ///
    /// Use this for SQEs which do not require an entry in `::state`
    /// to keep buffers live and/or for which the calling code wants
    /// to manage the idx space itself.
    ///
    /// # Safety:
    ///
    /// - sqe must meet the safety requirements <https://docs.rs/io-uring/latest/io_uring/squeue/struct.SubmissionQueue.html#method.push>
    pub(super) unsafe fn push(&mut self, sqe: SEntry) {
        self.sqe_ring.push_back(sqe);
    }

    /// Push all entries (added by `push_*_slot` or `push`) to the uring.
    pub(super) fn drain(&mut self, submitter: &Submitter, sq: &mut SubmissionQueue) -> Result<()> {
        while let Some(sqe) = self.sqe_ring.pop_front() {
            if sq.is_full() {
                match submitter.submit() {
                    Ok(_) => (),
                    Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => break,
                    Err(err) => return Err(err.into()),
                }
                sq.sync();
            }

            #[allow(unsafe_code)]
            // SAFETY: Safe according to the safety requirements of `push_*_slot` or `push`
            unsafe {
                sq.push(&sqe)?
            };

            sq.sync()
        }

        Ok(())
    }

    /// Complete an entry added with `push_*_slot`, intended to be
    /// called from the IoUringSource's `complete_*` method. Note that
    /// users of plain `push` are responsible for their own
    /// completion.
    pub(super) fn complete(&mut self, cqe: io_uring::cqueue::Entry, idx: u32) -> Result<()> {
        let _res = io_uring_res(cqe.result()).with_context(|| "tx completion")?;

        let slot = &mut self.state[idx as usize];

        slot.buf = None;

        self.slots.push(idx);

        Ok(())
    }
}
