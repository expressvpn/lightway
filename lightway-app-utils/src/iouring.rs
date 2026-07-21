use anyhow::{Context, Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};
use lightway_core::IOCallbackResult;
use thiserror::Error;

use crate::metrics;
use io_uring::{
    Builder, IoUring, SubmissionQueue, Submitter, cqueue::Entry as CEntry, opcode,
    squeue::Entry as SEntry, types::Fixed,
};
use std::{
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
    thread,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, mpsc},
};
use tokio_eventfd::EventFd;

const REGISTERED_FD_INDEX: u32 = 0;

/// IO-uring Struct
pub struct IOUring<T: AsRawFd> {
    /// Any struct corresponds to a file descriptor
    owned_fd: Arc<T>,

    tx_queue: mpsc::Sender<Bytes>,
    rx_queue: Mutex<mpsc::Receiver<BytesMut>>,
}

/// An error from read/write operation
#[derive(Debug, Error)]
pub enum IOUringError {
    /// A recv error occurred
    #[error("Recv Error")]
    RecvError,

    /// A send error occurred
    #[error("Send Error")]
    SendError,
}

pub type IOUringResult<T> = std::result::Result<T, IOUringError>;

impl<T: AsRawFd> IOUring<T> {
    /// Create `IOUring` struct
    pub async fn new(
        owned_fd: Arc<T>,
        ring_size: usize,
        channel_size: usize,
        mtu: usize,
        sqpoll_idle_time: Duration,
    ) -> Result<Self> {
        let fd = owned_fd.as_raw_fd();

        let (tx_queue_sender, tx_queue_receiver) = mpsc::channel(channel_size);
        let (rx_queue_sender, rx_queue_receiver) = mpsc::channel(channel_size);
        thread::Builder::new()
            .name("io_uring-main".to_string())
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                    .expect("Failed building Tokio Runtime")
                    .block_on(iouring_task(
                        fd,
                        ring_size,
                        mtu,
                        sqpoll_idle_time,
                        tx_queue_receiver,
                        rx_queue_sender,
                    ))
                    .inspect_err(|err| {
                        tracing::error!("i/o uring task stopped: {:?}", err);
                    })
            })?;

        Ok(Self {
            owned_fd,
            tx_queue: tx_queue_sender,
            rx_queue: Mutex::new(rx_queue_receiver),
        })
    }

    /// Retrieve a reference to the underlying device
    pub fn owned_fd(&self) -> &T {
        &self.owned_fd
    }

    /// Receive packet from Tun device
    pub async fn recv(&self) -> IOUringResult<BytesMut> {
        self.rx_queue
            .lock()
            .await
            .recv()
            .await
            .ok_or(IOUringError::RecvError)
    }

    /// Receive up to `max` packets from the Tun device, appending them
    /// to `out`. Waits only when the rx queue is empty; when packets
    /// are already queued it returns what is immediately available.
    pub async fn recv_many(&self, out: &mut Vec<BytesMut>, max: usize) -> IOUringResult<usize> {
        if max == 0 {
            return Ok(0);
        }
        let n = self.rx_queue.lock().await.recv_many(out, max).await;
        if n == 0 {
            // With max > 0, recv_many returns 0 only when the channel
            // is closed.
            return Err(IOUringError::RecvError);
        }
        Ok(n)
    }

    /// Try Send packet to Tun device
    pub fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        let buf_len = buf.len();
        let try_send_res = self.tx_queue.try_send(buf.freeze());
        match try_send_res {
            Ok(()) => IOCallbackResult::Ok(buf_len),
            Err(mpsc::error::TrySendError::Full(_)) => IOCallbackResult::WouldBlock,
            Err(_) => IOCallbackResult::Err(std::io::Error::other(IOUringError::SendError)),
        }
    }
}

#[derive(Debug)]
enum SlotIdx {
    Tx(isize),
    Rx(isize),
}

impl SlotIdx {
    fn from_user_data(u: u64) -> Self {
        let u = u as isize;
        if u < 0 { Self::Rx(!u) } else { Self::Tx(u) }
    }

    fn idx(&self) -> usize {
        match *self {
            SlotIdx::Tx(idx) => idx as usize,
            SlotIdx::Rx(idx) => idx as usize,
        }
    }

    fn user_data(&self) -> u64 {
        match *self {
            SlotIdx::Tx(idx) => idx as u64,
            SlotIdx::Rx(idx) => (!idx) as u64,
        }
    }
}

struct RxState {
    sender: Option<mpsc::OwnedPermit<BytesMut>>,
    buf: BytesMut,
}

fn push_one_tx_event_to(
    buf: Bytes,
    sq: &mut SubmissionQueue,
    bufs: &mut [Option<Bytes>],
    slot: SlotIdx,
) -> std::result::Result<(), SlotIdx> {
    let sqe = opcode::Write::new(Fixed(REGISTERED_FD_INDEX), buf.as_ptr(), buf.len() as _)
        .build()
        .user_data(slot.user_data());

    #[allow(unsafe_code)]
    // SAFETY: sqe points to a buffer on the heap, owned
    // by a `Bytes` in `bufs[slot]`, we will not reuse
    // `bufs[slot]` until `slot` is returned to the slots vector.
    if unsafe { sq.push(&sqe) }.is_err() {
        return Err(slot);
    }

    // SAFETY: By construction instances of SlotIdx are always in bounds.
    #[allow(unsafe_code)]
    unsafe {
        *bufs.get_unchecked_mut(slot.idx()) = Some(buf)
    };

    Ok(())
}

fn push_tx_events_to(
    sbmt: &Submitter,
    sq: &mut SubmissionQueue,
    txq: &mut mpsc::Receiver<Bytes>,
    slots: &mut Vec<SlotIdx>,
    bufs: &mut [Option<Bytes>],
) -> Result<()> {
    while !slots.is_empty() {
        if sq.is_full() {
            match sbmt.submit() {
                Ok(_) => (),
                Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => break,
                Err(err) => {
                    return Err(anyhow!(err)).context("Push TX events failed for sq submit");
                }
            }
        }
        sq.sync();

        match txq.try_recv() {
            Ok(buf) => {
                let slot = slots.pop().expect("no tx slots left"); // we are inside `!slots.is_empty()`.
                if let Err(slot) = push_one_tx_event_to(buf, sq, bufs, slot) {
                    slots.push(slot);
                    break;
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                break;
            }
            Err(err) => {
                return Err(anyhow!(err)).context("Push TX events failed for try_recv");
            }
        }
    }
    Ok(())
}

fn push_rx_events_to(
    sbmt: &Submitter,
    sq: &mut SubmissionQueue,
    slots: &mut Vec<SlotIdx>,
    state: &mut [RxState],
) -> Result<()> {
    loop {
        if sq.is_full() {
            match sbmt.submit() {
                Ok(_) => (),
                Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => break,
                Err(err) => {
                    return Err(anyhow!(err)).context("Push RX events failed for sq submit");
                }
            }
        }
        sq.sync();

        match slots.pop() {
            Some(slot) => {
                // SAFETY: By construction instances of SlotIdx are always in bounds.
                #[allow(unsafe_code)]
                let state = unsafe { state.get_unchecked_mut(slot.idx()) };

                // queue a new rx
                let sqe = opcode::Read::new(
                    Fixed(REGISTERED_FD_INDEX),
                    state.buf.as_mut_ptr(),
                    state.buf.capacity() as _,
                )
                .build()
                .user_data(slot.user_data());
                #[allow(unsafe_code)]
                // SAFETY: sqe points to a buffer on the heap, owned
                // by a `BytesMut` in `rx_bufs[slot]`, we will not reuse
                // `rx_bufs[slot]` until `slot` is returned to the slots vector.
                if unsafe { sq.push(&sqe) }.is_err() {
                    slots.push(slot);
                    break;
                }
            }
            None => break,
        }
    }

    Ok(())
}

async fn iouring_task(
    fd: RawFd,
    ring_size: usize,
    mtu: usize,
    sqpoll_idle_time: Duration,
    mut tx_queue: mpsc::Receiver<Bytes>,
    rx_queue: mpsc::Sender<BytesMut>,
) -> Result<()> {
    let mut event_fd: EventFd = EventFd::new(0, false)?;
    let mut builder: Builder<SEntry, CEntry> = IoUring::builder();

    if sqpoll_idle_time.as_millis() > 0 {
        let idle_time: u32 = sqpoll_idle_time
            .as_millis()
            .try_into()
            .with_context(|| "invalid sqpoll idle time")?;
        // This setting makes CPU go 100% when there is continuous traffic
        builder.setup_sqpoll(idle_time); // Needs 5.13
    }
    let mut ring = builder
        .build(ring_size as u32)
        .inspect_err(|e| tracing::error!("iouring setup failed: {e}"))?;

    let (sbmt, mut sq, mut cq) = ring.split();

    // Register event-fd to cqe entries
    sbmt.register_eventfd(event_fd.as_raw_fd())?;
    sbmt.register_files(&[fd])?;

    // Using half of total io-uring size for rx and half for tx
    let nr_tx_rx_slots = (ring_size / 2) as isize;
    tracing::info!(
        ring_size,
        nr_tx_rx_slots,
        ?sqpoll_idle_time,
        "uring main task"
    );

    let mut rx_slots: Vec<_> = (0..nr_tx_rx_slots).map(SlotIdx::Rx).collect();
    let mut rx_state: Vec<_> = rx_slots
        .iter()
        .map(|_| RxState {
            sender: None,
            buf: BytesMut::with_capacity(mtu),
        })
        .collect();
    for state in rx_state.iter_mut() {
        state.sender = Some(rx_queue.clone().reserve_owned().await?)
    }

    let rx_sq_entries: Vec<_> = rx_slots
        .drain(..)
        .map(|slot| {
            let state = &mut rx_state[slot.idx()];
            opcode::Read::new(
                Fixed(REGISTERED_FD_INDEX),
                state.buf.as_mut_ptr(),
                state.buf.capacity() as _,
            )
            .build()
            .user_data(slot.user_data())
        })
        .collect();

    // SAFETY: sqe points to a buffer on the heap, owned
    // by a `BytesMut` in `rx_bufs[slot]`, we will not reuse
    // `rx_bufs[slot]` until `slot` is returned to the slots vector.
    #[allow(unsafe_code)]
    unsafe {
        let entries = rx_sq_entries;
        // This call should not fail since the SubmissionQueue should be empty now
        sq.push_multiple(&entries)?
    };
    sq.sync();

    let mut tx_slots: Vec<_> = (0..nr_tx_rx_slots).map(SlotIdx::Tx).collect();
    let mut tx_bufs = vec![None; tx_slots.len()];

    tracing::info!("Entering i/o uring loop");

    loop {
        let _ = sbmt.submit()?;

        cq.sync();

        if cq.is_empty() && tx_queue.is_empty() {
            let mut completed_number: [u8; 8] = [0; 8];
            tokio::select! {
                // There is no "wait until the queue contains
                // something" method so we have to actually receive
                // and treat that as a special case.
                Some(buf) = tx_queue.recv(), if !tx_slots.is_empty() && !sq.is_full() => {

                    let slot = tx_slots.pop().expect("no tx slots left"); // we are inside `!slots.is_empty()` guard.
                    if let Err(slot) = push_one_tx_event_to(buf, &mut sq, &mut tx_bufs, slot) {
                        tx_slots.push(slot);
                    }
                }

                Ok(a) = event_fd.read(&mut completed_number) => {
                    assert_eq!(a, 8);
                },

            };
            cq.sync();
        }

        // fill tx slots
        push_tx_events_to(&sbmt, &mut sq, &mut tx_queue, &mut tx_slots, &mut tx_bufs)?;

        // refill rx slots
        push_rx_events_to(&sbmt, &mut sq, &mut rx_slots, &mut rx_state)?;

        sq.sync();

        for cqe in &mut cq {
            let res = cqe.result();
            let slot = SlotIdx::from_user_data(cqe.user_data());

            match slot {
                SlotIdx::Rx(_) => {
                    if res > 0 {
                        // SAFETY: By construction instances of SlotIdx are always in bounds.
                        #[allow(unsafe_code)]
                        let RxState {
                            sender: maybe_sender,
                            buf,
                        } = unsafe { rx_state.get_unchecked_mut(slot.idx()) };

                        let mut buf = std::mem::replace(buf, BytesMut::with_capacity(mtu));

                        // SAFETY: We trust that the read operation
                        // returns the correct number of bytes received.
                        #[allow(unsafe_code)]
                        unsafe {
                            buf.advance_mut(res as _);
                        }

                        if let Some(sender) = maybe_sender.take() {
                            let sender = sender.send(buf);
                            maybe_sender.replace(sender.reserve_owned().await?);
                        } else {
                            panic!("inflight rx state with no sender!");
                        };
                    } else if res != -libc::EAGAIN {
                        metrics::tun_iouring_rx_err();
                    };

                    rx_slots.push(slot);
                }
                SlotIdx::Tx(_) => {
                    if res <= 0 {
                        tracing::info!("rx slot {slot:?} completed with {res}");
                    }
                    // handle tx complete, we just need to drop the buffer
                    // SAFETY: By construction instances of SlotIdx are always in bounds.
                    #[allow(unsafe_code)]
                    unsafe {
                        *tx_bufs.get_unchecked_mut(slot.idx()) = None
                    };
                    tx_slots.push(slot);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(SlotIdx::Tx(0) => 0x0000_0000_0000_0000)]
    #[test_case(SlotIdx::Tx(10) => 0x0000_0000_0000_000a)]
    #[test_case(SlotIdx::Tx(isize::MAX) => 0x7fff_ffff_ffff_ffff)]
    #[test_case(SlotIdx::Rx(0) => 0x0000_0000_0000_0000)]
    #[test_case(SlotIdx::Rx(10) => 0x0000_0000_0000_000a)]
    #[test_case(SlotIdx::Rx(isize::MAX) => 0x7fff_ffff_ffff_ffff)]
    fn slotid_idx(id: SlotIdx) -> usize {
        id.idx()
    }

    #[test_case(SlotIdx::Tx(0) => 0x0000_0000_0000_0000)]
    #[test_case(SlotIdx::Tx(10) => 0x0000_0000_0000_000a)]
    #[test_case(SlotIdx::Tx(isize::MAX) => 0x7fff_ffff_ffff_ffff)]
    #[test_case(SlotIdx::Rx(0) => 0xffff_ffff_ffff_ffff)]
    #[test_case(SlotIdx::Rx(10) => 0xffff_ffff_ffff_fff5)]
    #[test_case(SlotIdx::Rx(isize::MAX) => 0x8000_0000_0000_0000)]
    fn slotid_user_data(id: SlotIdx) -> u64 {
        id.user_data()
    }

    #[test_case(0x0000_0000_0000_0000 => matches SlotIdx::Tx(0))]
    #[test_case(0x0000_0000_0000_000a => matches SlotIdx::Tx(10))]
    #[test_case(0x7fff_ffff_ffff_ffff => matches SlotIdx::Tx(isize::MAX))]
    #[test_case(0xffff_ffff_ffff_ffff => matches SlotIdx::Rx(0))]
    #[test_case(0xffff_ffff_ffff_fff5 => matches SlotIdx::Rx(10))]
    #[test_case(0x8000_0000_0000_0000 => matches SlotIdx::Rx(isize::MAX))]
    fn slotid_from(u: u64) -> SlotIdx {
        SlotIdx::from_user_data(u)
    }
}
