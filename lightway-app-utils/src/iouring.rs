use crate::metrics;
use anyhow::{Context, Result};
use bytes::BytesMut;
use io_uring::{IoUring, opcode, squeue::PushError, types};
use libc::iovec;
use lightway_core::IOCallbackResult;
use parking_lot::Mutex;
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::sync::Notify;

// -------------------------------------------------------------
// -      IMPLEMENT read-multishot and RUNTIME variations      -
// -------------------------------------------------------------

// NOTE: temp until this is merged: https://github.com/tokio-rs/io-uring/pull/317

use io_uring::squeue::Entry;

pub const IORING_OP_READ_MULTISHOT: u8 = 49;

#[repr(C)]
pub struct CustomSQE {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off_or_addr2: Union1,
    pub addr_or_splice_off_in: Union2,
    pub len: u32,
    pub msg_flags: Union3,
    pub user_data: u64,
    pub buf_index: PackedU16, // Note: this is packed!
    pub personality: u16,
    pub splice_fd: Union5,
    pub __pad2: [u64; 2], // The final union covers 16 bytes
}

#[repr(C)]
pub union Union1 {
    pub off: u64,
    pub addr2: u64,
    pub cmd_op: std::mem::ManuallyDrop<CmdOp>,
}

#[repr(C)]
pub struct CmdOp {
    pub cmd_op: u32,
    pub __pad1: u32,
}

#[repr(C)]
pub union Union2 {
    pub addr: u64,
    pub splice_off_in: u64,
    pub level_optname: std::mem::ManuallyDrop<SockLevel>,
}

#[repr(C)]
pub struct SockLevel {
    pub level: u32,
    pub optname: u32,
}

#[repr(C)]
pub union Union3 {
    pub rw_flags: i32,
    pub fsync_flags: u32,
    pub poll_events: u16,
    pub poll32_events: u32,
    pub sync_range_flags: u32,
    pub msg_flags: u32,
    pub timeout_flags: u32,
    pub accept_flags: u32,
    pub cancel_flags: u32,
    pub open_flags: u32,
    pub statx_flags: u32,
    pub fadvise_advice: u32,
    pub splice_flags: u32,
    pub rename_flags: u32,
    pub unlink_flags: u32,
    pub hardlink_flags: u32,
    pub xattr_flags: u32,
    pub msg_ring_flags: u32,
    pub uring_cmd_flags: u32,
    pub waitid_flags: u32,
    pub futex_flags: u32,
    pub install_fd_flags: u32,
    pub nop_flags: u32,
}

#[repr(C, packed)]
pub struct PackedU16 {
    pub buf_index: u16,
}

#[repr(C)]
pub union Union5 {
    pub splice_fd_in: i32,
    pub file_index: u32,
    pub optlen: u32,
    pub addr_len_stuff: std::mem::ManuallyDrop<AddrLenPad>,
}

#[repr(C)]
pub struct AddrLenPad {
    pub addr_len: u16,
    pub __pad3: [u16; 1],
}

impl Default for CustomSQE {
    fn default() -> Self {
        // Safety: memzero is ok
        #[allow(unsafe_code)]
        unsafe {
            std::mem::zeroed()
        }
    }
}

pub struct ReadMulti {
    fd: i32,
    buf_group: u16,
    flags: i32,
}

impl ReadMulti {
    #[inline]
    pub fn new(fd: i32, buf_group: u16) -> Self {
        ReadMulti {
            fd,
            buf_group,
            flags: 0,
        }
    }

    #[inline]
    pub fn build(self) -> Entry {
        let sqe = CustomSQE {
            opcode: IORING_OP_READ_MULTISHOT as _,
            flags: io_uring::squeue::Flags::BUFFER_SELECT.bits(),
            fd: self.fd,
            buf_index: PackedU16 {
                buf_index: self.buf_group,
            },
            msg_flags: Union3 {
                msg_flags: self.flags as _,
            },
            ..Default::default()
        };

        // Safety: CustomSQE has identical memory layout to io_uring_sqe
        #[allow(unsafe_code)]
        unsafe {
            std::mem::transmute(sqe)
        }
    }
}

// Static for one-time initialization
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static SUPPORTED: AtomicBool = AtomicBool::new(false);

#[cold]
fn initialize_kernel_check() -> bool {
    let supported = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .and_then(|v| {
            let version_numbers = v.split('-').next()?;
            let parts: Vec<_> = version_numbers.split('.').collect();
            if parts.len() >= 2 {
                Some((parts[0].parse::<u32>().ok()?, parts[1].parse::<u32>().ok()?))
            } else {
                None
            }
        })
        .is_some_and(|(major, minor)| major > 6 || (major == 6 && minor >= 7));

    SUPPORTED.store(supported, Ordering::Release);
    INITIALIZED.store(true, Ordering::Release);
    supported
}

#[inline(always)]
pub fn kernel_supports_multishot() -> bool {
    // Fast path - just load if initialized
    if INITIALIZED.load(Ordering::Acquire) {
        SUPPORTED.load(Ordering::Acquire)
    } else {
        // Slow path - do initialization
        initialize_kernel_check()
    }
}

// Safety: SQE operations are always unsafe
/// Inline operation to ensure we queue reads without impacting runtime (multi-kernel)
#[inline(always)]
#[allow(unsafe_code)]
pub unsafe fn queue_reads(
    sq: &mut io_uring::SubmissionQueue<'_>,
    fd: i32,
    n_entries: usize,
    buf_group: u16,
    user_data: u64,
) -> Result<(), PushError> {
    if kernel_supports_multishot() {
        tracing::debug!("Kernel supports - adding MULTISHOT_READ");
        // Safety: Ring is initialized and file descriptor is valid
        unsafe {
            let op = ReadMulti::new(fd, buf_group).build().user_data(user_data);
            sq.push(&op)
        }
    } else {
        tracing::debug!("NO Kernel support - adding {} READ", n_entries);
        let mut ops = Vec::with_capacity(n_entries);
        for _ in 0..n_entries {
            let op = opcode::Read::new(types::Fd(fd), std::ptr::null_mut(), 0)
                .buf_group(buf_group)
                .build()
                .flags(io_uring::squeue::Flags::BUFFER_SELECT)
                .user_data(user_data);
            ops.push(op);
        }
        // Safety: Ring is initialized and file descriptor is valid
        unsafe { sq.push_multiple(&ops) }
    }
}

// -------------------------------------------------------------

#[repr(u64)]
enum IOUringActionID {
    RecycleBuffers = 0x10001000,
    ReceivedBuffer = 0xfeedfeed,
}
const RX_BUFFER_GROUP: u16 = 0xdead;

// Required 32MB for io-uring to function properly
const REQUIRED_RLIMIT_MEMLOCK_MAX: u64 = 32 * 1024 * 1024;

/// A wrapper around a raw pointer that guarantees thread safety through Arc ownership
struct BufferPtr(*mut u8);

#[allow(unsafe_code)]
// Safety: The pointer is owned by Arc<BufferPool> which ensures exclusive access
unsafe impl Send for BufferPtr {}
#[allow(unsafe_code)]
// Safety: The pointer is owned by Arc<BufferPool> which ensures synchronized access
unsafe impl Sync for BufferPtr {}

impl BufferPtr {
    fn as_ptr(&self) -> *mut u8 {
        self.0
    }
}

struct PageAlignedBuffer {
    ptr: *mut u8,
    layout: Layout,
    entry_size: usize,
    num_entries: usize,
}

#[allow(unsafe_code)]
// Safety: The pointer is owned by Arc<BufferPool> which ensures exclusive access
unsafe impl Send for PageAlignedBuffer {}
#[allow(unsafe_code)]
// Safety: The pointer is owned by Arc<BufferPool> which ensures synchronized access
unsafe impl Sync for PageAlignedBuffer {}

impl PageAlignedBuffer {
    fn new(entry_size: usize, num_entries: usize) -> Self {
        #[allow(unsafe_code)]
        // Safety: libc is not safe, variable is fine
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;

        // Round up entry_size to 16-byte alignment first
        let aligned_entry_size = (entry_size + 15) & !15;

        // Calculate how many entries fit in one page
        let entries_per_page = page_size / aligned_entry_size;

        // Calculate total pages needed
        let pages_needed = num_entries.div_ceil(entries_per_page);
        let total_size = pages_needed * page_size;

        let layout = Layout::from_size_align(total_size, page_size).expect("Invalid layout");

        // Safety: allocate per layout selected (no aligned-allocator in rust)
        #[allow(unsafe_code)]
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }

        Self {
            ptr,
            layout,
            entry_size: aligned_entry_size,
            num_entries,
        }
    }

    fn get_ptr(&self, idx: usize) -> *mut u8 {
        assert!(idx < self.num_entries);
        // Safety: asserted size within boundry before
        #[allow(unsafe_code)]
        unsafe {
            self.ptr.add(idx * self.entry_size)
        }
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }
}

impl Drop for PageAlignedBuffer {
    fn drop(&mut self) {
        // Safety: we know what layout we allocated (saved)
        #[allow(unsafe_code)]
        unsafe {
            dealloc(self.ptr, self.layout);
        }
    }
}

/// A pool of buffers with an underlying contiguous memory block
struct BufferPool {
    data: PageAlignedBuffer,
    lengths: Vec<AtomicUsize>,
    states: Vec<AtomicBool>, // 0 (false) = free, 1 (true) = in-use
    usage_idx: AtomicUsize,
}

impl BufferPool {
    fn new(entry_size: usize, pool_size: usize) -> Self {
        Self {
            data: PageAlignedBuffer::new(entry_size, pool_size),
            lengths: (0..pool_size).map(|_| AtomicUsize::new(0)).collect(),
            states: (0..pool_size).map(|_| AtomicBool::new(false)).collect(),
            usage_idx: AtomicUsize::new(0),
        }
    }

    fn get_buffer(&self, idx: usize) -> (BufferPtr, &AtomicUsize, &AtomicBool) {
        (
            BufferPtr(self.data.get_ptr(idx)),
            &self.lengths[idx],
            &self.states[idx],
        )
    }
}

/// IO-uring Struct
pub struct IOUring<T: AsRawFd> {
    owned_fd: Arc<T>,
    rx_pool: Arc<BufferPool>,
    tx_pool: Arc<BufferPool>,
    rx_notify: Arc<Notify>,
    ring: Arc<IoUring>,
    submission_lock: Arc<Mutex<()>>,
}

// Safety: IOUring implementation does direct memory manipulations for performence benifits
#[allow(unsafe_code)]
impl<T: AsRawFd> IOUring<T> {
    /// Create `IOUring` struct
    pub async fn new(
        owned_fd: Arc<T>,
        ring_size: usize,
        _channel_size: usize,
        mtu: usize,
        sqpoll_idle_time: Duration,
    ) -> Result<Self> {
        // NOTE: it's probably a good idea for now to allocate rx/tx/ring at the same size
        //  this is because the VPN use-case usually has MTU-sized buffers going in-and-out

        tracing::debug!(
            "INIT io-uring, estimated memory (user | kernel): {}Mb | {}Mb",
            (2 * (size_of::<BufferPool>() + (mtu * ring_size))) / 1024 / 1024,
            (ring_size * 2 * (16 + (2 * 64)) + 8192) / 1024 / 1024,
        );

        let rx_pool = Arc::new(BufferPool::new(mtu, ring_size));
        let tx_pool = Arc::new(BufferPool::new(mtu, ring_size));

        let ring = Arc::new(
            IoUring::builder()
                .setup_sqpoll(sqpoll_idle_time.as_millis() as u32)
                .build((ring_size * 2) as u32)?,
        );

        let rx_notify = Arc::new(Notify::new());

        // NOTE: for now this ensures we only create 1 kthread per tunnel, and not 2 (rx/tx)
        //  we can opt to change this going forward, or redo the structure to not need a lock
        let submission_lock = Arc::new(Mutex::new(()));

        // We can provide the buffers without a lock, as we still havn't shared the ownership
        let fd = owned_fd.as_raw_fd();

        // Scope submission-queue operations to avoid borrowing ring
        {
            // Safety: Ring submission can be used without locks at this point
            let mut sq = unsafe { ring.submission_shared() };

            tracing::debug!("Sending PROVIDE_BUFFERS");
            // Safety: Buffer memory is owned by rx_pool and outlives the usage
            unsafe {
                sq.push(
                    &opcode::ProvideBuffers::new(
                        rx_pool.data.as_ptr(),
                        mtu as i32,
                        ring_size as u16,
                        RX_BUFFER_GROUP,
                        0,
                    )
                    .build()
                    .user_data(IOUringActionID::RecycleBuffers as u64),
                )?
            };

            // Safety: Ring is initialized and file descriptor is valid
            unsafe {
                queue_reads(
                    &mut sq,
                    fd,
                    ring_size,
                    RX_BUFFER_GROUP,
                    IOUringActionID::ReceivedBuffer as _,
                )?
            };
        }

        let tx_iovecs: Vec<_> = (0..ring_size)
            .map(|idx| {
                let (ptr, _, _) = tx_pool.get_buffer(idx);
                iovec {
                    iov_base: ptr.as_ptr() as *mut libc::c_void,
                    iov_len: mtu,
                }
            })
            .collect();

        // Safety: memory for libc calls
        let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
        // Safety: fetch memory limitations defined
        unsafe {
            libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim);
        }

        // Check memory usage needed
        if rlim.rlim_max < REQUIRED_RLIMIT_MEMLOCK_MAX {
            tracing::info!("RLIMIT too low ({}), adjusting", rlim.rlim_max);
            rlim.rlim_max = REQUIRED_RLIMIT_MEMLOCK_MAX;
            // Safety: rlimit API requires unsafe block
            if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
                tracing::warn!(
                    "Failed to set RLIMIT_MEMLOCK: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        // Safety: tx_iovecs point to valid memory owned by tx_pool
        unsafe { ring.submitter().register_buffers(&tx_iovecs)? };
        ring.submitter()
            .register_files(&[fd])
            .expect("io-uring support");

        let config = IOUringTaskConfig {
            rx_pool: rx_pool.clone(),
            tx_pool: tx_pool.clone(),
            rx_notify: rx_notify.clone(),
            ring: ring.clone(),
        };

        // NOTE: currently we don't implement any Drop for class, it will require changes
        //  so until then, we can also ignore the need to close the FDs in rx_eventfd and owned_fd
        thread::Builder::new()
            .name("io_uring-main".to_string())
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                    .expect("Failed building Tokio Runtime")
                    .block_on(iouring_task(config))
            })
            .context("io_uring-task")?;

        Ok(Self {
            owned_fd,
            rx_pool,
            tx_pool,
            rx_notify,
            ring,
            submission_lock,
        })
    }

    /// Retrieve a reference to the underlying device
    pub fn owned_fd(&self) -> &T {
        &self.owned_fd
    }

    /// Send packet on Tun device (push to RING and submit)
    pub fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        tracing::debug!("try_send {} bytes", buf.len());
        // For semantics, see recv() function below
        let idx = self
            .tx_pool
            .usage_idx
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |idx| {
                Some((idx + 1) % self.rx_pool.states.len())
            })
            .unwrap();
        let (buffer, length, state) = self.tx_pool.get_buffer(idx);

        let len = buf.len();
        if len > self.tx_pool.data.entry_size {
            tracing::warn!(
                "We dont support buffer-splitting for now (max: {}, got: {})",
                self.tx_pool.data.entry_size,
                len
            );
            return IOCallbackResult::WouldBlock;
        }

        // Check if buffer is free (state = 0)
        if state
            .compare_exchange(
                false,
                true, // free -> in-use
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            // Out of buffers, need kernel to work faster
            // consider a bigger queue if we see this counter
            metrics::tun_iouring_tx_err();
            return IOCallbackResult::WouldBlock;
        }

        // Safety: Buffer is allocated with sufficient size and ownership is checked via state
        unsafe { std::slice::from_raw_parts_mut(buffer.as_ptr(), len).copy_from_slice(&buf) };
        length.store(len, Ordering::Release);

        // NOTE: IOUringActionID values have to be bigger then the ring-size
        //  this is because we use <index> here as data for send_fixed operations
        let write_op =
            opcode::WriteFixed::new(types::Fixed(0), buffer.as_ptr(), len as _, idx as _)
                .build()
                .user_data(idx as u64);

        tracing::debug!("queuing WRITE_FIXED on buf-id {}", idx);

        // Safely queue submission
        {
            let _guard = self.submission_lock.lock();
            // Safety: protected by lock above
            let mut sq = unsafe { self.ring.submission_shared() };
            // Safety: entry uses buffers from tx_pool which outlive task using them
            unsafe {
                // let res = libc::write(
                //     self.owned_fd.as_raw_fd(),
                //     buffer.as_ptr() as *const libc::c_void,
                //     len,
                // );
                // tracing::debug!("write (sync) results: {}", res);
                // if res > 0 {
                //     return IOCallbackResult::Ok(res as usize);
                // }

                // let err = std::io::Error::last_os_error();
                // tracing::error!("write faild: {}", err);
                // IOCallbackResult::Err(err)

                match sq.push(&write_op) {
                    Ok(_) => IOCallbackResult::Ok(len),
                    Err(_) => {
                        tracing::warn!("Failed to queue send");
                        metrics::tun_iouring_tx_err();
                        IOCallbackResult::WouldBlock
                    }
                }
            }
        }
    }

    /// Receive packet from Tun device
    pub async fn recv(&self) -> IOCallbackResult<BytesMut> {
        // NOTE: Explanation on why these semantics were used:
        // Flow:
        // 1. The current value is loaded
        // 2. Our closure is called with that value
        // 3. A compare-and-swap (CAS) operation attempts to update with our new value
        //
        // The calculation of (X+1 % len) happens INSIDE closure, after the load but before the CAS.
        // So if multiple threads are running concurrently:
        // - Thread A loads value X
        // - Thread B loads value X (before A's CAS completes)
        // - Both calculate X+1 % len
        // - We need AqcRel to ensure threads don't set values on top of each-other.
        // - First thread's CAS should succeed as no value changed
        // - Second thread's CAS should fail because the value changed
        // - Second thread would retry, so we need Acquire on fetch to see Thread A's value
        let idx = self
            .rx_pool
            .usage_idx
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |idx| {
                Some((idx + 1) % self.rx_pool.states.len())
            })
            .unwrap();
        let (buffer, length, state) = self.rx_pool.get_buffer(idx);

        tracing::debug!("recv blocking until buf-id {} is available", idx);
        loop {
            // NOTE: unlike the above case, here we can use Relaxed ordering for better performance.
            // This is because we don't use the value in a closure, so we don't care for ensuring it's current value
            if state
                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // Last buffer - need to reload
                // NOTE: this is why io_uring is not really practical in a lot of use-cases...
                if idx + 1 == self.rx_pool.data.num_entries {
                    let _guard = self.submission_lock.lock();
                    // Safety: protected by lock above
                    let mut sq = unsafe { self.ring.submission_shared() };
                    let rx_ring_size = self.rx_pool.states.len();
                    // Safety: buffers are mapped from rx_pool which outlives this task
                    unsafe {
                        sq.push(
                            &opcode::ProvideBuffers::new(
                                self.rx_pool.data.as_ptr(),
                                rx_ring_size as i32,
                                self.rx_pool.states.len() as u16,
                                RX_BUFFER_GROUP,
                                0,
                            )
                            .build()
                            .user_data(IOUringActionID::RecycleBuffers as u64),
                        )
                        .expect("iouring queue should work")
                    };
                    // Safety: buffer-group originates from rx_pool which outlives this task
                    unsafe {
                        queue_reads(
                            &mut sq,
                            self.owned_fd.as_raw_fd(),
                            rx_ring_size,
                            RX_BUFFER_GROUP,
                            IOUringActionID::ReceivedBuffer as _,
                        )
                        .expect("iouring queue should work")
                    };
                }

                let len = length.load(Ordering::Acquire);
                let mut new_buf = BytesMut::with_capacity(len);

                tracing::debug!("recv, got {} bytes", len);

                // Safety: Buffer is allocated with sufficient size and ownership is checked via state
                unsafe {
                    new_buf.extend_from_slice(std::slice::from_raw_parts(buffer.as_ptr(), len))
                };
                return IOCallbackResult::Ok(new_buf);
            }
            // IO-Bound wait for available buffers
            self.rx_notify.notified().await;
        }
    }
}

/// Task variables
struct IOUringTaskConfig {
    rx_pool: Arc<BufferPool>,
    tx_pool: Arc<BufferPool>,
    rx_notify: Arc<Notify>,
    ring: Arc<IoUring>,
}

// Safety: To manage ring completion and results effeciantly requires direct memory manipulations
#[allow(unsafe_code)]
async fn iouring_task(config: IOUringTaskConfig) -> Result<()> {
    tracing::debug!("Started iouring_task");

    loop {
        // Work once we have at least 1 task to perform
        config.ring.submit_and_wait(1)?;

        tracing::debug!("iotask woke up");

        // Safety: only task is using the completion-queue (concept should not change)
        for cqe in unsafe { config.ring.completion_shared() } {
            match cqe.user_data() {
                x if x == IOUringActionID::RecycleBuffers as u64 => {
                    // Buffer provision completed
                    tracing::debug!("Buffer provision completed");
                }

                x if x == IOUringActionID::ReceivedBuffer as u64 => {
                    let result = cqe.result();
                    if result < 0 {
                        tracing::error!(
                            "Receive failed: {}",
                            std::io::Error::from_raw_os_error(-result)
                        );
                        metrics::tun_iouring_rx_err();
                        continue;
                    }

                    let buf_id = io_uring::cqueue::buffer_select(cqe.flags()).unwrap();
                    let (_, length, state) = config.rx_pool.get_buffer(buf_id as _);

                    tracing::debug!("recv {} bytes, saving to buf-id {}", result, buf_id);

                    length.store(result as usize, Ordering::Release);
                    state.store(true, Ordering::Release); // Mark as ready-for-user
                    config.rx_notify.notify_waiters();

                    // TODO: consider below implementation in the future
                    //  issue with this is that we have to gurentee no in-flight buffers !
                    //  see the comment under `recv` function, we can consider a buffer migration.
                    // NOTE: Here if we use new kernels we can auto-opt for multishot via:
                    //  if !io_uring::cqueue::more(cqe.flags()) {
                    //      let opt = ReadMulti::new(fd, buf_group).build().user_data(IOUringActionID::ReceivedBuffer);
                    //      unsafe { sq.push(&opt) };
                    //  }
                }

                idx => {
                    // TX completion
                    let result = cqe.result();
                    if result < 0 {
                        tracing::error!(
                            "Send failed: {}",
                            std::io::Error::from_raw_os_error(-result)
                        );
                        metrics::tun_iouring_tx_err();
                    }
                    tracing::debug!("sent {} bytes from buf-id {}", result, idx);
                    let (_, _, state) = config.tx_pool.get_buffer(idx as _);
                    state.store(false, Ordering::Release); // mark as available for send
                }
            }
        }
    }
}
