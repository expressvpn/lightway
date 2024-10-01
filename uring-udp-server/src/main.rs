#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::undocumented_unsafe_blocks)]

use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap, VecDeque},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    os::fd::AsRawFd,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Context, Result};
use arrayvec::ArrayVec;
use bytes::BytesMut;
use io_uring::{
    cqueue::Entry as CEntry,
    opcode,
    squeue::{/*self,*/ Entry as SEntry},
    types::Fixed,
    IoUring, SubmissionQueue, Submitter,
};
use lightway_core::{
    ipv4_update_destination, ipv4_update_source, ConnectionType, EventCallback, IOCallbackResult,
    InsideIOSendCallback, InsideIpConfig, OutsideIOSendCallback, OutsidePacket, Secret, ServerAuth,
    ServerAuthResult, ServerContextBuilder, ServerIpPool,
};
use pnet::packet::ipv4::Ipv4Packet;
use sync_unsafe_cell::SyncUnsafeCell;

const REGISTERED_OUTSIDE_FD_INDEX: u32 = 0;
const REGISTERED_INSIDE_FD_INDEX: u32 = 1;
const IOURING_SQPOLL_IDLE_TIME: u32 = 100;

const RING_SIZE: u32 = 1024;
const TX_SLOTS: usize = 512;
const INSIDE_RX_SLOTS: usize = 8;
const OUTSIDE_RX_SLOTS: usize = 8;

const BIND_ADDR: &str = "0.0.0.0:27690";
const MAX_OUTSIDE_MTU: usize = 1500;
const MAX_INSIDE_MTU: usize = 1350;

const CONN_ASSIGNED_IP: Ipv4Addr = Ipv4Addr::new(10, 125, 0, 42);

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 10, 1);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 10, 2);
const DNS_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 10, 5);

const SOCKET_BUFFER_SIZE: usize = 15 * 1024 * 1024;

const OUTSIDE_RECV_SLOT: u64 = u64::MAX;
const INSIDE_READ_SLOT: u64 = u64::MAX - (OUTSIDE_RX_SLOTS as u64);

enum TxBuf {
    Empty,
    #[allow(dead_code, reason = "Read is in uring/FFI")]
    Inside(BytesMut),
    #[allow(dead_code, reason = "Read is in uring/FFI")]
    Outside(Vec<u8>),
}

struct TxRing {
    sqe_ring: VecDeque<SEntry>,
    slots: ArrayVec<usize, TX_SLOTS>,
    state: ArrayVec<TxSlotState, TX_SLOTS>,
}

impl TxRing {
    fn new() -> Self {
        let sqe_ring = VecDeque::with_capacity(TX_SLOTS);
        let slots: ArrayVec<usize, TX_SLOTS> = (0..TX_SLOTS).collect();
        let state: ArrayVec<_, TX_SLOTS> = slots.iter().map(|_| TxSlotState::new()).collect();

        Self {
            sqe_ring,
            slots,
            state,
        }
    }
}

struct TxSlotState {
    buf: TxBuf,
    addr: libc::sockaddr_in,
    iov: [libc::iovec; 1],
    msghdr: libc::msghdr,
}

unsafe impl Sync for TxSlotState {}
unsafe impl Send for TxSlotState {}

impl TxSlotState {
    fn new() -> Self {
        Self {
            buf: TxBuf::Empty,
            addr: unsafe { std::mem::zeroed() },
            iov: [unsafe { std::mem::zeroed() }],
            msghdr: unsafe { std::mem::zeroed() },
        }
    }
}

struct RxState {
    buf: BytesMut,
    addr: libc::sockaddr_in,
    iov: [libc::iovec; 1],
}

impl RxState {
    fn new() -> Self {
        let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
        let iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.capacity(),
        };
        Self {
            buf,
            addr: unsafe { std::mem::zeroed() },
            iov: [iov],
        }
    }
}

struct State {
    socket_addr: SocketAddrV4,
}

type Connection = lightway_core::Connection<State>;

struct EventHandler;

impl EventCallback for EventHandler {
    fn event(&self, event: lightway_core::Event) {
        tracing::info!(?event, "event");
    }
}

struct Auth;

impl ServerAuth<State> for Auth {
    fn authorize_user_password(
        &self,
        _user: &str,
        _password: &str,
        _app_state: &mut State,
    ) -> lightway_core::ServerAuthResult {
        ServerAuthResult::Granted {
            handle: None,
            tunnel_protocol_version: None,
        }
    }
}

// Static allocator which remembers most recent connection.
struct IpManager(Mutex<Option<SocketAddrV4>>);

impl ServerIpPool<State> for IpManager {
    fn alloc(&self, state: &mut State) -> Option<InsideIpConfig> {
        self.0.lock().unwrap().replace(state.socket_addr);
        Some(InsideIpConfig {
            client_ip: CLIENT_IP,
            server_ip: SERVER_IP,
            dns_ip: DNS_IP,
        })
    }

    fn free(&self, _state: &mut State) {
        todo!()
    }
}

struct InsideIO(Arc<SyncUnsafeCell<TxRing>>);

impl InsideIOSendCallback<State> for InsideIO {
    fn send(&self, mut buf: BytesMut, _state: &mut State) -> IOCallbackResult<usize> {
        let len = buf.len();
        // println!("push inside send of {len} bytes");
        let tx_ring = unsafe { &mut *self.0.get() };
        let Some(slot) = tx_ring.slots.pop() else {
            return IOCallbackResult::WouldBlock;
        };

        ipv4_update_source(buf.as_mut(), CONN_ASSIGNED_IP);

        let state = unsafe { tx_ring.state.get_unchecked_mut(slot) };

        let sqe = opcode::Write::new(
            Fixed(REGISTERED_INSIDE_FD_INDEX),
            buf.as_mut_ptr() as *mut _,
            buf.len() as _,
        )
        .build()
        // .flags(squeue::Flags::ASYNC)
        .user_data(slot as u64);

        state.buf = TxBuf::Inside(buf);

        tx_ring.sqe_ring.push_back(sqe);
        IOCallbackResult::Ok(len)
    }

    fn mtu(&self) -> usize {
        1350
    }
}

struct OutsideIO(Arc<SyncUnsafeCell<TxRing>>, libc::sockaddr_in);

impl OutsideIOSendCallback for OutsideIO {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        let mut buf = buf.to_vec();
        let len = buf.len();
        // println!("push outside send of {len} bytes");
        let tx_ring = unsafe { &mut *self.0.get() };
        if tx_ring.sqe_ring.len() == tx_ring.sqe_ring.capacity() {
            println!("Failed to push outside tx to ring");
            IOCallbackResult::WouldBlock
        } else {
            let Some(slot) = tx_ring.slots.pop() else {
                panic!("out of send slots");
            };

            let state = unsafe { tx_ring.state.get_unchecked_mut(slot) };

            state.iov[0].iov_base = buf.as_mut_ptr() as *mut _;
            state.iov[0].iov_len = buf.len();
            state.addr = self.1;

            state.buf = TxBuf::Outside(buf);

            state.msghdr.msg_name = &mut state.addr as *mut libc::sockaddr_in as *mut _;
            state.msghdr.msg_namelen = std::mem::size_of_val(&state.addr) as _;
            state.msghdr.msg_iov = &mut state.iov as *mut _;
            state.msghdr.msg_iovlen = state.iov.len();

            let sqe = opcode::SendMsg::new(
                Fixed(REGISTERED_OUTSIDE_FD_INDEX),
                &mut state.msghdr as *const _,
            )
            .build()
            .user_data(slot as u64);

            tx_ring.sqe_ring.push_back(sqe);

            IOCallbackResult::Ok(len)
        }
    }

    fn peer_addr(&self) -> std::net::SocketAddr {
        todo!()
    }
}

fn drain_tx_queue(
    ring: &Arc<SyncUnsafeCell<TxRing>>,
    submitter: &Submitter,
    sq: &mut SubmissionQueue,
) -> Result<()> {
    let ring = unsafe { &mut *ring.get() };

    for sqe in ring.sqe_ring.drain(..) {
        if sq.is_full() {
            println!("drain_tx_queue: sq is full");
            match submitter.submit() {
                Ok(_) => (),
                Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => break,
                Err(err) => return Err(err.into()),
            }
        }
        sq.sync();

        unsafe { sq.push(&sqe)? }

        sq.sync();
    }

    Ok(())
}

fn main() -> Result<()> {
    // lightway_core::enable_tls_debug();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let mut connections = HashMap::<SocketAddrV4, Connection>::new();

    let server_cert = Secret::PemBuffer(include_bytes!("../../tests/certs/server.crt"));
    let server_key = Secret::PemBuffer(include_bytes!("../../tests/certs/server.key"));

    let tx_ring = Arc::new(SyncUnsafeCell::new(TxRing::new()));

    let auth = Arc::new(Auth);
    let ip_manager = Arc::new(IpManager(Mutex::new(None)));
    let inside_io = Arc::new(InsideIO(tx_ring.clone()));

    let server = ServerContextBuilder::new(
        ConnectionType::Datagram,
        server_cert,
        server_key,
        auth,
        ip_manager.clone(),
        inside_io,
    )?
    .with_pq_crypto()?
    .build()?;

    let sock = UdpSocket::bind(BIND_ADDR)?;

    let socket = socket2::SockRef::from(&sock);
    socket.set_send_buffer_size(SOCKET_BUFFER_SIZE)?;
    socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE)?;

    let mut tun_config = tun2::Configuration::default();
    tun_config.tun_name(std::env::var("TUN_NAME").unwrap_or_else(|_| "lightway".to_string()));
    let tun = tun2::create(&tun_config)?;
    tun.set_nonblock()?;

    let mut ring: IoUring<SEntry, CEntry> = IoUring::builder()
        .dontfork()
        // This setting makes CPU go 100% when there is continuous traffic
        .setup_sqpoll(IOURING_SQPOLL_IDLE_TIME) // Needs 5.13
        .build(RING_SIZE)?;

    let (submitter, mut sq, mut cq) = ring.split();

    // let mut max_ioworkers = [0, 8];
    // submitter.register_iowq_max_workers(&mut max_ioworkers)?;
    submitter.register_files(&[sock.as_raw_fd(), tun.as_raw_fd()])?;

    let mut outside_recv_state: ArrayVec<_, OUTSIDE_RX_SLOTS> =
        (0..OUTSIDE_RX_SLOTS).map(|_| RxState::new()).collect();
    let mut outside_recv_msghdr: ArrayVec<libc::msghdr, OUTSIDE_RX_SLOTS> = outside_recv_state
        .iter_mut()
        .map(|s| libc::msghdr {
            msg_name: &mut s.addr as *mut libc::sockaddr_in as *mut _,
            msg_namelen: std::mem::size_of::<libc::sockaddr_in>() as _,
            msg_iov: &mut s.iov as *mut _,
            msg_iovlen: s.iov.len(),
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        })
        .collect();

    for (slot, msghdr) in outside_recv_msghdr.iter_mut().enumerate() {
        // let state = &mut outside_recv_state[slot];
        // println!(
        //     "OutsideRecv> {} {:?} {:x} ({:?})",
        //     slot,
        //     state.buf.as_ptr(),
        //     OUTSIDE_RECV_SLOT - slot as u64,
        //     unsafe { (*msghdr.msg_iov).iov_base },
        // );

        let sqe = opcode::RecvMsg::new(Fixed(REGISTERED_OUTSIDE_FD_INDEX), msghdr as *mut _)
            .build()
            //.flags(squeue::Flags::ASYNC)
            .user_data(OUTSIDE_RECV_SLOT - slot as u64);
        unsafe { sq.push(&sqe)? }
    }

    let mut inside_read_bufs: ArrayVec<_, INSIDE_RX_SLOTS> = (0..INSIDE_RX_SLOTS)
        .map(|_| BytesMut::with_capacity(MAX_INSIDE_MTU))
        .collect();

    for (slot, buf) in inside_read_bufs.iter_mut().enumerate() {
        // println!(
        //     "InsideRead> {} {:?} {:x}",
        //     slot,
        //     buf.as_mut_ptr(),
        //     INSIDE_READ_SLOT - slot as u64
        // );
        let sqe = opcode::Read::new(
            Fixed(REGISTERED_INSIDE_FD_INDEX),
            buf.as_mut_ptr() as *mut _,
            buf.capacity() as _,
        )
        .build()
        // .flags(squeue::Flags::ASYNC)
        .user_data(INSIDE_READ_SLOT - slot as u64);
        unsafe { sq.push(&sqe)? }
    }

    sq.sync();

    #[derive(Debug, Default)]
    struct Stats {
        total_completions: usize,

        total_inside_read_completions: usize,
        ok_inside_read_completions: usize,
        eagain_inside_read_completions: usize,

        total_outside_recv_completions: usize,
        ok_outside_recv_completions: usize,
        eagain_outside_recv_completions: usize,

        total_tx_completions: usize,
    }

    let mut stats = Stats::default();

    let mut last_stats = std::time::Instant::now();
    println!("Listening to {BIND_ADDR}");
    // let mut cqe_count = 0;
    loop {
        if last_stats.elapsed().as_secs() > 5 {
            println!("{stats:#?}");
            last_stats = std::time::Instant::now();
        }

        let _nr = submitter.submit_and_wait(1)?;
        cq.sync();

        stats.total_completions += cq.len();

        for cqe in &mut cq {
            let res = cqe.result();

            match cqe.user_data() {
                user_data
                    if (INSIDE_READ_SLOT - (INSIDE_RX_SLOTS as u64)..=INSIDE_READ_SLOT)
                        .contains(&user_data) =>
                {
                    stats.total_inside_read_completions += 1;
                    let slot = (INSIDE_READ_SLOT - user_data) as usize;
                    let buf = unsafe { inside_read_bufs.get_unchecked_mut(slot) };
                    // println!("inside read {res}");

                    // submitter.submit()?;

                    // println!(
                    //     "InsideRead< {} {:?} {:x}",
                    //     slot,
                    //     buf.as_mut_ptr(),
                    //     user_data
                    // );

                    // println!(
                    //     "InsideRead> {} {:?} {:x}",
                    //     slot,
                    //     state.as_mut_ptr(),
                    //     INSIDE_READ_SLOT - slot as u64
                    // );

                    if res == -libc::EAGAIN {
                        // println!("inside rx got EAGAIN");
                        stats.eagain_inside_read_completions += 1;
                    } else if res <= 0 {
                        println!("inside rx got err {res}");
                    } else {
                        stats.ok_inside_read_completions += 1;

                        // println!("inside rx got {res} byte packet");
                        unsafe {
                            buf.set_len(res as usize);
                        }

                        let Some(packet) = Ipv4Packet::new(buf) else {
                            println!("Invalid inside packet size (less than Ipv4 header)!");
                            continue;
                        };

                        if packet.get_destination() != CONN_ASSIGNED_IP {
                            println!("Invalid inside packet not for us!");
                            continue;
                        }

                        let Some(last_ip_alloc) = *ip_manager.0.lock().unwrap() else {
                            println!("Invalid inside packet no IP assigned to connection");
                            continue;
                        };
                        let Some(conn) = connections.get_mut(&last_ip_alloc) else {
                            println!("Invalid inside packet no  connection");
                            continue;
                        };

                        ipv4_update_destination(buf, CLIENT_IP);

                        // Update TUN device DNS IP address to server provided DNS address
                        // let packet = Ipv4Packet::new(buf.as_ref());
                        // if let Some(packet) = packet {
                        //     if packet.get_destination() == tun_dns_ip {
                        //         ipv4_update_destination(buf.as_mut(), ip_config.dns_ip);
                        //     }
                        // };

                        conn.inside_data_received(buf)?;

                        // Recover full capacity
                        buf.clear();
                        buf.reserve(MAX_INSIDE_MTU);
                    };

                    let sqe = opcode::Read::new(
                        Fixed(REGISTERED_INSIDE_FD_INDEX),
                        buf.as_mut_ptr() as *mut _,
                        buf.capacity() as _,
                    )
                    .build()
                    // .flags(squeue::Flags::ASYNC)
                    .user_data(user_data);
                    unsafe { sq.push(&sqe)? }

                    sq.sync();
                }
                user_data
                    if (OUTSIDE_RECV_SLOT - (OUTSIDE_RX_SLOTS as u64)..=OUTSIDE_RECV_SLOT)
                        .contains(&user_data) =>
                {
                    stats.total_outside_recv_completions += 1;
                    let slot = (OUTSIDE_RECV_SLOT - user_data) as usize;

                    let state = unsafe { outside_recv_state.get_unchecked_mut(slot) };
                    let msghdr = unsafe { outside_recv_msghdr.get_unchecked_mut(slot) };

                    // submitter.submit()?;

                    // println!(
                    //     "OutsideRecv< {} {:?} {:x}",
                    //     slot,
                    //     buf.as_mut_ptr(),
                    //     user_data
                    // );

                    // println!(
                    //     "OutsideRecv> {} {:?} {:x} ({:?})",
                    //     slot,
                    //     state.buf.as_mut_ptr(),
                    //     user_data,
                    //     unsafe { (*msghdr.msg_iov).iov_base },
                    // );

                    if res == -libc::EAGAIN {
                        // println!("outside rx got EGAIN");
                        stats.eagain_outside_recv_completions += 1;
                    } else if res <= 0 {
                        println!("outside rx got err {res}");
                    } else {
                        let buf = &mut state.buf;
                        let peer_sockaddr = state.addr;
                        let ip = u32::from_be(peer_sockaddr.sin_addr.s_addr);
                        let ip = Ipv4Addr::from_bits(ip);
                        let port = u16::from_be(peer_sockaddr.sin_port);
                        let addr = SocketAddrV4::new(ip, port);

                        stats.ok_outside_recv_completions += 1;

                        // println!("outside rx got {res} byte packet");
                        unsafe {
                            buf.set_len(res as usize);
                        }

                        let pkt = OutsidePacket::Wire(buf, ConnectionType::Datagram);
                        let pkt = match server.parse_raw_outside_packet(pkt) {
                            Ok(hdr) => hdr,
                            Err(e) => {
                                return Err(e).with_context(|| {
                                    "Extracting header from packet failed".to_string()
                                });
                            }
                        };

                        let Some(hdr) = pkt.header() else {
                            return Err(anyhow!("Packet parsing error: Not a UDP frame"));
                        };

                        let conn = match connections.entry(addr) {
                            HashMapEntry::Occupied(e) => e.into_mut(),
                            HashMapEntry::Vacant(e) => {
                                println!("New connection from {addr:?}");
                                println!("outside_recv_addr = {:?}", peer_sockaddr);
                                let outside_io =
                                    Arc::new(OutsideIO(tx_ring.clone(), peer_sockaddr));
                                let conn = server
                                    .start_accept(hdr.version, outside_io)?
                                    .with_event_cb(Box::new(EventHandler))
                                    .accept(State { socket_addr: addr })?;
                                e.insert(conn)
                            }
                        };
                        conn.outside_data_received(pkt)?;

                        // Recover full capacity
                        buf.clear();
                        buf.reserve(MAX_OUTSIDE_MTU);
                    }

                    let sqe =
                        opcode::RecvMsg::new(Fixed(REGISTERED_OUTSIDE_FD_INDEX), msghdr as *mut _)
                            .build()
                            //.flags(squeue::Flags::ASYNC)
                            .user_data(user_data);
                    unsafe { sq.push(&sqe)? }

                    sq.sync();
                }
                user_data if (0..TX_SLOTS).contains(&(user_data as usize)) => {
                    // println!("tx slot {user_data:x} complete");
                    stats.total_tx_completions += 1;
                    let slot = user_data as usize;
                    let state = unsafe { &mut *tx_ring.get() };
                    let tx_state = unsafe { state.state.get_unchecked_mut(slot) };

                    tx_state.buf = TxBuf::Empty;
                    state.slots.push(slot);
                }

                user_data => {
                    println!("unknown user data {user_data:x}");
                }
            };

            drain_tx_queue(&tx_ring, &submitter, &mut sq)?;
        }
    }

    // Ok(())
}
