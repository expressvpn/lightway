//! UdpServer UringIoSource
//!
//! Uses uring indexes:
//!
//! Loop::outside_rx_user_data:
//!  - 0..UdpServer::rx.len(): A set of recv requests
//!
//! Loop::outside_tx_user_data:
//!  - Managed by TxQueue

pub(crate) mod cmsg;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::{AsRawFd as _, RawFd},
    sync::{Arc, Mutex, MutexGuard, RwLock},
};

use anyhow::{Context as _, Result};
use bytes::{Bytes, BytesMut};
use bytesize::ByteSize;
use io_uring::opcode;
use lightway_app_utils::{
    sockaddr_from_socket_addr, socket_addr_from_sockaddr, sockopt::socket_enable_pktinfo,
};
use lightway_core::{
    ConnectionType, CowBytes, Header, IOCallbackResult, OutsideIOSendCallback, OutsidePacket,
    SessionId, Version, MAX_OUTSIDE_MTU,
};
use tracing::warn;

use crate::{connection_manager::ConnectionManager, metrics};

use super::{io_uring_res, iovec, msghdr, Loop, TxQueue, UringIoSource};

enum BindMode {
    UnspecifiedAddress { local_port: u16 },
    SpecificAddress { local_addr: SocketAddr },
}

impl BindMode {
    fn needs_pktinfo(&self) -> bool {
        matches!(self, BindMode::UnspecifiedAddress { .. })
    }
}

impl std::fmt::Display for BindMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindMode::UnspecifiedAddress { local_port } => {
                write!(f, "port {local_port}")
            }
            BindMode::SpecificAddress { local_addr } => local_addr.fmt(f),
        }
    }
}

fn queue_tx(
    mut tx_queue: MutexGuard<TxQueue>,
    buf: Bytes,
    peer_addr: libc::sockaddr_storage,
    peer_addr_len: libc::socklen_t,
    pktinfo: Option<libc::in_pktinfo>,
) -> IOCallbackResult<usize> {
    let len = buf.len();

    let Some((slot, state)) = tx_queue.take_slot() else {
        return IOCallbackResult::WouldBlock;
    };

    state.iov[0].iov_base = buf.as_ptr() as *mut _;
    state.iov[0].iov_len = buf.len();
    state.addr = peer_addr;
    state.addr_len = peer_addr_len;

    state.buf = Some(buf);

    state.msghdr.msg_name = &mut state.addr as *mut libc::sockaddr_storage as *mut _;
    state.msghdr.msg_namelen = state.addr_len;
    state.msghdr.msg_iov = state.iov.as_mut_ptr() as *mut _;
    state.msghdr.msg_iovlen = state.iov.len();

    if let Some(pktinfo) = pktinfo {
        let mut builder = state.control.builder();
        if let Err(err) = builder.fill_next(libc::SOL_IP, libc::IP_PKTINFO, pktinfo) {
            return IOCallbackResult::Err(err);
        }
        state.msghdr.msg_control = state.control.as_mut_ptr() as *mut _;
        // Get from builder?
        state.msghdr.msg_controllen = std::mem::size_of_val(&state.control) as _;
    } else {
        state.msghdr.msg_control = std::ptr::null_mut();
        state.msghdr.msg_controllen = 0;
    }

    let sqe = opcode::SendMsg::new(Loop::FIXED_OUTSIDE_FD, state.msghdr.as_mut_ptr()).build();

    #[allow(unsafe_code)]
    // SAFETY:
    // - slot was optained from take_slot above
    // - The buffer is owned by `state` and which is owned by the `TxRing`
    unsafe {
        tx_queue.push_outside_slot(slot, sqe)
    };

    IOCallbackResult::Ok(len)
}

struct UdpSocket {
    tx_queue: Arc<Mutex<TxQueue>>,
    peer_addr: RwLock<(SocketAddr, libc::sockaddr_storage, libc::socklen_t)>,
    reply_pktinfo: Option<libc::in_pktinfo>,
}

impl OutsideIOSendCallback for UdpSocket {
    fn send(&self, buf: CowBytes) -> IOCallbackResult<usize> {
        let buf = buf.into_owned();
        let peer_addr = self.peer_addr.read().unwrap();
        let tx_queue = self.tx_queue.lock().unwrap();

        queue_tx(tx_queue, buf, peer_addr.1, peer_addr.2, self.reply_pktinfo)
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr.read().unwrap().0
    }

    fn set_peer_addr(&self, addr: SocketAddr) -> SocketAddr {
        let mut peer_addr = self.peer_addr.write().unwrap();
        let old_addr = peer_addr.0;

        let (raw_addr, raw_addr_len) = sockaddr_from_socket_addr(addr);

        *peer_addr = (addr, raw_addr, raw_addr_len);
        old_addr
    }
}

struct RxState {
    buf: BytesMut,
    addr: libc::sockaddr_storage,
    control: cmsg::Buffer<{ Self::CONTROL_SIZE }>,
    iov: [iovec; 1],
    msghdr: msghdr,
}

impl RxState {
    const CONTROL_SIZE: usize = cmsg::Message::space::<libc::in_pktinfo>();

    fn new() -> Self {
        let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
        let iov = iovec::new(libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.capacity(),
        });
        #[allow(unsafe_code)]
        Self {
            buf,
            // SAFETY: All zeroes is a valid sockaddr
            addr: unsafe { std::mem::zeroed() },
            control: cmsg::Buffer::new(),
            iov: [iov],
            // SAFETY: All zeroes is a valid msghdr
            msghdr: unsafe { std::mem::zeroed() },
        }
    }
}
pub(crate) struct UdpServer {
    conn_manager: Arc<ConnectionManager>,
    sock: Arc<std::net::UdpSocket>,
    bind_mode: BindMode,
    tx_queue: Arc<Mutex<TxQueue>>,
    // The contents are used for I/O syscalls, ensure they stay put.
    rx: Vec<RxState>,
}

impl UdpServer {
    pub(crate) async fn new(
        nr_slots: u32,
        conn_manager: Arc<ConnectionManager>,
        tx_queue: Arc<Mutex<TxQueue>>,
        bind_address: SocketAddr,
        udp_buffer_size: ByteSize,
    ) -> Result<UdpServer> {
        tracing::info!("UdpServer with {nr_slots} slots");

        let sock = tokio::net::UdpSocket::bind(bind_address).await?;

        let sock = sock.into_std()?;
        sock.set_nonblocking(false)?;
        let sock = Arc::new(sock);

        let bind_mode = if bind_address.ip().is_unspecified() {
            BindMode::UnspecifiedAddress {
                local_port: bind_address.port(),
            }
        } else {
            BindMode::SpecificAddress {
                local_addr: bind_address,
            }
        };

        let socket = socket2::SockRef::from(&sock);
        let udp_buffer_size = udp_buffer_size.as_u64().try_into()?;
        socket.set_send_buffer_size(udp_buffer_size)?;
        socket.set_recv_buffer_size(udp_buffer_size)?;

        if bind_mode.needs_pktinfo() {
            socket_enable_pktinfo(&sock)?;
        }

        let rx = (0..nr_slots).map(|_| RxState::new()).collect();

        #[allow(unsafe_code)]
        Ok(Self {
            conn_manager,
            sock,
            bind_mode,
            tx_queue,
            rx,
        })
    }

    fn data_received(
        &mut self,
        peer_addr: SocketAddr,
        raw_peer_addr: libc::sockaddr_storage,
        raw_peer_addr_len: libc::socklen_t,
        local_addr: SocketAddr,
        reply_pktinfo: Option<libc::in_pktinfo>,
        idx: u32,
    ) {
        #[allow(unsafe_code)]
        // SAFETY: The caller must already have validated this.
        let buf = &mut unsafe { self.rx.get_unchecked_mut(idx as usize) }.buf;

        let pkt = OutsidePacket::Wire(buf, ConnectionType::Datagram);
        let pkt = match self.conn_manager.parse_raw_outside_packet(pkt) {
            Ok(hdr) => hdr,
            Err(e) => {
                metrics::udp_parse_wire_failed();
                warn!("Extracting header from packet failed: {e}");
                return;
            }
        };

        let Some(hdr) = pkt.header() else {
            metrics::udp_no_header();
            warn!("Packet parsing error: Not a UDP frame");
            return;
        };
        if !self.conn_manager.is_supported_version(hdr.version) {
            // If the protocol version is not supported then drop
            // the packet.
            metrics::udp_bad_packet_version(hdr.version);
            return;
        }

        let may_be_conn = self.conn_manager.find_datagram_connection_with(peer_addr);
        let (conn, update_peer_address) = match may_be_conn {
            Some(conn) => (conn, false),
            None => {
                let conn_result = self.conn_manager.find_or_create_datagram_connection_with(
                    peer_addr,
                    hdr.version,
                    hdr.session,
                    local_addr,
                    || {
                        Arc::new(UdpSocket {
                            tx_queue: self.tx_queue.clone(),
                            peer_addr: RwLock::new((peer_addr, raw_peer_addr, raw_peer_addr_len)),
                            reply_pktinfo,
                        })
                    },
                );

                match conn_result {
                    Ok(conn) => conn,
                    Err(_e) => {
                        self.send_reject(raw_peer_addr, raw_peer_addr_len, reply_pktinfo);
                        return;
                    }
                }
            }
        };

        let session = hdr.session;

        match conn.outside_data_received(pkt) {
            Ok(0) => {
                // We will hit this case when there is UDP packet duplication.
                // Wolfssl skip duplicate packets and thus no frames read.
                // It is also possible that adversary can capture the packet
                // and replay it. In any case, skip processing further
                if update_peer_address {
                    metrics::udp_session_rotation_attempted_via_replay();
                }
            }
            Ok(_) => {
                // NOTE: We wait until the first successful WolfSSL
                // decrypt to protect against the case where a crafted
                // packet with a session ID causes us to change the
                // connection IP without verifying the SSL connection
                // first
                if update_peer_address {
                    metrics::udp_conn_recovered_via_session(session);
                    conn.begin_session_id_rotation();
                    self.conn_manager.set_peer_addr(&conn, peer_addr);
                }
            }
            Err(err) => {
                warn!("Failed to process outside data: {err}");
                let _ = conn.handle_outside_data_error(&err);
                // Fatal or not, we are done with this packet.
            }
        }
    }

    fn send_reject(
        &self,
        peer_addr: libc::sockaddr_storage,
        peer_addr_len: libc::socklen_t,
        pktinfo: Option<libc::in_pktinfo>,
    ) {
        metrics::udp_rejected_session();
        let msg = Header {
            version: Version::MINIMUM,
            aggressive_mode: false,
            session: SessionId::REJECTED,
        };

        let mut buf = BytesMut::with_capacity(Header::WIRE_SIZE);
        msg.append_to_wire(&mut buf);

        let tx_queue = self.tx_queue.lock().unwrap();

        // Ignore failure to send.

        let _ = queue_tx(tx_queue, buf.freeze(), peer_addr, peer_addr_len, pktinfo);
    }

    fn push_rx(&mut self, sq: &mut io_uring::SubmissionQueue, idx: u32) -> Result<()> {
        let rx = &mut self.rx[idx as usize];

        // Recover full capacity in case this is a resubmit
        rx.buf.clear();
        rx.buf.reserve(MAX_OUTSIDE_MTU);

        rx.msghdr = msghdr::new(libc::msghdr {
            msg_name: &mut rx.addr as *mut libc::sockaddr_storage as *mut _,
            msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as _,
            msg_iov: rx.iov.as_mut_ptr() as *mut libc::msghdr as *mut _,
            msg_iovlen: rx.iov.len(),
            msg_control: rx.control.as_mut_ptr() as *mut _,
            msg_controllen: RxState::CONTROL_SIZE,
            msg_flags: 0,
        });
        let sqe = opcode::RecvMsg::new(Loop::FIXED_OUTSIDE_FD, rx.msghdr.as_mut_ptr())
            .build()
            .user_data(Loop::outside_rx_user_data(idx));

        #[allow(unsafe_code)]
        // SAFETY: The buffer is owned by `self.rx` and `self` is owned by the `io::Loop`
        unsafe {
            sq.push(&sqe)?
        };

        sq.sync();

        Ok(())
    }
}

impl UringIoSource for UdpServer {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    fn push_initial_ops(&mut self, sq: &mut io_uring::SubmissionQueue) -> Result<()> {
        for idx in 0..self.rx.len() as u32 {
            self.push_rx(sq, idx)?
        }
        Ok(())
    }

    fn complete_rx(
        &mut self,
        sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
        idx: u32,
    ) -> Result<()> {
        let res = {
            let res = io_uring_res(cqe.result()).with_context(|| "outside recvmsg completion")?;

            let rx = &mut self.rx[idx as usize];

            #[allow(unsafe_code)]
            // SAFETY: We rely on recv_from giving us the correct size
            unsafe {
                rx.buf.set_len(res as usize);
            }

            let raw_peer_addr = rx.addr;
            let raw_peer_addr_len = rx.msghdr.msg_namelen;

            let peer_addr = match socket_addr_from_sockaddr(&raw_peer_addr, raw_peer_addr_len) {
                Ok(a) => a,
                Err(err) => {
                    metrics::udp_recv_invalid_addr();
                    return Err(err.into());
                }
            };

            if (rx.msghdr.msg_flags & libc::MSG_TRUNC) != 0 {
                metrics::udp_recv_truncated();
            }

            let control_len = rx.msghdr.msg_controllen;

            #[allow(unsafe_code)]
            let (local_addr, reply_pktinfo) = match self.bind_mode {
                BindMode::UnspecifiedAddress { local_port } => {
                    let Some((local_addr, reply_pktinfo)) =
                                // SAFETY: The call to `recvmsg` above updated
                                // the control buffer length field.
                                unsafe { rx.control.iter(control_len) }.find_map(|cmsg| {
                                    match cmsg {
                                        cmsg::Message::IpPktinfo(pi) => {
                                            // From https://pubs.opengroup.org/onlinepubs/009695399/basedefs/netinet/in.h.html
                                            // the `s_addr` is an `in_addr`
                                            // which is in network byte order
                                            // (big endian).
                                            let ipv4 = u32::from_be(pi.ipi_spec_dst.s_addr);
                                            let ipv4 = Ipv4Addr::from_bits(ipv4);
                                            let ip = IpAddr::V4(ipv4);

                                            let reply_pktinfo = libc::in_pktinfo{
                                                ipi_ifindex: 0,
                                                ipi_spec_dst: pi.ipi_spec_dst,
                                                ipi_addr: libc::in_addr { s_addr: 0 },
                                            };

                                            Some((SocketAddr::new(ip, local_port), reply_pktinfo))
                                        },
                                        _ => None,
                                    }
                                }) else {
                                    // Since we have a bound socket
                                    // and we have set IP_PKTINFO
                                    // sockopt this shouldn't happen.
                                    metrics::udp_recv_missing_pktinfo();
                                    println!("outside user data {:016x}, idx {:x} had no PKTINFO", cqe.user_data(),idx);
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        "recvmsg did not return IP_PKTINFO",
                                    ).into());
                                };
                    (local_addr, Some(reply_pktinfo))
                }
                BindMode::SpecificAddress { local_addr } => (local_addr, None),
            };

            self.data_received(
                peer_addr,
                raw_peer_addr,
                raw_peer_addr_len,
                local_addr,
                reply_pktinfo,
                idx,
            );

            Ok(())
        };

        // Queue another recv
        self.push_rx(sq, idx)?;

        res
    }

    fn complete_tx(
        &mut self,
        _sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
        idx: u32,
    ) -> Result<()> {
        let _ = self.tx_queue.lock().unwrap().complete(cqe, idx);
        Ok(())
    }
}
