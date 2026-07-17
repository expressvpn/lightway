mod batch_receive;

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use bytesize::ByteSize;
use lightway_app_utils::cmsg;
#[cfg(target_os = "linux")]
use lightway_app_utils::sockopt;
use lightway_app_utils::sockopt::socket_enable_pktinfo;
use lightway_core::{
    ConnectionType, Header, IOCallbackResult, MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU,
    OutsideIOSendCallback, OutsidePacket, SessionId, Version,
};
use socket2::{MaybeUninitSlice, MsgHdr, MsgHdrMut, SockAddr, SockRef};
use std::os::fd::AsRawFd;
use std::{
    io::IoSlice,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};
use tokio::io::Interest;
use tracing::{info, warn};

use super::Server;
use crate::io::outside::udp::batch_receive::{BatchRecvSlot, recv_multiple_with_metadata};
use crate::{connection_manager::ConnectionManager, metrics};

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

fn send_to_socket(
    sock: &Arc<tokio::net::UdpSocket>,
    bufs: &[IoSlice<'_>],
    peer_addr: &SockAddr,
    pktinfo: Option<libc::in_pktinfo>,
    gso_size: Option<u16>,
) -> IOCallbackResult<usize> {
    #[cfg(target_vendor = "apple")]
    const IP_PKTINFO_LEVEL: libc::c_int = libc::IPPROTO_IP;
    #[cfg(not(target_vendor = "apple"))]
    const IP_PKTINFO_LEVEL: libc::c_int = libc::SOL_IP;

    const CMSG_SIZE: usize =
        cmsg::Message::space::<libc::in_pktinfo>() + cmsg::Message::space::<u16>();

    let res = sock.try_io(Interest::WRITABLE, || {
        let sock = SockRef::from(sock.as_ref());

        // Track used bytes so we don't pass trailing zeroes that
        // the kernel would interpret as a malformed cmsg header.
        let mut cmsg = cmsg::BufferMut::<CMSG_SIZE>::zeroed();
        let mut cmsg_len: usize = 0;

        if pktinfo.is_some() || gso_size.is_some() {
            let mut builder = cmsg.builder();
            if let Some(pi) = pktinfo {
                builder.fill_next(IP_PKTINFO_LEVEL, libc::IP_PKTINFO, pi)?;
                cmsg_len += cmsg::Message::space::<libc::in_pktinfo>();
            }
            #[cfg(target_os = "linux")]
            if let Some(size) = gso_size {
                builder.fill_next(libc::SOL_UDP, libc::UDP_SEGMENT, size)?;
                cmsg_len += cmsg::Message::space::<u16>();
            }
        }

        // If cmsg_len is 0, the kernel will never read cmsg.
        let msghdr = MsgHdr::new()
            .with_addr(peer_addr)
            .with_buffers(bufs)
            .with_control(&cmsg.as_ref()[..cmsg_len]);

        sock.sendmsg(&msghdr, 0)
    });

    match res {
        Ok(nr) => IOCallbackResult::Ok(nr),
        Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
            IOCallbackResult::WouldBlock
        }
        Err(err) => IOCallbackResult::Err(err),
    }
}

struct UdpSocket {
    sock: Arc<tokio::net::UdpSocket>,
    peer_addr: RwLock<(SocketAddr, SockAddr)>,
    reply_pktinfo: Option<libc::in_pktinfo>,
}

impl OutsideIOSendCallback for UdpSocket {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        let peer_addr = self.peer_addr.read().unwrap();
        send_to_socket(
            &self.sock,
            &[IoSlice::new(buf)],
            &peer_addr.1,
            self.reply_pktinfo,
            None,
        )
    }

    fn send_gso(&self, bufs: &[IoSlice<'_>], gso_size: u16) -> IOCallbackResult<usize> {
        let peer_addr = self.peer_addr.read().unwrap();
        send_to_socket(
            &self.sock,
            bufs,
            &peer_addr.1,
            self.reply_pktinfo,
            Some(gso_size),
        )
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr.read().unwrap().0
    }

    fn set_peer_addr(&self, addr: SocketAddr) -> SocketAddr {
        let mut peer_addr = self.peer_addr.write().unwrap();
        let old_addr = peer_addr.0;
        *peer_addr = (addr, addr.into());
        old_addr
    }
}

pub(crate) struct UdpServer {
    conn_manager: Arc<ConnectionManager>,
    sock: Arc<tokio::net::UdpSocket>,
    bind_mode: BindMode,
    batch_receive_enabled: bool,
}

impl UdpServer {
    pub(crate) async fn new(
        conn_manager: Arc<ConnectionManager>,
        bind_address: SocketAddr,
        udp_buffer_size: ByteSize,
        enable_batch_receive: bool,
        sock: Option<tokio::net::UdpSocket>,
    ) -> Result<UdpServer> {
        let sock = match sock {
            Some(s) => s,
            None => tokio::net::UdpSocket::bind(bind_address).await?,
        };

        // Set Omit to ignore ICMP FragNeeded PMTU updates. If fragmentation is needed
        // in the path, routers will take care of fragmenting, since we do not set DF
        // This is to avoid PMTU poisoning by attackers
        #[cfg(target_os = "linux")]
        sockopt::set_ip_mtu_discover(&sock, sockopt::IpPmtudisc::Omit)?;

        // Check for the socket's writable ready status, so that it can be used
        // successfully in `OutsideIOSendCallback` callback
        sock.writable().await?;
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

        #[cfg(linux)]
        let batch_receive_enabled = enable_batch_receive;
        #[cfg(macos)]
        let batch_receive_enabled = if enable_batch_receive {
            if lightway_app_utils::recvmsg_x::is_batch_receive_available() {
                true
            } else {
                warn!(
                    "batch receive (recvmsg_x) not available on this system, batch receive disabled"
                );
                false
            }
        } else {
            false
        };

        Ok(Self {
            conn_manager,
            sock,
            bind_mode,
            batch_receive_enabled,
        })
    }

    fn data_received(
        &mut self,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        reply_pktinfo: Option<libc::in_pktinfo>,
        buf: &mut BytesMut,
    ) {
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
                            sock: self.sock.clone(),
                            peer_addr: RwLock::new((peer_addr, peer_addr.into())),
                            reply_pktinfo,
                        })
                    },
                );

                match conn_result {
                    Ok(conn) => conn,
                    Err(_e) => {
                        self.send_reject(peer_addr.into(), reply_pktinfo);
                        return;
                    }
                }
            }
        };

        let session = hdr.session;

        match conn.outside_data_received(pkt) {
            Ok(0) => {
                // We will hit this case when there is UDP packet duplication.
                // TLS library skips duplicate packets and thus no frames read.
                // It is also possible that adversary can capture the packet
                // and replay it. In any case, skip processing further
                if update_peer_address {
                    metrics::udp_session_rotation_attempted_via_replay();
                }
            }
            Ok(_) => {
                // NOTE: We wait until the first successful TLS
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

    fn send_reject(&self, peer_addr: SockAddr, reply_pktinfo: Option<libc::in_pktinfo>) {
        metrics::udp_rejected_session();
        let msg = Header {
            version: Version::MINIMUM,
            aggressive_mode: false,
            session: SessionId::REJECTED,
            expresslane_data: false,
        };

        let mut buf = BytesMut::with_capacity(Header::WIRE_SIZE);
        msg.append_to_wire(&mut buf);

        // Ignore failure to send.
        let _ = send_to_socket(
            &self.sock,
            &[IoSlice::new(&buf)],
            &peer_addr,
            reply_pktinfo,
            None,
        );
    }
}

impl UdpServer {
    /// Receive and process one packet at a time using `recvmsg`.
    async fn run_single(&mut self) -> Result<()> {
        let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
        loop {
            // Recover full capacity
            buf.clear();
            buf.reserve(MAX_OUTSIDE_MTU);

            let (peer_addr, local_addr, reply_pktinfo) = self
                .sock
                .async_io(Interest::READABLE, || {
                    read_single_from_socket(&self.sock, &mut buf, &self.bind_mode)
                })
                .await?;

            self.data_received(peer_addr, local_addr, reply_pktinfo, &mut buf);
        }
    }

    /// Receive and process packets in batches using the platform batch-receive
    /// syscall (`recvmmsg` on Linux, `recvmsg_x` on macOS).
    async fn run_batch(&mut self) -> Result<()> {
        const SIZE: usize = cmsg::Message::space::<libc::in_pktinfo>();
        let mut buf_slots: [BatchRecvSlot<SIZE>; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BatchRecvSlot::new());
        loop {
            let pkt_metadata = self
                .sock
                .async_io(Interest::READABLE, || {
                    read_multiple_from_socket(
                        &self.sock,
                        &mut buf_slots,
                        MAX_IO_BATCH_SIZE,
                        &self.bind_mode,
                    )
                })
                .await?;
            // `zip` stops at the shorter iterator, so this processes exactly the
            // slots that batch receive filled (one metadata entry per slot).
            for (slot, meta) in buf_slots.iter_mut().zip(pkt_metadata) {
                self.data_received(meta.peer, meta.local, meta.reply_pktinfo, &mut slot.buf);
                // Recover full capacity
                slot.reset();
            }
        }
    }
}

#[async_trait]
impl Server for UdpServer {
    async fn run(&mut self) -> Result<()> {
        info!("Accepting traffic on {}", self.bind_mode);

        if self.batch_receive_enabled {
            info!("Using batch receive");
            return self.run_batch().await;
        }

        self.run_single().await
    }
}

fn find_pktinfo_from_iter<const N: usize>(
    mut iter: cmsg::Iter<'_, N>,
    local_port: u16,
) -> Option<(SocketAddr, libc::in_pktinfo)> {
    iter.find_map(|cmsg| {
        match cmsg {
            cmsg::Message::IpPktinfo(pi) => {
                // From https://pubs.opengroup.org/onlinepubs/009695399/basedefs/netinet/in.h.html
                // the `s_addr` is an `in_addr`
                // which is in network byte order
                // (big endian).
                let ipv4 = u32::from_be(pi.ipi_spec_dst.s_addr);
                let ipv4 = Ipv4Addr::from_bits(ipv4);
                let ip = IpAddr::V4(ipv4);

                let reply_pktinfo = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: pi.ipi_spec_dst,
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };

                Some((SocketAddr::new(ip, local_port), reply_pktinfo))
            }
            _ => None,
        }
    })
}

fn read_single_from_socket(
    sock: &Arc<tokio::net::UdpSocket>,
    buf: &mut BytesMut,
    bind_mode: &BindMode,
) -> std::io::Result<(SocketAddr, SocketAddr, Option<libc::in_pktinfo>)> {
    let sock = SockRef::from(sock.as_ref());
    let mut raw_buf = [MaybeUninitSlice::new(buf.spare_capacity_mut())];

    #[allow(unsafe_code)]
    let mut peer_sock_addr = {
        // SAFETY: sockaddr_storage is defined
        // (<https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/sys_socket.h.html>)
        // as being a suitable size and alignment for
        // "all supported protocol-specific address
        // structures" in the underlying OS APIs.
        //
        // All zeros is a valid representation,
        // corresponding to the `ss_family` having a
        // value of `AF_UNSPEC`.
        let addr_storage: socket2::SockAddrStorage = unsafe { std::mem::zeroed() };
        let len = std::mem::size_of_val(&addr_storage) as libc::socklen_t;
        // SAFETY: We initialized above as `AF_UNSPEC`
        // so the storage is correct from that
        // angle. The `recvmsg` call will change this
        // which should be ok since `sockaddr_storage`
        // is big enough.
        unsafe { SockAddr::new(addr_storage, len) }
    };

    // We only need this control buffer if
    // `self.bind_mode.needs_pktinfo()`. However the hit
    // on reserving a fairly small on stack buffer
    // should be small compared with the conditional
    // logic and dynamically sized buffer needed to
    // allow omitting it.
    const SIZE: usize = cmsg::Message::space::<libc::in_pktinfo>();
    let mut control = cmsg::Buffer::<SIZE>::new();

    let mut msg = MsgHdrMut::new()
        .with_addr(&mut peer_sock_addr)
        .with_buffers(&mut raw_buf)
        .with_control(control.spare_capacity_mut());

    let len = sock.recvmsg(&mut msg, 0)?;

    if msg.flags().is_truncated() {
        metrics::udp_recv_truncated();
    }

    let control_len = msg.control_len() as self::cmsg::LibcControlLen;

    // SAFETY: We rely on recv_from giving us the correct size
    #[allow(unsafe_code)]
    unsafe {
        buf.set_len(len)
    };

    let Some(peer_addr) = peer_sock_addr.as_socket() else {
        // Since we only bind to IP sockets this shouldn't happen.
        metrics::udp_recv_invalid_addr();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "failed to convert local addr to socketaddr",
        ));
    };

    #[allow(unsafe_code)]
    let (local_addr, reply_pktinfo) = match *bind_mode {
        BindMode::UnspecifiedAddress { local_port } => {
            let Some((local_addr, reply_pktinfo)) =
            // SAFETY: The call to `recvmsg` above updated
            // the control buffer length field.
                find_pktinfo_from_iter(unsafe { control.iter(control_len) }, local_port) else {
                // Since we have a bound socket
                // and we have set IP_PKTINFO
                // sockopt this shouldn't happen.
                metrics::udp_recv_missing_pktinfo();
                return Err(std::io::Error::other( "recvmsg did not return IP_PKTINFO",));
            };
            (local_addr, Some(reply_pktinfo))
        }
        BindMode::SpecificAddress { local_addr } => (local_addr, None),
    };

    Ok((peer_addr, local_addr, reply_pktinfo))
}

/// Per-packet metadata produced by batched receive.
struct BatchRecvMetadata {
    /// The peer (remote) address the packet was received from.
    peer: SocketAddr,
    /// The resolved local address the packet was received on.
    local: SocketAddr,
    /// The `in_pktinfo` to echo back on replies, when the bind mode needs it.
    reply_pktinfo: Option<libc::in_pktinfo>,
}

fn read_multiple_from_socket<const N: usize>(
    sock: &Arc<tokio::net::UdpSocket>,
    buf_slots: &mut [BatchRecvSlot<N>; MAX_IO_BATCH_SIZE],
    max_batch_size: usize,
    bind_mode: &BindMode,
) -> std::io::Result<Vec<BatchRecvMetadata>> {
    let sock = SockRef::from(sock.as_ref());

    let fd = sock.as_raw_fd();
    let n = recv_multiple_with_metadata(fd, buf_slots, max_batch_size)?;

    let mut metadata = Vec::with_capacity(n);

    for slot in buf_slots.iter_mut().take(n) {
        if slot.truncated {
            metrics::udp_recv_truncated();
        }

        let Some(peer_addr) = slot.take_peer_addr() else {
            // Since we only bind to IP sockets this shouldn't happen.
            metrics::udp_recv_invalid_addr();
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "failed to convert local addr to socketaddr",
            ));
        };

        let (local_addr, reply_pktinfo) = match *bind_mode {
            BindMode::UnspecifiedAddress { local_port } => {
                if let Some(ref mut control) = slot.control
                    && let Some(control_len) = slot.control_length
                {
                    #[allow(unsafe_code)]
                    let Some((local_addr, reply_pktinfo)) =
                        // SAFETY: The call to `recvmmsg` above updated
                        // the control buffer length field.
                        find_pktinfo_from_iter(unsafe { control.iter(control_len) }, local_port) else {
                        // Since we have a bound socket
                        // and we have set IP_PKTINFO
                        // sockopt this shouldn't happen.
                        metrics::udp_recv_missing_pktinfo();
                        return Err(std::io::Error::other("recvmmsg did not return IP_PKTINFO"));
                    };
                    (local_addr, Some(reply_pktinfo))
                } else {
                    // No cmsg found, returning error
                    metrics::udp_recv_missing_pktinfo();
                    return Err(std::io::Error::other(
                        "recvmmsg did not return cmsg and IP_PKTINFO",
                    ));
                }
            }
            BindMode::SpecificAddress { local_addr } => (local_addr, None),
        };

        metadata.push(BatchRecvMetadata {
            peer: peer_addr,
            local: local_addr,
            reply_pktinfo,
        });
    }

    Ok(metadata)
}
