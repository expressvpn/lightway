mod batch_receive;
pub(crate) mod send_queue;

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use bytesize::ByteSize;
use lightway_app_utils::cmsg;
#[cfg(target_os = "linux")]
use lightway_app_utils::sockopt;
use lightway_app_utils::sockopt::socket_enable_pktinfo;
use lightway_core::{
    IOCallbackResult, MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU, OutsideIOSendCallback,
    OutsideIOSendCallbackArg,
};
use socket2::{MaybeUninitSlice, MsgHdr, MsgHdrMut, SockAddr, SockRef};
use std::os::fd::AsRawFd;
use std::{
    io::IoSlice,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};
use tokio::io::Interest;
use tracing::info;

use super::{OutsideIO, RecvMeta};
use crate::io::outside::udp::batch_receive::{BatchRecvSlot, recv_multiple_with_metadata};
use crate::io::outside::udp::send_queue::SendQueue;
use crate::metrics;

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

        // Only attach control data when present: macOS rejects a
        // non-null msg_control paired with msg_controllen == 0.
        let msghdr = MsgHdr::new().with_addr(peer_addr).with_buffers(bufs);
        let msghdr = if cmsg_len > 0 {
            msghdr.with_control(&cmsg.as_ref()[..cmsg_len])
        } else {
            msghdr
        };

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
    send_queue: Option<Arc<SendQueue>>,
}

impl OutsideIOSendCallback for UdpSocket {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        let peer_addr = self.peer_addr.read().unwrap();
        if let Some(queue) = &self.send_queue
            && queue.try_enqueue(peer_addr.1.clone(), self.reply_pktinfo, buf)
        {
            return IOCallbackResult::Ok(buf.len());
        }
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

/// Control-buffer size for one `IP_PKTINFO` control message.
const PKTINFO_CONTROL_SIZE: usize = cmsg::Message::space::<libc::in_pktinfo>();

/// Outside IO over one UDP socket.
pub(crate) struct UdpIo {
    sock: Arc<tokio::net::UdpSocket>,
    bind_mode: BindMode,
    batch_receive_enabled: bool,
    send_queue: Option<Arc<SendQueue>>,
    /// Scratch for the batch receive path: per-packet control buffers and
    /// source-address storage, reused across calls. The payload buffers
    /// come from the caller.
    batch_slots: [BatchRecvSlot; MAX_IO_BATCH_SIZE],
}

impl UdpIo {
    pub(crate) async fn new(
        bind_address: SocketAddr,
        udp_buffer_size: ByteSize,
        enable_batch_receive: bool,
        enable_batch_send: bool,
        sock: Option<tokio::net::UdpSocket>,
    ) -> Result<UdpIo> {
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

        let send_queue = enable_batch_send.then(|| SendQueue::new(sock.clone()));

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
                tracing::warn!(
                    "batch receive (recvmsg_x) not available on this system, batch receive disabled"
                );
                false
            }
        } else {
            false
        };

        info!("Accepting traffic on {bind_mode}");

        Ok(Self {
            sock,
            bind_mode,
            batch_receive_enabled,
            send_queue,
            batch_slots: std::array::from_fn(|_| BatchRecvSlot::new()),
        })
    }

    /// Handle for the inside loop to open send-batch windows. `Some`
    /// only when inside-IO batching was enabled at construction.
    pub(crate) fn send_queue(&self) -> Option<Arc<SendQueue>> {
        self.send_queue.clone()
    }

    /// The `IP_PKTINFO` to echo on replies to a packet that arrived on
    /// `local_addr`.
    ///
    /// Derived rather than carried: the kernel's `ipi_spec_dst` is the
    /// local address, which is what `local_addr` already holds, so there
    /// is nothing extra to thread through the receive path.
    ///
    /// `None` when the socket is bound to a specific address, because the
    /// kernel then picks the right source itself.
    fn reply_pktinfo(&self, local_addr: SocketAddr) -> Option<libc::in_pktinfo> {
        if !self.bind_mode.needs_pktinfo() {
            return None;
        }
        let IpAddr::V4(v4) = local_addr.ip() else {
            // `IP_PKTINFO` is IPv4 only, and the receive path only
            // resolves a local address for IPv4.
            return None;
        };
        Some(libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: v4.to_bits().to_be(),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        })
    }
}

#[async_trait]
impl OutsideIO for UdpIo {
    async fn recv(&mut self, buf: &mut BytesMut) -> IOCallbackResult<RecvMeta> {
        buf.clear();
        buf.reserve(MAX_OUTSIDE_MTU);

        let res = self
            .sock
            .async_io(Interest::READABLE, || {
                read_single_from_socket(&self.sock, buf, &self.bind_mode)
            })
            .await;

        match res {
            Ok(meta) => IOCallbackResult::Ok(meta),
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    async fn recv_many(
        &mut self,
        bufs: &mut [BytesMut; MAX_IO_BATCH_SIZE],
        metas: &mut Vec<RecvMeta>,
    ) -> IOCallbackResult<()> {
        if !self.batch_receive_enabled {
            return match self.recv(&mut bufs[0]).await {
                IOCallbackResult::Ok(meta) => {
                    metas.push(meta);
                    IOCallbackResult::Ok(())
                }
                IOCallbackResult::WouldBlock => IOCallbackResult::WouldBlock,
                IOCallbackResult::Err(err) => IOCallbackResult::Err(err),
            };
        }

        // Split the borrow so the closure can hold the scratch slots
        // mutably while reading `sock` and `bind_mode`.
        let Self {
            sock,
            bind_mode,
            batch_slots,
            ..
        } = self;

        let res = sock
            .async_io(Interest::READABLE, || {
                read_multiple_from_socket(sock, bufs, batch_slots, bind_mode, metas)
            })
            .await;

        match res {
            Ok(()) => IOCallbackResult::Ok(()),
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    fn send_callback(&self, meta: &RecvMeta) -> OutsideIOSendCallbackArg {
        Arc::new(UdpSocket {
            sock: self.sock.clone(),
            peer_addr: RwLock::new((meta.peer, meta.peer.into())),
            reply_pktinfo: self.reply_pktinfo(meta.local),
            send_queue: self.send_queue.clone(),
        })
    }

    fn send_unconnected(&self, meta: &RecvMeta, buf: &[u8]) {
        // Ignore failure to send: there is no connection to report against.
        let _ = send_to_socket(
            &self.sock,
            &[IoSlice::new(buf)],
            &meta.peer.into(),
            self.reply_pktinfo(meta.local),
            None,
        );
    }
}

/// Resolve the local address a packet arrived on from its `IP_PKTINFO`
/// control message.
///
/// The reply `IP_PKTINFO` is not returned: it is a function of this
/// address, rebuilt by [`UdpIo::reply_pktinfo`] when a reply is needed.
fn find_local_addr_from_iter(mut iter: cmsg::Iter<'_>, local_port: u16) -> Option<SocketAddr> {
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

                Some(SocketAddr::new(ip, local_port))
            }
            _ => None,
        }
    })
}

fn read_single_from_socket(
    sock: &Arc<tokio::net::UdpSocket>,
    buf: &mut BytesMut,
    bind_mode: &BindMode,
) -> std::io::Result<RecvMeta> {
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
    let mut control = cmsg::Buffer::<PKTINFO_CONTROL_SIZE>::new();

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
    let local_addr = match *bind_mode {
        BindMode::UnspecifiedAddress { local_port } => {
            let Some(local_addr) =
            // SAFETY: The call to `recvmsg` above updated
            // the control buffer length field.
                find_local_addr_from_iter(unsafe { control.iter(control_len) }, local_port) else {
                // Since we have a bound socket
                // and we have set IP_PKTINFO
                // sockopt this shouldn't happen.
                metrics::udp_recv_missing_pktinfo();
                return Err(std::io::Error::other( "recvmsg did not return IP_PKTINFO",));
            };
            local_addr
        }
        BindMode::SpecificAddress { local_addr } => local_addr,
    };

    Ok(RecvMeta {
        peer: peer_addr,
        local: local_addr,
    })
}

fn read_multiple_from_socket(
    sock: &Arc<tokio::net::UdpSocket>,
    bufs: &mut [BytesMut; MAX_IO_BATCH_SIZE],
    slots: &mut [BatchRecvSlot; MAX_IO_BATCH_SIZE],
    bind_mode: &BindMode,
    metas: &mut Vec<RecvMeta>,
) -> std::io::Result<()> {
    let sock = SockRef::from(sock.as_ref());
    let n = recv_multiple_with_metadata(sock.as_raw_fd(), bufs, slots)?;

    for slot in slots.iter_mut().take(n) {
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

        let local_addr = match *bind_mode {
            BindMode::UnspecifiedAddress { local_port } => {
                let Some(local_addr) = slot
                    .control_messages()
                    .and_then(|iter| find_local_addr_from_iter(iter, local_port))
                else {
                    // The socket is bound and has the IP_PKTINFO sockopt
                    // set, so this does not happen.
                    metrics::udp_recv_missing_pktinfo();
                    return Err(std::io::Error::other("recvmmsg did not return IP_PKTINFO"));
                };
                local_addr
            }
            BindMode::SpecificAddress { local_addr } => local_addr,
        };

        metas.push(RecvMeta {
            peer: peer_addr,
            local: local_addr,
        });
    }

    Ok(())
}

#[cfg(linux)]
#[cfg(test)]
mod tests {
    use super::*;
    use bytesize::ByteSize;
    use lightway_core::MAX_OUTSIDE_MTU;
    use std::time::Duration;

    /// A socket bound to the unspecified address must echo the local
    /// address back as `IP_PKTINFO` on replies, so a multi-homed server
    /// answers from the address the client reached it on.
    ///
    /// The reply pktinfo is rebuilt from the received local address rather
    /// than carried through the receive path, so this checks the round
    /// trip: receive on 0.0.0.0, reply, and confirm the client sees the
    /// reply arriving from the address it sent to.
    ///
    /// The client sits on `127.0.0.1` and addresses the server as
    /// `127.0.0.2`, so the two outcomes differ: without the control message
    /// the kernel sources the reply from `127.0.0.1`, and only an applied
    /// `ipi_spec_dst` makes it `127.0.0.2`. Linux only, because macOS does
    /// not configure the rest of `127/8`.
    #[cfg(linux)]
    #[tokio::test]
    #[serial_test::serial]
    #[cfg_attr(
        miri,
        ignore = "binds a real UDP socket, unsupported under miri isolation"
    )]
    async fn reply_to_unconnected_peer_comes_from_the_address_it_arrived_on() {
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();

        let mut io = UdpIo::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            ByteSize::kib(64),
            false,
            false,
            Some(sock),
        )
        .await
        .unwrap();

        // A second loopback address, so the reply source distinguishes
        // "pktinfo applied" from "kernel picked the default".
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port);
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hello", server_addr).await.unwrap();

        let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
        let meta = match io.recv(&mut buf).await {
            IOCallbackResult::Ok(meta) => meta,
            other => panic!("recv failed: {other:?}"),
        };

        assert_eq!(&buf[..], b"hello");
        assert_eq!(
            meta.local, server_addr,
            "IP_PKTINFO must resolve the address the client sent to"
        );
        assert_eq!(meta.peer, client.local_addr().unwrap());

        // A missing control message is caught by the source-address
        // assertion below, because the kernel then sources the reply from
        // 127.0.0.1. A non-local `ipi_spec_dst` instead makes the send
        // fail, which `send_unconnected` swallows, and the timeout catches
        // that.
        io.send_unconnected(&meta, b"rejected");

        let mut reply = [0u8; 32];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut reply))
                .await
                .expect("reply must arrive")
                .unwrap();

        assert_eq!(&reply[..len], b"rejected");
        assert_eq!(
            from, server_addr,
            "reply must come from 127.0.0.2, which only an applied IP_PKTINFO achieves"
        );
    }
}
