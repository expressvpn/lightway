//! TcpServer UringIoSource
//!
//! Uses uring indexes:
//!
//! Loop::outside_rx_user_data:
//!  - TcpServer::ACCEPT_IDX:
//!      The accept request.
//!  - The fd for a connection (positive i32):
//!      The RX request for that connection.
//!  - The fd for a connection (positive i32) + TcpServer::RX_CANCEL_IDX_BIT:
//!      A cancellation request for that connection
//!
//! Loop::outside_tx_user_data:
//!  - The fd for a connection (positive i32):
//!      The TX request for that connection.

use std::{
    collections::HashMap,
    net::{SocketAddr, TcpStream},
    os::fd::{AsRawFd, FromRawFd as _, RawFd},
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Context as _, Result};
use bytes::BytesMut;
use bytesize::ByteSize;
use io_uring::{
    opcode,
    types::{CancelBuilder, Fd},
};
use lightway_app_utils::socket_addr_from_sockaddr;
use lightway_core::{
    ConnectionType, CowBytes, IOCallbackResult, OutsideIOSendCallback, OutsidePacket, Version,
};
use tracing::{debug, info, warn};

use crate::{connection::Connection, connection_manager::ConnectionManager, metrics};

use super::{io_uring_res, Loop, TxQueue, UringIoSource};

enum ConnectionPhase {
    ProxyInitial {
        local_addr: SocketAddr,
    },
    Proxy {
        local_addr: SocketAddr,
        rest: usize,
    },
    Connected {
        conn: Arc<Connection>,
        buffer: Arc<Mutex<TcpSocketBuffer>>,
    },
}

struct ConnectionState {
    sock: TcpStream,
    rx_buf: BytesMut,
    tx_buffer_size: usize,
    phase: ConnectionPhase,
}

impl ConnectionState {
    const RX_BUFFER_SIZE: usize = 15 * 1024 * 1024; // 15M

    fn push_rx(&mut self, sq: &mut io_uring::SubmissionQueue) -> Result<()> {
        use ConnectionPhase::*;
        let (buf, len) = match &mut self.phase {
            ProxyInitial { .. } => (self.rx_buf.as_mut_ptr(), 16),
            Proxy { rest, .. } => (self.rx_buf[16..].as_mut_ptr(), *rest),
            Connected { .. } => {
                // Recover full capacity
                self.rx_buf.clear();
                self.rx_buf.reserve(Self::RX_BUFFER_SIZE);
                (self.rx_buf.as_mut_ptr(), self.rx_buf.capacity())
            }
        };
        let fd = self.sock.as_raw_fd();

        let sqe = opcode::Recv::new(Fd(fd), buf, len as _)
            .build()
            .user_data(Loop::outside_rx_user_data(fd as u32));

        #[allow(unsafe_code)]
        // SAFETY: The buffer is owned by `self` and `self` is owned by `TcpServer::fd_map`
        unsafe {
            sq.push(&sqe)?
        };

        sq.sync();

        Ok(())
    }

    fn push_cancel(&mut self, sq: &mut io_uring::SubmissionQueue) -> Result<()> {
        let fd = self.sock.as_raw_fd();
        info!(fd, "Cancelling");
        let builder = CancelBuilder::fd(Fd(fd)).all();
        let sqe = opcode::AsyncCancel2::new(builder)
            .build()
            .user_data(Loop::outside_rx_user_data(
                fd as u32 + TcpServer::RX_CANCEL_IDX_BIT,
            ));

        #[allow(unsafe_code)]
        // SAFETY: The cancel sqe is well formed above
        unsafe {
            sq.push(&sqe)?
        };

        sq.sync();

        Ok(())
    }

    fn complete_tx(
        &mut self,
        sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
    ) -> Result<()> {
        match &mut self.phase {
            // Nothing to do for either of these cases.
            ConnectionPhase::ProxyInitial { .. } | ConnectionPhase::Proxy { .. } => Ok(()),
            ConnectionPhase::Connected {
                conn: _conn,
                buffer,
            } => buffer.lock().unwrap().complete_tx(sq, cqe),
        }
    }

    fn complete_rx(
        &mut self,
        sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
        tx_queue: &Arc<Mutex<TxQueue>>,
        conn_manager: &Arc<ConnectionManager>,
    ) -> Result<()> {
        use ppp::v2::{Header, ParseError};
        use ConnectionPhase::*;

        let res = io_uring_res(cqe.result()).with_context(|| "outside recv completion")?;

        match &mut self.phase {
            ProxyInitial { local_addr } => {
                assert!(16 == res);
                #[allow(unsafe_code)]
                // SAFETY: We rely on recv_from giving us the correct size
                unsafe {
                    self.rx_buf.set_len(res as usize);
                }

                let rest = match Header::try_from(&self.rx_buf[..]) {
                    // Failure tells us exactly how many more bytes are required.
                    Err(ParseError::Partial(_, rest)) => rest,

                    Ok(_) => {
                        // The initial 16 bytes is never enough to actually succeed.
                        return Err(anyhow!("Unexpectedly parsed initial PROXY header"));
                    }
                    Err(err) => {
                        return Err(anyhow!(err).context("Failed to parse initial PROXY header"));
                    }
                };

                self.phase = Proxy {
                    local_addr: *local_addr,
                    rest,
                }
            }
            Proxy { local_addr, rest } => {
                assert!(*rest == res as usize);
                #[allow(unsafe_code)]
                // SAFETY: We rely on recv_from giving us the correct size
                // We read 16 bytes in state ProxyInitial
                unsafe {
                    self.rx_buf.set_len((res + 16) as usize);
                }
                let header = match Header::try_from(&self.rx_buf[..]) {
                    Ok(h) => h,
                    Err(err) => {
                        return Err(anyhow!(err).context("Failed to parse complete PROXY header"));
                    }
                };

                let peer_addr = match header.addresses {
                    ppp::v2::Addresses::Unspecified => {
                        return Err(anyhow!("Unspecified PROXY connection"));
                    }
                    ppp::v2::Addresses::IPv4(addr) => {
                        SocketAddr::new(addr.source_address.into(), addr.source_port)
                    }
                    ppp::v2::Addresses::IPv6(_) => {
                        return Err(anyhow!("IPv6 PROXY connection"));
                    }
                    ppp::v2::Addresses::Unix(_) => {
                        return Err(anyhow!("Unix PROXY connection"));
                    }
                };

                let buffer =
                    TcpSocketBuffer::new(tx_queue.clone(), self.tx_buffer_size, &self.sock);
                let outside_io = Arc::new(TcpSocket {
                    buffer: buffer.clone(),
                    peer_addr,
                });
                let conn = conn_manager.create_streaming_connection(
                    Version::MINIMUM,
                    *local_addr,
                    outside_io,
                )?;
                self.phase = ConnectionPhase::Connected { conn, buffer }
            }
            Connected {
                conn,
                buffer: _buffer,
            } => {
                if res == 0 {
                    // EOF
                    conn.handle_end_of_stream();
                    return Err(anyhow!("End of stream"));
                }

                #[allow(unsafe_code)]
                // SAFETY: We rely on recv_from giving us the correct size
                unsafe {
                    self.rx_buf.set_len(res as usize);
                }
                let pkt = OutsidePacket::Wire(&mut self.rx_buf, ConnectionType::Stream);
                if let Err(err) = conn.outside_data_received(pkt) {
                    warn!("Failed to process outside data: {err}");
                    if conn.handle_outside_data_error(&err).is_break() {
                        return Err(anyhow!(err).context("Outside data fatal error"));
                    }
                }
            }
        };
        self.push_rx(sq)?;
        Ok(())
    }
}

pub(in super::super) struct TcpSocketBuffer {
    tx_queue: Arc<Mutex<TxQueue>>,
    fd: Fd,
    // We double buffer the tx.
    tx_in_flight: BytesMut,
    tx_buffer: BytesMut,
    tx_buffer_size: usize,
}

impl TcpSocketBuffer {
    fn new(
        tx_queue: Arc<Mutex<TxQueue>>,
        tx_buffer_size: usize,
        sock: &impl AsRawFd,
    ) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(TcpSocketBuffer {
            tx_queue,
            fd: Fd(sock.as_raw_fd()),
            tx_in_flight: BytesMut::new(),
            tx_buffer: BytesMut::new(),
            tx_buffer_size,
        }))
    }

    fn push_tx(&mut self) {
        let mut tx_queue = self.tx_queue.lock().unwrap();
        let len = self.tx_in_flight.len();

        let sqe = opcode::Send::new(self.fd, self.tx_in_flight.as_ptr() as *const _, len as _)
            .flags(libc::MSG_WAITALL)
            .build()
            .user_data(Loop::outside_tx_user_data(self.fd.0 as u32));

        #[allow(unsafe_code)]
        // SAFETY:
        // - The buffer is owned by `self` and which is owned by the connection and ultimately by `TcpServer::fd_map`
        unsafe {
            tx_queue.push(sqe)
        };
    }

    fn send(&mut self, buf: CowBytes) -> IOCallbackResult<usize> {
        let bytes = buf.as_bytes();

        if !self.tx_in_flight.is_empty() {
            // tx_buffer_size is not a strict limit, but once we have
            // exceeded it we stop adding more.
            if self.tx_buffer.len() > self.tx_buffer_size {
                return IOCallbackResult::WouldBlock;
            }

            self.tx_buffer.extend_from_slice(bytes);
            return IOCallbackResult::Ok(bytes.len());
        }

        self.tx_in_flight.extend_from_slice(bytes);
        self.push_tx();

        IOCallbackResult::Ok(bytes.len())
    }

    pub fn complete_tx(
        &mut self,
        _sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
    ) -> Result<()> {
        let res = io_uring_res(cqe.result()).with_context(|| "outside send completion")? as usize;

        // We use MSG_WAITALL so this should not happen
        assert!(res == self.tx_in_flight.len(), "Unexpected short send");

        self.tx_in_flight.clear();

        std::mem::swap(&mut self.tx_buffer, &mut self.tx_in_flight);

        if !self.tx_in_flight.is_empty() {
            self.push_tx();
        }

        Ok(())
    }
}

struct TcpSocket {
    buffer: Arc<Mutex<TcpSocketBuffer>>,
    peer_addr: SocketAddr,
}

impl OutsideIOSendCallback for TcpSocket {
    fn send(&self, buf: CowBytes) -> IOCallbackResult<usize> {
        self.buffer.lock().unwrap().send(buf)
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

pub(crate) struct TcpServer {
    conn_manager: Arc<ConnectionManager>,
    sock: Arc<std::net::TcpListener>,
    tx_queue: Arc<Mutex<TxQueue>>,
    tx_buffer_size: usize,
    proxy_protocol: bool,

    // Buffers passed to opcode::Accept
    accept_addr: Box<(libc::sockaddr_storage, libc::socklen_t)>,
    // Map from accepted fds to connections
    fd_map: HashMap<u32, ConnectionState>,
}

impl TcpServer {
    // idx reserved for the accept request. Cannot clash with indexes
    // for connections since those are fd numbers which are positive
    // i32 values.
    const ACCEPT_IDX: u32 = 0x8000_0000;

    // Signals a cancelation request for a connection when added to
    // the idx for a rx request (which is an fd number). Since fd is
    // never 0 (that is stdin) cannot clash with ACCEPT_IDX.
    //
    // We must cancel any in flight requests before destroying the
    // connection state since they may be reading from owned data or,
    // worse, writing to it!
    const RX_CANCEL_IDX_BIT: u32 = 0x8000_0000;

    pub(crate) async fn new(
        conn_manager: Arc<ConnectionManager>,
        tx_queue: Arc<Mutex<TxQueue>>,
        bind_address: SocketAddr,
        proxy_protocol: bool,
        tcp_buffer_size: ByteSize,
    ) -> Result<TcpServer> {
        eprintln!("Binding to {bind_address}");
        let sock = tokio::net::TcpListener::bind(bind_address).await?;
        eprintln!("Bound to {bind_address}");

        let sock = sock.into_std()?;
        sock.set_nonblocking(false)?;
        let sock = Arc::new(sock);

        let tx_buffer_size = tcp_buffer_size.as_u64().try_into()?;

        Ok(Self {
            conn_manager,
            sock,
            tx_queue,
            tx_buffer_size,
            proxy_protocol,

            #[allow(unsafe_code)]
            // SAFETY: All zeroes is a valid sockaddr_storage
            accept_addr: Box::new((unsafe { std::mem::zeroed() }, 0)),

            fd_map: Default::default(),
        })
    }

    fn push_accept(&mut self, sq: &mut io_uring::SubmissionQueue) -> Result<()> {
        info!("Accepting traffic on {}", self.sock.local_addr()?);

        let (addr, len) = &mut *self.accept_addr;
        *len = std::mem::size_of_val(addr) as _;

        let sqe = opcode::Accept::new(
            Loop::FIXED_OUTSIDE_FD,
            addr as *mut libc::sockaddr_storage as *mut _,
            len as *mut libc::socklen_t as *mut _,
        )
        .build()
        .user_data(Loop::outside_rx_user_data(Self::ACCEPT_IDX));

        #[allow(unsafe_code)]
        // SAFETY: The address buffers are owned by `self` and`` self` is owned by the `io::Loop`
        unsafe {
            sq.push(&sqe)?
        };

        sq.sync();

        Ok(())
    }

    fn complete_accept(
        &mut self,
        sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
    ) -> Result<()> {
        let res = io_uring_res(cqe.result()).with_context(|| "outside accept")?;
        // Should be impossible since as a twos complement i32 it would be negative.
        assert!(res as u32 != Self::ACCEPT_IDX);

        let peer_addr = socket_addr_from_sockaddr(&self.accept_addr.0, self.accept_addr.1)?;

        #[allow(unsafe_code)]
        // SAFETY: We trust that on success `accept(2)` returns a
        // valid socket fd.
        let sock = unsafe { TcpStream::from_raw_fd(res) };
        sock.set_nodelay(true)?;

        let local_addr = match sock.local_addr() {
            Ok(local_addr) => local_addr,
            Err(err) => {
                // Since we have a bound socket this shouldn't happen.
                debug!(?err, "Failed to get local addr");
                return Err(err.into());
            }
        };

        let rx_buf = BytesMut::with_capacity(ConnectionState::RX_BUFFER_SIZE);

        let phase = if self.proxy_protocol {
            ConnectionPhase::ProxyInitial { local_addr }
        } else {
            let buffer = TcpSocketBuffer::new(self.tx_queue.clone(), self.tx_buffer_size, &sock);
            let outside_io = Arc::new(TcpSocket {
                buffer: buffer.clone(),
                peer_addr,
            });
            let conn = self.conn_manager.create_streaming_connection(
                Version::MINIMUM,
                local_addr,
                outside_io,
            )?;
            ConnectionPhase::Connected { conn, buffer }
        };

        let mut state = ConnectionState {
            sock,
            rx_buf,
            phase,
            tx_buffer_size: self.tx_buffer_size,
        };

        // Before we add to the hash, due to insert taking ownership
        // of state, but we cannot complete anything until we return
        // so that's ok.
        state.push_rx(sq)?;

        self.fd_map.insert(res as u32, state);

        Ok(())
    }
}

impl UringIoSource for TcpServer {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    fn push_initial_ops(&mut self, sq: &mut io_uring::SubmissionQueue) -> Result<()> {
        self.push_accept(sq)
    }

    fn complete_rx(
        &mut self,
        sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
        idx: u32,
    ) -> Result<()> {
        if idx == Self::ACCEPT_IDX {
            if let Err(err) = self.complete_accept(sq, cqe) {
                // Some of the errors which accept(2) can return
                // <https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/accept.html>
                // while never a good thing needn't necessarily be
                // fatal to the entire server and prevent us from
                // servicing existing connections or potentially
                // new connections in the future.
                warn!(?err, "Failed to accept a new connection");
                metrics::connection_accept_failed();
            }
            self.push_accept(sq)?;
            return Ok(());
        }

        let (idx, cancelling) = if (idx & Self::RX_CANCEL_IDX_BIT) != 0 {
            (idx - Self::RX_CANCEL_IDX_BIT, true)
        } else {
            (idx, false)
        };

        use std::collections::hash_map::Entry;

        match self.fd_map.entry(idx) {
            Entry::Occupied(entry) if cancelling => {
                let nr = io_uring_res(cqe.result()).with_context(|| "Cancelling")?;
                info!(fd = idx, nr, "Cancelled");
                entry.remove_entry();
                Ok(())
            }

            Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                match state.complete_rx(sq, cqe, &self.tx_queue, &self.conn_manager) {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        if matches!(
                            state.phase,
                            ConnectionPhase::ProxyInitial { .. } | ConnectionPhase::Proxy { .. }
                        ) {
                            metrics::connection_accept_proxy_header_failed();
                        }
                        info!("Connection closed: {:?}", err);
                        state.push_cancel(sq)?;

                        if let ConnectionPhase::Connected { conn, .. } = &state.phase {
                            conn.handle_end_of_stream();
                        }

                        Ok(()) // Error is for the connection, not the process
                    }
                }
            }

            // Likely we raced with a cancellation request
            Entry::Vacant(_) => {
                match io_uring_res(cqe.result()) {
                    Err(err) => info!("complete unknown tcp rx {idx} with {err}"),
                    Ok(res) => info!("complete unknown tcp rx {idx} with {res}"),
                };
                Ok(())
            }
        }
    }

    fn complete_tx(
        &mut self,
        sq: &mut io_uring::SubmissionQueue,
        cqe: io_uring::cqueue::Entry,
        idx: u32,
    ) -> Result<()> {
        use std::collections::hash_map::Entry;
        match self.fd_map.entry(idx) {
            Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                match state.complete_tx(sq, cqe) {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        info!("Connection closed: {:?}", err);
                        state.push_cancel(sq)?;
                        Ok(()) // Error is for the connection, not the process
                    }
                }
            }

            // Likely we raced with a cancellation request
            Entry::Vacant(_) => {
                match io_uring_res(cqe.result()) {
                    Err(err) => info!("complete unknown tcp tx {idx} with {err}"),
                    Ok(res) => info!("complete unknown tcp tx {idx} with {res}"),
                };
                Ok(())
            }
        }
    }
}
