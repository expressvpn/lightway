//! Tun UringIoSource
//!
//! Uses uring indexes:
//!
//! Loop::inside_rx_user_data:
//!  - 0..Tun::rx.len(): A set of recv requests
//!
//! Loop::inside_tx_user_data:
//!  - Managed by TxQueue

use crate::ip_manager::IpManager;
use crate::metrics;

use super::{io_uring_res, Loop, TxQueue, UringIoSource};

use crate::connection::ConnectionState;

use anyhow::{Context as _, Result};
use bytes::BytesMut;
use io_uring::opcode;
use lightway_core::{
    ipv4_update_destination, ipv4_update_source, ConnectionError, IOCallbackResult,
    InsideIOSendCallback, InsideIOSendCallbackArg,
};
use pnet::packet::ipv4::Ipv4Packet;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd as _, RawFd};
use std::sync::{Arc, Mutex};
use tun::{AbstractDevice as _, Configuration as TunConfig, Device as TunDevice};

pub(crate) struct Tun {
    tun: TunDevice,
    lightway_client_ip: Ipv4Addr,
    ip_manager: Arc<IpManager>,

    tx_queue: Arc<Mutex<TxQueue>>,

    mtu: usize,

    rx: Vec<BytesMut>,
}

impl Tun {
    pub fn new(
        nr_slots: u32,
        blocking: bool,
        mut tun: TunConfig,
        lightway_client_ip: Ipv4Addr,
        ip_manager: Arc<IpManager>,
        tx_queue: Arc<Mutex<TxQueue>>,
    ) -> Result<Self> {
        tracing::info!("Tun with {nr_slots} slots (blocking: {blocking})");

        tun.platform_config(|cfg| {
            cfg.napi(true);
        });

        let tun = tun::create(&tun)?;
        if !blocking {
            tun.set_nonblock()?;
        }

        let mtu = tun.mtu()? as usize;

        let rx = (0..nr_slots).map(|_| BytesMut::new()).collect();

        Ok(Tun {
            tun,
            lightway_client_ip,
            ip_manager,
            tx_queue,
            mtu,
            rx,
        })
    }

    pub fn inside_io_sender(&self) -> InsideIOSendCallbackArg<ConnectionState> {
        Arc::new(TunInsideIO::new(self.tx_queue.clone(), self))
    }

    fn push_rx(&mut self, sq: &mut io_uring::SubmissionQueue, idx: u32) -> Result<()> {
        let buf = &mut self.rx[idx as usize];

        // Recover full capacity
        buf.clear();
        buf.reserve(self.mtu);

        let sqe = opcode::Read::new(
            Loop::FIXED_INSIDE_FD,
            buf.as_mut_ptr() as *mut _,
            buf.capacity() as _,
        )
        .build()
        .user_data(Loop::inside_rx_user_data(idx));

        #[allow(unsafe_code)]
        // SAFETY: The buffer is owned by `self.rx` and `self` is owned by the `io::Loop`
        unsafe {
            sq.push(&sqe)?;
        }

        sq.sync();

        Ok(())
    }
}

impl UringIoSource for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
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
        let res = match io_uring_res(cqe.result()) {
            Ok(res) => res,
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                self.push_rx(sq, idx)?;
                return Ok(());
            }
            Err(err) => return Err(err).with_context(|| "inside read completion"),
        };

        let buf = &mut self.rx[idx as usize];

        metrics::tun_to_client(res as usize);

        #[allow(unsafe_code)]
        // SAFETY: We rely on recv_from giving us the correct size
        unsafe {
            buf.set_len(res as usize);
        }

        // Find connection based on client ip (dest ip) and forward packet
        let packet = Ipv4Packet::new(buf.as_ref());
        let Some(packet) = packet else {
            eprintln!("Invalid inside packet size (less than Ipv4 header)!");
            // Queue another recv
            self.push_rx(sq, idx)?;
            return Ok(());
        };
        let conn = self.ip_manager.find_connection(packet.get_destination());

        // Update destination IP address to client's ip
        ipv4_update_destination(buf.as_mut(), self.lightway_client_ip);

        if let Some(conn) = conn {
            match conn.inside_data_received(buf) {
                Ok(()) => {}
                Err(ConnectionError::InvalidState) => {
                    // Skip forwarding packet when offline
                    metrics::tun_rejected_packet_invalid_state();
                }
                Err(ConnectionError::InvalidInsidePacket(_)) => {
                    // Skip processing invalid packet
                    metrics::tun_rejected_packet_invalid_inside_packet();
                }
                Err(err) => {
                    let fatal = err.is_fatal(conn.connection_type());
                    metrics::tun_rejected_packet_invalid_other(fatal);
                    if fatal {
                        conn.handle_end_of_stream();
                        return Ok(());
                    }
                }
            }
        } else {
            metrics::tun_rejected_packet_no_connection();
        };

        // Queue another recv
        self.push_rx(sq, idx)?;

        Ok(())
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

pub(crate) struct TunInsideIO(Arc<Mutex<TxQueue>>, usize);

impl TunInsideIO {
    pub(crate) fn new(queue: Arc<Mutex<TxQueue>>, tun: &Tun) -> Self {
        Self(queue, tun.mtu)
    }
}

impl InsideIOSendCallback<ConnectionState> for TunInsideIO {
    fn send(&self, mut buf: BytesMut, state: &mut ConnectionState) -> IOCallbackResult<usize> {
        let len = buf.len();

        let Some(client_ip) = state.internal_ip else {
            metrics::tun_rejected_packet_no_client_ip();
            // Ip address not found, dropping the packet
            return IOCallbackResult::Ok(buf.len());
        };

        ipv4_update_source(buf.as_mut(), client_ip);
        metrics::tun_from_client(len);

        let buf = buf.freeze();

        let mut tx_queue = self.0.lock().unwrap();

        let Some((slot, state)) = tx_queue.take_slot() else {
            return IOCallbackResult::WouldBlock;
        };

        let sqe = opcode::Write::new(
            Loop::FIXED_INSIDE_FD,
            buf.as_ptr() as *mut _,
            buf.len() as _,
        )
        .build();

        state.buf = Some(buf);

        #[allow(unsafe_code)]
        // SAFETY:
        // - slot was optained from take_slot above
        // - The buffer is owned by `state` and which is owned by the `TxRing`
        unsafe {
            tx_queue.push_inside_slot(slot, sqe)
        };

        IOCallbackResult::Ok(len)
    }

    fn mtu(&self) -> usize {
        self.1
    }
}
