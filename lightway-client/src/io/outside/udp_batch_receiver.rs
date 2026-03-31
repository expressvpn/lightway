#![cfg(batch_receive)]

use anyhow::Result;
use bytes::BytesMut;
use rtrb::RingBuffer;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio_util::sync::{CancellationToken, DropGuard};

pub(crate) struct BatchReceiver {
    recv_ready: Arc<Semaphore>,
    recv_consumer: Mutex<rtrb::Consumer<BytesMut>>,
    _drop_guard: DropGuard,
}

const MAX_BUFFER_SIZE: usize = 1024;
impl BatchReceiver {
    pub fn new(sock: Arc<UdpSocket>) -> Self {
        let recv_ready = Arc::new(Semaphore::new(0));
        let (recv_producer, recv_consumer) = RingBuffer::new(MAX_BUFFER_SIZE);
        let cancellation_token = CancellationToken::new();
        let io_error = Arc::new(Mutex::new(None));
        Self {
            recv_ready,
            recv_consumer: Mutex::new(recv_consumer),
            _drop_guard: cancellation_token.drop_guard(),
        }
    }

    pub async fn recv_queue_ready(&self) -> Result<()> {
        // Using a semaphore so bursts are counted correctly: each
        // received packet adds exactly one permit, and each readable() consumes one.
        self.recv_ready
            .acquire()
            .await
            .map_err(|e| anyhow::anyhow!("recv_ready semaphore closed: {e}"))?
            .forget(); // consume the permit without dropping it back
        Ok(())
    }
}
