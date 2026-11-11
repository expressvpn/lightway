use bytes::{Buf, BytesMut};
use std::fmt;

use crate::encapsulation::Encapsulation;
use crate::tls::IOCallbackResult;

/// Adapt requirements of [`crate::Connection`] to those of the TLS/DTLS I/O API.
pub(crate) struct TlsIOAdapter {
    /// Bytes received from outside, but not yet consumed
    pub(crate) recv_buf: BytesMut,

    pub(crate) encapsulation: Encapsulation,
}

/// To satisfy BoringSSL SSL_stream debug trait
impl fmt::Debug for TlsIOAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIOAdapter").finish_non_exhaustive()
    }
}

impl crate::tls::IOCallbacks for TlsIOAdapter {
    fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult<usize> {
        let pending_buf = &mut self.recv_buf;
        if pending_buf.is_empty() {
            return IOCallbackResult::WouldBlock;
        }

        let n = std::cmp::min(buf.len(), pending_buf.len());
        let mut pending_buf = pending_buf.split_to(n).freeze();
        pending_buf.copy_to_slice(&mut buf[..n]);
        debug_assert!(pending_buf.is_empty(), "Should have consumed everything");
        IOCallbackResult::Ok(n)
    }

    fn send(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        self.encapsulation.send(buf)
    }
}
