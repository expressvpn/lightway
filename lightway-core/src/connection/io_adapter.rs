use bytes::{Buf, BytesMut};
use std::collections::VecDeque;
use std::fmt;

use crate::tls::IOCallbackResult;
use crate::tls::IOCallbacks;

/// Adapt requirements of [`crate::Connection`] to those of the TLS/DTLS I/O API.
///
/// The session never sends on the outside IO. It writes records into
/// `records`, and the connection takes them from there.
#[derive(Default)]
pub(crate) struct TlsIOAdapter {
    /// Bytes received from outside, but not yet consumed
    pub(crate) recv_buf: BytesMut,

    /// Records that the session wrote and the connection did not take yet
    pub(crate) records: VecDeque<BytesMut>,

    /// DTLS client only, until the connection is online: write each
    /// record three times
    pub(crate) aggressive_send: bool,
}

/// To satisfy BoringSSL SSL_stream debug trait
impl fmt::Debug for TlsIOAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIOAdapter").finish_non_exhaustive()
    }
}

impl IOCallbacks for TlsIOAdapter {
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
        let copies = if self.aggressive_send { 3 } else { 1 };
        for _ in 0..copies {
            self.records.push_back(BytesMut::from(buf));
        }
        IOCallbackResult::Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_queues_one_record() {
        let mut a = TlsIOAdapter::default();
        assert!(matches!(a.send(b"abc"), IOCallbackResult::Ok(3)));
        assert_eq!(a.records, [BytesMut::from(&b"abc"[..])]);
    }

    #[test]
    fn aggressive_send_queues_three_records() {
        let mut a = TlsIOAdapter {
            aggressive_send: true,
            ..Default::default()
        };
        assert!(matches!(a.send(b"abc"), IOCallbackResult::Ok(3)));
        assert_eq!(a.records.len(), 3);
        assert!(a.records.iter().all(|r| r == &b"abc"[..]));
    }
}
