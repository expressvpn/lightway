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

    /// Records that the session wrote and the connection did not take
    /// yet, back to back in one buffer, so that a record needs no
    /// allocation of its own
    pub(crate) records: BytesMut,

    /// Length of each record in `records`, oldest first
    pub(crate) record_lens: VecDeque<usize>,

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

impl TlsIOAdapter {
    /// Take the oldest record.
    pub(crate) fn pop_record(&mut self) -> Option<BytesMut> {
        let len = self.record_lens.pop_front()?;
        Some(self.records.split_to(len))
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
            self.records.extend_from_slice(buf);
            self.record_lens.push_back(buf.len());
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
        assert_eq!(a.pop_record().unwrap(), &b"abc"[..]);
        assert!(a.pop_record().is_none());
    }

    #[test]
    fn aggressive_send_queues_three_records() {
        let mut a = TlsIOAdapter {
            aggressive_send: true,
            ..Default::default()
        };
        assert!(matches!(a.send(b"abc"), IOCallbackResult::Ok(3)));
        for _ in 0..3 {
            assert_eq!(a.pop_record().unwrap(), &b"abc"[..]);
        }
        assert!(a.pop_record().is_none());
    }
}
