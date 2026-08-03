//! The control loop the engine process runs.
//!
//! It lives in the library rather than in the binary so a test can drive it
//! over a socket pair, without a process to fork or descriptors to inherit.
//!
//! No packet ever arrives here. The kernel's BPF steering delivers offloaded
//! traffic straight to the descriptors this loop receives, so the socket
//! carries control messages only and a blocking read on it costs nothing.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use crate::engine::Engine;
use crate::fdpass::{recv_with_fds, send_with_fds};
use crate::ipc::{ControlMsg, IpcError, MAX_CONTROL_MSG_LEN};

/// Receive buffer size.
///
/// `recv_with_fds` refuses a read that both carries descriptors and fills the
/// buffer, because that is indistinguishable from a message split away from
/// them. Sizing the buffer well past the largest message the protocol defines
/// is what keeps that from ever happening.
const RECV_BUF_LEN: usize = 4096;
const _: () = assert!(RECV_BUF_LEN > MAX_CONTROL_MSG_LEN);

/// Descriptors the engine is handed, once: the TUN queue and the UDP socket.
///
/// Both an upper bound and an expectation. Nothing else is ever passed, so a
/// stream carrying more is a peer this process should not go on serving, and
/// an `Attach` carrying fewer means the engine has nothing to work with - a
/// state that must be visible rather than look like a healthy engine that
/// happens never to see a packet.
pub const EXPECTED_FDS: usize = 2;
const _: () = assert!(EXPECTED_FDS <= crate::fdpass::MAX_FDS);

/// Serve control messages until the peer closes the socket.
///
/// `engine` is shared, not owned: this loop only ever needs `&Engine`, so the
/// same reference drives any number of packet threads at the same time. How
/// many, and on which descriptor, is process A's decision and nothing here
/// pre-empts it.
///
/// `on_attach` is called once, with the descriptors the peer passed - the TUN
/// queue and the UDP socket, in that order - at the moment `Attach` completes
/// them. It takes ownership: hold them for as long as the offload runs, or
/// move them into whatever reads them, because dropping one closes the offload
/// path. It is called before the loop reads again, so a packet loop started
/// from it runs alongside the rest of this function.
///
/// `control` must be a *blocking* socket: the loop reads it with `recvmsg` and
/// a non-blocking descriptor would fail out on the first `EAGAIN`.
///
/// Returns `Ok(())` on end of file. The VPN process going away is the fallback
/// signal, not an error: the kernel drops `numqueues` as this process exits and
/// the inside path returns to queue 0 on its own.
pub fn run_engine<F>(control: &UnixStream, engine: &Engine, on_attach: F) -> io::Result<()>
where
    F: FnOnce(Vec<OwnedFd>),
{
    // A stream socket splits messages wherever it likes, so a read is a slice
    // of the byte stream and not a message. `pending` cannot grow without
    // limit: `decode` rejects any length no variant can have as soon as the
    // prefix lands, so it holds at most a partial message between reads.
    let mut pending: Vec<u8> = Vec::with_capacity(MAX_CONTROL_MSG_LEN);
    let mut buf = [0u8; RECV_BUF_LEN];
    // Descriptors accumulate here only until the `Attach` that completes them;
    // they are handed to `on_attach` whole and never held past that.
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut on_attach = Some(on_attach);

    loop {
        let n = recv_with_fds(control, &mut buf, &mut fds)?;
        if fds.len() > EXPECTED_FDS || (on_attach.is_none() && !fds.is_empty()) {
            // Bounded the same way `pending` is, and for the same reason: the
            // peer decides how much arrives, so it does not get to decide how
            // much this process holds. A repeated Attach lands here.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} descriptors crossed, only {EXPECTED_FDS} are ever passed",
                    fds.len()
                ),
            ));
        }
        if n == 0 {
            return Ok(());
        }
        pending.extend_from_slice(&buf[..n]);

        loop {
            match ControlMsg::decode(&pending) {
                Ok((msg, used)) => {
                    if matches!(msg, ControlMsg::Attach) {
                        if fds.len() != EXPECTED_FDS {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "attach arrived with {} of {EXPECTED_FDS} descriptors",
                                    fds.len()
                                ),
                            ));
                        }
                        let Some(deliver) = on_attach.take() else {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "attach repeated; the engine is handed its descriptors once",
                            ));
                        };
                        deliver(std::mem::take(&mut fds));
                    }
                    if let Some(reply) = engine.apply(&msg) {
                        let mut out = Vec::new();
                        reply.encode(&mut out);
                        if let Err(e) = send_with_fds(control, &out, &[]) {
                            // A parent that died between asking and being
                            // answered is the same fallback signal as EOF, and
                            // must not become a different exit status.
                            if matches!(
                                e.kind(),
                                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                            ) {
                                return Ok(());
                            }
                            return Err(e);
                        }
                    }
                    pending.drain(..used);
                }
                Err(IpcError::Incomplete) => break,
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("control protocol error: {e:?}"),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::mpsc;

    const SID: [u8; 8] = [0x5A; 8];

    fn keys() -> ControlMsg {
        ControlMsg::PushKeys {
            session_id: SID,
            version: 2,
            lightway_version: [1, 3],
            self_key: ExpresslaneKey([0x21; EXPRESSLANE_KEY_SIZE]),
            peer_key: ExpresslaneKey([0x22; EXPRESSLANE_KEY_SIZE]),
        }
    }

    /// Stand-ins for the TUN queue and the UDP socket.
    fn two_descriptors() -> Vec<std::io::PipeReader> {
        (0..EXPECTED_FDS)
            .map(|_| std::io::pipe().unwrap().0)
            .collect()
    }

    /// Run the loop against `script`, written a byte at a time from another
    /// thread, and return what it wrote back and how many descriptors were
    /// delivered to the attach callback.
    ///
    /// `handed_over` rides with the first byte, which is where the kernel
    /// attaches ancillary data on a stream socket: the descriptors therefore
    /// arrive with a *fragment* of the message they belong to, exactly as they
    /// will in the real hand-over.
    ///
    /// One byte per `write` means the reader wakes with a fraction of a
    /// message in hand, which is the case a loop that assumed one read equals
    /// one message would get wrong. Nothing here depends on how the kernel
    /// happens to coalesce those writes: the assertions are on the end state,
    /// so a run that saw whole messages still checks the same thing.
    fn drive(script: Vec<u8>, handed_over: &[RawFd]) -> (io::Result<()>, Vec<u8>, usize) {
        let (parent, child) = UnixStream::pair().unwrap();
        let handed_over = handed_over.to_vec();
        let writer = std::thread::spawn(move || {
            let mut sock = &parent;
            let mut rest = script.as_slice();
            if let Some((first, tail)) = script.split_first() {
                send_with_fds(&parent, std::slice::from_ref(first), &handed_over).unwrap();
                rest = tail;
            }
            for b in rest {
                sock.write_all(std::slice::from_ref(b)).unwrap();
            }
            // End of file is how the loop is told to stop; keeping the read
            // half open lets the reply come back afterwards.
            parent.shutdown(Shutdown::Write).unwrap();
            parent
        });

        let engine = Engine::new();
        let (delivered_tx, delivered_rx) = mpsc::channel();
        let result = run_engine(&child, &engine, move |fds| {
            delivered_tx.send(fds).unwrap();
        });

        let parent = writer.join().unwrap();
        drop(child);
        let mut replies = Vec::new();
        match std::io::Read::read_to_end(&mut &parent, &mut replies) {
            Ok(_) => {}
            // A loop that bailed left script bytes unread, so closing its end
            // resets the connection. Whatever it did reply to is already here.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
            Err(e) => panic!("reading replies failed: {e}"),
        }
        let delivered = delivered_rx.try_recv().map(|f| f.len()).unwrap_or(0);
        (result, replies, delivered)
    }

    /// The whole point of accumulating: a message delivered in fragments must
    /// still be applied exactly once, and the loop must end cleanly at EOF.
    #[test]
    fn messages_split_across_reads_are_reassembled() {
        let mut script = Vec::new();
        ControlMsg::Attach.encode(&mut script);
        keys().encode(&mut script);
        ControlMsg::StatsRequest { session_id: SID }.encode(&mut script);

        let passed = two_descriptors();
        let raw: Vec<RawFd> = passed.iter().map(|p| p.as_raw_fd()).collect();
        let (result, replies, delivered) = drive(script, &raw);
        result.expect("a closed peer is not an error");
        assert_eq!(
            delivered, EXPECTED_FDS,
            "the loop did not deliver both descriptors"
        );

        let (reply, used) = ControlMsg::decode(&replies).expect("no StatsReply came back");
        assert_eq!(used, replies.len(), "unexpected extra reply bytes");
        let ControlMsg::StatsReply {
            session_id,
            known_session,
            ..
        } = reply
        else {
            panic!("expected StatsReply, got {reply:?}")
        };
        assert_eq!(session_id, SID);
        assert!(
            known_session,
            "the keys did not survive being split across reads"
        );
    }

    /// A length no variant can have must end the loop instead of making it
    /// wait for bytes that will never come while `pending` grows.
    #[test]
    fn a_bogus_length_prefix_ends_the_loop() {
        let (result, ..) = drive(vec![0xFF, 0xFF, 0xFF, 0xFF, 0x02], &[]);
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "a length the protocol cannot produce must be refused"
        );
    }

    /// An engine with no descriptors has nothing to encrypt or decrypt with.
    /// Serving on regardless would look exactly like a healthy engine that
    /// happens never to see a packet, which is the failure nobody diagnoses.
    #[test]
    fn attach_without_its_descriptors_is_refused() {
        let mut script = Vec::new();
        ControlMsg::Attach.encode(&mut script);

        let (result, _, delivered) = drive(script, &[]);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(delivered, 0, "nothing may be delivered without an attach");
    }

    /// The peer decides how many descriptors it sends; it does not get to
    /// decide how many this process holds. Without the cap a repeated Attach
    /// grows the fd table for as long as the peer keeps sending.
    #[test]
    fn more_descriptors_than_the_engine_takes_are_refused() {
        let mut script = Vec::new();
        ControlMsg::Attach.encode(&mut script);

        let passed = two_descriptors();
        let mut raw: Vec<RawFd> = passed.iter().map(|p| p.as_raw_fd()).collect();
        raw.push(passed[0].as_raw_fd());

        let (result, _, delivered) = drive(script, &raw);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(delivered, 0, "an over-long hand-over must deliver nothing");
    }

    /// The descriptors are handed over once. A second Attach - or descriptors
    /// arriving after the first one completed - is a peer this process must
    /// stop serving, not a second set to juggle.
    #[test]
    fn a_second_attach_is_refused() {
        let mut script = Vec::new();
        ControlMsg::Attach.encode(&mut script);
        ControlMsg::Attach.encode(&mut script);

        let passed = two_descriptors();
        let raw: Vec<RawFd> = passed.iter().map(|p| p.as_raw_fd()).collect();
        let (result, _, delivered) = drive(script, &raw);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(delivered, EXPECTED_FDS, "the first attach still stands");
    }

    /// The module's fallback policy is that losing the parent is not an error.
    /// A parent that dies between asking and being answered is the same loss
    /// as one that closes cleanly, and must not exit differently.
    #[test]
    fn a_parent_that_dies_before_its_reply_is_not_an_error() {
        let (parent, child) = UnixStream::pair().unwrap();
        let mut script = Vec::new();
        ControlMsg::StatsRequest { session_id: SID }.encode(&mut script);
        send_with_fds(&parent, &script, &[]).unwrap();
        // Gone before the reply can be written, with the request still queued.
        drop(parent);

        let engine = Engine::new();
        run_engine(&child, &engine, |_| ())
            .expect("a dead parent is the fallback signal, not a failure");
    }

    /// Nothing has been handed over yet, so the loop must not act as though a
    /// session existed - and it must still answer.
    #[test]
    fn stats_before_any_keys_report_unknown() {
        let mut script = Vec::new();
        ControlMsg::StatsRequest { session_id: SID }.encode(&mut script);

        let (result, replies, _) = drive(script, &[]);
        result.unwrap();
        let (reply, _) = ControlMsg::decode(&replies).unwrap();
        assert_eq!(
            reply,
            ControlMsg::StatsReply {
                session_id: SID,
                sent: 0,
                received: 0,
                sent_bytes: 0,
                received_bytes: 0,
                decrypt_failures: 0,
                refused: 0,
                known_session: false,
            }
        );
    }

    /// The signature has to let a packet path run while the loop is blocked in
    /// `recv`: that is the whole reason the engine is shared and the
    /// descriptors leave through a callback instead of an out-parameter.
    #[test]
    fn a_packet_path_can_run_while_the_loop_is_still_serving() {
        let (parent, child) = UnixStream::pair().unwrap();
        let engine = Engine::new();

        let mut script = Vec::new();
        ControlMsg::Attach.encode(&mut script);
        let passed = two_descriptors();
        let raw: Vec<RawFd> = passed.iter().map(|p| p.as_raw_fd()).collect();
        send_with_fds(&parent, &script, &raw).unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        std::thread::scope(|s| {
            let engine = &engine;
            let child = &child;
            s.spawn(move || {
                run_engine(child, engine, |fds| {
                    // Exactly what process A does here: take the descriptors
                    // and start reading packets on another thread.
                    started_tx.send(fds.len()).unwrap();
                })
                .expect("a closed parent is not an error");
            });

            // The loop is now blocked in recv with the engine borrowed. Both
            // must still be usable from here.
            assert_eq!(started_rx.recv().unwrap(), EXPECTED_FDS);
            let mut payload = Vec::new();
            keys().encode(&mut payload);
            send_with_fds(&parent, &payload, &[]).unwrap();
            while engine.encrypt(SID, b"while serving", [7; 12]).is_none() {
                std::thread::yield_now();
            }
            parent.shutdown(Shutdown::Write).unwrap();
        });
    }
}
