//! Handle `lightway_core::ScheduleEncodingReqRetransmitCb` callbacks using Tokio.

use lightway_core::{Connection, ConnectionResult};
use std::sync::{Mutex, Weak};
use tokio::{sync::mpsc, task::JoinSet, time::Duration};

/// App state compatible with [`encoding_request_ticker_cb`]
pub trait EncodingReqRetransmitState {
    /// Obtain the [`EncodingReqRetransmitTicker`] from the state.
    fn encoding_req_retransmit_ticker(&self) -> Option<&EncodingReqRetransmitTicker>;
}

/// Callback for use with
/// [`lightway_core::ClientContextBuilder::with_schedule_encoding_req_retransmit_cb`].
pub fn encoding_request_ticker_cb<AppState: EncodingReqRetransmitState>(
    d: std::time::Duration,
    request_id: u64,
    state: &mut AppState,
) {
    if let Some(ticker) = state.encoding_req_retransmit_ticker() {
        ticker.schedule(d, request_id);
    }
}

/// Embed this into a [`Connection`]'s `AppState` and call
/// [`EncodingReqRetransmitTicker::schedule`] from your
/// `lightway_core::ScheduleEncodingReqRetransmitCb` implementation.
pub struct EncodingReqRetransmitTicker(mpsc::UnboundedSender<u64>);

impl EncodingReqRetransmitTicker {
    /// Create a new [`EncodingReqRetransmitTicker`]. Once the connection is built
    /// call [`EncodingReqRetransmitTickerTask::spawn_in`] with a `Weak` reference to
    /// it.
    pub fn new() -> (Self, EncodingReqRetransmitTickerTask) {
        let (send, recv) = mpsc::unbounded_channel();

        (Self(send), EncodingReqRetransmitTickerTask(recv))
    }

    /// Schedule a tick.
    pub fn schedule(&self, d: Duration, request_id: u64) {
        let sender = self.0.clone();
        tokio::spawn(async move {
            tokio::time::sleep(d).await;
            let _ = sender.send(request_id);
        });
    }
}

/// Allow [`EncodingReqRetransmitTicker`] to be used as `AppState` directly.
impl EncodingReqRetransmitState for EncodingReqRetransmitTicker {
    fn encoding_req_retransmit_ticker(&self) -> Option<&EncodingReqRetransmitTicker> {
        Some(self)
    }
}

/// Get a suitable `lightway_core::Connection` on which to call
/// `retransmit`.
pub trait EncodingRequestRetransmitTickable: Send + Sync {
    /// Kick this tickable.
    fn retransmit(&self, request_id: u64) -> ConnectionResult<()>;
}

impl<AppState: Send> EncodingRequestRetransmitTickable for Mutex<Connection<AppState>> {
    fn retransmit(&self, request_id: u64) -> ConnectionResult<()> {
        self.lock()
            .unwrap()
            .retransmit_pending_encoding_request(request_id)
    }
}

/// Task which receives tick requests from channel and calls tick.
pub struct EncodingReqRetransmitTickerTask(mpsc::UnboundedReceiver<u64>);

impl EncodingReqRetransmitTickerTask {
    /// Spawn the handler task in a JoinSet
    pub fn spawn_in<T: EncodingRequestRetransmitTickable + 'static>(
        self,
        weak: Weak<T>,
        join_set: &mut JoinSet<()>,
    ) -> tokio::task::AbortHandle {
        let mut recv = self.0;
        join_set.spawn(async move {
            while let Some(request_id) = recv.recv().await {
                let Some(tickable) = weak.upgrade() else {
                    return;
                };

                let _ = tickable.retransmit(request_id);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ticks() {
        use std::sync::{Arc, Mutex};
        use tokio::sync::oneshot;

        let (ticker, ticker_task) = EncodingReqRetransmitTicker::new();

        // We'll "tick" this channel
        let (tx, rx) = oneshot::channel();

        struct Dummy(Mutex<Option<oneshot::Sender<u64>>>);

        impl EncodingRequestRetransmitTickable for Dummy {
            fn retransmit(&self, request_id: u64) -> ConnectionResult<()> {
                self.0
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(request_id)
                    .unwrap();
                Ok(())
            }
        }

        let conn = Arc::new(Dummy(Mutex::new(Some(tx))));
        let mut join_set = JoinSet::new();

        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        ticker.schedule(Duration::ZERO, 102);

        let received_request_id = rx.await.unwrap(); // Should get the tick
        assert_eq!(received_request_id, 102);
    }

    #[tokio::test]
    async fn task_exits_when_ticker_released() {
        use std::sync::Arc;

        let (ticker, ticker_task) = EncodingReqRetransmitTicker::new();

        struct Dummy;

        impl EncodingRequestRetransmitTickable for Dummy {
            fn retransmit(&self, _request_id: u64) -> ConnectionResult<()> {
                panic!("Not expecting to retransmit");
            }
        }

        let conn = Arc::new(Dummy);
        let mut join_set = JoinSet::new();

        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        drop(ticker);

        while (join_set.join_next().await).is_some() {}
    }

    #[tokio::test]
    async fn task_exits_when_conn_released() {
        use std::sync::Arc;

        let (ticker, ticker_task) = EncodingReqRetransmitTicker::new();

        struct Dummy;

        impl EncodingRequestRetransmitTickable for Dummy {
            fn retransmit(&self, _request_id: u64) -> ConnectionResult<()> {
                panic!("Not expecting to retransmit");
            }
        }

        let conn = Arc::new(Dummy);
        let mut join_set = JoinSet::new();

        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        drop(conn);

        ticker.schedule(Duration::ZERO, 0);

        // Task should exit cleanly
        while (join_set.join_next().await).is_some() {}
    }
}
