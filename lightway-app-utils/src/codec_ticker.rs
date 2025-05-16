//! Handle `lightway_core::ScheduleCodecTickCb` callbacks using Tokio.

use lightway_core::{Connection, ConnectionResult};
use std::sync::{Mutex, Weak};
use tokio::{sync::mpsc, task::JoinSet, time::Duration};

/// App state compatible with [`codec_ticker_cb`]
pub trait CodecTickerState {
    /// Obtain the [`CodecTicker`] from the state.
    fn ticker(&self) -> Option<&CodecTicker>;
}

/// Callback for use with
/// [`lightway_core::ClientContextBuilder::with_schedule_codec_tick_cb`].
pub fn codec_ticker_cb<AppState: CodecTickerState>(
    d: std::time::Duration,
    request_id: u64,
    state: &mut AppState,
) {
    if let Some(ticker) = state.ticker() {
        ticker.schedule(d, request_id);
    }
}

/// Embed this into a [`Connection`]'s `AppState` and call
/// [`CodecTicker::schedule`] from your
/// `lightway_core::ScheduleCodecTickCb` implementation.
pub struct CodecTicker(mpsc::UnboundedSender<u64>);

impl CodecTicker {
    /// Create a new [`CodecTicker`]. Once the connection is built
    /// call [`CodecTickerTask::spawn_in`] with a `Weak` reference to
    /// it.
    pub fn new() -> (Self, CodecTickerTask) {
        let (send, recv) = mpsc::unbounded_channel();

        (Self(send), CodecTickerTask(recv))
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

/// Allow [`CodecTicker`] to be used as `AppState` directly.
impl CodecTickerState for CodecTicker {
    fn ticker(&self) -> Option<&CodecTicker> {
        Some(self)
    }
}

/// Get a suitable `lightway_core::Connection` on which to call
/// `retransmit`.
pub trait CodecTickable: Send + Sync {
    /// Kick this tickable.
    fn tick(&self, request_id: u64) -> ConnectionResult<()>;
}

impl<AppState: Send> CodecTickable for Mutex<Connection<AppState>> {
    fn tick(&self, request_id: u64) -> ConnectionResult<()> {
        self.lock().unwrap().codec_tick(request_id)
    }
}

/// Task which receives tick requests from channel and calls tick.
pub struct CodecTickerTask(mpsc::UnboundedReceiver<u64>);

impl CodecTickerTask {
    /// Spawn the handler task in a JoinSet
    pub fn spawn_in<T: CodecTickable + 'static>(
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

                let _ = tickable.tick(request_id);
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

        let (ticker, ticker_task) = CodecTicker::new();

        // We'll "tick" this channel
        let (tx, rx) = oneshot::channel();

        struct Dummy(Mutex<Option<oneshot::Sender<u64>>>);

        impl CodecTickable for Dummy {
            fn tick(&self, request_id: u64) -> ConnectionResult<()> {
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

        let (ticker, ticker_task) = CodecTicker::new();

        struct Dummy;

        impl CodecTickable for Dummy {
            fn tick(&self, _request_id: u64) -> ConnectionResult<()> {
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

        let (ticker, ticker_task) = CodecTicker::new();

        struct Dummy;

        impl CodecTickable for Dummy {
            fn tick(&self, _request_id: u64) -> ConnectionResult<()> {
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
