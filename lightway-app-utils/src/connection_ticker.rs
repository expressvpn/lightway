//! Handle `lightway_core::ScheduleTickCb` callbacks using Tokio.

use lightway_core::{Connection, ConnectionError, ConnectionResult};
use std::{
    sync::{Mutex, Weak},
    time::Duration,
};
use tokio::{
    sync::mpsc::{self, UnboundedReceiver},
    task::JoinSet,
};
use tracing::warn;

/// App state compatible with [`connection_ticker_cb`]
pub trait ConnectionTickerState {
    /// Obtain the [`ConnectionTicker`] from the state.
    fn connection_ticker(&self) -> &ConnectionTicker;
}

/// Callback for use with
/// [`lightway_core::Connection::schedule_tick_cb`] and
pub fn connection_ticker_cb<AppState: ConnectionTickerState>(
    d: std::time::Duration,
    state: &mut AppState,
) {
    state.connection_ticker().schedule(d);
}

/// Embed this into a [`Connection`]'s `AppState` and call
/// [`ConnectionTicker::schedule`] from your
/// `lightway_core::ScheduleTickCb` implementation. `tick_channel_cb`
/// is a helper callback.
pub struct ConnectionTicker(mpsc::UnboundedSender<()>);

impl ConnectionTicker {
    /// Create a new [`ConnectionTicker`]. Once the connection is built
    /// call [`ConnectionTickerTask::spawn`] with a `Weak` reference to
    /// it.
    pub fn new() -> (Self, ConnectionTickerTask) {
        let (send, recv) = mpsc::unbounded_channel();

        (Self(send), ConnectionTickerTask(recv))
    }

    /// Schedule a tick.
    pub fn schedule(&self, d: Duration) {
        let sender = self.0.clone();
        tokio::spawn(async move {
            tokio::time::sleep(d).await;
            if let Err(e) = sender.send(()) {
                warn!("Ticker send error: {:?}", e);
            }
        });
    }
}

/// Allow [`ConnectionTicker`] to be used as `AppState` directly.
impl ConnectionTickerState for ConnectionTicker {
    fn connection_ticker(&self) -> &ConnectionTicker {
        self
    }
}

/// Get a suitable `lightway_core::Connection` on which to call
/// `tick`.
pub trait Tickable: Send + Sync {
    /// Kick this tickable.
    fn tick(&self) -> ConnectionResult<()>;
}

impl<AppState: Send> Tickable for Mutex<Connection<AppState>> {
    fn tick(&self) -> ConnectionResult<()> {
        self.lock().unwrap().tick()
    }
}

/// Task which receives tick requests from channel and calls tick.
pub struct ConnectionTickerTask(mpsc::UnboundedReceiver<()>);

impl ConnectionTickerTask {
    /// Spawn the handler task
    pub fn spawn<T: Tickable + 'static>(self, weak: Weak<T>) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn(Self::task(weak, self.0))
    }

    /// Spawn the handler task in a JoinSet
    pub fn spawn_in<T: Tickable + 'static>(
        self,
        weak: Weak<T>,
        join_set: &mut JoinSet<()>,
    ) -> tokio::task::AbortHandle {
        join_set.spawn(Self::task(weak, self.0))
    }

    async fn task<T: Tickable + 'static>(weak: Weak<T>, mut recv: UnboundedReceiver<()>) {
        while let Some(()) = recv.recv().await {
            let Some(tickable) = weak.upgrade() else {
                break;
            };

            if let Err(e) = tickable.tick() {
                match e {
                    ConnectionError::TimedOut => {
                        warn!("DTLS connection timed out");
                        break;
                    }
                    _ => warn!("Connection tick failed: {e:?}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ticks() {
        use std::sync::{Arc, Mutex};
        use tokio::sync::oneshot;

        let (ticker, ticker_task) = ConnectionTicker::new();

        // We'll "tick" this channel
        let (tx, rx) = oneshot::channel();

        struct Dummy(Mutex<Option<oneshot::Sender<()>>>);

        impl Tickable for Dummy {
            fn tick(&self) -> ConnectionResult<()> {
                self.0.lock().unwrap().take().unwrap().send(()).unwrap();
                Ok(())
            }
        }

        let conn = Arc::new(Dummy(Mutex::new(Some(tx))));

        ticker_task.spawn(Arc::downgrade(&conn));

        ticker.schedule(Duration::ZERO);

        rx.await.unwrap(); // Should get the tick
    }

    #[tokio::test]
    async fn task_exits_when_ticker_released() {
        use std::sync::Arc;

        let (ticker, ticker_task) = ConnectionTicker::new();

        struct Dummy;

        impl Tickable for Dummy {
            fn tick(&self) -> ConnectionResult<()> {
                panic!("Not expecting to tick");
            }
        }

        let conn = Arc::new(Dummy);

        let task = ticker_task.spawn(Arc::downgrade(&conn));

        drop(ticker);

        task.await.unwrap(); // Task should exit cleanly
    }

    #[tokio::test]
    async fn task_exits_when_conn_released() {
        use std::sync::Arc;

        let (ticker, ticker_task) = ConnectionTicker::new();

        struct Dummy;

        impl Tickable for Dummy {
            fn tick(&self) -> ConnectionResult<()> {
                panic!("Not expecting to tick");
            }
        }

        let conn = Arc::new(Dummy);

        let task = ticker_task.spawn(Arc::downgrade(&conn));

        drop(conn);

        ticker.schedule(Duration::ZERO);

        task.await.unwrap(); // Task should exit cleanly
    }

    #[tokio::test]
    async fn joinset_ticks() {
        use std::sync::{Arc, Mutex};
        use tokio::sync::oneshot;

        let (ticker, ticker_task) = ConnectionTicker::new();

        // We'll "tick" this channel
        let (tx, rx) = oneshot::channel();

        struct Dummy(Mutex<Option<oneshot::Sender<()>>>);

        impl Tickable for Dummy {
            fn tick(&self) -> ConnectionResult<()> {
                self.0.lock().unwrap().take().unwrap().send(()).unwrap();
                Ok(())
            }
        }

        let conn = Arc::new(Dummy(Mutex::new(Some(tx))));
        let mut join_set = JoinSet::new();

        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        ticker.schedule(Duration::ZERO);

        rx.await.unwrap(); // Should get the tick
    }

    #[tokio::test]
    async fn joinset_task_exits_when_ticker_released() {
        use std::sync::Arc;

        let (ticker, ticker_task) = ConnectionTicker::new();

        struct Dummy;

        impl Tickable for Dummy {
            fn tick(&self) -> ConnectionResult<()> {
                panic!("Not expecting to tick");
            }
        }

        let conn = Arc::new(Dummy);
        let mut join_set = JoinSet::new();

        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        drop(ticker);

        while (join_set.join_next().await).is_some() {}
    }

    #[tokio::test]
    async fn joinset_task_exits_when_conn_released() {
        use std::sync::Arc;

        let (ticker, ticker_task) = ConnectionTicker::new();

        struct Dummy;

        impl Tickable for Dummy {
            fn tick(&self) -> ConnectionResult<()> {
                panic!("Not expecting to tick");
            }
        }

        let conn = Arc::new(Dummy);
        let mut join_set = JoinSet::new();

        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        drop(conn);

        ticker.schedule(Duration::ZERO);

        // Task should exit cleanly
        while (join_set.join_next().await).is_some() {}
    }
}
