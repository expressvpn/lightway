//! Provide `lightway_core::DplpmtudTimer` using Tokio
use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use lightway_core::{ConnectionResult, WolfsslConnection};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

/// Implements `lightway_core::DplpmtudTimer` using Tokio.
pub struct DplpmtudTimer {
    tick: mpsc::UnboundedSender<()>,
    running: Mutex<Option<CancellationToken>>,
}

impl DplpmtudTimer {
    /// Create a new [`DplpmtudTimer`]. Pass [`Self`] to
    /// [`lightway_core::ClientConnectionBuilder::with_pmtud_timer`].
    /// Once the connection is built call [`DplpmtudTimerTask::spawn`]
    /// with a weak reference to it.
    pub fn new() -> (Arc<Self>, DplpmtudTimerTask) {
        let (send, recv) = mpsc::unbounded_channel();

        (
            Arc::new(Self {
                tick: send,
                running: Mutex::new(None),
            }),
            DplpmtudTimerTask(recv),
        )
    }
}

impl<AppState> lightway_core::DplpmtudTimer<AppState> for DplpmtudTimer {
    fn start(&self, d: Duration, _state: &mut AppState) {
        let token = CancellationToken::new();
        if let Some(running) = self.running.lock().unwrap().replace(token.clone()) {
            running.cancel();
        }

        let sender = self.tick.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = token.cancelled() => {},
                _ = tokio::time::sleep(d) => {
                    let _ = sender.send(());
                }
            }
        });
    }

    fn stop(&self, _state: &mut AppState) {
        if let Some(running) = self.running.lock().unwrap().take() {
            running.cancel()
        }
    }
}

/// Get a suitable `lightway_core::Connection` on which to call
/// `pmtud_tick`.
pub trait DplpmtudTickable: Send + Sync {
    /// Kick.
    fn pmtud_tick(&self) -> ConnectionResult<()>;
}

impl<AppState: Send> DplpmtudTickable for Mutex<WolfsslConnection<AppState>> {
    fn pmtud_tick(&self) -> ConnectionResult<()> {
        self.lock().unwrap().pmtud_tick()
    }
}

/// Task which receives tick requests from channel and calls pmtud_tick.
pub struct DplpmtudTimerTask(mpsc::UnboundedReceiver<()>);

impl DplpmtudTimerTask {
    /// Spawn the handler task
    pub fn spawn<T: DplpmtudTickable + 'static>(
        self,
        weak: Weak<T>,
        join_set: &mut JoinSet<()>,
    ) -> tokio::task::AbortHandle {
        let mut ticks = self.0;
        join_set.spawn(async move {
            while let Some(()) = ticks.recv().await {
                let Some(tickable) = weak.upgrade() else {
                    return;
                };

                let _ = tickable.pmtud_tick();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use lightway_core::DplpmtudTimer as _;

    #[tokio::test]
    async fn ticks() {
        use std::sync::{Arc, Mutex};
        use tokio::sync::oneshot;

        let (timer, timer_task) = DplpmtudTimer::new();

        // We'll "tick" this channel
        let (tx, rx) = oneshot::channel();

        struct Dummy(Mutex<Option<oneshot::Sender<()>>>);

        impl DplpmtudTickable for Dummy {
            fn pmtud_tick(&self) -> ConnectionResult<()> {
                self.0.lock().unwrap().take().unwrap().send(()).unwrap();
                Ok(())
            }
        }

        let conn = Arc::new(Dummy(Mutex::new(Some(tx))));

        let mut join_set = JoinSet::new();

        timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

        timer.start(Duration::ZERO, &mut ());

        rx.await.unwrap(); // Should get the tick
    }

    #[tokio::test]
    async fn existing_timer_cancelled_when_new_timer_started() {
        use std::sync::{Arc, Mutex};
        use tokio::sync::oneshot;

        let (timer, timer_task) = DplpmtudTimer::new();

        // We'll "tick" this channel
        let (tx, rx) = oneshot::channel();

        struct Dummy(Mutex<Option<oneshot::Sender<()>>>);

        impl DplpmtudTickable for Dummy {
            fn pmtud_tick(&self) -> ConnectionResult<()> {
                self.0.lock().unwrap().take().unwrap().send(()).unwrap();
                Ok(())
            }
        }

        let conn = Arc::new(Dummy(Mutex::new(Some(tx))));

        let mut join_set = JoinSet::new();
        timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

        // this needs to be long enough that we can replace it before
        // it fires but slow enough that we can wait for it not to
        // happen below without the test taking too long.
        timer.start(Duration::from_millis(250), &mut ());

        // this should replace the 250ms timer above
        timer.start(Duration::ZERO, &mut ());

        rx.await.unwrap(); // Should get the tick

        // we should never see the 250ms timer from above fire, but if
        // it down the `pmtud_tick()` will panic in `.take().unwrap()`.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    #[tokio::test]
    async fn timer_can_be_stopped() {
        use std::sync::Arc;

        let (timer, timer_task) = DplpmtudTimer::new();

        struct Dummy;

        impl DplpmtudTickable for Dummy {
            fn pmtud_tick(&self) -> ConnectionResult<()> {
                panic!("Not expecting to tick");
            }
        }

        let conn = Arc::new(Dummy);

        let mut join_set = JoinSet::new();
        timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

        // this needs to be long enough that we can stop it before it
        // fires but slow enough that we can wait for it not to happen
        // below without the test taking too long.
        timer.start(Duration::from_millis(250), &mut ());

        // this should stop the 250ms timer
        timer.stop(&mut ());

        // we should never see the 250ms timer from above fire, but if
        // it down the `pmtud_tick()` will panic in `.take().unwrap()`.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    #[tokio::test]
    async fn task_exits_when_ticker_released() {
        use std::sync::Arc;

        let (timer, timer_task) = DplpmtudTimer::new();

        struct Dummy;

        impl DplpmtudTickable for Dummy {
            fn pmtud_tick(&self) -> ConnectionResult<()> {
                panic!("Not expecting to tick");
            }
        }

        let conn = Arc::new(Dummy);

        let mut join_set = JoinSet::new();
        timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

        drop(timer);

        // Should get the tick
        while (join_set.join_next().await).is_some() {}
    }

    #[tokio::test]
    async fn task_exits_when_conn_released() {
        use std::sync::Arc;

        let (timer, timer_task) = DplpmtudTimer::new();

        struct Dummy;

        impl DplpmtudTickable for Dummy {
            fn pmtud_tick(&self) -> ConnectionResult<()> {
                panic!("Not expecting to tick");
            }
        }

        let conn = Arc::new(Dummy);

        let mut join_set = JoinSet::new();
        timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

        drop(conn);

        timer.start(Duration::ZERO, &mut ());

        // Should get the tick
        while (join_set.join_next().await).is_some() {}
    }
}
