//! Provide `lightway_core::DplpmtudTimer` using Tokio
use std::{
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use lightway_core::{Connection, ConnectionResult};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

/// Implements `lightway_core::DplpmtudTimer` using Tokio.
pub struct DplpmtudTimer {
    tick: mpsc::UnboundedSender<u64>,
    running: Mutex<Option<CancellationToken>>,
    /// Bumped by every `start()` and `stop()`. Each tick carries the
    /// generation which armed it, so that a tick still queued when the
    /// timer is restarted or stopped can be dropped.
    generation: Arc<AtomicU64>,
}

impl DplpmtudTimer {
    /// Create a new [`DplpmtudTimer`]. Pass [`Self`] to
    /// [`lightway_core::ClientConnectionBuilder::with_pmtud_timer`].
    /// Once the connection is built call [`DplpmtudTimerTask::spawn`]
    /// with a weak reference to it.
    pub fn new() -> (Arc<Self>, DplpmtudTimerTask) {
        let (send, recv) = mpsc::unbounded_channel();
        let generation = Arc::new(AtomicU64::new(0));

        (
            Arc::new(Self {
                tick: send,
                running: Mutex::new(None),
                generation: generation.clone(),
            }),
            DplpmtudTimerTask {
                ticks: recv,
                generation,
            },
        )
    }

    /// Cancel any running timer, replacing it with `token`, and return
    /// the new generation.
    fn replace_running(&self, token: Option<CancellationToken>) -> u64 {
        let mut running = self.running.lock().unwrap();
        if let Some(running) = std::mem::replace(&mut *running, token) {
            running.cancel();
        }
        self.generation.fetch_add(1, Ordering::Relaxed) + 1
    }
}

impl<AppState> lightway_core::DplpmtudTimer<AppState> for DplpmtudTimer {
    fn start(&self, d: Duration, _state: &mut AppState) {
        let token = CancellationToken::new();
        let generation = self.replace_running(Some(token.clone()));

        let sender = self.tick.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = token.cancelled() => {},
                _ = tokio::time::sleep(d) => {
                    let _ = sender.send(generation);
                }
            }
        });
    }

    fn stop(&self, _state: &mut AppState) {
        self.replace_running(None);
    }
}

/// Get a suitable `lightway_core::Connection` on which to call
/// `pmtud_tick`.
pub trait DplpmtudTickable: Send + Sync {
    /// Kick, if `current()` still holds once the connection is locked.
    fn pmtud_tick(&self, current: impl FnOnce() -> bool) -> ConnectionResult<()>;
}

impl<AppState: Send> DplpmtudTickable for Mutex<Connection<AppState>> {
    fn pmtud_tick(&self, current: impl FnOnce() -> bool) -> ConnectionResult<()> {
        let mut conn = self.lock().unwrap();
        // The timer is started and stopped under this lock, so no
        // restart can slip in between the check and the tick.
        if !current() {
            return Ok(());
        }
        conn.pmtud_tick()
    }
}

/// Task which receives tick requests from channel and calls pmtud_tick.
pub struct DplpmtudTimerTask {
    ticks: mpsc::UnboundedReceiver<u64>,
    generation: Arc<AtomicU64>,
}

impl DplpmtudTimerTask {
    /// Spawn the handler task
    pub fn spawn<T: DplpmtudTickable + 'static>(
        self,
        weak: Weak<T>,
        join_set: &mut JoinSet<()>,
    ) -> tokio::task::AbortHandle {
        let Self {
            mut ticks,
            generation,
        } = self;
        join_set.spawn(async move {
            while let Some(tick) = ticks.recv().await {
                let Some(tickable) = weak.upgrade() else {
                    return;
                };

                // Drop the tick if the timer was restarted or stopped
                // after it was queued, including while waiting for the
                // connection lock.
                let _ = tickable.pmtud_tick(|| tick == generation.load(Ordering::Relaxed));
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
            fn pmtud_tick(&self, _current: impl FnOnce() -> bool) -> ConnectionResult<()> {
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
            fn pmtud_tick(&self, _current: impl FnOnce() -> bool) -> ConnectionResult<()> {
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
            fn pmtud_tick(&self, _current: impl FnOnce() -> bool) -> ConnectionResult<()> {
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

    /// Start a zero length timer and wait until its tick is queued,
    /// before anything is draining the queue.
    async fn queue_tick(timer: &DplpmtudTimer, timer_task: &DplpmtudTimerTask) {
        timer.start(Duration::ZERO, &mut ());
        while timer_task.ticks.is_empty() {
            tokio::task::yield_now().await;
        }
    }

    /// Release `timer`, then run `timer_task` until it has handled every
    /// queued tick. Returns the number of ticks delivered.
    async fn deliver_ticks(timer: Arc<DplpmtudTimer>, timer_task: DplpmtudTimerTask) -> usize {
        use std::sync::atomic::AtomicUsize;

        struct Counter(AtomicUsize);

        impl DplpmtudTickable for Counter {
            fn pmtud_tick(&self, current: impl FnOnce() -> bool) -> ConnectionResult<()> {
                if current() {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }
        }

        let conn = Arc::new(Counter(AtomicUsize::new(0)));

        let mut join_set = JoinSet::new();
        timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

        // The task exits once the timer and all its sleeps have gone.
        drop(timer);
        while (join_set.join_next().await).is_some() {}

        conn.0.load(Ordering::Relaxed)
    }

    #[tokio::test]
    async fn queued_tick_dropped_when_new_timer_started() {
        let (timer, timer_task) = DplpmtudTimer::new();

        queue_tick(&timer, &timer_task).await;

        // Replaces the timer whose tick is already queued
        timer.start(Duration::ZERO, &mut ());

        // Only the new timer ticks
        assert_eq!(deliver_ticks(timer, timer_task).await, 1);
    }

    #[tokio::test]
    async fn queued_tick_dropped_when_timer_stopped() {
        let (timer, timer_task) = DplpmtudTimer::new();

        queue_tick(&timer, &timer_task).await;

        // Stops the timer whose tick is already queued
        timer.stop(&mut ());

        assert_eq!(deliver_ticks(timer, timer_task).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tick_dropped_when_new_timer_started_while_waiting_for_lock() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};

        /// Stands in for `Mutex<Connection>`.
        struct Conn {
            lock: Mutex<()>,
            waiting: AtomicBool,
            ticks: AtomicUsize,
        }

        impl DplpmtudTickable for Conn {
            fn pmtud_tick(&self, current: impl FnOnce() -> bool) -> ConnectionResult<()> {
                self.waiting.store(true, Ordering::Relaxed);
                let _conn = self.lock.lock().unwrap();
                if current() {
                    self.ticks.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }
        }

        let (timer, timer_task) = DplpmtudTimer::new();
        let conn = Arc::new(Conn {
            lock: Mutex::new(()),
            waiting: AtomicBool::new(false),
            ticks: AtomicUsize::new(0),
        });

        let mut join_set = JoinSet::new();
        timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

        // The timer expires while the connection is locked, so its tick
        // waits for the lock...
        let guard = conn.lock.lock().unwrap();
        timer.start(Duration::ZERO, &mut ());
        let start = std::time::Instant::now();
        while !conn.waiting.load(Ordering::Relaxed) {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::yield_now();
        }

        // ...and the lock holder replaces the timer.
        timer.start(Duration::ZERO, &mut ());
        drop(guard);

        // Only the new timer ticks
        drop(timer);
        while (join_set.join_next().await).is_some() {}
        assert_eq!(conn.ticks.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn task_exits_when_ticker_released() {
        use std::sync::Arc;

        let (timer, timer_task) = DplpmtudTimer::new();

        struct Dummy;

        impl DplpmtudTickable for Dummy {
            fn pmtud_tick(&self, _current: impl FnOnce() -> bool) -> ConnectionResult<()> {
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
            fn pmtud_tick(&self, _current: impl FnOnce() -> bool) -> ConnectionResult<()> {
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
