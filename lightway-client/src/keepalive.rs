//! Keepalive processing
use futures::{FutureExt, future::FusedFuture, future::OptionFuture};
use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::ConnectionState;

pub trait Connection: Send {
    fn keepalive(&self) -> lightway_core::ConnectionResult<()>;
}

impl<T: Send + Sync> Connection for Weak<Mutex<lightway_core::Connection<ConnectionState<T>>>> {
    fn keepalive(&self) -> lightway_core::ConnectionResult<()> {
        let Some(conn) = self.upgrade() else {
            return Ok(());
        };
        let mut conn = conn.lock().unwrap();
        conn.keepalive()
    }
}

pub trait SleepManager: Send {
    fn sleep_for_interval(&self) -> impl std::future::Future<Output = ()> + std::marker::Send;
    fn sleep_for_timeout(&self) -> impl std::future::Future<Output = ()> + std::marker::Send;
    fn continuous(&self) -> bool;
}

#[derive(Clone)]
pub struct Config {
    pub interval: Duration,
    pub timeout: Duration,
    pub continuous: bool,
    pub tracer_trigger_timeout: Option<Duration>,
}

impl SleepManager for Config {
    async fn sleep_for_interval(&self) {
        tokio::time::sleep(self.interval).await
    }

    async fn sleep_for_timeout(&self) {
        tokio::time::sleep(self.timeout).await
    }

    fn continuous(&self) -> bool {
        self.continuous
    }
}

#[derive(Debug)]
pub enum Message {
    Online,
    OutsideActivity,
    ReplyReceived,
    NetworkChange,
    TracerDeltaExceeded,
    Suspend,
}

pub enum KeepaliveResult {
    Cancelled,
    Timedout,
}

#[derive(Clone)]
pub struct Keepalive {
    tx: mpsc::Sender<Message>,
    _cancellation: Arc<DropGuard>,
}

impl Keepalive {
    /// Create a new keepalive manager for the given connection
    pub fn new<CONFIG: SleepManager + 'static, CONNECTION: Connection + 'static>(
        config: CONFIG,
        conn: CONNECTION,
    ) -> (Self, OptionFuture<JoinHandle<KeepaliveResult>>) {
        let cancel = CancellationToken::new();

        let (tx, rx) = mpsc::channel(1024);
        let task = tokio::spawn(keepalive(config, conn, rx, cancel.clone()));
        let cancel = Arc::new(cancel.drop_guard());
        (
            Self {
                tx,
                _cancellation: cancel,
            },
            Some(task).into(),
        )
    }

    /// Signal that the connection is now online
    pub async fn online(&self) {
        let _ = self.tx.send(Message::Online).await;
    }

    /// Signal that outside activity was observed
    pub async fn outside_activity(&self) {
        let _ = self.tx.try_send(Message::OutsideActivity);
    }

    /// Signal that a pong was received
    pub async fn reply_received(&self) {
        let _ = self.tx.send(Message::ReplyReceived).await;
    }

    /// Signal that the network has changed.
    /// In the case we are offline, this will start the keepalives immediately
    /// Otherwise this will reset our timeouts
    pub async fn network_changed(&self) {
        let _ = self.tx.send(Message::NetworkChange).await;
    }

    /// Signal that we haven't heard from server in a while
    /// This will trigger a keepalive immediately if keepalive is not suspended.
    pub async fn tracer_delta_exceeded(&self) {
        let _ = self.tx.send(Message::TracerDeltaExceeded).await;
    }

    /// Signal to suspend keepalives.
    /// Suspends the sleep interval timer if it's active.
    pub async fn suspend(&self) {
        let _ = self.tx.send(Message::Suspend).await;
    }
}

async fn keepalive<CONFIG: SleepManager, CONNECTION: Connection>(
    config: CONFIG,
    conn: CONNECTION,
    mut rx: mpsc::Receiver<Message>,
    token: CancellationToken,
) -> KeepaliveResult {
    enum State {
        // Keepalive is suspended
        Suspended,
        // No pending keepalive
        Inactive,
        // Need to send keepalive immediately
        Needed,
        // We are waiting between keepalive intervals
        Waiting,
        // A keepalive has been sent, reply is pending
        Pending,
    }

    let mut state = State::Inactive;

    // Unlike the interval timeout this should not be reset if the
    // select picks a different case.
    let timeout: OptionFuture<_> = None.into();
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                tracing::debug!("Keepalive cancelled");
                return KeepaliveResult::Cancelled;
            }
            Some(msg) = rx.recv() => {
                match msg {
                    Message::Online => {
                        if matches!(state, State::Inactive | State::Suspended) && config.continuous() {
                            tracing::info!("Starting keepalives");
                            state = State::Waiting;
                        }
                    },
                    Message::OutsideActivity => {
                        // The interval timer is restarted on the next
                        // iteration of the loop. IOW just by taking
                        // this branch of the select we have achieved
                        // the aim of not sending keepalives if there
                        // is active traffic.
                        timeout.as_mut().set(None.into());
                        continue
                    },
                    Message::ReplyReceived => {
                        state = if config.continuous() {
                            State::Waiting
                        } else {
                            tracing::info!("reply received turning off network change keepalives");
                            State::Inactive
                        };
                        timeout.as_mut().set(None.into())
                    },
                    Message::NetworkChange => {
                        if !matches!(state, State::Pending) {
                            tracing::info!("sending keepalives because of {:?}", msg);
                            state = State::Needed;
                        }
                    },
                    Message::TracerDeltaExceeded => {
                        // Do not trigger keepalive if it is suspended or waiting for reply
                        if !matches!(state, State::Pending | State::Suspended) {
                            tracing::info!("sending keepalives because of {:?}", msg);
                            state = State::Needed;
                        }
                    }
                    Message::Suspend => {
                        // Suspend keepalives whenever the timer is active
                        tracing::info!("suspending keepalives");
                        state = State::Suspended;
                        timeout.as_mut().set(None.into())
                    },
                }
            }

            _ = futures::future::ready(()), if matches!(state, State::Needed) => {
                if let Err(e) = conn.keepalive() {
                    tracing::error!("Send Keepalive failed: {e:?}");
                }
                state = State::Pending;
                if timeout.is_terminated() {
                    let fut = config.sleep_for_timeout().fuse();
                    timeout.as_mut().set(Some(fut).into());
                }
            }

            _ = config.sleep_for_interval(), if matches!(state, State::Pending | State::Waiting) => {
                if let Err(e) = conn.keepalive() {
                    tracing::error!("Send Keepalive failed: {e:?}");
                }
                state = State::Pending;
                if timeout.is_terminated() {
                    let fut = config.sleep_for_timeout().fuse();
                    timeout.as_mut().set(Some(fut).into());
                }
            }

            // Note that `timeout` is `Some` only when state == `State::Pending`
            // Evaluates to `None` otherwise.
            Some(_) = timeout.as_mut() => {
                tracing::warn!("keepalive timed out");
                // Return will exit the client
                return KeepaliveResult::Timedout;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use test_case::test_case;
    use tokio::sync::Notify;
    use tokio::time::sleep;

    /// Mock connection that tracks keepalive calls
    #[derive(Clone)]
    struct MockConnection {
        keepalive_count: Arc<AtomicUsize>,
    }

    impl MockConnection {
        fn new() -> Self {
            Self {
                keepalive_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn keepalive_count(&self) -> usize {
            self.keepalive_count.load(Ordering::SeqCst)
        }
    }

    impl Connection for MockConnection {
        fn keepalive(&self) -> lightway_core::ConnectionResult<()> {
            self.keepalive_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Controllable sleep manager for deterministic testing
    #[derive(Clone)]
    struct MockSleepManager {
        interval: Duration,
        timeout: Duration,
        continuous: bool,
        interval_trigger: Arc<Notify>,
        timeout_trigger: Arc<Notify>,
    }

    impl MockSleepManager {
        fn new(interval: Duration, timeout: Duration, continuous: bool) -> Self {
            Self {
                interval,
                timeout,
                continuous,
                interval_trigger: Arc::new(Notify::new()),
                timeout_trigger: Arc::new(Notify::new()),
            }
        }

        fn trigger_interval(&self) {
            self.interval_trigger.notify_one();
        }

        fn trigger_timeout(&self) {
            self.timeout_trigger.notify_one();
        }
    }

    impl SleepManager for MockSleepManager {
        async fn sleep_for_interval(&self) {
            if self.interval.is_zero() {
                return;
            }
            self.interval_trigger.notified().await;
        }

        async fn sleep_for_timeout(&self) {
            if self.timeout.is_zero() {
                return;
            }
            self.timeout_trigger.notified().await;
        }

        fn continuous(&self) -> bool {
            self.continuous
        }
    }

    /// start keepalives based on mode
    async fn start_keepalives(
        keepalive: &Keepalive,
        sleep_manager: &MockSleepManager,
        continuous: bool,
    ) {
        if continuous {
            keepalive.online().await;
            sleep(Duration::from_millis(10)).await;
            // Trigger keepalive by kicking interval
            sleep_manager.trigger_interval();
            sleep(Duration::from_millis(10)).await;
        } else {
            keepalive.network_changed().await;
            sleep(Duration::from_millis(10)).await;
        }
    }

    /// Test helper for setting up keepalive scenarios
    struct KeepaliveTestBuilder {
        interval: Duration,
        timeout: Duration,
        continuous: bool,
    }

    impl KeepaliveTestBuilder {
        fn new() -> Self {
            Self {
                interval: Duration::from_millis(100),
                timeout: Duration::from_millis(200),
                continuous: true,
            }
        }

        fn continuous(mut self, continuous: bool) -> Self {
            self.continuous = continuous;
            self
        }

        fn build(self) -> (MockSleepManager, MockConnection) {
            let sleep_manager = MockSleepManager::new(self.interval, self.timeout, self.continuous);
            let connection = MockConnection::new();
            (sleep_manager, connection)
        }
    }

    #[test_case(true, 1; "continuous")]
    #[test_case(false, 2; "non-continuous")]
    #[tokio::test]
    async fn keepalive_activation(continuous: bool, exp_count: usize) {
        let (sleep_manager, connection) =
            KeepaliveTestBuilder::new().continuous(continuous).build();

        let (keepalive, task) = Keepalive::new(sleep_manager.clone(), connection.clone());

        if continuous {
            keepalive.online().await;
            sleep(Duration::from_millis(10)).await;

            // For Online, keepalive will not be sent immediately
            assert_eq!(connection.keepalive_count(), 0);
        } else {
            keepalive.network_changed().await;
            sleep(Duration::from_millis(10)).await;
            // For NetworkChange, keepalive will be sent immediately
            assert_eq!(connection.keepalive_count(), 1);
        }

        sleep_manager.trigger_interval();
        sleep(Duration::from_millis(10)).await;

        // Now, both modes keepalive count should have been incremented by 1
        assert_eq!(connection.keepalive_count(), exp_count);

        drop(keepalive);
        let result = task.await.unwrap().unwrap();
        assert!(matches!(result, KeepaliveResult::Cancelled));
    }

    #[test_case(true, 0; "continuous")]
    #[test_case(false, 1; "non-continuous")]
    #[tokio::test]
    async fn multiple_keepalives_sent_at_intervals(continuous: bool, exp_start: usize) {
        let (sleep_manager, connection) =
            KeepaliveTestBuilder::new().continuous(continuous).build();

        let (keepalive, task) = Keepalive::new(sleep_manager.clone(), connection.clone());

        if continuous {
            keepalive.online().await;
            sleep(Duration::from_millis(10)).await;
        } else {
            keepalive.network_changed().await;
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(connection.keepalive_count(), exp_start);

        // Trigger multiple intervals and verify keepalive count
        for i in 1..=5 {
            sleep_manager.trigger_interval();
            sleep(Duration::from_millis(10)).await;
            assert_eq!(connection.keepalive_count(), exp_start + i);
        }

        drop(keepalive);
        let result = task.await.unwrap().unwrap();
        assert!(matches!(result, KeepaliveResult::Cancelled));
    }

    #[test_case(true; "continuous")]
    #[test_case(false; "non-continuous")]
    #[tokio::test]
    async fn timeout_causes_task_termination(continuous: bool) {
        let (sleep_manager, connection) =
            KeepaliveTestBuilder::new().continuous(continuous).build();

        let (keepalive, task) = Keepalive::new(sleep_manager.clone(), connection.clone());

        start_keepalives(&keepalive, &sleep_manager, continuous).await;
        assert_eq!(connection.keepalive_count(), 1);

        sleep_manager.trigger_timeout();

        let result = task.await.unwrap().unwrap();
        assert!(matches!(result, KeepaliveResult::Timedout));
    }

    #[test_case(true, 2; "continuous")]
    #[test_case(false, 1; "non-continuous")]
    #[tokio::test]
    async fn reply_received_behavior(continuous: bool, exp_count: usize) {
        let (sleep_manager, connection) =
            KeepaliveTestBuilder::new().continuous(continuous).build();

        let (keepalive, task) = Keepalive::new(sleep_manager.clone(), connection.clone());
        start_keepalives(&keepalive, &sleep_manager, continuous).await;
        assert_eq!(connection.keepalive_count(), 1);

        // Reply received - behavior differs between modes
        keepalive.reply_received().await;
        sleep(Duration::from_millis(10)).await;

        // Verify keepalive count has not increased
        assert_eq!(connection.keepalive_count(), 1);

        // Trigger interval to test post-reply behavior
        sleep_manager.trigger_interval();
        sleep(Duration::from_millis(10)).await;

        // For continuous, after reply, interval triger will increase
        // For non continuous, after reply, no more keepalives sent
        assert_eq!(connection.keepalive_count(), exp_count);

        drop(keepalive);
        let result = task.await.unwrap().unwrap();
        assert!(matches!(result, KeepaliveResult::Cancelled));
    }

    #[test_case(true; "continuous")]
    #[test_case(false; "non-continuous")]
    #[tokio::test]
    async fn outside_activity_resets_interval(continuous: bool) {
        let (sleep_manager, connection) =
            KeepaliveTestBuilder::new().continuous(continuous).build();

        let (keepalive, task) = Keepalive::new(sleep_manager.clone(), connection.clone());
        start_keepalives(&keepalive, &sleep_manager, continuous).await;

        // Outside activity should reset interval timer but not affect timeout
        keepalive.outside_activity().await;
        sleep(Duration::from_millis(10)).await;

        // Trigger interval - should still send keepalive
        sleep_manager.trigger_interval();
        sleep(Duration::from_millis(10)).await;

        assert_eq!(connection.keepalive_count(), 2);

        drop(keepalive);
        let result = task.await.unwrap().unwrap();
        assert!(matches!(result, KeepaliveResult::Cancelled));
    }

    #[test_case(true; "continuous")]
    #[test_case(false; "non-continuous")]
    #[tokio::test]
    async fn suspend_stops_keepalives(continuous: bool) {
        let (sleep_manager, connection) =
            KeepaliveTestBuilder::new().continuous(continuous).build();

        let (keepalive, task) = Keepalive::new(sleep_manager.clone(), connection.clone());
        start_keepalives(&keepalive, &sleep_manager, continuous).await;
        assert_eq!(connection.keepalive_count(), 1);

        // Suspend keepalives
        keepalive.suspend().await;
        sleep(Duration::from_millis(10)).await;

        // Trigger interval - should not send keepalive while suspended
        sleep_manager.trigger_interval();
        sleep(Duration::from_millis(10)).await;

        assert_eq!(connection.keepalive_count(), 1);

        drop(keepalive);
        let result = task.await.unwrap().unwrap();
        assert!(matches!(result, KeepaliveResult::Cancelled));
    }

    #[test_case(true; "continuous")]
    #[test_case(false; "non-continuous")]
    #[tokio::test]
    async fn tracer_delta_exceeded_should_not_trigger_suspended_keepalive(continuous: bool) {
        let (sleep_manager, connection) =
            KeepaliveTestBuilder::new().continuous(continuous).build();

        let (keepalive, task) = Keepalive::new(sleep_manager.clone(), connection.clone());
        start_keepalives(&keepalive, &sleep_manager, continuous).await;
        assert_eq!(connection.keepalive_count(), 1);

        // Suspend keepalives
        keepalive.suspend().await;
        sleep(Duration::from_millis(10)).await;

        // Send out a `TracerDeltaExceeded` event
        keepalive.tracer_delta_exceeded().await;
        sleep(Duration::from_millis(10)).await;

        assert_eq!(connection.keepalive_count(), 1);

        drop(keepalive);
        let result = task.await.unwrap().unwrap();
        assert!(matches!(result, KeepaliveResult::Cancelled));
    }

    #[test_case(true; "continuous")]
    #[test_case(false; "non-continuous")]
    #[tokio::test]
    async fn suspend_and_resume(continuous: bool) {
        let (sleep_manager, connection) =
            KeepaliveTestBuilder::new().continuous(continuous).build();

        let (keepalive, task) = Keepalive::new(sleep_manager.clone(), connection.clone());

        start_keepalives(&keepalive, &sleep_manager, continuous).await;
        assert_eq!(connection.keepalive_count(), 1);

        // Suspend
        keepalive.suspend().await;
        sleep(Duration::from_millis(10)).await;

        // Resume with the appropriate trigger based on mode
        start_keepalives(&keepalive, &sleep_manager, continuous).await;

        assert_eq!(connection.keepalive_count(), 2);

        drop(keepalive);
        let result = task.await.unwrap().unwrap();
        assert!(matches!(result, KeepaliveResult::Cancelled));
    }

    #[test_case(true; "continuous")]
    #[test_case(false; "non-continuous")]
    #[tokio::test]
    async fn task_cancellation_on_drop(continuous: bool) {
        let (sleep_manager, connection) =
            KeepaliveTestBuilder::new().continuous(continuous).build();

        let (keepalive, task) = Keepalive::new(sleep_manager.clone(), connection.clone());

        start_keepalives(&keepalive, &sleep_manager, continuous).await;

        // Drop keepalive to cancel task
        drop(keepalive);

        let result = task.await.unwrap().unwrap();
        assert!(matches!(result, KeepaliveResult::Cancelled));
    }
}
