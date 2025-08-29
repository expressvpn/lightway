//! Keepalive processing
use futures::future::OptionFuture;
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
    fn interval_is_zero(&self) -> bool;
    fn timeout_is_zero(&self) -> bool;
    fn sleep_for_interval(&self) -> impl std::future::Future<Output = ()> + std::marker::Send;
    fn sleep_for_timeout(&self) -> impl std::future::Future<Output = ()> + std::marker::Send;
    fn continuous(&self) -> bool;
}

#[derive(Clone)]
pub struct Config {
    pub interval: Duration,
    pub timeout: Duration,
    pub continuous: bool,
}

impl SleepManager for Config {
    fn interval_is_zero(&self) -> bool {
        self.interval.is_zero()
    }

    fn timeout_is_zero(&self) -> bool {
        self.timeout.is_zero()
    }

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

pub enum Message {
    Online,
    OutsideActivity,
    ReplyReceived,
    NetworkChange,
    Suspend,
}

pub enum KeepaliveResult {
    Cancelled,
    Timedout,
}

#[derive(Clone)]
pub struct Keepalive {
    tx: Option<mpsc::Sender<Message>>,
    _cancellation: Arc<DropGuard>,
}

impl Keepalive {
    /// Create a new keepalive manager for the given connection
    pub fn new<CONFIG: SleepManager + 'static, CONNECTION: Connection + 'static>(
        config: CONFIG,
        conn: CONNECTION,
    ) -> (Self, OptionFuture<JoinHandle<KeepaliveResult>>) {
        let cancel = CancellationToken::new();

        if config.interval_is_zero() {
            return (
                Self {
                    tx: None,
                    _cancellation: Arc::new(cancel.drop_guard()),
                },
                None.into(),
            );
        }

        let (tx, rx) = mpsc::channel(1024);
        let task = tokio::spawn(keepalive(config, conn, rx, cancel.clone()));
        let cancel = Arc::new(cancel.drop_guard());
        (
            Self {
                tx: Some(tx),
                _cancellation: cancel,
            },
            Some(task).into(),
        )
    }

    /// Signal that the connection is now online
    pub async fn online(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Message::Online).await;
        }
    }

    /// Signal that outside activity was observed
    pub async fn outside_activity(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.try_send(Message::OutsideActivity);
        }
    }

    /// Signal that a pong was received
    pub async fn reply_received(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Message::ReplyReceived).await;
        }
    }

    /// Signal that the network has changed.
    /// In the case we are offline, this will start the keepalives
    /// Otherwise this will reset our timeouts
    pub async fn network_changed(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Message::NetworkChange).await;
        }
    }

    /// Signal to suspend keepalives.
    /// Suspends the sleep interval timer if it's active.
    pub async fn suspend(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Message::Suspend).await;
        }
    }
}

async fn keepalive<CONFIG: SleepManager, CONNECTION: Connection>(
    config: CONFIG,
    conn: CONNECTION,
    mut rx: mpsc::Receiver<Message>,
    token: CancellationToken,
) -> KeepaliveResult {
    enum State {
        // No pending keepalive
        Inactive,
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
                    Message::Online  => {
                        if matches!(state, State::Inactive) && config.continuous() {
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
                        //
                        // On the other hand the timeout timer is not
                        // restarted, if a ping has been sent then a
                        // pong is required even in the presence of
                        // other outside traffic. This helps to catch
                        // connectivity issues even if traffic is
                        // flowing only in one direction.
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
                        // In the case we are Offline this will start
                        // the keepalives otherwise this will
                        // reset our timeouts
                        tracing::info!("network change keepalives");
                        state = State::Waiting;
                        timeout.as_mut().set(None.into())
                    },
                    Message::Suspend => {
                        // Suspend keepalives whenever the timer is active
                        if matches!(state, State::Waiting | State::Pending) {
                            tracing::info!("suspending keepalives");
                            state = State::Inactive;
                            timeout.as_mut().set(None.into())
                        }
                    },
                }
            }

            _ = config.sleep_for_interval(), if matches!(state, State::Waiting | State::Pending) => {
                if let Err(e) = conn.keepalive() {
                    tracing::error!("Send Keepalive failed: {e:?}");
                }
                if matches!(state, State::Waiting) && !config.timeout_is_zero() {
                    state = State::Pending;
                    let fut = config.sleep_for_timeout();
                    timeout.as_mut().set(Some(fut).into());
                }
            }

            // Note that `timeout` is `Some` only when state ==
            // `State::Pending` and `config.timeout` is non-zero and
            // evaluates to `None` otherwise.
            Some(_) = timeout.as_mut() => {
                tracing::info!("keep alives timed out");
                // Return will exit the client
                return KeepaliveResult::Timedout;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use more_asserts::*;
    use std::collections::VecDeque;
    use test_case::test_case;
    use tokio::sync::{Mutex as TokioMutex, mpsc, oneshot};

    #[derive(Copy, Clone, Debug)]
    enum FixtureEvent {
        Wait,
        Online,
        IntervalExpired,
        ReplyReceived,
        OutsideActivity,
        NetworkChange,
        TimeoutExpired,
        Suspend,
    }

    struct FixtureState {
        events: VecDeque<FixtureEvent>,
        sleep_requests: usize,
        keepalive_count: usize,
        done: mpsc::UnboundedSender<()>,
        pending_interval: Option<oneshot::Sender<()>>,
        pending_timeout: Option<oneshot::Sender<()>>,
        continuous: bool,
    }

    impl FixtureState {
        fn sleep_event(&mut self) {
            let Some(ev) = self.events.front() else {
                return;
            };

            // In order to operate in lockstep with the keepalive task
            // we model which timers the keepalive main loop is
            // expected to become armed on each iteration.
            //
            // Most events just expect the interval timer to be
            // created (since it is recreated on every loop).
            //
            // `TimeoutExpired` must follow `IntervalExpired` and in
            // this case both timers are primed, the timeout while
            // handling interval expiration and then interval again on
            // the next iteration of the loop.
            //
            // Note that `tokio::select` always executes the
            // expression of each branch, even if the guard condition
            // is false (it just never polls the resulting future in
            // that case). This is why one timer is expected even for
            // `Online`.
            let required_sleeps = if matches!(ev, FixtureEvent::TimeoutExpired) {
                2
            } else {
                1
            };

            assert_lt!(self.sleep_requests, required_sleeps);

            self.sleep_requests += 1;

            if self.sleep_requests == required_sleeps {
                println!("ev {ev:?} is complete");
                self.sleep_requests = 0;
                self.events.pop_front();
                self.done.send(()).unwrap();
            } else {
                println!("ev {ev:?} still waiting");
            }
        }
    }

    #[derive(Clone)]
    struct Fixture(
        Arc<Mutex<FixtureState>>,
        Arc<TokioMutex<mpsc::UnboundedReceiver<()>>>,
    );

    impl Fixture {
        fn new(value: Vec<FixtureEvent>, continuous: bool) -> Self {
            let (tx, rx) = mpsc::unbounded_channel();

            Self(
                Arc::new(Mutex::new(FixtureState {
                    events: value.into(),
                    sleep_requests: 0,
                    keepalive_count: 0,
                    done: tx,
                    pending_interval: None,
                    pending_timeout: None,
                    continuous,
                })),
                Arc::new(TokioMutex::new(rx)),
            )
        }

        fn event(&self) -> Option<FixtureEvent> {
            let inner = self.0.lock().unwrap();
            inner.events.front().copied()
        }

        fn keepalive_count(&self) -> usize {
            self.0.lock().unwrap().keepalive_count
        }

        fn interval_expired(&self) {
            println!("Interval expired");
            let mut inner = self.0.lock().unwrap();
            let tx = inner.pending_interval.take().unwrap();
            tx.send(()).unwrap();
        }

        fn timeout_expired(&self) {
            println!("Timeout expired");
            let mut inner = self.0.lock().unwrap();
            let tx = inner.pending_timeout.take().unwrap();
            tx.send(()).unwrap();
        }

        async fn run(&self) -> (Keepalive, OptionFuture<JoinHandle<KeepaliveResult>>) {
            let (keepalive, task) = Keepalive::new(self.clone(), self.clone());

            loop {
                let Some(ev) = self.event() else { break };
                println!("run: wait for tick: {ev:?}");
                self.1.lock().await.recv().await.unwrap();
                println!("run: handle {ev:?}");
                match ev {
                    FixtureEvent::Online => keepalive.online().await,
                    FixtureEvent::IntervalExpired => self.interval_expired(),
                    FixtureEvent::ReplyReceived => keepalive.reply_received().await,
                    FixtureEvent::OutsideActivity => keepalive.outside_activity().await,
                    FixtureEvent::NetworkChange => keepalive.network_changed().await,
                    FixtureEvent::TimeoutExpired => self.timeout_expired(),
                    FixtureEvent::Suspend => keepalive.suspend().await,
                    FixtureEvent::Wait => {}
                }
            }

            (keepalive, task)
        }
    }

    impl SleepManager for Fixture {
        fn interval_is_zero(&self) -> bool {
            println!("interval_is_zero");
            self.0.lock().unwrap().events.is_empty()
        }

        fn timeout_is_zero(&self) -> bool {
            println!("timeout_is_zero");
            !self
                .0
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|ev| matches!(ev, FixtureEvent::TimeoutExpired))
        }

        fn sleep_for_interval(&self) -> impl futures::Future<Output = ()> + std::marker::Send {
            println!("sleep_for_interval");
            let mut inner = self.0.lock().unwrap();

            inner.sleep_event();

            let (tx, rx) = oneshot::channel();
            inner.pending_interval = Some(tx);
            Box::pin(async move { rx.await.unwrap() })
        }

        fn sleep_for_timeout(&self) -> impl futures::Future<Output = ()> + std::marker::Send {
            println!("sleep_for_timeout");
            let mut inner = self.0.lock().unwrap();

            inner.sleep_event();

            let (tx, rx) = oneshot::channel();
            inner.pending_timeout = Some(tx);
            Box::pin(async move { rx.await.unwrap() })
        }

        fn continuous(&self) -> bool {
            self.0.lock().unwrap().continuous
        }
    }

    impl Connection for Fixture {
        fn keepalive(&self) -> lightway_core::ConnectionResult<()> {
            println!("Ping!");
            self.0.lock().unwrap().keepalive_count += 1;
            Ok(())
        }
    }

    #[test_case(true; "Continuous keep alive")]
    #[test_case(false; "Non-continuous keep alives")]
    #[tokio::test]
    async fn keepalives_can_be_disabled(continuous: bool) {
        let fixture = Fixture::new(vec![], continuous);

        let (keepalive, task) = fixture.run().await;

        keepalive.online().await;
        keepalive.outside_activity().await;
        keepalive.reply_received().await;
        keepalive.network_changed().await;

        assert!(task.await.is_none());

        assert_eq!(0, fixture.keepalive_count());
    }

    #[test_case(true; "Continuous uses Online to start keepalives")]
    #[test_case(false; "Non-Continuous uses NetworkChange to start keepalives")]
    #[tokio::test]
    async fn keepalives_are_sent(continuous: bool) {
        use FixtureEvent::*;
        let first_event = if continuous { Online } else { NetworkChange };
        let fixture = Fixture::new(vec![first_event, IntervalExpired, Wait], continuous);

        let (keepalive, task) = fixture.run().await;

        drop(keepalive);
        assert!(matches!(
            task.await.unwrap(),
            Ok(KeepaliveResult::Cancelled)
        ));

        assert_eq!(1, fixture.keepalive_count());
    }

    #[test_case(true; "Continuous uses Online to start keepalives")]
    #[test_case(false; "Non-Continuous uses NetworkChange to start keepalives")]
    #[tokio::test]
    async fn multiple_keepalives_are_sent_without_reply(continuous: bool) {
        use FixtureEvent::*;
        let first_event = if continuous { Online } else { NetworkChange };
        let fixture = Fixture::new(
            vec![
                first_event,
                IntervalExpired,
                IntervalExpired,
                IntervalExpired,
                Wait,
            ],
            continuous,
        );

        let (keepalive, task) = fixture.run().await;

        drop(keepalive);
        assert!(matches!(
            task.await.unwrap(),
            Ok(KeepaliveResult::Cancelled)
        ));

        assert_eq!(3, fixture.keepalive_count());
    }

    #[tokio::test]
    async fn multiple_keepalives_are_sent_with_reply() {
        use FixtureEvent::*;
        let fixture = Fixture::new(
            vec![
                Online,
                IntervalExpired,
                ReplyReceived,
                IntervalExpired,
                ReplyReceived,
                IntervalExpired,
                ReplyReceived,
                Wait,
            ],
            true,
        );

        let (keepalive, task) = fixture.run().await;

        drop(keepalive);
        assert!(matches!(
            task.await.unwrap(),
            Ok(KeepaliveResult::Cancelled)
        ));

        assert_eq!(3, fixture.keepalive_count());
    }

    #[test_case(true; "Continuous uses Online to start keepalives")]
    #[test_case(false; "Non-Continuous uses NetworkChange to start keepalives")]
    #[tokio::test]
    async fn multiple_keepalives_are_sent_before_reply(continuous: bool) {
        use FixtureEvent::*;
        let first_event = if continuous { Online } else { NetworkChange };
        let fixture = Fixture::new(
            vec![
                first_event,
                IntervalExpired,
                IntervalExpired,
                IntervalExpired,
                ReplyReceived,
                Wait,
            ],
            continuous,
        );

        let (keepalive, task) = fixture.run().await;

        drop(keepalive);
        assert!(matches!(
            task.await.unwrap(),
            Ok(KeepaliveResult::Cancelled)
        ));

        assert_eq!(3, fixture.keepalive_count());
    }

    #[test_case(true; "Continuous uses Online to start keepalives")]
    #[test_case(false; "Non-Continuous uses NetworkChange to start keepalives")]
    #[tokio::test]
    async fn timeout_if_no_reply(continuous: bool) {
        use FixtureEvent::*;
        let first_event = if continuous { Online } else { NetworkChange };
        let fixture = Fixture::new(
            vec![first_event, IntervalExpired, TimeoutExpired],
            continuous,
        );

        let (_keepalive, task) = fixture.run().await;

        assert!(matches!(task.await.unwrap(), Ok(KeepaliveResult::Timedout)));

        assert_eq!(1, fixture.keepalive_count());
    }

    #[test_case(true; "Continuous uses Online to start keepalives")]
    #[test_case(false; "Non-Continuous uses NetworkChange to start keepalives")]
    #[tokio::test]
    async fn timeout_if_no_reply_even_if_outside_data(continuous: bool) {
        use FixtureEvent::*;
        let first_event = if continuous { Online } else { NetworkChange };
        let fixture = Fixture::new(
            vec![
                first_event,
                IntervalExpired,
                OutsideActivity,
                TimeoutExpired,
            ],
            continuous,
        );

        let (_keepalive, task) = fixture.run().await;

        assert!(matches!(task.await.unwrap(), Ok(KeepaliveResult::Timedout)));

        assert_eq!(1, fixture.keepalive_count());
    }

    #[test_case(true; "Continuous uses Online to start keepalives")]
    #[test_case(false; "Non-Continuous uses NetworkChange to start keepalives")]
    #[tokio::test]
    async fn suspend_keepalives_and_enable_again(continuous: bool) {
        use FixtureEvent::*;
        let enable_keepalive = if continuous { Online } else { NetworkChange };
        let fixture = Fixture::new(
            vec![
                enable_keepalive,
                IntervalExpired,
                Suspend,
                enable_keepalive,
                IntervalExpired,
                Wait,
            ],
            continuous,
        );

        let (keepalive, task) = fixture.run().await;

        drop(keepalive);
        assert!(matches!(
            task.await.unwrap(),
            Ok(KeepaliveResult::Cancelled)
        ));

        assert_eq!(2, fixture.keepalive_count());
    }
}
