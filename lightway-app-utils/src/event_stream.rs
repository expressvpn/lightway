//! Forward event notifications to a channel

use lightway_core::{Event, EventCallback};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;

/// Helper to propagate events into an async stream. Pass this type to
/// `with_event_cb`. Events arrive on the stream in the order they are
/// raised.
#[derive(Clone)]
pub struct EventStreamCallback(mpsc::UnboundedSender<Event>);

/// A stream of [`Event`].
pub type EventStream = UnboundedReceiverStream<Event>;

impl EventStreamCallback {
    /// Construct a new `EventStreamChannel` and the correspondining
    /// `EventStreamCallback`.
    pub fn new() -> (Self, EventStream) {
        let (send, recv) = mpsc::unbounded_channel();

        (Self(send), EventStream::new(recv))
    }
}

impl EventCallback for EventStreamCallback {
    fn event(&mut self, event: Event) {
        // Fails only once the stream is gone, when nobody is listening.
        let _ = self.0.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightway_core::SessionId;
    use tokio_stream::StreamExt;

    fn numbered(i: u64) -> Event {
        let id = SessionId::from_bytes(i.to_be_bytes());
        Event::SessionIdRotationStarted { old: id, new: id }
    }

    fn number(event: Event) -> u64 {
        match event {
            Event::SessionIdRotationStarted { old, .. } => u64::from_be_bytes(*old.as_bytes()),
            e => panic!("unexpected event {e:?}"),
        }
    }

    /// As a connection does: events raised from several worker threads, one
    /// at a time under a lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn events_raised_from_many_threads_under_a_lock_arrive_in_order() {
        const COUNT: u64 = 10_000;
        let (cb, stream) = EventStreamCallback::new();
        let raiser = std::sync::Arc::new(std::sync::Mutex::new((cb, 0u64)));

        let tasks: Vec<_> = (0..4)
            .map(|_| {
                let raiser = raiser.clone();
                tokio::spawn(async move {
                    loop {
                        {
                            let mut guard = raiser.lock().unwrap();
                            let (cb, next) = &mut *guard;
                            if *next == COUNT {
                                return;
                            }
                            cb.event(numbered(*next));
                            *next += 1;
                        }
                        tokio::task::yield_now().await;
                    }
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
        drop(raiser);

        let got: Vec<u64> = stream.map(number).collect().await;
        assert_eq!(got, (0..COUNT).collect::<Vec<_>>());
    }
}
