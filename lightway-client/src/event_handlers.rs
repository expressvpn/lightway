//! Event handler mod for lightway

use crate::ConnectionState;
use crate::keepalive::Keepalive;
use futures::StreamExt;
use lightway_app_utils::EventStream;
use lightway_core::{Connection, Event, EventCallback, State};
#[cfg(feature = "mobile")]
use std::sync::Arc;
use std::sync::{Mutex, Weak};

/// Eventhandler in Rust
#[cfg(not(feature = "mobile"))]
pub struct EventHandler;

#[cfg(not(feature = "mobile"))]
impl EventCallback for EventHandler {
    fn event(&mut self, event: lightway_core::Event) {
        use lightway_core::Event;
        match event {
            Event::StateChanged(state) => {
                tracing::debug!("State changed to {:?}", state);
            }
            Event::EncodingStateChanged { enabled } => {
                tracing::debug!("Encoding state changed to {:?}", enabled);
            }
            _ => {}
        }
    }
}

/// Eventhandlers trait for the foreign language
#[cfg(feature = "mobile")]
#[uniffi::export(with_foreign)]
#[cfg_attr(test, mockall::automock)]
pub trait EventHandlers: Send + Sync {
    /// Handles VPN connection status changes from the native Lightway client.
    /// State values: 2=Connecting, 6=LinkUp, 5=Authenticating, 7=Online, 4=Disconnecting, 1=Disconnected (from lightway-core)
    ///
    /// `Online` state is advertised when we have selected the best connection in parallel connect
    fn handle_status_change(&self, state: u8);

    /// Handles Expresslane state change. This will be called whenever there's a new update on
    /// the Expresslane state change, see `ExpresslaneState` enum for details.
    fn handle_expresslane_state_change(&self, state: crate::state::ExpresslaneState);

    /// Called when the first packet is received from the server.
    ///
    /// It returns time in milliseconds from the connection start until the first packet is received
    fn received_first_packet(&self, time_in_ms: u64);

    /// Notify the mobile app that an outside socket has been created and pass the FD (by reference, not owned)
    fn created_outside_fd(&self, fd: i32);

    /// Notify the mobile app that connection has floated and do not need a reconnect after outside
    /// IO has been changed, which could happen when the device is online again or the device is
    /// using a different network interface (Cellular <-> WiFi). (iOS-only)
    fn connection_has_floated(&self);

    /// Handles inside pkt codec status changes from the native Lightway client. When the server
    /// agrees to enable or disable the inside packet codec (after the client requests), this
    /// handler will be called with the resulting state.
    fn handle_inside_pkt_codec_status_change(&self, enabled: bool);
}

/// This event handler is used to advertise State changes and First Packet Received event to mobile application
///
/// Only `Connecting`, `LinkUp`, and `Authenticating` are advertised from this handler. The mobile
/// app can ignore the status if it wasn't supported. Plus, we will return the disconnection result to the client now
/// so once the client has disconnected from the server, the mobile app would instantly know it has disconnected.
/// `Online` state is advertised from `async_lightway_start` since we are waiting for parallel connect to finish.
/// Only the first FirstPacketReceived event is advertised to mobile application
/// since only the first one makes sense.
#[cfg(feature = "mobile")]
pub async fn handle_global_events(
    mut stream: EventStream,
    connection_start_time: tokio::time::Instant,
    event_handler: Arc<dyn EventHandlers>,
) {
    let mut current_state = State::Connecting;
    let mut is_first_packet_received = false;

    while let Some(event) = stream.next().await {
        match event {
            Event::StateChanged(state) => {
                let allowed_states: &[State] = match current_state {
                    State::Connecting => &[State::LinkUp, State::Authenticating, State::Online],
                    State::LinkUp => &[State::Authenticating, State::Online],
                    State::Authenticating => &[],
                    State::Online => &[],
                    State::Disconnecting => &[],
                    State::Disconnected => &[],
                };

                if allowed_states.contains(&state) {
                    if !matches!(state, State::Online) {
                        event_handler.handle_status_change(state as u8);
                    }
                    current_state = state;
                }
            }
            Event::FirstPacketReceived if !is_first_packet_received => {
                tracing::info!("First packet received");
                let elapsed_ms = connection_start_time.elapsed().as_millis();
                // UniFFI does not support u128 types in its interface bindings.
                // In the unlikely event that connection time exceeds u64::MAX ms,
                // we clamp to u64::MAX rather than panic.
                let time_to_receive_first_packet_in_ms =
                    u64::try_from(elapsed_ms).unwrap_or(u64::MAX);
                event_handler.received_first_packet(time_to_receive_first_packet_in_ms);
                is_first_packet_received = true;
            }
            Event::EncodingStateChanged { enabled } => {
                tracing::info!("Encoding state changed to {enabled}");
                event_handler.handle_inside_pkt_codec_status_change(enabled);
            }
            _ => (),
        }
    }
}

/// Event handler for individual parallel connections
#[cfg(not(feature = "mobile"))]
pub async fn handle_events<A: 'static + Send + EventCallback, ExtAppState: Send + Sync>(
    mut stream: EventStream,
    keepalive: Keepalive,
    weak: Weak<Mutex<Connection<ConnectionState<ExtAppState>>>>,
    enable_encoding_when_online: bool,
    mut event_handler: Option<A>,
    connected_signal: tokio::sync::oneshot::Sender<()>,
    disconnected_signal: tokio::sync::oneshot::Sender<()>,
) {
    let mut connected_signal = Some(connected_signal);
    let mut disconnected_signal = Some(disconnected_signal);
    while let Some(event) = stream.next().await {
        match &event {
            Event::StateChanged(state) => {
                if matches!(state, State::Online) {
                    if let Some(connected_signal) = connected_signal.take() {
                        let _ = connected_signal.send(());
                    }
                    keepalive.online().await;
                    let Some(conn) = weak.upgrade() else {
                        break; // Connection disconnected.
                    };

                    if enable_encoding_when_online
                        && let Err(e) = conn.lock().unwrap().set_encoding(true)
                    {
                        tracing::error!("Error encoutered when trying to toggle encoding. {}", e);
                    }
                } else if matches!(state, State::Disconnected)
                    && let Some(disconnected_tx) = disconnected_signal.take()
                {
                    let _ = disconnected_tx.send(());
                }
            }
            Event::KeepaliveReply => keepalive.reply_received().await,
            Event::FirstPacketReceived => {
                tracing::info!("First outside packet received");
            }
            Event::ExpresslaneStateChanged(state) => {
                tracing::info!(?state, "Expresslane State Change");
            }
            Event::EncodingStateChanged { enabled } => {
                tracing::info!("Encoding state changed to {enabled}");
            }

            // Server only events
            Event::SessionIdRotationAcknowledged { .. }
            | Event::TlsKeysUpdateStart
            | Event::TlsKeysUpdateCompleted => {
                unreachable!("server only event received");
            }
        }
        if let Some(ref mut handler) = event_handler {
            handler.event(event);
        }
    }
}

/// Event handler for individual parallel connections
#[cfg(feature = "mobile")]
#[allow(clippy::too_many_arguments)]
pub async fn handle_events<A: 'static + Send + EventCallback>(
    mut stream: EventStream,
    keepalive: Keepalive,
    notify_keepalive_reply: Arc<tokio::sync::Notify>,
    weak: Weak<Mutex<Connection<ConnectionState<crate::mobile::lightway::TunnelState>>>>,
    mut event_handler: A,
    online_signal: tokio::sync::mpsc::Sender<usize>,
    instance_id: usize,
    expresslane_event_tx: Option<tokio::sync::mpsc::Sender<crate::state::ExpresslaneState>>,
) {
    while let Some(event) = stream.next().await {
        match &event {
            Event::StateChanged(state) => {
                if matches!(state, State::Online) {
                    let _ = online_signal.send(instance_id).await;
                    keepalive.online().await;

                    let Some(_conn) = weak.upgrade() else {
                        break; // Connection disconnected.
                    };
                }
            }
            Event::KeepaliveReply => {
                notify_keepalive_reply.notify_waiters();
                keepalive.reply_received().await
            }
            Event::ExpresslaneStateChanged(state) => {
                if let Some(tx) = expresslane_event_tx.as_ref()
                    && let Ok(state) = (*state).try_into()
                {
                    if let Err(e) = tx.try_send(state) {
                        tracing::warn!("Unable to send Expresslane state change event: {:?}", e);
                    }
                }
                continue;
            }
            Event::FirstPacketReceived | Event::EncodingStateChanged { .. } => (), // will be handled by handle_global_events

            // Server-only events
            Event::SessionIdRotationAcknowledged { .. }
            | Event::TlsKeysUpdateStart
            | Event::TlsKeysUpdateCompleted => {
                unreachable!("server only event received");
            }
        }
        event_handler.event(event);
    }
}

#[cfg(test)]
#[cfg(feature = "mobile")]
mod test {
    use super::*;
    use crate::event_handlers::MockEventHandlers;
    use lightway_app_utils::EventStreamCallback;
    use lightway_core::{Event, State};
    use mockall::Sequence;
    use mockall::predicate::eq;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::Instant;

    #[tokio::test]
    async fn test_handle_global_events() {
        let (mut sender, receiver) = lightway_app_utils::EventStreamCallback::new();
        let instant = Instant::now();
        tokio::spawn(async move {
            sender.event(Event::StateChanged(State::Connecting));
            sender.event(Event::StateChanged(State::LinkUp));
            sender.event(Event::StateChanged(State::Authenticating));
            sender.event(Event::StateChanged(State::Online));
        });

        // Make sure we don't advertise Online state in this function
        let mut seq = Sequence::new();
        let mut mock_event_handler = MockEventHandlers::new();
        mock_event_handler
            .expect_handle_status_change()
            .times(1)
            .in_sequence(&mut seq)
            .with(eq(State::LinkUp as u8))
            .return_const(());
        mock_event_handler
            .expect_handle_status_change()
            .times(1)
            .in_sequence(&mut seq)
            .with(eq(State::Authenticating as u8))
            .return_const(());
        mock_event_handler
            .expect_handle_status_change()
            .times(0)
            .with(eq(State::Online as u8))
            .return_const(());
        handle_global_events(receiver, instant, Arc::new(mock_event_handler)).await;
    }

    #[tokio::test]
    async fn test_handle_global_events_invalid_state_sequence() {
        let (mut sender, receiver) = EventStreamCallback::new();
        let instant = Instant::now();

        tokio::spawn(async move {
            sender.event(Event::StateChanged(State::Online));
            sender.event(Event::StateChanged(State::LinkUp));
            sender.event(Event::StateChanged(State::Authenticating));
            sender.event(Event::StateChanged(State::Disconnecting));
            sender.event(Event::StateChanged(State::Disconnected));
        });

        let mut mock_event_handler = MockEventHandlers::new();
        mock_event_handler
            .expect_handle_status_change()
            .times(0)
            .return_const(());
        handle_global_events(receiver, instant, Arc::new(mock_event_handler)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_handle_global_events_first_packet_received_only_send_once() {
        let (mut sender, receiver) = EventStreamCallback::new();
        let instant = Instant::now();

        tokio::spawn(async move {
            tokio::time::advance(Duration::from_millis(174)).await;
            sender.event(Event::FirstPacketReceived);
            sender.event(Event::FirstPacketReceived);
            sender.event(Event::FirstPacketReceived);
        });

        let mut mock_event_handler = MockEventHandlers::new();
        mock_event_handler
            .expect_received_first_packet()
            .with(eq(174u64))
            .times(1)
            .return_const(());
        handle_global_events(receiver, instant, Arc::new(mock_event_handler)).await;
    }
}
