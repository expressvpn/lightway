use crate::io::inside::TunnelState;
use crate::keepalive::{Keepalive, KeepaliveResult};
use crate::state::ExpresslaneState;
use crate::{ConnectionState, keepalive::Config as KeepaliveConfig};
use futures::future::{FutureExt, OptionFuture, select_all};
use lightway_core::Connection;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::Receiver as MpscReceiver;
use tokio::sync::mpsc::Sender as MpscSender;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tracing::{debug, info, info_span};

pub(crate) fn first_outside_io_exit(
    connections: &mut HashMap<usize, LightwayConnection>,
) -> impl Future<Output = (usize, Result<uniffi::Result<()>, tokio::task::JoinError>)> + '_ {
    if connections.is_empty() {
        return futures::future::Either::Left(std::future::pending());
    }
    futures::future::Either::Right(
        select_all(
            connections
                .values_mut()
                .map(|c| Box::pin(async move { (c.instance_id, (&mut c.outside_io_task).await) })),
        )
        .map(|((id, result), _, _)| (id, result)),
    )
}

pub async fn cleanup_connections(
    in_progress_connections_abort_handle: Vec<AbortHandle>,
    completed_connections: Vec<LightwayConnection>,
) {
    for conn in in_progress_connections_abort_handle {
        if !conn.is_finished() {
            conn.abort();
        }
    }
    for mut c in completed_connections.into_iter() {
        let span = info_span!("CleanupConnection", instance_id = ?c.instance_id);
        span.in_scope(|| {
            debug!("Disconnecting completed connection");
            let _ = c.conn.lock().unwrap().disconnect();
            c.outside_io_task.abort();
            c.join_set.abort_all();
        });
        drop(c.keepalive);
        c.keepalive_task.await;
    }
    info!("Cleaned up unused connections");
}

pub struct LightwayConnection {
    pub conn: Arc<Mutex<Connection<ConnectionState<TunnelState>>>>,
    pub outside_io_task: JoinHandle<uniffi::Result<()>>,
    pub new_outside_io_sender: MpscSender<()>,
    pub keepalive: Keepalive,
    pub keepalive_task: OptionFuture<JoinHandle<KeepaliveResult>>,
    pub keepalive_config: KeepaliveConfig,
    pub join_set: JoinSet<()>,
    pub instance_id: usize,
    pub expresslane_event_rx: Option<MpscReceiver<ExpresslaneState>>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::event_handlers::MockEventHandlers;
    use mockall::Sequence;
    use mockall::predicate::eq;

    #[tokio::test]
    async fn test_outside_socket_new_calls_created_outside_fd() {
        // Test TCP socket creation
        let mut mock_event_handler = MockEventHandlers::new();

        mock_event_handler
            .expect_created_outside_fd()
            .times(1)
            .return_const(());

        let tcp_result = OutsideSocket::new(true, Some(Arc::new(mock_event_handler)));
        assert!(tcp_result.is_ok());

        // Test UDP socket creation
        let mut mock_event_handler = MockEventHandlers::new();

        mock_event_handler
            .expect_created_outside_fd()
            .times(1)
            .return_const(());

        let udp_result = OutsideSocket::new(false, Some(Arc::new(mock_event_handler)));
        assert!(udp_result.is_ok());
    }
}
