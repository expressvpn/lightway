use std::sync::Arc;

use lightway_core::OffloadEvent;
use tokio::sync::mpsc::Receiver;
use tracing::{debug, info};

use crate::connection_manager::ConnectionManager;

/// Apply events an offload engine reported. Ends when the sender is dropped
/// or the server shuts down.
pub(crate) async fn run(conn_manager: Arc<ConnectionManager>, mut events: Receiver<OffloadEvent>) {
    let weak = Arc::downgrade(&conn_manager);
    drop(conn_manager);

    while let Some(event) = events.recv().await {
        let Some(conn_manager) = weak.upgrade() else {
            return;
        };
        match event {
            OffloadEvent::PeerAddrChanged { session_id, addr } => {
                if conn_manager.update_peer_addr(session_id, addr) {
                    info!(?session_id, %addr, "adopted offload-reported peer address");
                } else {
                    debug!(?session_id, %addr, "offload-reported peer address was a no-op");
                }
            }
            OffloadEvent::KeyRotationNeeded { session_id } => {
                if conn_manager.rotate_expresslane_key(session_id) {
                    info!(?session_id, "forwarded offload-requested key rotation");
                } else {
                    debug!(?session_id, "offload-requested key rotation was a no-op");
                }
            }
        }
    }
}
