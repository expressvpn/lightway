use std::sync::Arc;

use crate::SessionId;
use crate::wire::ExpresslaneKey;

/// Struct to publish expresslane keys
#[derive(Debug)]
pub struct ExpresslaneCbData {
    /// Self key
    pub self_key: ExpresslaneKey,
    /// Peer key
    pub peer_key: ExpresslaneKey,
}

/// Lightway [`ExpresslaneCb`] trait for getting updates of expresslane
pub trait ExpresslaneCb {
    /// Hook to run during packet egress
    fn update(&self, session_id: SessionId, data: ExpresslaneCbData);
}

/// Convenience type to use [`ExpresslaneCb`] as function arguments
pub type ExpresslaneCbType = Arc<dyn ExpresslaneCb + Sync + Send>;
