use std::{collections::HashSet, sync::Arc};

use bytes::Bytes;
use tracing::info;

use crate::{LightwayFeature, Version, wire};

/// A handle onto a successful auth result.
pub trait ServerAuthHandle: std::fmt::Debug {
    /// Validate if this authentication is still valid, returns
    /// true if it has expired.
    fn expired(&self) -> bool;
    /// All features available to this connection.
    fn features(&self) -> HashSet<LightwayFeature>;
}

/// Result of [`ServerAuth`] `authorize_*` methods.
#[derive(Debug)]
pub enum ServerAuthResult {
    /// Access is Ok.
    Granted {
        /// Handle for this successful authentication. If none then
        /// the connection will never expire.
        handle: Option<Box<dyn ServerAuthHandle + Sync + Send>>,
        /// if [`Some`] then the connection will
        /// switch to that tunnel protocol version.
        tunnel_protocol_version: Option<Version>,
    },

    /// Access is not allowed
    Denied,
}

/// Server auth backend. Servers can implement only the methods they
/// support, all others will reject by default.
pub trait ServerAuth<T> {
    /// Authorize the connection based on `method`, defers to the more
    /// specific `authorize_*` methods on this trait.
    fn authorize(&self, method: &wire::AuthMethod, app_state: &mut T) -> ServerAuthResult {
        match method {
            wire::AuthMethod::UserPass { user, password } => {
                self.authorize_user_password(user, password, app_state)
            }
            wire::AuthMethod::Token { token } => self.authorize_token(token, app_state),
            wire::AuthMethod::VersionedToken { token, .. } => {
                self.authorize_token(token, app_state)
            }
            wire::AuthMethod::CustomCallback { data } => self.authorize_cb_data(data, app_state),
        }
    }

    /// Authorize the given `user` with `password`.
    fn authorize_user_password(
        &self,
        _user: &str,
        _password: &str,
        _app_state: &mut T,
    ) -> ServerAuthResult {
        info!("ServerAuth: user+password auth not supported");
        ServerAuthResult::Denied
    }

    /// Authorize based on the given `token`
    fn authorize_token(&self, _token: &str, _app_state: &mut T) -> ServerAuthResult {
        info!("ServerAuth: token based auth not supported");
        ServerAuthResult::Denied
    }

    /// Authorize based on the given callback data `cb_data`
    fn authorize_cb_data(&self, _data: &Bytes, _app_state: &mut T) -> ServerAuthResult {
        info!("ServerAuth: callback data auth not supported");
        ServerAuthResult::Denied
    }
}

/// Convenience type to use as function arguments
pub type ServerAuthArg<AppState> = Arc<dyn ServerAuth<AppState> + Send + Sync>;
