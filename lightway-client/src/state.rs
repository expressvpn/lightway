//! The exposed states for external handler

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(mobile, derive(uniffi::Enum))]
/// Current state of Expresslane
pub enum ExpresslaneState {
    /// Expresslane not enabled in the config
    Disabled,
    /// Expresslane enabled in the config, but handshake not completed or peer has disabled Expresslane, so inactive
    Inactive,
    /// Expresslane enabled and being used in the current connection
    Active,
    /// Expresslane enabled, but connection is degraded and back to normal D/TLS for data packets
    Degraded,
}

impl TryFrom<lightway_core::ExpresslaneState> for ExpresslaneState {
    type Error = Error;

    fn try_from(state: lightway_core::ExpresslaneState) -> Result<Self, Self::Error> {
        match state {
            lightway_core::ExpresslaneState::Disabled => Ok(ExpresslaneState::Disabled),
            lightway_core::ExpresslaneState::Inactive => Ok(ExpresslaneState::Inactive),
            lightway_core::ExpresslaneState::Active => Ok(ExpresslaneState::Active),
            lightway_core::ExpresslaneState::Degraded => Ok(ExpresslaneState::Degraded),
            lightway_core::ExpresslaneState::WaitingForClient => Err(Error::InvalidStateForClient),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(mobile, derive(uniffi::Enum))]
/// Current network state of the device
/// For Android, all the 3 enums (Online/InterfaceChanged/RouteUpdated) have the same behaviour
pub enum DeviceNetworkState {
    /// Device transitioned from offline to online
    /// Socket recreation is required on iOS due to potential interface changes after we have gone online
    /// for UDP connections.
    Online,
    /// Network interface changed has changed (e.g. WiFi -> Cellular)
    InterfaceChanged,
    /// Network updated, but the interface remains unchanged
    RouteUpdated,
    /// No usable route
    Offline,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The expresslane state should not should in client side
    #[error("Invalid expresslane state in client")]
    InvalidStateForClient,
}
