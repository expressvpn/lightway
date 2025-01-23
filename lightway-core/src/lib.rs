//! The core lightway protocol.

#![warn(missing_docs)]

mod borrowed_bytesmut;
mod builder_predicates;
mod cipher;
mod connection;
mod context;
mod io;
mod metrics;
mod packet;
mod plugin;
mod utils;
mod version;
mod wire;

// Reexport wolfssl types
pub use wolfssl::{IOCallbackResult, ProtocolVersion, RootCertificate, Secret};

// Re-export wolfssl in case applications need it
pub use wolfssl;

#[cfg(feature = "debug")]
pub use wolfssl::Tls13SecretCallbacks;

// Reexport our own types
pub use builder_predicates::BuilderPredicates;
pub use cipher::Cipher;
pub use connection::{
    dplpmtud::Timer as DplpmtudTimer, ClientConnectionBuilder, Connection, ConnectionActivity,
    ConnectionBuilderError, ConnectionError, ConnectionResult, Event, EventCallback,
    EventCallbackArg, ServerConnectionBuilder, State,
};
pub use context::{
    ip_pool::{ClientIpConfig, ClientIpConfigArg, InsideIpConfig, ServerIpPool, ServerIpPoolArg},
    ClientContext, ClientContextBuilder, ConnectionType, ContextError, ScheduleTickCb, ServerAuth,
    ServerAuthArg, ServerAuthHandle, ServerAuthResult, ServerContext, ServerContextBuilder,
};
pub use io::{
    CowBytes, InsideIOSendCallback, InsideIOSendCallbackArg, OutsideIOSendCallback,
    OutsideIOSendCallbackArg,
};
pub use packet::OutsidePacket;
pub use plugin::{
    Plugin, PluginFactory, PluginFactoryError, PluginFactoryList, PluginFactoryType, PluginResult,
    PluginType,
};
pub use utils::{ipv4_update_destination, ipv4_update_source};
pub use version::Version;
pub use wire::{AuthMethod, Header, SessionId};

/// Default MTU size for a packet on the outside path (on the wire)
pub const MAX_OUTSIDE_MTU: usize = 1500;

/// Required by RFC-791
///
/// <https://datatracker.ietf.org/doc/html/rfc791>
pub const MIN_OUTSIDE_MTU: usize = 68;

/// The minimum usable outside path (wire) MTU required for a given
/// inside path MTU
const fn dtls_required_outside_mtu(inside_mtu: usize) -> usize {
    inside_mtu + IPV4_HEADER_SIZE + UDP_HEADER_SIZE + wire::Header::WIRE_SIZE + MAX_DTLS_HEADER_SIZE
}

const IPV4_HEADER_SIZE: usize = 20;
const TCP_HEADER_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;

// D/TLS headers + AES crypto fields
const MAX_DTLS_HEADER_SIZE: usize = 37;

/// Default MTU size for DTLS on the outside path (max outside MTU less IP and UDP header size)
const fn max_dtls_outside_mtu(outside_mtu: usize) -> usize {
    outside_mtu - IPV4_HEADER_SIZE - UDP_HEADER_SIZE - wire::Header::WIRE_SIZE
}

/// Default MTU size for DTLS payload (max DTLS wire MTU less DTLS overheads)
const fn max_dtls_mtu(outside_mtu: usize) -> usize {
    max_dtls_outside_mtu(outside_mtu) - MAX_DTLS_HEADER_SIZE
}

/// The smallest supported inside MTU.
pub const MIN_INSIDE_MTU: usize = 1250;

/// The largest supported inside MTU.
pub const MAX_INSIDE_MTU: usize = 1500;

/// Enable debug logging from WolfSSL
#[cfg(feature = "debug")]
pub fn enable_tls_debug() {
    wolfssl::enable_debugging(true)
}

#[cfg(feature = "fuzzing_api")]
pub use wire::{FromWireError, FromWireResult};

#[cfg(feature = "fuzzing_api")]
/// Entry point for `fuzz_targets/fuzz_parse_frame.rs`. Parses as many
/// frames as possible from the input buffer. Any successfully parsed
/// frames are reserialized to cover the append_to_wire functionality.
pub fn fuzz_frame_parse(buf: &mut bytes::BytesMut) {
    loop {
        match wire::Frame::try_from_wire(buf) {
            Ok(f) => {
                let mut buf = bytes::BytesMut::new();
                f.append_to_wire(&mut buf);
            }
            Err(wire::FromWireError::InsufficientData) => break,
            Err(_) => {}
        }
    }
}
