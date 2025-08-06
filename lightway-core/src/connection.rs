mod builders;
pub(crate) mod dplpmtud;
mod event;
mod fragment_map;
mod io_adapter;
mod key_update;

use bytes::{Bytes, BytesMut};
use dplpmtud::BASE_PLPMTU;
use rand::Rng;
use std::borrow::Cow;
use std::net::AddrParseError;
use std::num::{NonZeroU16, Wrapping};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};
use wolfssl::{ErrorKind, IOCallbackResult, ProtocolVersion};

use crate::{
    ConnectionType, IPV4_HEADER_SIZE, InsideIOSendCallbackArg, PluginResult, SessionId,
    TCP_HEADER_SIZE, Version,
    context::{ScheduleTickCb, ServerAuthArg, ServerAuthHandle, ServerAuthResult},
    encoding_request_states::EncodingRequestStates,
    metrics,
    packet_codec::{CodecStatus, PacketDecoderType, PacketEncoderType},
    plugin::PluginList,
    utils::tcp_clamp_mss,
    wire::{self, AuthMethod},
};
use crate::{
    LightwayFeature, OutsideIOSendCallbackArg, TickType, dtls_required_outside_mtu, max_dtls_mtu,
};

use crate::context::ip_pool::{ClientIpConfigArg, ServerIpPoolArg};
use crate::packet::{OutsidePacket, OutsidePacketError};
use crate::utils::ipv4_is_valid_packet;
use crate::wire::AuthSuccessWithConfigV4;
pub use builders::{ClientConnectionBuilder, ConnectionBuilderError, ServerConnectionBuilder};
pub use event::Event;
use fragment_map::{FragmentMap, FragmentMapResult};
pub(crate) use io_adapter::{SendBuffer as IOAdapterSendBuffer, WolfSSLIOAdapter};

/// D/TLS is a UDP based protocol and requires the application
/// (rather than the OS as with TCP) to keep track of the need to do
/// retransmits on packet loss.
///
/// Currently Wolf has timeouts based in seconds. However this is not
/// sufficient for our goal of sub-second connection times.
///
/// As WolfSSL lacks millisecond timers we use its internal timers but
/// change its definition to be in 100 millisecond intervals instead of
/// seconds. So a wolf timeout of 1 second means 100 milliseconds.
///
/// By default wolf's DTLS max timeout is 64 seconds which translates to
/// 6.4 seconds. Since it scales from 1 to 64 by a factor
/// of 2 each timeout. The total timeout is 12.7 seconds with this scaling
/// which for our purposes is plenty.
///
/// In lightway for simplicity we do not treat this as a strict
/// timeout (firing after a period of inactivity) but instead treat it
/// as a tick (albeit with an interval which may be adjusted over
/// time). This tick runs until the connection reaches `State::Online`.
const WOLF_TICK_INTERVAL_DIVISOR: u32 = 1000 / 100;

const WOLF_TICK_DTLS13_QUICK_TIMEOUT_DIVISOR: u32 = 4;

/// Maximum number of retransmissions attempts for each encoding request packet.
const ENCODING_REQUEST_PKT_MAX_RETRANSMISSION_ATTEMPTS: u8 = 5;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum State {
    /// Secure connection is being established.
    Connecting = 2,

    /// Secure connection is established
    LinkUp = 6,

    /// Connection is established, client is authenticating
    Authenticating = 5,
    // Configuring,
    /// Tunnel is online
    Online = 7,

    /// Disconnect is in progress
    Disconnecting = 4,

    /// Connection has been disconnected
    Disconnected = 1,
}

#[derive(Debug, Error)]
pub enum InvalidPacketError {
    /// Packet is not IPv4
    #[error("Invalid ipv4 packet")]
    InvalidIpv4Packet,

    /// Packet size greater than MAX_MTU
    #[error("Packet size greater than MAX_MTU")]
    InvalidPacketSize,
}

/// An error from an operation on a [`Connection`]
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// The peer has disconnected
    #[error("Peer has disconnected: Goodbye")]
    Goodbye,

    /// Connection timed out
    #[error("TimedOut")]
    TimedOut,

    /// Connection already disconnected
    #[error("Disconnected")]
    Disconnected,

    /// User is not authorized / authentication failed
    #[error("Unauthorized")]
    Unauthorized,

    /// An invalid message for the connection state was received.
    #[error("Invalid State")]
    InvalidState,

    /// Operation is not valid for the connection's mode (client vs server)
    #[error("Invalid Connection Mode")]
    InvalidMode,

    /// Operation is not valid for the connection type (udp vs tcp)
    #[error("Invalid Connection Type")]
    InvalidConnectionType,

    /// Inside io is not configured
    #[error("Invalid Inside Io")]
    InvalidInsideIo,

    /// Message contained a rejected session id
    #[error("Rejected Session ID")]
    RejectedSessionID,

    /// Message contained an unknown session id
    #[error("Unknown Session ID")]
    UnknownSessionID,

    /// A message had invalid protocol version for this connection
    #[error("Invalid Protocol")]
    InvalidProtocolVersion,

    /// Connection failed authentication
    #[error("Access Denied")]
    AccessDenied,

    /// Server IP pool exhausted
    #[error("No IP address available for client")]
    NoAvailableClientIp,

    /// Failed to parse inside ip config
    #[error("Invalid inside IP config: {0}")]
    InvalidInsideIpConfig(#[from] AddrParseError),

    /// Inside packet is either not IPv4 or length greater than MAX_MTU
    #[error("Invalid inside packet: {0}")]
    InvalidInsidePacket(InvalidPacketError),

    /// Invalid Outside MTU
    #[error(
        "PMTUD required: inside MTU {inside_mtu} needs at least {required_outside_mtu} outside MTU"
    )]
    PathMtuDiscoveryRequired {
        /// The inside MTU
        inside_mtu: usize,
        /// The required outside MTU to support the inside MTU without PMTUD
        required_outside_mtu: usize,
    },

    /// Plugin returns a reply packet
    #[error("Plugin dropped with a reply packet")]
    PluginDropWithReply(BytesMut),

    /// Plugin returns error
    #[error("Plugin error: {0}")]
    PluginError(Box<dyn std::error::Error + Sync + Send>),

    /// Packet parsing error occurred
    #[error("Packet Error: {0}")]
    PacketError(#[from] OutsidePacketError),

    /// A wire protocol error occurred
    #[error("Protocol Error: {0}")]
    WireError(#[from] wire::FromWireError),

    /// Failed to recombine fragmented data.
    #[error("Data Fragment Error: {0}")]
    DataFragmentError(#[from] fragment_map::FragmentMapError),

    /// A WolfSSL error occurred
    #[error("WolfSSL Error: {0}")]
    WolfSSL(#[from] wolfssl::Error),

    /// Packet Codec does not exist
    #[error("Packet Codec Does Not Exist")]
    PacketCodecDoesNotExist,

    /// A Packet Codec error occurred
    #[error("Packet Codec error: {0}")]
    PacketCodecError(Box<dyn std::error::Error + Sync + Send>),

    /// Encoding Request Retransmit CB does not exist
    #[error("Schedule Encoding Request Retransmit Cb Does Not Exist")]
    EncodingReqRetransmitCbDoesNotExist,
}

impl ConnectionError {
    /// Determine if a given error is fatal for this connection.
    pub fn is_fatal(&self, connection_type: ConnectionType) -> bool {
        match connection_type {
            ConnectionType::Stream => {
                // All errors are fatal for TCP/TLS
                true
            }
            ConnectionType::Datagram => {
                // For UDP/DTLS many errors can be ignored
                use ConnectionError::*;
                match self {
                    TimedOut => true,
                    Unauthorized => true,
                    InvalidProtocolVersion => true,
                    InvalidMode => true,
                    InvalidConnectionType => true,
                    NoAvailableClientIp => true,
                    InvalidInsideIpConfig(_) => true,
                    AccessDenied => true,
                    Goodbye => true,
                    PacketCodecDoesNotExist => true,
                    PacketCodecError(_) => true,
                    Disconnected => true,
                    EncodingReqRetransmitCbDoesNotExist => true,
                    PathMtuDiscoveryRequired { .. } => true,
                    WolfSSL(wolfssl::Error::Fatal(ErrorKind::DomainNameMismatch)) => true,
                    WolfSSL(wolfssl::Error::Fatal(ErrorKind::DuplicateMessage)) => true,
                    WolfSSL(wolfssl::Error::Fatal(ErrorKind::PeerClosed)) => true,
                    WolfSSL(wolfssl::Error::Fatal(ErrorKind::CaCertNotAvailable)) => true,

                    WireError(wire::FromWireError::UnknownFrameType) => false,
                    WireError(_) => true,

                    InvalidState => false, // Can be due to out of order or repeated messages
                    InvalidInsideIo => false, // Can be used for test only test control plane
                    UnknownSessionID => false,
                    InvalidInsidePacket(_) => false,
                    RejectedSessionID => false,
                    PluginDropWithReply(_) => false,
                    PluginError(_) => false,
                    PacketError(_) => false,
                    DataFragmentError(_) => false,
                    WolfSSL(_) => false,
                }
            }
        }
    }
}

/// Callbacks for this particular connection
pub trait EventCallback {
    /// Called when Lightway wishes to notify about an event
    fn event(&mut self, event: Event);
}

/// Convenience type to use as function arguments
///
/// Take care if calling [`Connection`] methods from within the
/// callback to avoid deadlock with any application lock you have
/// wrapped the connection in.
pub type EventCallbackArg = Box<dyn EventCallback + Send + Sync>;

/// Client vs Server state.
enum ConnectionMode<AppState> {
    Client {
        /// Authentication info to use
        auth_method: AuthMethod,
        /// Callback to notify about inside ip config
        ip_config_cb: ClientIpConfigArg<AppState>,
    },
    Server {
        /// Authentication oracle.
        auth: ServerAuthArg<AppState>,
        /// Set after successful authentication.
        auth_handle: Option<Box<dyn ServerAuthHandle + Sync + Send>>,
        ip_pool: ServerIpPoolArg<AppState>,
        key_update: key_update::State,
        rng: Arc<Mutex<dyn rand_core::CryptoRng + Send>>,
        /// `Some(_)` iff a session ID rotation is in progress.
        pending_session_id: Option<SessionId>,
    },
}

/// Tracks when [`Connection`] was last active
#[derive(Copy, Clone)]
pub struct ConnectionActivity {
    /// Last time any traffic was received from client.
    pub last_outside_data_received: Instant,

    /// When the last `wire::Frame::Data` from peer (going to inside
    /// path) was seen.
    pub last_data_traffic_from_peer: Instant,
}

/// The result of an operation on a [`Connection`].
pub type ConnectionResult<T> = Result<T, ConnectionError>;

/// A lightway connection
pub struct Connection<AppState: Send = ()> {
    /// Type of connection
    connection_type: ConnectionType,

    /// Protocol version used by this connection
    tunnel_protocol_version: Version,

    /// App specific state.
    ///
    /// If you want to recover a Sync/Send handle to the
    /// [`Connection`] in callbacks then it can be added here but be
    /// sure to use a weak handle (e.g. a `Weak<Connection>`) rather
    /// than a strong one (e.g. `Arc<Connection>`) to avoid a ref
    /// count loop.
    ///
    /// When doing so take care not to deadlock by calling methods on
    /// an already locked `Connection` object.
    app_state: AppState,

    /// Current state of the connection
    state: State,

    /// The WolfSSL connection/session
    session: wolfssl::Session<WolfSSLIOAdapter>,

    /// Client vs Server state.
    mode: ConnectionMode<AppState>,

    /// The MTU for the outside path
    outside_mtu: usize,

    /// Session ID
    session_id: SessionId,

    /// Bytes received from outside after decryption. The is where we
    /// accumulate `Frame` data until we have one or more complete
    /// frames.
    receive_buf: BytesMut,

    /// Application provided trait to deliver the inside packet
    inside_io: Option<InsideIOSendCallbackArg<AppState>>,

    /// Application provided callback to schedule a tick
    schedule_tick_cb: ScheduleTickCb<AppState>,

    /// Application provided callback to notify events
    event_cb: Option<EventCallbackArg>,

    /// Inside plugins
    inside_plugins: PluginList,

    /// Outside plugins
    outside_plugins: Arc<PluginList>,

    /// Is a tick callback pending
    is_tick_timer_running: bool,

    /// Connection activity stats
    activity: ConnectionActivity,

    /// When is next tick due (independent of
    /// `is_tick_timer_running`, since application might be using
    /// [`Connection::tick_interval`] and [`Connection::tick`] instead)
    wolfssl_tick_interval: Option<Duration>,

    /// Pending packet to write to WolfSSL
    /// In nonblocking I/O mode, if the underlying I/O could not satisfy the
    /// needs of wolfSSL_write() to continue, the api will return SSL_ERROR_WANT_WRITE.
    /// In that case, application has to call the api with same buffer again.
    /// Ref: <https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_write>
    wolfssl_pending_pkt: Option<BytesMut>,

    /// Track partially constructed data fragments from [`wire::DataFrag`].
    fragment_map: once_cell::unsync::Lazy<FragmentMap, Box<dyn FnOnce() -> FragmentMap + Send>>,

    /// PMTU discovery state ([`ConnectionType::Datagram`] only)
    pmtud: Option<dplpmtud::Dplpmtud<AppState>>,

    /// Counter to use for `wire::DataFrag`
    fragment_counter: std::num::Wrapping<u16>,

    // Is the first outside packet received
    is_first_packet_received: bool,

    // Inside packet encoder
    inside_pkt_encoder: Option<PacketEncoderType>,

    // Inside packet decoder
    inside_pkt_decoder: Option<PacketDecoderType>,

    // Whether the server will accept inside packet encoding requests
    can_use_inside_pkt_encoding: bool,

    // States for encoding request
    encoding_request_states: EncodingRequestStates,
}

/// Information about the new session being established with a new
/// connection.
struct NewConnectionArgs<AppState> {
    app_state: AppState,
    connection_type: ConnectionType,
    protocol_version: Version,
    session: wolfssl::Session<WolfSSLIOAdapter>,
    session_id: SessionId,
    mode: ConnectionMode<AppState>,
    outside_mtu: usize,
    inside_io: Option<InsideIOSendCallbackArg<AppState>>,
    schedule_tick_cb: ScheduleTickCb<AppState>,
    event_cb: Option<EventCallbackArg>,
    inside_plugins: PluginList,
    outside_plugins: Arc<PluginList>,
    max_fragment_map_entries: NonZeroU16,
    pmtud_timer: Option<dplpmtud::TimerArg<AppState>>,
    pmtud_base_mtu: Option<u16>,
    inside_pkt_codec: Option<(PacketEncoderType, PacketDecoderType)>,
}

impl<AppState: Send> Connection<AppState> {
    /// Construct a new connection
    fn new(args: NewConnectionArgs<AppState>) -> ConnectionResult<Self> {
        let now = Instant::now();
        let max_fragment_map_entries = args.max_fragment_map_entries;
        let (inside_pkt_encoder, inside_pkt_decoder) = match args.inside_pkt_codec {
            Some(e) => (Some(e.0), Some(e.1)),
            None => (None, None),
        };
        let mut conn = Connection {
            connection_type: args.connection_type,
            tunnel_protocol_version: args.protocol_version,
            app_state: args.app_state,
            state: State::Connecting,
            session: args.session,
            session_id: args.session_id,
            mode: args.mode,
            outside_mtu: args.outside_mtu,
            receive_buf: BytesMut::new(),
            inside_io: args.inside_io,
            schedule_tick_cb: args.schedule_tick_cb,
            event_cb: args.event_cb,
            inside_plugins: args.inside_plugins,
            outside_plugins: args.outside_plugins,
            is_tick_timer_running: false,
            activity: ConnectionActivity {
                last_data_traffic_from_peer: now,
                last_outside_data_received: now,
            },
            wolfssl_tick_interval: None,
            wolfssl_pending_pkt: None,
            fragment_map: once_cell::unsync::Lazy::new(Box::new(move || {
                metrics::connection_alloc_frag_map();
                FragmentMap::new(max_fragment_map_entries)
            })),
            pmtud: match args.connection_type {
                ConnectionType::Stream => None,
                ConnectionType::Datagram => args.pmtud_timer.map(|t| {
                    dplpmtud::Dplpmtud::new(
                        args.pmtud_base_mtu.unwrap_or(BASE_PLPMTU),
                        max_dtls_mtu(args.outside_mtu) as u16,
                        t,
                    )
                }),
            },
            fragment_counter: Wrapping(0),
            is_first_packet_received: false,
            inside_pkt_encoder,
            inside_pkt_decoder,
            can_use_inside_pkt_encoding: false,
            encoding_request_states: EncodingRequestStates::default(),
        };

        // This will very likely fail since negotiation always needs
        // more data than will be available. It's just about possible
        // it might succeed under test conditions.
        match conn.session.try_negotiate()? {
            wolfssl::Poll::PendingWrite | wolfssl::Poll::PendingRead => {}
            wolfssl::Poll::Ready(_) => conn.set_state(State::LinkUp)?,
            wolfssl::Poll::AppData(_) => metrics::wolfssl_appdata(&ProtocolVersion::Unknown),
        }

        conn.update_tick_interval();

        Ok(conn)
    }

    /// Gets the application state for this [`Connection`].
    pub fn app_state(&self) -> &AppState {
        &self.app_state
    }

    /// Gets mutable application state for this [`Connection`].
    pub fn app_state_mut(&mut self) -> &mut AppState {
        &mut self.app_state
    }

    /// Sets inside_io
    pub fn inside_io(&mut self, inside_io: InsideIOSendCallbackArg<AppState>) {
        self.inside_io = Some(inside_io)
    }

    /// Get the [`ConnectionType`] of this [`Connection`]
    pub fn connection_type(&self) -> ConnectionType {
        self.connection_type
    }

    /// Get the current session ID.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Get the current pending session ID, if any
    pub fn pending_session_id(&self) -> Option<SessionId> {
        use ConnectionMode::*;

        match self.mode {
            Client { .. } => None,
            Server {
                pending_session_id, ..
            } => pending_session_id,
        }
    }

    fn set_state(&mut self, new_state: State) -> ConnectionResult<()> {
        if self.state == new_state {
            return Ok(());
        };

        info!(state = ?new_state);

        self.state = new_state;

        self.event(Event::StateChanged(new_state));

        if matches!(new_state, State::Online) {
            debug!(curve = ?self.current_curve(), cipher = ?self.current_cipher(), "ONLINE");
            self.session.io_cb_mut().aggressive_send = false;
            if let Some(ref mut pmtud) = self.pmtud {
                let action = pmtud.online(&mut self.app_state);
                self.handle_pmtud_action(action)?;
            }
        }

        if matches!(new_state, State::LinkUp)
            && let ConnectionMode::Client { auth_method, .. } = &self.mode
        {
            self.authenticate(auth_method.clone())?;
        };
        Ok(())
    }

    /// Get the current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Get the current connection activity statistics.
    pub fn activity(&self) -> ConnectionActivity {
        self.activity
    }

    /// Query the TLS protocol version of this connection, only valid
    /// after [`State::LinkUp`] has been reached.
    pub fn tls_protocol_version(&mut self) -> ProtocolVersion {
        self.session.version()
    }

    /// Query the lightway protocol version of this connection.
    ///
    /// Note: For a server connection this may change during
    /// connection establishment up until [`State::Online`] and in
    /// particular during authentication.
    pub fn tunnel_protocol_version(&self) -> Version {
        self.tunnel_protocol_version
    }

    /// Set the lightway protocol version of this connection.
    ///
    /// This may only be called on `ConnectionMode::Server` and only
    /// prior to reaching [`State::Online`].
    ///
    /// If called while in [`State::Online`] then `v` must be the same
    /// as the current `self.tunnel_protocol_version`.
    pub fn set_tunnel_protocol_version(&mut self, v: Version) -> ConnectionResult<()> {
        if !matches!(self.mode, ConnectionMode::Server { .. }) {
            error!(
                version = ?v, "Attempted to set tunnel protocol version on client"
            );
            return Err(ConnectionError::InvalidMode);
        }

        if matches!(self.state, State::Online) && self.tunnel_protocol_version == v {
            return Ok(());
        }

        if !matches!(
            self.state,
            State::Connecting | State::LinkUp | State::Authenticating
        ) {
            error!(
                state = ?self.state,
                current_version = ?self.tunnel_protocol_version,
                version = ?v, "Attempted to set tunnel protocol version in invalid state"
            );
            return Err(ConnectionError::InvalidState);
        }

        self.tunnel_protocol_version = v;

        Ok(())
    }

    /// Query the address of this connection's peer
    pub fn peer_addr(&self) -> SocketAddr {
        self.session.io_cb().io.peer_addr()
    }

    /// Set the address of this connection's peer
    pub fn set_peer_addr(&mut self, addr: SocketAddr) -> SocketAddr {
        self.session.io_cb_mut().io.set_peer_addr(addr)
    }

    /// Get the negotiated cipher, only valid after [`State::LinkUp`]
    /// has been reached.
    pub fn current_cipher(&mut self) -> Option<String> {
        self.session.get_current_cipher_name()
    }

    /// Get the negotiated curve, only valid after [`State::LinkUp`]
    /// has been reached.
    pub fn current_curve(&mut self) -> Option<String> {
        self.session.get_current_curve_name()
    }

    fn update_tick_interval(&mut self) {
        // Only Datagram (DTLS) connections need ticks
        if !self.connection_type.is_datagram() {
            return;
        }

        let key_update_pending = if let ConnectionMode::Server { key_update, .. } = &self.mode {
            key_update.is_pending()
        } else {
            false
        };

        if matches!(self.state, State::Online) && !key_update_pending {
            self.wolfssl_tick_interval = None;
            return;
        }

        // Get and scale the tick interval
        let mut interval = self.session.dtls_current_timeout() / WOLF_TICK_INTERVAL_DIVISOR;

        if matches!(self.tls_protocol_version(), ProtocolVersion::DtlsV1_3)
            && self.session.dtls13_use_quick_timeout()
        {
            interval /= WOLF_TICK_DTLS13_QUICK_TIMEOUT_DIVISOR;
        }
        self.wolfssl_tick_interval = Some(interval);

        // Trigger a callback if timer is not already running
        if !self.is_tick_timer_running {
            trace!("Scheduling tick for {:?}", interval);
            (self.schedule_tick_cb)(
                interval,
                &mut self.app_state,
                crate::TickType::ConnectionTick,
            );

            self.is_tick_timer_running = true;
        }
    }

    /// Returns the time the application should wait before calling
    /// [`Connection::tick`].
    ///
    /// Lightway uses D/TLS which needs to be able to resend certain
    /// messages if they are not received in time. As Lightway does not
    /// have its own threads or timers, it is up to the host application
    /// to tell Lightway when a certain amount of time has passed. Because
    /// D/TLS implements exponential back off, the amount of waiting time
    /// can change after every read.
    ///
    /// If in use this should be called after every read cycle and, if
    /// `Some(_)`, [`Connection::tick`] should be called that amount
    /// of time later.
    pub fn tick_interval(&self) -> Option<Duration> {
        self.wolfssl_tick_interval
    }

    /// Inject a tick to the connection. See
    /// [`Connection::tick_interval`] for usage.
    pub fn tick(&mut self, tick_type: TickType) -> ConnectionResult<()> {
        match tick_type {
            TickType::ConnectionTick => self.connection_tick(),
            TickType::PktCodecTick(request_id) => self.codec_tick(request_id),
        }
    }

    /// Inject a tick to the connection. See
    /// [`Connection::tick_interval`] for usage.
    pub fn connection_tick(&mut self) -> ConnectionResult<()> {
        self.is_tick_timer_running = false;
        trace!(session_id = ?self.session_id, "Processing connection tick");

        match self.state {
            State::Authenticating => {
                if let ConnectionMode::Client { auth_method, .. } = &self.mode {
                    self.authenticate(auth_method.clone())?; // Resend authentication request
                } else {
                    // Server should never be authenticating.
                    return Err(ConnectionError::InvalidMode);
                }
            }
            State::Disconnecting | State::Disconnected => {
                return Err(ConnectionError::Disconnected);
            }
            _ if self.connection_type.is_datagram() => match self.session.dtls_has_timed_out() {
                wolfssl::Poll::Ready(true) => {
                    warn!(session_id = ?self.session_id, "DTLS timed out, disconnecting client");
                    let _ = self.disconnect();
                    return Err(ConnectionError::TimedOut);
                }
                wolfssl::Poll::PendingWrite
                | wolfssl::Poll::PendingRead
                | wolfssl::Poll::Ready(false) => {}
                wolfssl::Poll::AppData(_) => metrics::wolfssl_appdata(&self.tls_protocol_version()),
            },
            _ => {}
        };

        self.update_tick_interval();

        Ok(())
    }

    /// Return true if this server connection's authentication has
    /// expired.
    ///
    /// Valid for server connections only.
    pub fn authentication_expired(&self) -> ConnectionResult<bool> {
        let ConnectionMode::Server { auth_handle, .. } = &self.mode else {
            return Err(ConnectionError::InvalidMode);
        };

        let Some(auth_handle) = auth_handle else {
            // Not yet authenticated, so not eligible to have expired
            return Ok(false);
        };

        Ok(auth_handle.expired())
    }

    /// Update WolfSSL Session to use the new outside IO Callback
    pub fn set_outside_io(&mut self, new_io: OutsideIOSendCallbackArg) {
        self.session.io_cb_mut().io = new_io;
    }

    /// Accept some data from outside and run an iteration of the I/O
    /// loop. Applications should call this whenever data becomes
    /// available.
    ///
    /// Return the count of valid lightway frames read
    /// In case of TCP, it is possible that each packet does not correspond
    /// to one lightway frame. So count can be 0.
    /// In case of UDP, it is almost always one frame per packet. With duplicated
    /// UDP packets, count can be 0.
    pub fn outside_data_received(&mut self, pkt: OutsidePacket) -> ConnectionResult<usize> {
        // Fatal error:
        // In case of protocol disconnection instead of explicit disconnect
        // from Application, notify application that connection is not alive
        if matches!(self.state, State::Disconnected) {
            return Err(ConnectionError::Disconnected);
        }

        if !self.is_first_packet_received && matches!(self.mode, ConnectionMode::Client { .. }) {
            self.event(Event::FirstPacketReceived);
            self.is_first_packet_received = true;
        }

        let pkt = pkt.apply_ingress_chain(&self.outside_plugins)?;

        let session_id = match pkt.header() {
            Some(hdr) => {
                if matches!(self.mode, ConnectionMode::Server { .. }) {
                    if hdr.version != self.tunnel_protocol_version {
                        return Err(ConnectionError::InvalidProtocolVersion);
                    }

                    if hdr.session == SessionId::REJECTED {
                        // Drop reject packets to prevent an infinite loop
                        // where an attacker causes us to send rejected
                        // packets between servers.
                        return Err(ConnectionError::RejectedSessionID);
                    }
                }
                Some(hdr.session)
            }
            None => None,
        };

        let Some(payload) = pkt.into_payload() else {
            return Err(ConnectionError::RejectedSessionID);
        };

        let result = self.process_new_outside_data(payload);
        match result {
            // We only look into the session id after we verify the connection is valid
            Ok(frames_read) if frames_read > 0 => self.update_session_id(session_id),
            _ => {}
        }
        result
    }

    /// Consume data received from inside path and send it as
    /// outside data packet.
    /// The returned Poll value reflects the inside I/O requirements.
    pub fn inside_data_received(&mut self, pkt: &mut BytesMut) -> ConnectionResult<()> {
        use ConnectionError::InvalidInsidePacket;
        use InvalidPacketError::{InvalidIpv4Packet, InvalidPacketSize};

        // Fatal error:
        // In case of protocol disconnection instead of explicit disconnect
        // from Application, notify application that connection is not alive
        if matches!(self.state, State::Disconnected) {
            return Err(ConnectionError::Disconnected);
        }

        // Not a fatal error, Might be due to packet reordering
        if !matches!(self.state, State::Online) {
            return Err(ConnectionError::InvalidState);
        }

        let Some(inside_io) = &self.inside_io else {
            return Err(ConnectionError::InvalidState);
        };
        // Should not be larger than inside MTU.
        if pkt.len() > inside_io.mtu() {
            return Err(InvalidInsidePacket(InvalidPacketSize));
        }
        // If not ipv4 packet, return error
        if !ipv4_is_valid_packet(pkt.as_ref()) {
            return Err(InvalidInsidePacket(InvalidIpv4Packet));
        }

        // This should be enabled only for client for now.
        // But since we enable PMTU check only on client, there is no direct
        // check for client/server
        if let Some(pmtud) = self.pmtud.as_ref()
            && let Some((mps, _)) = pmtud.maximum_packet_sizes()
        {
            let tcp_mss = mps - (IPV4_HEADER_SIZE + TCP_HEADER_SIZE);
            tcp_clamp_mss(pkt.as_mut(), tcp_mss as _);
        }

        match self.inside_plugins.do_ingress(pkt) {
            PluginResult::Accept => {}
            PluginResult::Drop => {
                return Ok(());
            }
            PluginResult::DropWithReply(b) => {
                return Err(ConnectionError::PluginDropWithReply(b));
            }
            PluginResult::Error(e) => {
                return Err(ConnectionError::PluginError(e));
            }
        }

        if let Some(encoder) = &mut self.inside_pkt_encoder {
            let codec_state = encoder.store(pkt);
            match codec_state {
                Ok(CodecStatus::PacketAccepted) => Ok(()),
                Ok(CodecStatus::SkipPacket) => {
                    // The encoder does not accept the packet.
                    // Packet should not be encoded. Sending to outside directly.
                    self.send_to_outside(pkt, false)
                }
                Err(e) => Err(ConnectionError::PacketCodecError(e)),
            }
        } else {
            // If no packet encoder presents, directly send to outside
            self.send_to_outside(pkt, false)
        }
    }

    /// Send a packet to the outside
    pub fn send_to_outside(
        &mut self,
        pkt: &mut BytesMut,
        is_encoded: bool,
    ) -> ConnectionResult<()> {
        if !matches!(self.state, State::Online) {
            return Err(ConnectionError::InvalidState);
        }

        if let Some(pmtu) = &self.pmtud
            && let Some((data_mps, frag_mps)) = pmtu.maximum_packet_sizes()
            && pkt.len() > data_mps
        {
            self.send_fragmented_outside_data(pkt.clone().freeze(), frag_mps, is_encoded)
        } else {
            self.send_outside_data(pkt, is_encoded)
        }
    }

    fn send_outside_data(&mut self, data: &mut BytesMut, is_encoded: bool) -> ConnectionResult<()> {
        // If PMTUD is not active or the search has not completed then
        // we can only send up to the configured MTU.
        if self.connection_type.is_datagram()
            && data.len() > wire::Data::maximum_packet_size_for_plpmtu(self.outside_mtu)
        {
            return Err(ConnectionError::InvalidInsidePacket(
                InvalidPacketError::InvalidPacketSize,
            ));
        }

        let inside_pkt = wire::Data {
            data: Cow::Borrowed(data),
        };
        let msg = if is_encoded {
            wire::Frame::EncodedData(inside_pkt)
        } else {
            wire::Frame::Data(inside_pkt)
        };
        self.send_frame_or_drop(msg)
    }

    fn next_fragment_id(&mut self) -> u16 {
        self.fragment_counter += 1;
        self.fragment_counter.0
    }

    fn send_fragmented_outside_data(
        &mut self,
        mut data: Bytes,
        mps: usize,
        is_encoded: bool,
    ) -> ConnectionResult<()> {
        // NB: pkt.len() is checked vs MAX MTU by the caller so this
        // is currently redundant, but reflects what fragmentation can
        // actually handle.
        if data.len() > u16::MAX as usize {
            return Err(ConnectionError::InvalidInsidePacket(
                InvalidPacketError::InvalidPacketSize,
            ));
        }

        let id = self.next_fragment_id();
        let mut offset = 0;
        while !data.is_empty() {
            let frag = data.split_to(std::cmp::min(mps, data.len()));
            let frag = wire::DataFrag {
                id,
                offset,
                data: frag,
                more_fragments: !data.is_empty(),
            };

            let msg = if is_encoded {
                wire::Frame::EncodedDataFrag(frag)
            } else {
                wire::Frame::DataFrag(frag)
            };

            self.send_frame_or_drop(msg)?;
            offset += mps;
        }
        Ok(())
    }

    /// Send a keepalive packet to the peer.
    pub fn keepalive(&mut self) -> ConnectionResult<()> {
        if !matches!(self.state, State::Online) {
            return Ok(());
        };

        let id = 0;

        debug!(session = ?self.session_id, id, "Sending ping");

        let ping = wire::Ping {
            id,
            payload: Default::default(),
        };

        let msg = wire::Frame::Ping(ping);

        self.send_frame_or_drop(msg)
    }

    /// Disconnect this connection
    pub fn disconnect(&mut self) -> ConnectionResult<()> {
        // Return error if in the wrong state
        if matches!(
            self.state,
            State::Disconnecting | State::Connecting | State::Disconnected
        ) {
            return Err(ConnectionError::InvalidState);
        }

        self.set_state(State::Disconnecting)?;

        // Free the allocated IP to this connection
        if let ConnectionMode::Server { ip_pool, .. } = &self.mode {
            ip_pool.free(&mut self.app_state);
        }

        let msg = wire::Frame::Goodbye;

        // here, goodbye + shutdown are just a courtesy.
        let _ = self.send_frame_or_drop(msg);
        let _ = self.session.try_shutdown();

        self.set_state(State::Disconnected)?;

        Ok(())
    }

    /// Generate an event
    fn event(&mut self, event: Event) {
        if let Some(event_cb) = &mut self.event_cb {
            debug!(?event, "event");
            event_cb.event(event);
        }
    }

    /// Try to send a frame.
    /// In case I/O would block, save the frame inside `ConnectionState` .
    /// and send the frame in next call.
    fn send_frame_or_drop(&mut self, frame: wire::Frame) -> ConnectionResult<()> {
        // If there is a packet pending, send it first and drop the current one
        let mut buf = match self.wolfssl_pending_pkt.take() {
            None => {
                let mut buf = BytesMut::new();
                frame.append_to_wire(&mut buf);
                buf
            }
            Some(buf) => buf,
        };

        match self.session.try_write(&mut buf)? {
            wolfssl::Poll::PendingWrite | wolfssl::Poll::PendingRead => {
                self.wolfssl_pending_pkt = Some(buf);
                Ok(())
            }
            wolfssl::Poll::Ready(_) => Ok(()),
            wolfssl::Poll::AppData(_) => {
                metrics::wolfssl_appdata(&self.tls_protocol_version());
                Ok(())
            }
        }
    }

    /// Start a session ID rotation, returning the pending session id.
    ///
    /// NOP if a rotation is already in progress, the existing pending
    /// session id is returned.
    ///
    /// This is a server side operation only.
    ///
    /// Once the rotation completes (i.e. traffic is observed from the
    /// client using the new session ID) then
    /// [`Event::SessionIdRotationAcknowledged`] will be fired.
    pub fn rotate_session_id(&mut self) -> ConnectionResult<SessionId> {
        use ConnectionMode::*;

        match self.mode {
            Client { .. } => Err(ConnectionError::InvalidMode),
            Server {
                pending_session_id: Some(pending_session_id),
                ..
            } => Ok(pending_session_id),
            Server {
                ref mut rng,
                ref mut pending_session_id,
                ..
            } => {
                let new_session_id = rng.lock().unwrap().random();

                self.session.io_cb_mut().set_session_id(new_session_id);

                *pending_session_id = Some(new_session_id);

                Ok(new_session_id)
            }
        }
    }

    fn handle_pmtud_action(&mut self, a: dplpmtud::Action) -> ConnectionResult<()> {
        match a {
            dplpmtud::Action::SendProbe { id, size } => {
                info!(id, "Sending PMTUD probe (id {id}, size {size})");

                let payload = BytesMut::zeroed(size as usize).freeze();
                let ping = wire::Ping { id, payload };

                let msg = wire::Frame::Ping(ping);

                self.session.io_cb().enable_pmtud_probe();
                let res = self.send_frame_or_drop(msg);
                self.session.io_cb().disable_pmtud_probe();
                res
            }
            dplpmtud::Action::None => Ok(()),
        }
    }

    /// Inject a tick to PMTUD (after timer started with
    /// [`crate::DplpmtudTimer::start`] expires).
    pub fn pmtud_tick(&mut self) -> ConnectionResult<()> {
        if !matches!(self.state, State::Online) {
            return Ok(());
        };

        let Some(pmtud) = self.pmtud.as_mut() else {
            return Ok(());
        };

        let action = pmtud.tick(&mut self.app_state);
        self.handle_pmtud_action(action)
    }

    /// Update the session id (only the one we wanted to rotate to) after the connection is validated.
    fn update_session_id(&mut self, session_id: Option<wire::SessionId>) {
        use ConnectionMode::*;

        let Some(session_id) = session_id else {
            return;
        };

        if session_id == wire::SessionId::EMPTY {
            return;
        }

        // No update required
        if session_id == self.session_id {
            return;
        }

        match self.mode {
            Client { .. } => {
                self.session_id = session_id;
                self.session.io_cb_mut().set_session_id(session_id);
            }
            Server {
                ref mut pending_session_id,
                ..
            } => {
                match pending_session_id {
                    Some(new) if *new == session_id => {
                        let new = *new;
                        let old = std::mem::replace(&mut self.session_id, new);

                        *pending_session_id = None;

                        self.event(Event::SessionIdRotationAcknowledged { old, new });
                    }
                    // Session id in server is only used to look up the session if it was not found by client IP/Port, so a mismatch here won't affect anything.
                    _ => metrics::session_id_mismatch(),
                }
            }
        }
    }

    fn authenticate(&mut self, auth_method: AuthMethod) -> ConnectionResult<()> {
        assert!(matches!(self.state, State::LinkUp | State::Authenticating));
        self.set_state(State::Authenticating)?;

        let msg = wire::Frame::AuthRequest(wire::AuthRequest { auth_method });
        self.send_frame_or_drop(msg)
    }

    // Trigger a periodic key update for TLS/DTLS 1.3 server
    // connections.
    fn maybe_update_tls_keys(&mut self) -> ConnectionResult<()> {
        // Only for TLS/DTLS 1.3
        match self.tls_protocol_version() {
            ProtocolVersion::DtlsV1_3 | ProtocolVersion::TlsV1_3 => {}
            _ => return Ok(()),
        }

        // Only if a server
        let ConnectionMode::Server { key_update, .. } = &mut self.mode else {
            return Ok(());
        };

        // Is a key update required
        if !key_update.required() {
            return Ok(());
        }

        // It's time to update keys!
        info!(session = ?self.session_id, "Update TLS keys");
        match self.session.try_trigger_update_key()? {
            // From https://github.com/wolfSSL/wolfssl/blob/3b3c175af0e993ffaae251871421e206cc41963f/src/tls13.c#L12167:
            //
            // > If using non-blocking I/O and
            // > WOLFSSL_ERROR_WANT_WRITE is returned then calling
            // > wolfSSL_write() will have the message sent when ready.
            //
            // So we need not worry about `PendingWrite` here -- the
            // actual update will happen at some future `try_write`.
            wolfssl::Poll::PendingWrite | wolfssl::Poll::PendingRead | wolfssl::Poll::Ready(_) => {
                self.event(Event::TlsKeysUpdateStart);
                self.update_tick_interval();
                Ok(())
            }
            wolfssl::Poll::AppData(_) => {
                metrics::wolfssl_appdata(&self.tls_protocol_version());
                Ok(())
            }
        }
    }

    fn process_new_outside_data(&mut self, buf: &BytesMut) -> ConnectionResult<usize> {
        let outside_received_pending = &mut self.session.io_cb_mut().recv_buf;
        outside_received_pending.extend_from_slice(&buf[..]);

        self.activity.last_outside_data_received = Instant::now();
        let frame_read_count_result = match self.state {
            State::Connecting => match self.session.try_negotiate()? {
                wolfssl::Poll::PendingWrite => {
                    self.update_tick_interval();
                    Ok(0)
                }
                wolfssl::Poll::PendingRead => {
                    self.update_tick_interval();
                    Ok(0)
                }
                wolfssl::Poll::Ready(_) => {
                    self.set_state(State::LinkUp)?;
                    self.handle_messages()
                }
                wolfssl::Poll::AppData(_) => {
                    metrics::wolfssl_appdata(&self.tls_protocol_version());
                    Ok(0)
                }
            },

            State::LinkUp | State::Authenticating | State::Online => self.handle_messages(),

            State::Disconnecting | State::Disconnected => Err(ConnectionError::InvalidState),
        };

        // RFC6347 mandates each datagram should have full record and one TLS record cannot span
        // over multiple datagrams
        // https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.2.6
        // So drop remaining buffer if any in case of UDP transport
        if self.connection_type.is_datagram() {
            let outside_received_pending = &mut self.session.io_cb_mut().recv_buf;
            outside_received_pending.clear();
        }

        frame_read_count_result
    }

    fn handle_messages(&mut self) -> ConnectionResult<usize> {
        let mut frames_read = 0;

        // Loop consuming frames until we either run out of data or
        // get an error.
        loop {
            let frame = match wire::Frame::try_from_wire(&mut self.receive_buf) {
                Ok(f) => f,
                Err(wire::FromWireError::InsufficientData) => {
                    // We've run out of data in `receive_buf`. Attempt to receive some more,
                    // if not return appropriate hint to the application.

                    // Ensure we will have room for a whole new frame.
                    self.receive_buf.reserve(self.outside_mtu);

                    match self.session.try_read(&mut self.receive_buf)? {
                        wolfssl::Poll::PendingWrite => break,
                        wolfssl::Poll::PendingRead => break,
                        wolfssl::Poll::Ready(_) => continue,
                        wolfssl::Poll::AppData(data) => {
                            self.receive_buf.extend_from_slice(&data[..]);
                            metrics::wolfssl_appdata(&self.tls_protocol_version());
                            continue;
                        }
                    }
                }
                Err(e) => return Err(e.into()),
            };

            frames_read += 1;
            match frame {
                wire::Frame::NoOp => {}
                wire::Frame::Ping(ping) => self.handle_ping(ping)?,
                wire::Frame::Pong(pong) => self.handle_pong(pong)?,
                wire::Frame::AuthRequest(auth_request) => {
                    self.handle_auth_request(auth_request)?;
                }
                wire::Frame::Data(data) => self.handle_outside_data_packet(data, false)?,
                wire::Frame::DataFrag(frag) => self.handle_outside_data_fragment(frag, false)?,
                wire::Frame::EncodedData(data) => self.handle_outside_data_packet(data, true)?,
                wire::Frame::EncodedDataFrag(frag) => {
                    self.handle_outside_data_fragment(frag, true)?
                }
                wire::Frame::AuthSuccessWithConfigV4(cfg) => self.handle_auth_response(cfg)?,
                wire::Frame::AuthFailure(_) => return Err(ConnectionError::Unauthorized),
                wire::Frame::Goodbye => return Err(ConnectionError::Goodbye),
                wire::Frame::ServerConfig(_) => warn!("Ignoring ServerConfig"),
                wire::Frame::EncodingRequest(er) => self.process_encoding_request_pkt(er)?,
                wire::Frame::EncodingResponse(er) => self.process_encoding_response_pkt(er)?,
            };
        }

        self.maybe_update_tls_keys()?;
        if let ConnectionMode::Server { key_update, .. } = &mut self.mode {
            let pending = self.session.is_update_keys_pending();
            if !pending && key_update.complete() {
                self.event(Event::TlsKeysUpdateCompleted);
                self.update_tick_interval()
            }
        }

        Ok(frames_read)
    }

    fn handle_ping(&mut self, ping: wire::Ping) -> ConnectionResult<()> {
        if !matches!(self.state, State::Online) {
            return Err(ConnectionError::InvalidState);
        }

        debug!(
            session = ?self.session_id,
            id = ping.id,
            payload_length = ping.payload.len(),
            "Received ping"
        );

        let pong = wire::Pong { id: ping.id };

        debug!(session = ?self.session_id(), id = pong.id, "Sending pong");

        let msg = wire::Frame::Pong(pong);

        self.send_frame_or_drop(msg)
    }

    fn handle_pong(&mut self, pong: wire::Pong) -> ConnectionResult<()> {
        if !matches!(self.state, State::Online) {
            return Err(ConnectionError::InvalidState);
        }

        debug!(id = pong.id, "Received pong");
        if pong.id == 0 {
            self.event(Event::KeepaliveReply);
        }
        if let Some(ref mut pmtud) = self.pmtud {
            let action = pmtud.pong_received(&pong, &mut self.app_state);
            self.handle_pmtud_action(action)?;
        }

        Ok(())
    }

    fn send_auth_failure(&mut self) {
        let msg = wire::Frame::AuthFailure(wire::AuthFailure);

        let _ = self.send_frame_or_drop(msg);
        let _ = self.disconnect();
    }

    fn handle_auth_request(&mut self, auth_request: wire::AuthRequest) -> ConnectionResult<()> {
        let ConnectionMode::Server {
            auth,
            auth_handle,
            ip_pool,
            key_update,
            ..
        } = &mut self.mode
        else {
            return Err(ConnectionError::InvalidMode);
        };

        // Normally we would expect to be in `State::LinkUp` when
        // authenticating. However with aggressive connection mode we
        // may have seen the first request and therefore moved to
        // `State::Online` but the reply might have been lost,
        // therefore we also process auth requests while already in
        // `State::Online` so that the reply will be repeated.
        if !matches!(self.state, State::LinkUp | State::Online) {
            return Err(ConnectionError::InvalidState);
        }

        let Some(ip_config) = ip_pool.alloc(&mut self.app_state) else {
            self.send_auth_failure();
            return Err(ConnectionError::NoAvailableClientIp);
        };

        let Some(inside_io) = self.inside_io.as_ref() else {
            self.send_auth_failure();
            return Err(ConnectionError::InvalidInsideIo);
        };

        match auth.authorize(&auth_request.auth_method, &mut self.app_state) {
            ServerAuthResult::Granted {
                tunnel_protocol_version,
                handle,
            } => {
                key_update.online();

                let msg = wire::Frame::AuthSuccessWithConfigV4(wire::AuthSuccessWithConfigV4 {
                    local_ip: ip_config.client_ip.to_string(),
                    peer_ip: ip_config.server_ip.to_string(),
                    dns_ip: ip_config.dns_ip.to_string(),
                    mtu: format!("{}", inside_io.mtu()),
                    session: self.session_id,
                });

                if let Some(ref handle) = handle {
                    self.can_use_inside_pkt_encoding =
                        handle.features().contains(&LightwayFeature::InsidePktCodec);
                }

                *auth_handle = handle;

                self.send_frame_or_drop(msg)?;

                if let Some(v) = tunnel_protocol_version {
                    self.set_tunnel_protocol_version(v)?
                }

                self.set_state(State::Online)?;
                Ok(())
            }
            ServerAuthResult::Denied => {
                self.send_auth_failure();
                Err(ConnectionError::AccessDenied)
            }
        }
    }

    fn handle_auth_response(&mut self, cfg: AuthSuccessWithConfigV4) -> ConnectionResult<()> {
        info!(config = ?cfg, "Authentication succeeded");

        // Ignore the message if client is already online
        if matches!(self.state, State::Online) {
            return Ok(());
        }

        if let Ok(inside_mtu) = cfg.mtu.parse()
            && self.connection_type.is_datagram()
            && self.outside_mtu < dtls_required_outside_mtu(inside_mtu)
            && self.pmtud.is_some()
        {
            return Err(ConnectionError::PathMtuDiscoveryRequired {
                inside_mtu,
                required_outside_mtu: dtls_required_outside_mtu(inside_mtu),
            });
        }

        if let ConnectionMode::Client { ip_config_cb, .. } = &self.mode {
            let ip_config = cfg.try_into()?;
            ip_config_cb.ip_config(&mut self.app_state, ip_config);
        } else {
            // Server should never be authenticating.
            return Err(ConnectionError::InvalidMode);
        }

        // Set connection state to Online
        self.set_state(State::Online)?;

        Ok(())
    }

    fn handle_outside_data_bytes(
        &mut self,
        mut inside_bytes: BytesMut,
        is_encoded: bool,
    ) -> ConnectionResult<()> {
        if !is_encoded {
            return self.send_to_inside(inside_bytes);
        }

        let decoder = match &mut self.inside_pkt_decoder {
            Some(decoder) => decoder,
            None => {
                // No decoder exists to process the encoded packet
                return Err(ConnectionError::PacketCodecDoesNotExist);
            }
        };

        let decoder_state = decoder.store(&mut inside_bytes);
        match decoder_state {
            Ok(CodecStatus::PacketAccepted) => Ok(()),
            Ok(CodecStatus::SkipPacket) => {
                // The decoder does not accept the packet.
                // Packet should not be decoded. Sending to inside directly.
                self.send_to_inside(inside_bytes)
            }
            Err(e) => Err(ConnectionError::PacketCodecError(e)),
        }
    }

    /// Send a packet to the inside
    pub fn send_to_inside(&mut self, mut inside_pkt: BytesMut) -> ConnectionResult<()> {
        use ConnectionError::InvalidInsidePacket;
        use InvalidPacketError::InvalidIpv4Packet;

        if !matches!(self.state, State::Online) {
            return Err(ConnectionError::InvalidState);
        }

        if !ipv4_is_valid_packet(inside_pkt.as_ref()) {
            return Err(InvalidInsidePacket(InvalidIpv4Packet));
        }

        let Some(inside_io) = &self.inside_io else {
            return Err(InvalidInsidePacket(InvalidIpv4Packet));
        };

        match self.inside_plugins.do_egress(&mut inside_pkt) {
            PluginResult::Accept => {}
            PluginResult::Drop => {
                return Ok(());
            }
            PluginResult::DropWithReply(b) => {
                return Err(ConnectionError::PluginDropWithReply(b));
            }
            PluginResult::Error(e) => {
                return Err(ConnectionError::PluginError(e));
            }
        }

        self.activity.last_data_traffic_from_peer = Instant::now();
        match inside_io.send(inside_pkt, &mut self.app_state) {
            IOCallbackResult::Ok(_nr) => {}
            IOCallbackResult::Err(err) => {
                metrics::inside_io_send_failed(err);
            }
            IOCallbackResult::WouldBlock => {}
        }

        Ok(())
    }

    fn handle_outside_data_packet(
        &mut self,
        data: wire::Data,
        is_encoded: bool,
    ) -> ConnectionResult<()> {
        if !matches!(self.state, State::Online) {
            return Err(ConnectionError::InvalidState);
        }

        // into_owned should be a NOP here since
        // `wire::Data::try_from_wire` produced a `Cow::Owned`
        // variant.
        self.handle_outside_data_bytes(data.data.into_owned(), is_encoded)
    }

    fn handle_outside_data_fragment(
        &mut self,
        frag: wire::DataFrag,
        is_encoded: bool,
    ) -> ConnectionResult<()> {
        if !matches!(self.state, State::Online) {
            return Err(ConnectionError::InvalidState);
        }

        match self.fragment_map.add_fragment(frag) {
            FragmentMapResult::Complete(data) => {
                self.handle_outside_data_bytes(data, is_encoded)?;
                Ok(())
            }
            FragmentMapResult::Incomplete => Ok(()),
            FragmentMapResult::Err(err) => Err(err.into()),
        }
    }

    /// Process an EncodingRequest packet (Server only)
    fn process_encoding_request_pkt(&mut self, er: wire::EncodingRequest) -> ConnectionResult<()> {
        let encoder = match self.inside_pkt_encoder.clone() {
            Some(encoder) => encoder,
            None => {
                debug!("Received EncodingRequest packet without an encoder.");
                return Ok(()); // No encoder. Ignoring the request.
            }
        };

        if !self.can_use_inside_pkt_encoding {
            warn!(
                "Received EncodingRequest packet while connection has no authorization to use inside packet encoding"
            );
            metrics::received_encoding_req_no_authorization();
            let msg = wire::Frame::EncodingResponse(wire::EncodingResponse {
                id: er.id,
                enable: false,
            });
            return self.send_frame_or_drop(msg);
        }

        if !matches!(self.state, State::Online) {
            warn!("Received EncodingRequest packet before state is Online");
            metrics::received_encoding_req_non_online();
            return Err(ConnectionError::InvalidState);
        }

        if !matches!(self.connection_type, ConnectionType::Datagram) {
            warn!("Received EncodingRequest packet in TCP mode.");
            metrics::received_encoding_req_with_tcp();
            return Err(ConnectionError::InvalidConnectionType);
        }

        if !matches!(self.mode, ConnectionMode::Server { .. }) {
            error!("Received EncodingRequest as a client");
            return Err(ConnectionError::InvalidMode);
        }

        // Stale request as it is older than the latest acknowledged encoding request.
        // Do nothing and return.
        if er.id < self.encoding_request_states.id_counter {
            debug!(
                "Client {:?}: received stale encode request. request: {}, current: {}",
                self.session_id, er.id, self.encoding_request_states.id_counter
            );
            return Ok(());
        }

        // Update the latest acknowledged packet's id
        self.encoding_request_states.id_counter = er.id;

        encoder.set_encoding_state(er.enable);
        debug!(
            "Client {:?}: EncodingRequest {} received. encoding state now: {}.",
            self.session_id,
            self.encoding_request_states.id_counter,
            encoder.get_encoding_state()
        );

        self.event(Event::EncodingStateChanged { enabled: er.enable });

        // Reply to the client.
        let msg = wire::Frame::EncodingResponse(wire::EncodingResponse {
            id: er.id,
            enable: er.enable,
        });
        self.send_frame_or_drop(msg)
    }

    /// Process an EncodingResponse packet (Client only)
    fn process_encoding_response_pkt(
        &mut self,
        te: wire::EncodingResponse,
    ) -> ConnectionResult<()> {
        let encoder = match &mut self.inside_pkt_encoder {
            Some(encoder) => encoder,
            None => {
                error!("Received EncodingResponse packet even without an encoder.");
                return Err(ConnectionError::PacketCodecDoesNotExist);
            }
        };

        if !matches!(self.state, State::Online) {
            warn!("Received encoding request packet before state is Online");
            return Err(ConnectionError::InvalidState);
        }

        if !matches!(self.connection_type, ConnectionType::Datagram) {
            error!("Received Encoding response packet in TCP mode.");
            return Err(ConnectionError::InvalidConnectionType);
        }

        if !matches!(self.mode, ConnectionMode::Client { .. }) {
            warn!("Received an encoding response as a server");
            metrics::received_encoding_res_as_server();
            return Err(ConnectionError::InvalidMode);
        }

        // Latest encoding request is already acknowledged
        if self.encoding_request_states.pending_request_pkt.is_none() {
            debug!("response received when request already acknowledged");
            return Ok(());
        }

        if te.id != self.encoding_request_states.id_counter {
            debug!(
                "stale encoding response received. response id: {}, current id: {}",
                te.id, self.encoding_request_states.id_counter
            );
            return Ok(());
        }

        let new_setting = te.enable;

        encoder.set_encoding_state(new_setting);
        info!("inside packet encoding state is now set to {}", new_setting);

        self.event(Event::EncodingStateChanged {
            enabled: new_setting,
        });

        // Removes from pending pkt store such that it is no longer retransmitted
        self.encoding_request_states.pending_request_pkt = None;

        Ok(())
    }

    /// Get the current encoding state from the encoder
    pub fn is_encoding_enabled(&self) -> bool {
        self.inside_pkt_encoder
            .as_ref()
            .map(|encoder| encoder.get_encoding_state())
            .unwrap_or(false)
    }

    /// Create and send an encoding request to the server. (Client only)
    pub fn set_encoding(&mut self, enable: bool) -> ConnectionResult<()> {
        if self.inside_pkt_encoder.is_none() {
            return Err(ConnectionError::PacketCodecDoesNotExist);
        }

        if !matches!(self.state, State::Online) {
            error!("Attempting to send encoding request packet before state is Online");
            return Err(ConnectionError::InvalidState);
        }

        if !matches!(self.connection_type, ConnectionType::Datagram) {
            return Err(ConnectionError::InvalidConnectionType);
        }

        self.encoding_request_states.id_counter =
            self.encoding_request_states.id_counter.wrapping_add(1);
        let encoding_request = wire::EncodingRequest {
            id: self.encoding_request_states.id_counter,
            enable,
        };

        self.encoding_request_states.pending_request_pkt = Some(encoding_request.clone());
        self.encoding_request_states.retransmissions_counter = 0;

        let msg = wire::Frame::EncodingRequest(encoding_request);

        // Callback to schedule a re-transmission
        (self.schedule_tick_cb)(
            self.encoding_request_states.retransmit_wait_time(),
            &mut self.app_state,
            TickType::PktCodecTick(self.encoding_request_states.id_counter),
        );

        debug!(
            "Encoding Request {} created",
            self.encoding_request_states.id_counter
        );

        self.send_frame_or_drop(msg)
    }

    /// Attempts to retransmit the currently pending encoding request packet. (Client only)
    pub fn codec_tick(&mut self, request_id: u64) -> ConnectionResult<()> {
        if self.inside_pkt_encoder.is_none() {
            return Err(ConnectionError::PacketCodecDoesNotExist);
        }

        if !matches!(self.state, State::Online) {
            warn!("Attempting to send encoding request packet before state is Online");
            return Err(ConnectionError::InvalidState);
        }

        if !matches!(self.connection_type, ConnectionType::Datagram) {
            return Err(ConnectionError::InvalidConnectionType);
        }

        if !matches!(self.mode, ConnectionMode::Client { .. }) {
            error!("Attempting to send an EncodingRequest as a server");
            return Err(ConnectionError::InvalidMode);
        }

        let pending_request_pkt = match &self.encoding_request_states.pending_request_pkt {
            Some(pkt) => pkt,
            None => {
                // Latest encoding request is already acknowledged/failed
                debug!(
                    "retransmit for {} cancelled as there is no pending pkt",
                    request_id
                );
                return Ok(());
            }
        };

        // Ignore retransmit calls for the stale requests.
        if request_id != self.encoding_request_states.id_counter {
            debug!(
                "retransmit request for stale request {} cancelled",
                request_id
            );
            return Ok(());
        }

        if self.encoding_request_states.retransmissions_counter
            >= ENCODING_REQUEST_PKT_MAX_RETRANSMISSION_ATTEMPTS
        {
            warn!("EncodingRequest retransmission max attempts reached");

            // Remove the pending packet
            self.encoding_request_states.pending_request_pkt = None;

            return Ok(());
        }

        self.encoding_request_states.retransmissions_counter += 1;

        debug!(
            "encoding request {} attempting retransmission no. {}",
            request_id, self.encoding_request_states.retransmissions_counter
        );

        // Callback to schedule another re-transmission
        (self.schedule_tick_cb)(
            self.encoding_request_states.retransmit_wait_time(),
            &mut self.app_state,
            TickType::PktCodecTick(self.encoding_request_states.id_counter),
        );

        let msg = wire::Frame::EncodingRequest(pending_request_pkt.clone());
        self.send_frame_or_drop(msg)
    }
}
