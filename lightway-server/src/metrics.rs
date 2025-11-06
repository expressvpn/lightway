use lightway_core::{SessionId, Version};
use metrics::{Counter, Gauge, Histogram, counter, gauge, histogram};
use std::sync::LazyLock;
use tracing::trace;

use crate::connection::Connection;

// Connection lifecycle
static METRIC_CONNECTION_ACCEPT: LazyLock<Counter> =
    LazyLock::new(|| counter!("conn_accept_failed"));
static METRIC_CONNECTION_ACCEPT_PROXY_HEADER_FAILED: LazyLock<Counter> =
    LazyLock::new(|| counter!("connection_accept_proxy_header_failed"));

const METRIC_CONNECTION_CREATE_FAILED: &str = "conn_create_failed";
const METRIC_CONNECTION_CREATED: &str = "conn_created";
const METRIC_CONNECTION_LINK_UP: &str = "conn_link_up";
const METRIC_CONNECTION_ONLINE: &str = "conn_online";
static METRIC_CONNECTION_REJECTED_NO_FREE_IP: LazyLock<Counter> =
    LazyLock::new(|| counter!("conn_rejected_no_free_ip"));
static METRIC_CONNECTION_REJECTED_ACCESS_DENIED: LazyLock<Counter> =
    LazyLock::new(|| counter!("conn_rejected_access_denied"));
static METRIC_CONNECTION_DATA_AFT_DISCONNECT: LazyLock<Counter> =
    LazyLock::new(|| counter!("conn_data_after_disconnect"));
const METRIC_CONNECTION_TLS_ERROR: &str = "conn_tls_error";
const METRIC_CONNECTION_UNKNOWN_ERROR: &str = "conn_unknown_error";
static METRIC_CONNECTION_AGED_OUT: LazyLock<Counter> = LazyLock::new(|| counter!("conn_aged_out"));
static METRIC_CONNECTION_EVICTED: LazyLock<Counter> =
    LazyLock::new(|| counter!("user_auth_eviction"));
static METRIC_CONNECTION_CLOSED: LazyLock<Counter> = LazyLock::new(|| counter!("conn_closed"));
static METRIC_CONNECTION_CLIENT_CLOSED: LazyLock<Counter> =
    LazyLock::new(|| counter!("conn_client_closed"));
static METRIC_CONNECTION_STALE_CLOSED: LazyLock<Counter> =
    LazyLock::new(|| counter!("conn_stale_closed"));
static METRIC_CONNECTION_KEY_UPDATE_START: LazyLock<Counter> =
    LazyLock::new(|| counter!("key_update_start"));
static METRIC_CONNECTION_KEY_UPDATE_COMPLETE: LazyLock<Counter> =
    LazyLock::new(|| counter!("key_update_complete"));

// UDP specific session and version handling
static METRIC_UDP_CONNECTION_RECOVERED_VIA_SESSION: LazyLock<Counter> =
    LazyLock::new(|| counter!("udp_conn_recovered_via_session"));
const METRIC_UDP_BAD_PACKET_VERSION: &str = "udp_bad_packet_version";
static METRIC_UDP_REJECTED_SESSION: LazyLock<Counter> =
    LazyLock::new(|| counter!("udp_rejected_session"));
static METRIC_UDP_PARSE_WIRE_FAILED: LazyLock<Counter> =
    LazyLock::new(|| counter!("udp_parse_wire_failed"));
static METRIC_UDP_NO_HEADER: LazyLock<Counter> = LazyLock::new(|| counter!("udp_no_header"));
static METRIC_UDP_SESSION_ROTATION_BEGIN: LazyLock<Counter> =
    LazyLock::new(|| counter!("udp_session_rotation_begin"));
static METRIC_UDP_SESSION_ROTATION_FINALIZED: LazyLock<Counter> =
    LazyLock::new(|| counter!("udp_session_rotation_finalized"));
static METRIC_UDP_SESSION_ROTATION_ATTEMPTED_VIA_REPLAY: LazyLock<Counter> =
    LazyLock::new(|| counter!("udp_session_rotation_attempted_via_replay"));
static METRIC_UDP_RECV_TRUNCATED: LazyLock<Counter> =
    LazyLock::new(|| counter!("udp_recv_truncated"));
static METRIC_UDP_RECV_INVALID_ADDR: LazyLock<Counter> =
    LazyLock::new(|| counter!("udp_recv_invalid_addr"));
static METRIC_UDP_RECV_MISSING_PKTINFO: LazyLock<Counter> =
    LazyLock::new(|| counter!("udp_recv_missing_pktinfo"));

// Connection performance
static METRIC_TO_LINK_UP_TIME: LazyLock<Histogram> =
    LazyLock::new(|| histogram!("to_link_up_time"));
static METRIC_TO_ONLINE_TIME: LazyLock<Histogram> = LazyLock::new(|| histogram!("to_online_time"));

// TUN
static METRIC_TUN_REJECTED_INVALID_STATE: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_rejected_packet_invalid_state"));
static METRIC_TUN_REJECTED_INVALID_INSIDE_PACKET: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_rejected_packet_invalid_inside_packet"));
static METRIC_TUN_REJECTED_OTHER: &str = "tun_rejected_packet_invalid_other";
static METRIC_TUN_REJECTED_NO_CONNECTION: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_rejected_packet_no_connection"));
static METRIC_TUN_REJECTED_NO_CLIENT_IP: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_rejected_packet_no_client_ip"));

// Traffic volume
static METRIC_TUN_FROM_CLIENT: LazyLock<Counter> = LazyLock::new(|| counter!("tun_from_client"));
static METRIC_TUN_TO_CLIENT: LazyLock<Counter> = LazyLock::new(|| counter!("tun_to_client"));

static METRIC_SESSIONS_CURRENT_ONLINE: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("sessions_current_online"));
static METRIC_SESSIONS_LIFETIME_TOTAL: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("sessions_lifetime_total"));
static METRIC_SESSIONS_PENDING_ID_ROTATIONS: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("sessions_pending_id_rotations"));
static METRIC_SESSIONS_ACTIVE_5M: LazyLock<Gauge> = LazyLock::new(|| gauge!("sessions_active_5m"));
static METRIC_SESSIONS_ACTIVE_15M: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("sessions_active_15m"));
static METRIC_SESSIONS_ACTIVE_60M: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("sessions_active_60m"));
static METRIC_SESSIONS_STANDBY_5M: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("sessions_standby_5m"));
static METRIC_SESSIONS_STANDBY_15M: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("sessions_standby_15m"));
static METRIC_SESSIONS_STANDBY_60M: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("sessions_standby_60m"));
static METRIC_SESSIONS_ENCODING_ENABLED: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("sessions_encoding_enabled"));

static METRIC_ASSIGNED_INTERNAL_IPS: LazyLock<Gauge> =
    LazyLock::new(|| gauge!("assigned_internal_ips"));

// Labels for use with the above
const CIPHER_LABEL: &str = "cipher";
const CURVE_LABEL: &str = "curve";
const TLS_PROTOCOL_VERSION_LABEL: &str = "tls_protocol_version";
const LIGHTWAY_PROTOCOL_VERSION_LABEL: &str = "lightway_protocol_version";
const FATAL_LABEL: &str = "fatal";

#[derive(Default, Debug)]
pub(crate) struct ConnectionIntervalStats {
    pub five_minutes: usize,
    pub fifteen_minutes: usize,
    pub sixty_minutes: usize,
}

/// Calling `accept(2)` on our listening socket failed
pub(crate) fn connection_accept_failed() {
    METRIC_CONNECTION_ACCEPT.increment(1)
}

pub(crate) fn connection_accept_proxy_header_failed() {
    METRIC_CONNECTION_ACCEPT_PROXY_HEADER_FAILED.increment(1)
}

/// Connection lifecycle: Unable to create a new [`lightway_core::Connection`]
pub(crate) fn connection_create_failed(lw_protocol_version: &Version) {
    counter!(
        METRIC_CONNECTION_CREATE_FAILED,
        LIGHTWAY_PROTOCOL_VERSION_LABEL => lw_protocol_version.to_string()
    )
    .increment(1);
}

/// Connection lifecycle: New [`lightway_core::Connection`] created
pub(crate) fn connection_created(lw_protocol_version: &Version) {
    counter!(
        METRIC_CONNECTION_CREATED,
        LIGHTWAY_PROTOCOL_VERSION_LABEL => lw_protocol_version.to_string()
    )
    .increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] transitioned
/// to [`lightway_core::State::LinkUp`] state
pub(crate) fn connection_link_up(conn: &Connection) {
    let to_link_up = conn.connection_started.elapsed();
    let cipher = conn
        .current_cipher()
        .unwrap_or_else(|| "unknown".to_string());
    let curve = conn
        .current_curve()
        .unwrap_or_else(|| "unknown".to_string());

    let tls_protocol_version = conn.tls_protocol_version();

    trace!(cipher, curve, to_link_up = ?to_link_up);
    METRIC_TO_LINK_UP_TIME.record(to_link_up);
    counter!(METRIC_CONNECTION_LINK_UP,
                       CIPHER_LABEL => cipher,
                       CURVE_LABEL => curve,
                       TLS_PROTOCOL_VERSION_LABEL => tls_protocol_version.as_str(),
    )
    .increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] transitioned
/// to [`lightway_core::State::Online`] state
pub(crate) fn connection_online(conn: &Connection) {
    let to_online = conn.connection_started.elapsed();
    let cipher = conn
        .current_cipher()
        .unwrap_or_else(|| "unknown".to_string());
    let curve = conn
        .current_curve()
        .unwrap_or_else(|| "unknown".to_string());

    let tls_protocol_version = conn.tls_protocol_version();
    counter!(METRIC_CONNECTION_ONLINE,
                       CIPHER_LABEL => cipher,
                       CURVE_LABEL => curve,
                       TLS_PROTOCOL_VERSION_LABEL => tls_protocol_version.as_str(),
    )
    .increment(1);
    METRIC_TO_ONLINE_TIME.record(to_online);
}

/// Connection lifecycle: [`lightway_core::Connection`] rejected, no
/// available IPs.
pub(crate) fn connection_rejected_no_free_ip() {
    METRIC_CONNECTION_REJECTED_NO_FREE_IP.increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] rejected,
/// authentication failed.
pub(crate) fn connection_rejected_access_denied() {
    METRIC_CONNECTION_REJECTED_ACCESS_DENIED.increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] aged out due
/// to exceeding idle threshold.
pub(crate) fn connection_aged_out() {
    METRIC_CONNECTION_AGED_OUT.increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] authentication
/// expired.
pub(crate) fn connection_expired() {
    METRIC_CONNECTION_EVICTED.increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] closed when the
/// connection does not come online in 60 minutes after link up
pub(crate) fn connection_stale_closed() {
    METRIC_CONNECTION_STALE_CLOSED.increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] closed when the
/// peer closed the connection
pub(crate) fn connection_client_closed() {
    METRIC_CONNECTION_CLIENT_CLOSED.increment(1);
}

/// Connection lifecycle: [`lightway_core::Connection`] closed.
pub(crate) fn connection_closed() {
    METRIC_CONNECTION_CLOSED.increment(1);
}

pub(crate) fn connection_key_update_start() {
    METRIC_CONNECTION_KEY_UPDATE_START.increment(1);
}
pub(crate) fn connection_key_update_complete() {
    METRIC_CONNECTION_KEY_UPDATE_COMPLETE.increment(1);
}

/// UDP: Session recovered
pub(crate) fn udp_conn_recovered_via_session(session: SessionId) {
    trace!(?session, "Recovered UDP session");
    METRIC_UDP_CONNECTION_RECOVERED_VIA_SESSION.increment(1);
}

/// UDP: session id rotation using replay packets
pub(crate) fn udp_session_rotation_attempted_via_replay() {
    METRIC_UDP_SESSION_ROTATION_ATTEMPTED_VIA_REPLAY.increment(1);
}

/// UDP: Session ID rotation started
pub(crate) fn udp_session_rotation_begin() {
    trace!("Begin session rotation");
    METRIC_UDP_SESSION_ROTATION_BEGIN.increment(1);
}

/// UDP: Session ID rotation complete
pub(crate) fn udp_session_rotation_finalized() {
    trace!("Finalize session rotation");
    METRIC_UDP_SESSION_ROTATION_FINALIZED.increment(1);
}

/// UDP: Bad lightway protocol version
pub(crate) fn udp_bad_packet_version(version: Version) {
    counter!(
        METRIC_UDP_BAD_PACKET_VERSION,
        LIGHTWAY_PROTOCOL_VERSION_LABEL => version.to_string(),
    )
    .increment(1);
}

/// UDP: Session rejected
pub(crate) fn udp_rejected_session() {
    METRIC_UDP_REJECTED_SESSION.increment(1);
}

pub(crate) fn udp_parse_wire_failed() {
    METRIC_UDP_PARSE_WIRE_FAILED.increment(1);
}

pub(crate) fn udp_no_header() {
    METRIC_UDP_NO_HEADER.increment(1);
}

pub(crate) fn udp_recv_truncated() {
    METRIC_UDP_RECV_TRUNCATED.increment(1);
}

pub(crate) fn udp_recv_invalid_addr() {
    METRIC_UDP_RECV_INVALID_ADDR.increment(1);
}

pub(crate) fn udp_recv_missing_pktinfo() {
    METRIC_UDP_RECV_MISSING_PKTINFO.increment(1);
}

/// Fatal TLS error for [`lightway_core::Connection`].
pub(crate) fn connection_tls_error(fatal: bool) {
    counter!(METRIC_CONNECTION_TLS_ERROR, FATAL_LABEL => fatal.to_string()).increment(1);
}

/// Unknown error for [`lightway_core::Connection`].
pub(crate) fn connection_unknown_error(fatal: bool) {
    counter!(METRIC_CONNECTION_UNKNOWN_ERROR, FATAL_LABEL => fatal.to_string()).increment(1);
}

/// [`lightway_core::Connection`] already in disconnected state
pub(crate) fn connection_data_after_disconnect() {
    METRIC_CONNECTION_DATA_AFT_DISCONNECT.increment(1)
}

/// Tunnel rejected packet, [`lightway_core::Connection`] not in
/// [`lightway_core::State::Online`] state
pub fn tun_rejected_packet_invalid_state() {
    METRIC_TUN_REJECTED_INVALID_STATE.increment(1);
}

/// Tunnel rejected packet, inside packet invalid
pub fn tun_rejected_packet_invalid_inside_packet() {
    METRIC_TUN_REJECTED_INVALID_INSIDE_PACKET.increment(1);
}

/// Tunnel rejected packet, other reasons
pub fn tun_rejected_packet_invalid_other(fatal: bool) {
    counter!(METRIC_TUN_REJECTED_OTHER, FATAL_LABEL => fatal.to_string()).increment(1);
}

/// Tunnel rejected packet, no corresponding
/// [`lightway_core::Connection`] found.
pub fn tun_rejected_packet_no_connection() {
    METRIC_TUN_REJECTED_NO_CONNECTION.increment(1);
}

/// Tunnel rejected packet, since there was no clientip in app state
pub fn tun_rejected_packet_no_client_ip() {
    METRIC_TUN_REJECTED_NO_CLIENT_IP.increment(1);
}

/// Bytes sent from client to the TUN device.
pub fn tun_from_client(sz: usize) {
    METRIC_TUN_FROM_CLIENT.increment(sz as u64);
}

/// Bytes received from TUN device (destined for client).
pub fn tun_to_client(sz: usize) {
    METRIC_TUN_TO_CLIENT.increment(sz as u64);
}

/// Current session statistics
pub(crate) fn sessions_statistics(
    current_sessions: usize,
    total_sessions: usize,
    pending_session_id_rotations: usize,
    active: ConnectionIntervalStats,
    standby: ConnectionIntervalStats,
) {
    METRIC_SESSIONS_CURRENT_ONLINE.set(current_sessions as f64);
    METRIC_SESSIONS_LIFETIME_TOTAL.set(total_sessions as f64);
    METRIC_SESSIONS_PENDING_ID_ROTATIONS.set(pending_session_id_rotations as f64);

    METRIC_SESSIONS_ACTIVE_5M.set(active.five_minutes as f64);
    METRIC_SESSIONS_ACTIVE_15M.set(active.fifteen_minutes as f64);
    METRIC_SESSIONS_ACTIVE_60M.set(active.sixty_minutes as f64);
    METRIC_SESSIONS_STANDBY_5M.set(standby.five_minutes as f64);
    METRIC_SESSIONS_STANDBY_15M.set(standby.fifteen_minutes as f64);
    METRIC_SESSIONS_STANDBY_60M.set(standby.sixty_minutes as f64);
}

/// Connection's [`lightway_app_utils::PacketCodec`] enabled
pub(crate) fn connection_encoding_enabled() {
    METRIC_SESSIONS_ENCODING_ENABLED.increment(1.0);
}

/// Connection's [`lightway_app_utils::PacketCodec`] disabled
pub(crate) fn connection_encoding_disabled() {
    METRIC_SESSIONS_ENCODING_ENABLED.decrement(1.0);
}

/// Number of IP addresses in use
pub(crate) fn assigned_internal_ips(nr: usize) {
    METRIC_ASSIGNED_INTERNAL_IPS.set(nr as f64);
}
