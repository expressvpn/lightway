use crate::tls::{Aes256GcmError, ProtocolVersion};
use metrics::{Counter, counter};
use std::sync::LazyLock;
use tracing::{debug, warn};

static METRIC_CONNECTION_ALLOC_FRAG_MAP: LazyLock<Counter> =
    LazyLock::new(|| counter!("conn_alloc_frag_map"));
const METRIC_TLS_APPDATA: &str = "tls_appdata";
static METRIC_INSIDE_IO_SEND_FAILED: LazyLock<Counter> =
    LazyLock::new(|| counter!("inside_io_send_failed"));
static METRIC_SESSION_ID_MISMATCH: LazyLock<Counter> =
    LazyLock::new(|| counter!("session_id_mismatch"));
static METRIC_RECEIVED_ENCODING_REQ_NO_AUTHORIZATION: LazyLock<Counter> =
    LazyLock::new(|| counter!("received_encoding_req_no_authorization"));
static METRIC_RECEIVED_ENCODING_REQ_NON_ONLINE: LazyLock<Counter> =
    LazyLock::new(|| counter!("received_encoding_req_non_online"));
static METRIC_RECEIVED_ENCODING_REQ_WITH_TCP: LazyLock<Counter> =
    LazyLock::new(|| counter!("received_encoding_req_with_tcp"));
static METRIC_RECEIVED_RECONDING_RES_AS_SERVER: LazyLock<Counter> =
    LazyLock::new(|| counter!("received_encoding_res_as_server"));

static TLS_PROTOCOL_VERSION_LABEL: &str = "tls_protocol_version";

static METRIC_EXPRESSLANE_ENCRYPT_NO_KEY: LazyLock<Counter> =
    LazyLock::new(|| counter!("expresslane_encrypt_no_key"));
static METRIC_EXPRESSLANE_DECRYPT_NO_KEY: LazyLock<Counter> =
    LazyLock::new(|| counter!("expresslane_decrypt_no_key"));
static METRIC_EXPRESSLANE_DECRYPT_FAILED: LazyLock<Counter> =
    LazyLock::new(|| counter!("expresslane_decrypt_failed"));

#[cfg(target_os = "linux")]
const METRIC_GSO_DROPPED_INVALID_HDR_LEN: &str = "gso_dropped_invalid_hdr_len";
#[cfg(target_os = "linux")]
const GSO_HDR_REASON_LABEL: &str = "reason";
#[cfg(target_os = "linux")]
static METRIC_GSO_DROPPED_ZERO_GSO_SIZE: LazyLock<Counter> =
    LazyLock::new(|| counter!("gso_dropped_zero_gso_size"));
#[cfg(target_os = "linux")]
static METRIC_GSO_DROPPED_OVERSIZED_SEGMENT: LazyLock<Counter> =
    LazyLock::new(|| counter!("gso_dropped_oversized_segment"));
#[cfg(target_os = "linux")]
static METRIC_GSO_SEND_FAILED: LazyLock<Counter> = LazyLock::new(|| counter!("gso_send_failed"));
#[cfg(target_os = "linux")]
const METRIC_GSO_BUILD_SEGMENT_FAILED: &str = "gso_build_segment_failed";
#[cfg(target_os = "linux")]
const GSO_BUILD_REASON_LABEL: &str = "reason";
#[cfg(any(target_os = "linux", test))]
static METRIC_GSO_NONE_CHECKSUM_SKIPPED: LazyLock<Counter> =
    LazyLock::new(|| counter!("gso_none_checksum_skipped"));
#[cfg(target_os = "linux")]
static METRIC_GSO_DROPPED_IOV_OVERFLOW: LazyLock<Counter> =
    LazyLock::new(|| counter!("gso_dropped_iov_overflow"));

/// [`crate::Connection`] has allocated its [`crate::Connection::fragment_map`]
pub(crate) fn connection_alloc_frag_map() {
    METRIC_CONNECTION_ALLOC_FRAG_MAP.increment(1);
}

/// TLS library returned [`crate::tls::Poll::AppData`] which is not expected with
/// TLS/DTLS 1.3
pub(crate) fn tls_appdata(tls_version: &ProtocolVersion) {
    counter!(METRIC_TLS_APPDATA, TLS_PROTOCOL_VERSION_LABEL => tls_version.as_str()).increment(1);
}

/// A call to [`crate::io::InsideIOSendCallback::send`] failed
pub(crate) fn inside_io_send_failed(err: std::io::Error) {
    debug!(%err, "Failed to send to inside IO");
    METRIC_INSIDE_IO_SEND_FAILED.increment(1);
}

/// Server has received a mismatched session_id in the header after the packet content has been validated
pub(crate) fn session_id_mismatch() {
    METRIC_SESSION_ID_MISMATCH.increment(1);
}

/// Server received an encoding request when the client does not have authorization to use inside packet encoding
pub(crate) fn received_encoding_req_no_authorization() {
    METRIC_RECEIVED_ENCODING_REQ_NO_AUTHORIZATION.increment(1);
}

/// Server received an encoding request when the Connection state is not Online
pub(crate) fn received_encoding_req_non_online() {
    METRIC_RECEIVED_ENCODING_REQ_NON_ONLINE.increment(1);
}

/// Server received an encoding request when the Connection type is TCP
pub(crate) fn received_encoding_req_with_tcp() {
    METRIC_RECEIVED_ENCODING_REQ_WITH_TCP.increment(1);
}

/// Server received an encoding response
pub(crate) fn received_encoding_res_as_server() {
    METRIC_RECEIVED_RECONDING_RES_AS_SERVER.increment(1);
}

/// Server try to send an expresslane packet, but no valid expresslane key
/// to encrypt
pub(crate) fn expresslane_encrypt_no_key() {
    warn!("No valid expresslane key to encrypt");
    METRIC_EXPRESSLANE_ENCRYPT_NO_KEY.increment(1);
}

/// Server received an expresslane packet, but no valid expresslane key
/// to decrypt
pub(crate) fn expresslane_decrypt_no_key() {
    warn!("No valid expresslane key to decrypt");
    METRIC_EXPRESSLANE_DECRYPT_NO_KEY.increment(1);
}

/// Server received an expresslane packet, but cannot be decrpyted by
/// current/prev key
pub(crate) fn expresslane_decrypt_failed(err: &Aes256GcmError) {
    warn!("Prev key failed: {err:?}");
    METRIC_EXPRESSLANE_DECRYPT_FAILED.increment(1);
}

/// Server dropped a GSO superpacket because the protocol header
/// length could not be parsed. `reason` is one of the
/// [`crate::gso::GsoHdrError::metric_reason`] labels.
#[cfg(target_os = "linux")]
pub(crate) fn gso_dropped_invalid_hdr_len(reason: &'static str) {
    counter!(METRIC_GSO_DROPPED_INVALID_HDR_LEN, GSO_HDR_REASON_LABEL => reason).increment(1);
}

/// Server dropped a GSO superpacket whose kernel-reported `gso_size`
/// was zero.
#[cfg(target_os = "linux")]
pub(crate) fn gso_dropped_zero_gso_size() {
    METRIC_GSO_DROPPED_ZERO_GSO_SIZE.increment(1);
}

/// Server dropped a GSO superpacket because a header-wrapped segment
/// would exceed the tunnel MTU.
#[cfg(target_os = "linux")]
pub(crate) fn gso_dropped_oversized_segment() {
    METRIC_GSO_DROPPED_OVERSIZED_SEGMENT.increment(1);
}

/// `sendmsg(UDP_SEGMENT)` of the GSO batch failed.
#[cfg(target_os = "linux")]
pub(crate) fn gso_send_failed() {
    METRIC_GSO_SEND_FAILED.increment(1);
}

/// `build_segment` could not parse the per-segment header (kernel
/// supplied a virtio_net_hdr with csum_start/hdr_len that disagree
/// with the actual packet bytes, or the packet was truncated mid-
/// header). `reason` is one of:
/// `empty` | `ipv4_parse` | `ipv6_parse` | `tcp_parse` | `udp_parse`.
#[cfg(target_os = "linux")]
pub(crate) fn gso_build_segment_failed(reason: &'static str) {
    counter!(METRIC_GSO_BUILD_SEGMENT_FAILED, GSO_BUILD_REASON_LABEL => reason).increment(1);
}

/// `gso_none_checksum` was called with `csum_start`/`csum_offset`
/// pointing outside the packet buffer — no checksum is written and
/// the packet is forwarded with whatever value the kernel left in
/// place. Indicates a malformed virtio_net_hdr from the TUN.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn gso_none_checksum_skipped() {
    METRIC_GSO_NONE_CHECKSUM_SKIPPED.increment(1);
}

/// Server dropped a GSO superpacket whose segment count exceeds the
/// `IOV_MAX`-derived cap. Each segment contributes 2 iovecs to the
/// outbound `sendmsg`, so the cap protects against `EMSGSIZE` /
/// `EINVAL` from the kernel under malformed virtio_net_hdr input.
#[cfg(target_os = "linux")]
pub(crate) fn gso_dropped_iov_overflow() {
    METRIC_GSO_DROPPED_IOV_OVERFLOW.increment(1);
}
