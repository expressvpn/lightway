use metrics::{Counter, counter};
use std::sync::LazyLock;
use tracing::{debug, warn};
use wolfssl::{Aes256GcmError, ProtocolVersion};

static METRIC_CONNECTION_ALLOC_FRAG_MAP: LazyLock<Counter> =
    LazyLock::new(|| counter!("conn_alloc_frag_map"));
const METRIC_WOLFSSL_APPDATA: &str = "wolfssl_appdata";
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

/// [`crate::Connection`] has allocated its [`crate::Connection::fragment_map`]
pub(crate) fn connection_alloc_frag_map() {
    METRIC_CONNECTION_ALLOC_FRAG_MAP.increment(1);
}

/// [`wolfssl`] returned [`wolfssl::Poll::AppData`] which is not expected with
/// TLS/DTLS 1.3
pub(crate) fn wolfssl_appdata(tls_version: &ProtocolVersion) {
    counter!(METRIC_WOLFSSL_APPDATA, TLS_PROTOCOL_VERSION_LABEL => tls_version.as_str())
        .increment(1);
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
