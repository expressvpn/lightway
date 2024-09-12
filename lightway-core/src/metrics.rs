use metrics::{counter, Counter};
use std::sync::LazyLock;
use tracing::warn;
use wolfssl::ProtocolVersion;

static METRIC_CONNECTION_ALLOC_FRAG_MAP: LazyLock<Counter> =
    LazyLock::new(|| counter!("conn_alloc_frag_map"));
const METRIC_WOLFSSL_APPDATA: &str = "wolfssl_appdata";
static METRIC_INSIDE_IO_SEND_FAILED: LazyLock<Counter> =
    LazyLock::new(|| counter!("inside_io_send_failed"));

static TLS_PROTOCOL_VERSION_LABEL: &str = "tls_protocol_version";

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
    warn!(%err, "Failed to send to inside IO");
    METRIC_INSIDE_IO_SEND_FAILED.increment(1);
}
