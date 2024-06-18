use metrics::counter;
use wolfssl::ProtocolVersion;

const METRIC_CONNECTION_ALLOC_FRAG_MAP: &str = "conn_alloc_frag_map";
const METRIC_WOLFSSL_APPDATA: &str = "wolfssl_appdata";
const METRIC_INSIDE_IO_SEND_FAILED: &str = "inside_io_send_failed";

const TLS_PROTOCOL_VERSION_LABEL: &str = "tls_protocol_version";

/// [`crate::Connection`] has allocated its [`crate::Connection::fragment_map`]
pub(crate) fn connection_alloc_frag_map() {
    counter!(METRIC_CONNECTION_ALLOC_FRAG_MAP).increment(1);
}

/// [`wolfssl`] returned [`wolfssl::Poll::AppData`] which is not expected with
/// TLS/DTLS 1.3
pub(crate) fn wolfssl_appdata(tls_version: &ProtocolVersion) {
    counter!(METRIC_WOLFSSL_APPDATA, TLS_PROTOCOL_VERSION_LABEL => tls_version.as_str())
        .increment(1);
}

/// A call to [`crate::io::InsideIOSendCallback::send`] failed
pub(crate) fn inside_io_send_failed() {
    counter!(METRIC_INSIDE_IO_SEND_FAILED).increment(1);
}
