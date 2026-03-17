use std::ffi::{c_int, c_void};
use std::sync::{Arc, OnceLock};

use boring::ssl::SslContextBuilder;

/// Application-provided callbacks to receive TLS 1.3 secrets.
///
/// BoringSSL's keylog callback produces pre-formatted NSS keylog lines
/// suitable for Wireshark; `wireshark_keylog` is invoked once per line.
pub trait Tls13SecretCallbacks {
    fn wireshark_keylog(&self, secret: String);
    fn secrets(&self, _secret_type: Tls13Secret, _random: &[u8], _secret: &[u8]) {}
}

pub enum Tls13Secret {}

pub type Tls13SecretCallbacksArg = Arc<dyn Tls13SecretCallbacks + Send + Sync>;

/// Application-supplied callback invoked for each TLS log line.
///
/// Mirrors the wolfSSL backend's `LoggingCallback` so the
/// `lightway-core::set_logging_callback` API works identically across
/// both TLS backends.
pub type LoggingCallback = fn(message: &str);

static LOGGING_CALLBACK: OnceLock<LoggingCallback> = OnceLock::new();

/// Install a Rust callback to receive TLS log lines.
pub fn install_logging_callback(cb: LoggingCallback) {
    let _ = LOGGING_CALLBACK.set(cb);
}

/// Wire the installed logging callback (if any) onto an `SSL_CTX` builder
/// via `SSL_CTX_set_info_callback`. Called once per context from `ContextBuilder::build`
pub(crate) fn attach_info_callback(builder: &mut SslContextBuilder) {
    use boring::ssl::{SslInfoCallbackMode as M, SslInfoCallbackValue};
    builder.set_info_callback(|ssl, mode, value| {
        let Some(cb) = LOGGING_CALLBACK.get() else {
            return;
        };
        let state = ssl.state_string_long();
        match mode {
            M::HANDSHAKE_START => cb(&format!("handshake start: {state}")),
            M::HANDSHAKE_DONE => cb(&format!("handshake done: {state}")),
            M::READ_ALERT | M::WRITE_ALERT => {
                if let SslInfoCallbackValue::Alert(alert) = value {
                    let dir = if mode == M::READ_ALERT {
                        "read"
                    } else {
                        "write"
                    };
                    cb(&format!(
                        "alert {dir}: level={:?} desc={:?}",
                        alert.alert_level(),
                        alert.alert()
                    ));
                }
            }
            _ => cb(&format!("{mode:?}: {state}")),
        }
    });
}

/// Enable or disable internal TLS library debug logging.
///
/// No-op for BoringSSL — there is no `BORINGSSL_Debugging_ON`. WolfSSL has
/// an explicit toggle (`wolfSSL_Debugging_ON`/`OFF`); BoringSSL exposes no
/// equivalent mechanism.
pub fn enable_debugging(_on: bool) {}

/// Wire `SSL_CTX_set_msg_callback` so the installed `LoggingCallback` (if any)
/// receives one line per TLS record sent or received.
///
/// Ref: <https://github.com/google/boringssl/blob/main/include/openssl/ssl.h> (`SSL_CTX_set_msg_callback`)
pub(crate) fn attach_msg_callback(builder: &mut SslContextBuilder) {
    // SAFETY: `builder.as_ptr()` returns the `SSL_CTX*` the builder owns and
    // which it will hand to the produced `SslContext` on `.build()`. The
    // installed callback is a `'static` C function with no captured state.
    unsafe {
        boring_sys::SSL_CTX_set_msg_callback(builder.as_ptr(), Some(msg_trampoline));
    }
}

unsafe extern "C" fn msg_trampoline(
    is_write: c_int,
    _version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    _ssl: *mut boring_sys::SSL,
    _arg: *mut c_void,
) {
    // Ignore SSL3_RT_HEADER and ECH inner ClientHello
    if content_type == boring_sys::SSL3_RT_HEADER
        || content_type == boring_sys::SSL3_RT_CLIENT_HELLO_INNER
    {
        return;
    }

    let Some(cb) = LOGGING_CALLBACK.get() else {
        return;
    };

    // SAFETY: BoringSSL guarantees `buf` is valid for `len` bytes for the duration of this call.
    let body: &[u8] = if buf.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(buf as *const u8, len) }
    };

    let _ = std::panic::catch_unwind(|| {
        let dir = if is_write == 0 { "<<<" } else { ">>>" };
        cb(&format_msg(dir, content_type, body, len));
    });
}

/// Ref: <https://github.com/google/boringssl/blob/main/include/openssl/ssl3.h> (`SSL3_RT_*` content types)
fn format_msg(dir: &str, content_type: c_int, body: &[u8], len: usize) -> String {
    match content_type {
        boring_sys::SSL3_RT_CHANGE_CIPHER_SPEC => format!("{dir} ChangeCipherSpec ({len} bytes)"),
        boring_sys::SSL3_RT_ALERT => format_alert(dir, body, len),
        boring_sys::SSL3_RT_HANDSHAKE => {
            let hs_type = body.first().copied().unwrap_or(0);
            format!("{dir} {} ({len} bytes)", handshake_name(hs_type))
        }
        boring_sys::SSL3_RT_APPLICATION_DATA => format!("{dir} ApplicationData ({len} bytes)"),
        other => format!("{dir} content_type={other} ({len} bytes)"),
    }
}

/// Ref: <https://github.com/google/boringssl/blob/main/include/openssl/ssl3.h> (`SSL3_AL_*` alert levels)
/// IANA alert descriptions: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6>
fn format_alert(dir: &str, body: &[u8], len: usize) -> String {
    if body.len() < 2 {
        return format!("{dir} alert (truncated, {len} bytes)");
    }
    let level = match c_int::from(body[0]) {
        boring_sys::SSL3_AL_WARNING => "warning",
        boring_sys::SSL3_AL_FATAL => "fatal",
        _ => "?",
    };
    format!("{dir} alert level={level} desc={}", body[1])
}

/// Ref: <https://github.com/google/boringssl/blob/main/include/openssl/ssl3.h> (`SSL3_MT_*` message types)
/// IANA HandshakeType registry: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7>
fn handshake_name(t: u8) -> &'static str {
    use boring_sys::*;
    match c_int::from(t) {
        SSL3_MT_HELLO_REQUEST => "HelloRequest",
        SSL3_MT_CLIENT_HELLO => "ClientHello",
        SSL3_MT_SERVER_HELLO => "ServerHello",
        SSL3_MT_NEW_SESSION_TICKET => "NewSessionTicket",
        SSL3_MT_END_OF_EARLY_DATA => "EndOfEarlyData",
        SSL3_MT_ENCRYPTED_EXTENSIONS => "EncryptedExtensions",
        SSL3_MT_CERTIFICATE => "Certificate",
        SSL3_MT_SERVER_KEY_EXCHANGE => "ServerKeyExchange",
        SSL3_MT_CERTIFICATE_REQUEST => "CertificateRequest",
        SSL3_MT_SERVER_HELLO_DONE => "ServerHelloDone",
        SSL3_MT_CERTIFICATE_VERIFY => "CertificateVerify",
        SSL3_MT_CLIENT_KEY_EXCHANGE => "ClientKeyExchange",
        SSL3_MT_FINISHED => "Finished",
        SSL3_MT_CERTIFICATE_STATUS => "CertificateStatus",
        SSL3_MT_KEY_UPDATE => "KeyUpdate",
        SSL3_MT_MESSAGE_HASH => "MessageHash",
        SSL3_MT_COMPRESSED_CERTIFICATE => "CompressedCertificate",
        _ => "Handshake",
    }
}
