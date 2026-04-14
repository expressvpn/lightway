//! Session configuration for TLS/DTLS connections.
//!
//! [`SessionConfig`] carries per-connection parameters such as the I/O adapter,
//! DTLS MTU, domain name verification, SNI, and post-quantum key share group
//! preferences.

use super::CurveGroup;

/// Configuration for creating a session
pub struct SessionConfig<IOCB> {
    pub io: IOCB,
    pub dtls_mtu: Option<u16>,
    /// Domain name for certificate verification in client mode.
    /// When set, the TLS handshake will FAIL if the server certificate's
    /// CN/SAN does not match this domain name. This is critical for security.
    pub checked_domain_name: Option<String>,
    /// SNI (Server Name Indication) sent to server.
    /// If not set but checked_domain_name is set, SNI will default to checked_domain_name.
    pub server_name_indication: Option<String>,
    /// Per-session client key share group preference. If set on a client
    /// session and the group is post-quantum, registers a precomputed key
    /// share for that group via BoringSSL's SSL_set1_client_key_shares so
    /// the ClientHello offers it up front. No effect on server sessions
    /// or classical groups, which negotiate normally through the
    /// supported_groups extension.
    pub keyshare_group: Option<CurveGroup>,
}

impl<IOCB> SessionConfig<IOCB> {
    /// Create a new session configuration
    pub fn new(io: IOCB) -> Self {
        Self {
            io,
            dtls_mtu: None,
            checked_domain_name: None,
            server_name_indication: None,
            keyshare_group: None,
        }
    }

    /// Set DTLS MTU
    pub fn with_dtls_mtu(mut self, mtu: u16) -> Self {
        self.dtls_mtu = Some(mtu);
        self
    }

    /// Enable DTLS non-blocking mode.
    ///
    /// No-op for BoringSSL: the BIO is driven by the non-blocking I/O
    /// callbacks (which report WouldBlock), so there is no separate flag.
    pub fn with_dtls_nonblocking(self, _nonblocking: bool) -> Self {
        self
    }

    /// No-op for BoringSSL
    pub fn with_dtls13_allow_ch_frag(self, _allow: bool) -> Self {
        self
    }

    /// Require the server certificate to match this domain name.
    ///
    /// Enables BoringSSL native hostname verification
    /// (`X509_VERIFY_PARAM_set1_host`); the handshake fails if the cert's
    /// SAN/CN doesn't match. This is the hostname-verification control: without
    /// it the chain is still verified but any valid cert from any host is
    /// accepted, which is a security downgrade for a client. SNI defaults to
    /// this domain when `with_sni` is unset.
    pub fn with_checked_domain_name(mut self, domain: &str) -> Self {
        self.checked_domain_name = Some(domain.to_string());
        self
    }

    /// Set SNI (Server Name Indication)
    pub fn with_sni(mut self, sni: &str) -> Self {
        self.server_name_indication = Some(sni.to_string());
        self
    }

    /// Set the per-session key share group preference (post-quantum).
    ///
    /// Only takes effect for a client offering a PQ group: `Session::new` then
    /// calls `SSL_set1_client_key_shares` so the ClientHello carries that share
    /// up front (skipping a HelloRetryRequest round trip). Server sessions and
    /// classical groups are a no-op here; they negotiate via `supported_groups`.
    pub fn with_keyshare_group(mut self, group: CurveGroup) -> Self {
        self.keyshare_group = Some(group);
        self
    }

    /// Apply a function conditionally
    pub fn when<F>(self, condition: bool, f: F) -> Self
    where
        F: FnOnce(Self) -> Self,
    {
        if condition {
            f(self)
        } else {
            self
        }
    }

    /// Apply a function conditionally when the value is Some
    pub fn when_some<F, T>(self, maybe: Option<T>, func: F) -> Self
    where
        F: FnOnce(Self, T) -> Self,
    {
        if let Some(t) = maybe {
            func(self, t)
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mock::MockIOAdapter;

    #[test]
    fn test_session_config_builder() {
        let mock_io = MockIOAdapter::new();

        let config = SessionConfig::new(mock_io)
            .with_dtls_mtu(1500)
            .with_checked_domain_name("example.com")
            .with_sni("example.com");

        assert_eq!(config.dtls_mtu, Some(1500));
        assert_eq!(config.checked_domain_name, Some("example.com".to_string()));
        assert_eq!(
            config.server_name_indication,
            Some("example.com".to_string())
        );
    }

    #[test]
    #[cfg(feature = "postquantum")]
    fn test_session_config_keyshare_group() {
        let mock_io = MockIOAdapter::new();

        let config = SessionConfig::new(mock_io).with_keyshare_group(CurveGroup::X25519MLKEM768);

        assert_eq!(config.keyshare_group, Some(CurveGroup::X25519MLKEM768));
    }

    #[test]
    fn test_session_config_when() {
        let mock_io = MockIOAdapter::new();

        // Test with condition true
        let config = SessionConfig::new(mock_io).when(true, |c| c.with_dtls_mtu(1500));
        assert_eq!(config.dtls_mtu, Some(1500));

        // Test with condition false
        let mock_io2 = MockIOAdapter::new();
        let config = SessionConfig::new(mock_io2).when(false, |c| c.with_dtls_mtu(1500));
        assert_eq!(config.dtls_mtu, None);
    }
}
