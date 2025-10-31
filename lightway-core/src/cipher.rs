use crate::ConnectionType;

/// Cipher suite to use for Lightway connection
/// Client can choose one based on hardware support
#[derive(Copy, Clone, Debug, Default)]
pub enum Cipher {
    /// AES256 cipher (default)
    #[default]
    Aes256,
    /// Chacha20 cipher
    Chacha20,
}

impl Cipher {
    /// Get the cipher list as string slice
    pub fn as_cipher_list(&self, conn_type: ConnectionType) -> &'static str {
        match (conn_type, self) {
            (ConnectionType::Stream, Cipher::Aes256) => "TLS13-AES256-GCM-SHA384",
            (ConnectionType::Stream, Cipher::Chacha20) => "TLS13-CHACHA20-POLY1305-SHA256",
            (ConnectionType::Datagram, Cipher::Aes256) => {
                "TLS13-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
            }
            (ConnectionType::Datagram, Cipher::Chacha20) => {
                "TLS13-CHACHA20-POLY1305-SHA256:ECDHE-RSA-CHACHA20-POLY1305"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(Cipher::Aes256,   ConnectionType::Stream   => "TLS13-AES256-GCM-SHA384")]
    #[test_case(Cipher::Aes256,   ConnectionType::Datagram => "TLS13-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")]
    #[test_case(Cipher::Chacha20, ConnectionType::Stream   => "TLS13-CHACHA20-POLY1305-SHA256")]
    #[test_case(Cipher::Chacha20, ConnectionType::Datagram => "TLS13-CHACHA20-POLY1305-SHA256:ECDHE-RSA-CHACHA20-POLY1305")]
    fn as_cipher_list(cipher: Cipher, connection_type: ConnectionType) -> &'static str {
        cipher.as_cipher_list(connection_type)
    }
}
