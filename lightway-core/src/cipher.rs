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

    /// In-memory I/O callback that records everything the TLS stack tries to
    /// send and reports "would block" on every read, so a single
    /// `try_negotiate()` step emits the ClientHello and then parks.
    struct CaptureIO {
        sent: Vec<u8>,
    }

    impl crate::tls::IOCallbacks for CaptureIO {
        fn recv(&mut self, _buf: &mut [u8]) -> crate::tls::IOCallbackResult<usize> {
            crate::tls::IOCallbackResult::WouldBlock
        }

        fn send(&mut self, buf: &[u8]) -> crate::tls::IOCallbackResult<usize> {
            self.sent.extend_from_slice(buf);
            crate::tls::IOCallbackResult::Ok(buf.len())
        }
    }

    /// Parse the `cipher_suites` list (Vec of IANA suite IDs) out of a raw
    /// TLS (TCP) ClientHello record. Returns `None` if the bytes are not a
    /// well-formed handshake ClientHello record. DTLS is not handled here —
    /// its record/handshake framing differs.
    fn parse_client_hello_cipher_suites(wire: &[u8]) -> Option<Vec<u16>> {
        // TLS record header: type(1) + version(2) + length(2)
        // type 22 == handshake
        if wire.len() < 5 || wire[0] != 22 {
            return None;
        }
        let body = &wire[5..];

        // Handshake header: msg_type(1) + length(3); msg_type 1 == ClientHello
        if body.len() < 4 || body[0] != 1 {
            return None;
        }
        let ch = &body[4..];

        // ClientHello: legacy_version(2) + random(32) + session_id(1+n)
        //              + cipher_suites(2 + n) + ...
        let mut off = 2 + 32;
        let sid_len = *ch.get(off)? as usize;
        off += 1 + sid_len;

        let cs_len = ((*ch.get(off)? as usize) << 8) | (*ch.get(off + 1)? as usize);
        off += 2;

        let cs_bytes = ch.get(off..off + cs_len)?;
        Some(
            cs_bytes
                .chunks_exact(2)
                .map(|c| ((c[0] as u16) << 8) | (c[1] as u16))
                .collect(),
        )
    }

    #[test]
    fn ensure_cipher_list() {
        let ctx = crate::tls::ContextBuilder::new(crate::tls::Method::TlsClientV1_3)
            .unwrap()
            .build();
        let mut session = ctx
            .new_session(crate::tls::SessionConfig::new(CaptureIO {
                sent: Vec::new(),
            }))
            .unwrap();
        let _ = session.try_negotiate();
        let wire = &session.io_cb().sent;
        let suites = parse_client_hello_cipher_suites(wire)
            .expect("captured bytes were not a well-formed ClientHello");

        // The following bytes are from
        // https://www.ssl.org/cipher-suite-mapping

        // The order MATTERS in the following vec, the order is the cipher preferences
        #[cfg(wolfssl)]
        assert_eq!(
            suites,
            vec![
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
                0xC023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
                0xC028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
                0xC024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
                0xC00A, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xCC14, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD
                0xCC13  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD
            ]
        );

        // Note: BoringSSL backend expose no APIs for restricting cipher list in TLS1.3.
        #[cfg(boringssl)]
        assert_eq!(
            suites,
            vec![
                0x1301, // AES-128
                0x1302, // AES-256
                0x1303  // ChaCha20
            ]
        );
    }

    fn parse_client_hello_supported_groups(wire: &[u8]) -> Option<Vec<u16>> {
        if wire.len() < 5 || wire[0] != 22 {
            return None;
        }
        let ch = wire.get(9..)?; // skip record(5) + handshake(4) headers

        // Walk to the extensions block.
        let mut off = 2 + 32; // legacy_version + random
        let sid_len = *ch.get(off)? as usize;
        off += 1 + sid_len;
        let cs_len = ((*ch.get(off)? as usize) << 8) | (*ch.get(off + 1)? as usize);
        off += 2 + cs_len;
        let comp_len = *ch.get(off)? as usize;
        off += 1 + comp_len;
        let ext_total = ((*ch.get(off)? as usize) << 8) | (*ch.get(off + 1)? as usize);
        off += 2;
        let ext_end = off + ext_total;
        while off + 4 <= ext_end {
            let ext_type = ((*ch.get(off)? as usize) << 8) | (*ch.get(off + 1)? as usize);
            let ext_len = ((*ch.get(off + 2)? as usize) << 8) | (*ch.get(off + 3)? as usize);
            let data = ch.get(off + 4..off + 4 + ext_len)?;
            if ext_type == 0x000a {
                // supported_groups: 2-byte list length prefix, then 2-byte ids.
                return Some(
                    data.get(2..)?
                        .chunks_exact(2)
                        .map(|c| ((c[0] as u16) << 8) | (c[1] as u16))
                        .collect(),
                );
            }
            off += 4 + ext_len;
        }
        None
    }

    #[test]
    fn ensure_supported_group_list() {
        let ctx = crate::tls::ContextBuilder::new(crate::tls::Method::TlsClientV1_3)
            .unwrap()
            .build();
        let mut session = ctx
            .new_session(crate::tls::SessionConfig::new(CaptureIO {
                sent: Vec::new(),
            }))
            .unwrap();
        let _ = session.try_negotiate();
        let wire = &session.io_cb().sent;
        let groups = parse_client_hello_supported_groups(wire)
            .expect("captured bytes were not a well-formed ClientHello");

        // Classical list can be found here:
        // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

        // PQ List can be found here:
        // https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md

        #[cfg(boringssl)]
        assert_eq!(
            groups,
            vec![
                0x11ec, // X25519MLKEM768
                0xfe32, // X25519Kyber768Draft00 (legacy hybrid, boring default)
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
            ]
        );

        #[cfg(wolfssl)]
        assert_eq!(
            groups,
            vec![
                4588,   // X25519MLKEM768
                4589,   // SecP384r1MLKEM1024
                4587,   // SecP256r1MLKEM768
                25,     // secp521r1
                24,     // secp384r1
                23,     // secp256r1
                29,     // x25519
                21,     // secp224r1
                0x2f4d, // p521_mlkem1024
                0x2f49, // Unknown
                0x2f4c, // p384_mlkem768
                0x2f48, // Unknown
                0x2f4b, // p256_mlkem512
                0x2f47, // Unknown
                0x2fb6, // x25519_mlkem512
                0x023d, // kyber1024
                0x2f3d, // p521_kyber1024
                0x023c, // kyber768 (from wireshark)
                0x2f3c, // p38_kyber1024 (from wireshark)
                0x639a, // SecP256r1Kyber768Draft00 (from wireshark)
                0x6399, // X25519Kyber768Draft00 (from wireshark)
                0x023a, // kyber512 (from wireshark)
                0x2f3a, // p256_kyber512 (from wireshark)
                0x2f39, // Unknown
            ]
        );
    }
}
