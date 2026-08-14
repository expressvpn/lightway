#[cfg(test)]
pub(crate) mod mock {
    use crate::*;
    use bytes::{Bytes, BytesMut};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // MockIOAdapter — simple single-buffer adapter (used by unit tests)
    // -----------------------------------------------------------------------

    #[derive(Debug)]
    pub(crate) struct MockIOAdapter {
        recv_buf: Arc<Mutex<BytesMut>>,
        send_buf: Arc<Mutex<BytesMut>>,
    }

    impl MockIOAdapter {
        pub(crate) fn new() -> Self {
            Self {
                recv_buf: Arc::new(Mutex::new(BytesMut::new())),
                send_buf: Arc::new(Mutex::new(BytesMut::new())),
            }
        }

        #[allow(dead_code)]
        pub(crate) fn push_recv_data(&self, data: &[u8]) {
            self.recv_buf.lock().unwrap().extend_from_slice(data);
        }

        #[allow(dead_code)]
        pub(crate) fn get_sent_data(&self) -> Vec<u8> {
            self.send_buf.lock().unwrap().to_vec()
        }

        #[allow(dead_code)]
        pub(crate) fn clear_buffers(&self) {
            self.recv_buf.lock().unwrap().clear();
            self.send_buf.lock().unwrap().clear();
        }
    }

    impl IOCallbacks for MockIOAdapter {
        fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult {
            let mut recv_buf = self.recv_buf.lock().unwrap();
            if recv_buf.is_empty() {
                return IOCallbackResult::WouldBlock;
            }
            let len = std::cmp::min(buf.len(), recv_buf.len());
            buf[..len].copy_from_slice(&recv_buf[..len]);
            let _ = recv_buf.split_to(len);
            IOCallbackResult::Ok(len)
        }

        fn send(&mut self, buf: &[u8]) -> IOCallbackResult {
            self.send_buf.lock().unwrap().extend_from_slice(buf);
            IOCallbackResult::Ok(buf.len())
        }
    }

    // -----------------------------------------------------------------------
    // Generated test certificates (rcgen, once per test process)
    // server cert CN/SAN = example.com - use with_checked_domain_name("example.com")
    // -----------------------------------------------------------------------

    struct TestPki {
        root_cert: Vec<u8>,
        server_cert: Vec<u8>,
        server_key: Vec<u8>,
    }

    static TEST_PKI: std::sync::LazyLock<TestPki> = std::sync::LazyLock::new(|| {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
            IsCa, KeyPair, KeyUsagePurpose, PKCS_RSA_SHA256, RsaKeySize,
        };

        // Same algorithm and key size as the previously checked-in test
        // certificates: RSA-2048, signed with SHA-256.
        let generate_key = || {
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
                .expect("generate RSA-2048 key")
        };
        use std::time::{Duration, SystemTime};

        // Valid from a day in the past (clock-skew margin) until 30 days out.
        const DAY: Duration = Duration::from_secs(60 * 60 * 24);
        let now = SystemTime::now();
        let set_validity = |params: &mut CertificateParams| {
            params.not_before = (now - DAY).into();
            params.not_after = (now + 30 * DAY).into();
        };

        let mut ca_params = CertificateParams::default();
        set_validity(&mut ca_params);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "lightway-boring test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = generate_key();
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("self-sign CA cert");

        let mut params =
            CertificateParams::new(vec!["example.com".to_string()]).expect("valid SAN");
        set_validity(&mut params);
        params
            .distinguished_name
            .push(DnType::CommonName, "example.com");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = generate_key();
        let cert = params.signed_by(&key, &ca).expect("sign server cert");

        TestPki {
            root_cert: ca.der().to_vec(),
            server_cert: cert.der().to_vec(),
            server_key: key.serialize_der(),
        }
    });

    /// Root CA certificate, DER encoded
    pub(crate) fn root_cert() -> &'static [u8] {
        &TEST_PKI.root_cert
    }

    /// Server certificate for "example.com" issued by [`root_cert`], DER encoded
    pub(crate) fn server_cert() -> &'static [u8] {
        &TEST_PKI.server_cert
    }

    /// Private key for [`server_cert`], DER (PKCS#8) encoded
    pub(crate) fn server_key() -> &'static [u8] {
        &TEST_PKI.server_key
    }

    // -----------------------------------------------------------------------
    // MessageQueue — datagram-preserving queue (used by UdpIOCallbacks)
    //
    // Each push() stores a complete datagram as a Bytes frame. pop() reads
    // one datagram at a time, truncating to the caller's buffer size. This
    // mirrors real UDP semantics where a short recv() silently drops the tail.
    // -----------------------------------------------------------------------

    struct MessageQueue {
        messages: VecDeque<Bytes>,
    }

    impl MessageQueue {
        fn new() -> Self {
            Self {
                messages: VecDeque::new(),
            }
        }

        fn push(&mut self, data: &[u8]) {
            self.messages.push_back(Bytes::copy_from_slice(data));
        }

        fn pop(&mut self, buf: &mut [u8]) -> Option<usize> {
            self.messages.pop_front().map(|msg| {
                let len = std::cmp::min(buf.len(), msg.len());
                buf[..len].copy_from_slice(&msg[..len]);
                len
            })
        }

        fn is_empty(&self) -> bool {
            self.messages.is_empty()
        }
    }

    // -----------------------------------------------------------------------
    // TcpIOCallbacks — stream semantics for TLS in-process tests
    //
    // Two instances share a pair of Rc<RefCell<BytesMut>> buffers with roles
    // swapped so bytes written by one are read by the other, just like a
    // loopback TCP socket but without any OS involvement.
    // -----------------------------------------------------------------------

    pub(crate) struct TcpIOCallbacks {
        r: Rc<RefCell<BytesMut>>,
        w: Rc<RefCell<BytesMut>>,
    }

    impl TcpIOCallbacks {
        /// Returns a connected pair: bytes written by one are read by the other.
        pub(crate) fn pair() -> (Self, Self) {
            let a = Rc::new(RefCell::new(BytesMut::new()));
            let b = Rc::new(RefCell::new(BytesMut::new()));
            let client = TcpIOCallbacks {
                r: Rc::clone(&a),
                w: Rc::clone(&b),
            };
            let server = TcpIOCallbacks {
                r: Rc::clone(&b),
                w: Rc::clone(&a),
            };
            (client, server)
        }
    }

    impl IOCallbacks for TcpIOCallbacks {
        fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult {
            let mut r = self.r.borrow_mut();
            if r.is_empty() {
                return IOCallbackResult::WouldBlock;
            }
            let len = std::cmp::min(buf.len(), r.len());
            buf[..len].copy_from_slice(&r[..len]);
            let _ = r.split_to(len);
            IOCallbackResult::Ok(len)
        }

        fn send(&mut self, buf: &[u8]) -> IOCallbackResult {
            self.w.borrow_mut().extend_from_slice(buf);
            IOCallbackResult::Ok(buf.len())
        }
    }

    // -----------------------------------------------------------------------
    // UdpIOCallbacks — datagram-preserving semantics for DTLS in-process tests
    //
    // Uses MessageQueue instead of BytesMut so each SSL record arrives as a
    // discrete datagram. DTLS relies on message boundaries being intact.
    // -----------------------------------------------------------------------

    pub(crate) struct UdpIOCallbacks {
        r: Rc<RefCell<MessageQueue>>,
        w: Rc<RefCell<MessageQueue>>,
    }

    impl UdpIOCallbacks {
        /// Returns a connected pair: datagrams sent by one are received by the other.
        pub(crate) fn pair() -> (Self, Self) {
            let a = Rc::new(RefCell::new(MessageQueue::new()));
            let b = Rc::new(RefCell::new(MessageQueue::new()));
            let client = UdpIOCallbacks {
                r: Rc::clone(&a),
                w: Rc::clone(&b),
            };
            let server = UdpIOCallbacks {
                r: Rc::clone(&b),
                w: Rc::clone(&a),
            };
            (client, server)
        }
    }

    impl IOCallbacks for UdpIOCallbacks {
        fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult {
            let mut r = self.r.borrow_mut();
            if r.is_empty() {
                return IOCallbackResult::WouldBlock;
            }
            IOCallbackResult::Ok(r.pop(buf).unwrap_or(0))
        }

        fn send(&mut self, buf: &[u8]) -> IOCallbackResult {
            self.w.borrow_mut().push(buf);
            IOCallbackResult::Ok(buf.len())
        }
    }

    // -----------------------------------------------------------------------
    // make_connected_tls_pair — fully handshaked TLS 1.3 session pair
    //
    // Drives the handshake loop until both sides report is_init_finished().
    // Panics if the handshake does not converge within 20 alternating steps.
    // -----------------------------------------------------------------------

    pub(crate) fn make_connected_tls_pair() -> (Session<TcpIOCallbacks>, Session<TcpIOCallbacks>) {
        let client_ctx = ContextBuilder::new(Method::TlsClientV1_3)
            .unwrap()
            .with_root_certificate(RootCertificate::Asn1Buffer(root_cert()))
            .unwrap()
            .build();

        let server_ctx = ContextBuilder::new(Method::TlsServerV1_3)
            .unwrap()
            .with_certificate(Secret::Asn1Buffer(server_cert()))
            .unwrap()
            .with_private_key(Secret::Asn1Buffer(server_key()))
            .unwrap()
            .build();

        let (client_io, server_io) = TcpIOCallbacks::pair();

        let mut client = client_ctx
            .new_session(SessionConfig::new(client_io).with_checked_domain_name("example.com"))
            .unwrap();
        let mut server = server_ctx
            .new_session(SessionConfig::new(server_io))
            .unwrap();

        for _ in 0..20 {
            let _ = client.try_negotiate();
            let _ = server.try_negotiate();
            if client.is_init_finished() && server.is_init_finished() {
                break;
            }
        }

        assert!(
            client.is_init_finished(),
            "TLS client handshake did not complete"
        );
        assert!(
            server.is_init_finished(),
            "TLS server handshake did not complete"
        );

        (client, server)
    }

    // -----------------------------------------------------------------------
    // make_connected_dtls_pair — fully handshaked DTLS 1.3 session pair
    //
    // DTLS 1.3 adds a cookie exchange (HRR) before the normal flight, so
    // more iterations are needed than TLS. 50 alternating steps is enough.
    // -----------------------------------------------------------------------

    pub(crate) fn make_connected_dtls_pair() -> (Session<UdpIOCallbacks>, Session<UdpIOCallbacks>) {
        let client_ctx = ContextBuilder::new(Method::DtlsClientV1_3)
            .unwrap()
            .with_root_certificate(RootCertificate::Asn1Buffer(root_cert()))
            .unwrap()
            .build();

        let server_ctx = ContextBuilder::new(Method::DtlsServerV1_3)
            .unwrap()
            .with_certificate(Secret::Asn1Buffer(server_cert()))
            .unwrap()
            .with_private_key(Secret::Asn1Buffer(server_key()))
            .unwrap()
            .build();

        let (client_io, server_io) = UdpIOCallbacks::pair();

        let mut client = client_ctx
            .new_session(SessionConfig::new(client_io).with_checked_domain_name("example.com"))
            .unwrap();
        let mut server = server_ctx
            .new_session(SessionConfig::new(server_io))
            .unwrap();

        for _ in 0..50 {
            let _ = client.try_negotiate();
            let _ = server.try_negotiate();
            if client.is_init_finished() && server.is_init_finished() {
                break;
            }
        }

        assert!(
            client.is_init_finished(),
            "DTLS client handshake did not complete"
        );
        assert!(
            server.is_init_finished(),
            "DTLS server handshake did not complete"
        );

        (client, server)
    }
}
