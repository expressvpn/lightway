//! Certificate-chain validation tests for backend.
//!
//! On-the-fly generation of certs is too slow on RISCV, skip this suite.
#![cfg(not(target_arch = "riscv64"))]

use std::sync::Arc;
use std::time::Duration;

use test_case::test_matrix;
use tokio::net::UnixStream;

pub mod common;
use crate::common::certgen::{Defect, Link, TestPki};
use crate::common::connection::{
    PQCrypto, TestAuth, TestClientConfig, TestServerConfig, TestSock, TestStreamSock, client,
    server,
};
use crate::common::get_test_timeout;
use rcgen::RsaKeySize;

async fn handshake(pki: &'static TestPki) -> Result<(), String> {
    let attempt = tokio::spawn(async move {
        let (client_sock, server_sock) = UnixStream::pair().expect("UnixStream");
        let client_sock = Arc::new(TestStreamSock(client_sock));
        let server_sock = Arc::new(TestStreamSock(server_sock));
        let _ = client_sock.writable().await;

        let auth = Arc::new(TestAuth::default());
        let pqc = PQCrypto::default();
        let (cert, key) = pki.server_secrets();
        tokio::join!(
            server(
                server_sock,
                TestServerConfig {
                    auth,
                    pqc,
                    expresslane: None,
                    conn_out: None,
                    metrics: None,
                    cert,
                    key,
                },
            ),
            client(
                client_sock,
                TestClientConfig {
                    cipher: None,
                    pqc,
                    server_dn: None,
                    enable_codec: false,
                    enable_expresslane: false,
                    use_versioned_token: false,
                    root_ca: pki.root_ca(),
                },
            )
        )
    });

    match tokio::time::timeout(Duration::from_millis(get_test_timeout()), attempt).await {
        Err(_elapsed) => panic!("handshake attempt timed out"),
        Ok(Ok(((), ()))) => Ok(()),
        Ok(Err(join_err)) if join_err.is_panic() => {
            let payload = join_err.into_panic();
            let reason = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "non-string panic payload".to_string());
            Err(reason)
        }
        Ok(Err(join_err)) => panic!("harness task failed: {join_err}"),
    }
}

/// Positive control: a defect-free chain must complete the handshake.
#[test_matrix(
    [2, 3],
    [RsaKeySize::_2048, RsaKeySize::_4096]
)]
#[tokio::test]
async fn valid_chain_accepted(chain_len: usize, key_size: RsaKeySize) {
    let pki = TestPki::get_valid(chain_len, key_size);
    handshake(pki)
        .await
        .expect("valid chain must complete the handshake");
}

/// A chain whose root, intermediate, or leaf certificate is corrupt,
/// untrusted, or expired must never produce a connection.
#[test_matrix(
    [Defect::Corrupt, Defect::Invalid, Defect::Expired],
    [Link::Root, Link::Intermediate, Link::Leaf],
    [RsaKeySize::_2048, RsaKeySize::_4096]
)]
#[tokio::test]
async fn defective_chain_rejected(defect: Defect, link: Link, key_size: RsaKeySize) {
    let pki = TestPki::get_defective(defect, link, key_size);
    match handshake(pki).await {
        Err(reason) => println!("rejected {defect:?} {link:?} {key_size:?}: {reason}"),
        Ok(()) => panic!("handshake completed despite {defect:?} {link:?} certificate"),
    }
}
