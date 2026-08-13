//! On-the-fly X.509 certificate generation for tests.

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_RSA_SHA256, RsaKeySize,
};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

pub const TEST_SERVER_DOMAIN: &str = "example.com";

/// A generated certificate and its private key, both DER encoded.
pub struct CertifiedKey {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// Generate a key pair matching the previously checked-in test certificates
fn generate_key() -> KeyPair {
    KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).expect("generate RSA-2048 key")
}

fn set_validity(params: &mut CertificateParams) {
    const DAY: Duration = Duration::from_secs(60 * 60 * 24);
    let now = SystemTime::now();
    params.not_before = (now - DAY).into();
    params.not_after = (now + 30 * DAY).into();
}

/// A certificate authority that can issue server certificates.
pub struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl Ca {
    pub fn new_self_signed(common_name: &str) -> Self {
        let cert_params = {
            let mut params = CertificateParams::default();
            set_validity(&mut params);
            params
                .distinguished_name
                .push(DnType::CommonName, common_name);
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params
        };
        let key = generate_key();
        let issuer = CertifiedIssuer::self_signed(cert_params, key).expect("self-sign CA cert");
        Self { issuer }
    }

    /// This CA's certificate, DER encoded.
    pub fn cert_der(&self) -> Vec<u8> {
        self.issuer.der().to_vec()
    }

    /// Issue an end-entity certificate for a TLS server at `domain`,
    /// used as both the subject CN and a dNSName SAN.
    pub fn issue_server(&self, domain: &str) -> CertifiedKey {
        let cert_params = {
            let mut params = CertificateParams::new(vec![domain.to_string()]).expect("valid SAN");
            set_validity(&mut params);
            params.distinguished_name.push(DnType::CommonName, domain);
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params
        };
        let key = generate_key();
        let cert = cert_params
            .signed_by(&key, &self.issuer)
            .expect("sign server cert");
        CertifiedKey {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }
}

/// The PKI shared by the standard connection tests: a root CA and a server
/// certificate it issued for [`TEST_SERVER_DOMAIN`].
pub struct TestPki {
    pub ca_cert_der: Vec<u8>,
    pub server: CertifiedKey,
}

/// The shared happy-path PKI, generated once per test process.
pub fn gen_shared_testing_pki() -> &'static TestPki {
    static PKI: LazyLock<TestPki> = LazyLock::new(|| {
        let ca = Ca::new_self_signed("lightway test CA");
        let server = ca.issue_server(TEST_SERVER_DOMAIN);
        TestPki {
            ca_cert_der: ca.cert_der(),
            server,
        }
    });
    &PKI
}
