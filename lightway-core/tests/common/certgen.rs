//! On-the-fly X.509 certificate generation for tests.
//!
//! The main export is the [`TestPki`], which defines the everything each
//! test connection needs. Call [`TestPki::get_valid`] to get a valid one,
//! or [`TestPki::get_defective`] to get one with your chosen defects.
//!
//! Note: Every request is automatically memoized,
//! so asking for the same PKI twice costs one keygen.

use lightway_core::{RootCertificate, Secret};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_RSA_SHA256, RsaKeySize,
};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

const DAY: Duration = Duration::from_secs(60 * 60 * 24);

/// Which certificate in the chain carries the defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Link {
    Root,
    Intermediate,
    Leaf,
}

/// How a certificate is unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Defect {
    /// Truncated DER, which no backend can even parse.
    Corrupt,
    /// Well-formed, but not part of the chain it claims to belong to.
    Invalid,
    /// Well-formed and correctly chained, but outside its validity window.
    Expired,
}

/// A trust anchor and a server certificate/key issued under it.
pub struct TestPki {
    trust_bundle_pem: Vec<u8>,
    server: CertifiedKey,
}

impl TestPki {
    /// The domain generated server certificates are issued for, and so the
    /// name a client may be told to validate.
    pub const SERVER_DOMAIN: &'static str = "example.com";

    /// A defect-free PKI of the given chain length (2 = root > leaf,
    /// 3 = root > intermediate > leaf).
    pub fn get_valid(chain_len: usize, key_size: RsaKeySize) -> &'static TestPki {
        cached(PkiSpec::Valid {
            chain_len,
            key_size,
        })
    }

    /// A PKI in which the certificate at `link` carries `defect`.
    pub fn get_defective(defect: Defect, link: Link, key_size: RsaKeySize) -> &'static TestPki {
        cached(PkiSpec::Defective {
            defect,
            link,
            key_size,
        })
    }

    fn generate_valid(chain_len: usize, key_size: RsaKeySize) -> TestPki {
        let root = Ca::new_self_signed("test root CA", key_size, false);
        match chain_len {
            2 => TestPki {
                trust_bundle_pem: pem_bundle(&[&root.cert_der()]),
                server: root.issue_server(Self::SERVER_DOMAIN, key_size, false),
            },
            3 => {
                let intermediate = root.issue_intermediate("test intermediate CA", key_size, false);
                TestPki {
                    trust_bundle_pem: pem_bundle(&[&root.cert_der(), &intermediate.cert_der()]),
                    server: intermediate.issue_server(Self::SERVER_DOMAIN, key_size, false),
                }
            }
            _ => unreachable!("unsupported chain length"),
        }
    }

    fn generate_defective(defect: Defect, link: Link, key_size: RsaKeySize) -> TestPki {
        let is_expired = matches!(defect, Defect::Expired);
        let unrelated_ca = || Ca::new_self_signed("unrelated CA", key_size, false);

        match link {
            Link::Root => {
                let root = Ca::new_self_signed("test root CA", key_size, is_expired);
                let server = root.issue_server(Self::SERVER_DOMAIN, key_size, false);
                let anchor_der = match defect {
                    Defect::Corrupt => corrupt_der(&root.cert_der()),
                    Defect::Invalid => unrelated_ca().cert_der(),
                    Defect::Expired => root.cert_der(),
                };
                TestPki {
                    trust_bundle_pem: pem_bundle(&[&anchor_der]),
                    server,
                }
            }
            Link::Intermediate => {
                let root = Ca::new_self_signed("test root CA", key_size, false);
                let intermediate =
                    root.issue_intermediate("test intermediate CA", key_size, is_expired);
                let server = intermediate.issue_server(Self::SERVER_DOMAIN, key_size, false);
                let intermediate_der = match defect {
                    Defect::Corrupt => corrupt_der(&intermediate.cert_der()),
                    Defect::Invalid => unrelated_ca()
                        .issue_intermediate("unrelated intermediate CA", key_size, false)
                        .cert_der(),
                    Defect::Expired => intermediate.cert_der(),
                };
                TestPki {
                    trust_bundle_pem: pem_bundle(&[&root.cert_der(), &intermediate_der]),
                    server,
                }
            }
            Link::Leaf => {
                let root = Ca::new_self_signed("test root CA", key_size, false);
                let intermediate = root.issue_intermediate("test intermediate CA", key_size, false);
                let server = match defect {
                    Defect::Corrupt => {
                        let sound = intermediate.issue_server(Self::SERVER_DOMAIN, key_size, false);
                        CertifiedKey {
                            cert_der: corrupt_der(&sound.cert_der),
                            key_der: sound.key_der,
                        }
                    }
                    Defect::Invalid => {
                        unrelated_ca().issue_server(Self::SERVER_DOMAIN, key_size, false)
                    }
                    Defect::Expired => {
                        intermediate.issue_server(Self::SERVER_DOMAIN, key_size, true)
                    }
                };
                TestPki {
                    trust_bundle_pem: pem_bundle(&[&root.cert_der(), &intermediate.cert_der()]),
                    server,
                }
            }
        }
    }

    /// The trust anchor to configure a client with.
    pub fn root_ca(&self) -> RootCertificate<'_> {
        RootCertificate::PemBuffer(&self.trust_bundle_pem)
    }

    /// The certificate and key for a server to present, in that order.
    pub fn server_secrets(&self) -> (Secret<'_>, Secret<'_>) {
        (
            Secret::Asn1Buffer(&self.server.cert_der),
            Secret::Asn1Buffer(&self.server.key_der),
        )
    }
}

/// What was asked for, and so the identity of a cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PkiSpec {
    Valid {
        chain_len: usize,
        key_size: RsaKeySize,
    },
    Defective {
        defect: Defect,
        link: Link,
        key_size: RsaKeySize,
    },
}

impl PkiSpec {
    fn generate(self) -> TestPki {
        match self {
            PkiSpec::Valid {
                chain_len,
                key_size,
            } => TestPki::generate_valid(chain_len, key_size),
            PkiSpec::Defective {
                defect,
                link,
                key_size,
            } => TestPki::generate_defective(defect, link, key_size),
        }
    }
}

/// Every PKI generated in this test process, keyed by the request that asked
/// for it.
static PKI_CACHE: LazyLock<Mutex<HashMap<PkiSpec, &'static OnceLock<TestPki>>>> =
    LazyLock::new(Mutex::default);

/// The PKI for `spec`, generating it if this is the first request.
fn cached(spec: PkiSpec) -> &'static TestPki {
    let entry = *PKI_CACHE
        .lock()
        .expect("PKI cache lock")
        .entry(spec)
        .or_insert_with(|| Box::leak(Box::new(OnceLock::new())));
    entry.get_or_init(|| spec.generate())
}

/// A generated certificate and its private key, both DER encoded.
struct CertifiedKey {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

/// A certificate authority that can issue server certificates and
/// intermediate CAs.
struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl Ca {
    fn new_self_signed(common_name: &str, key_size: RsaKeySize, is_expired: bool) -> Self {
        let params = Self::ca_params(common_name, is_expired);
        let key = generate_key(key_size);
        let issuer = CertifiedIssuer::self_signed(params, key).expect("self-sign CA cert");
        Self { issuer }
    }

    /// An intermediate CA signed by this CA.
    fn issue_intermediate(
        &self,
        common_name: &str,
        key_size: RsaKeySize,
        is_expired: bool,
    ) -> Self {
        let params = Self::ca_params(common_name, is_expired);
        let key = generate_key(key_size);
        let issuer = CertifiedIssuer::signed_by(params, key, &self.issuer)
            .expect("sign intermediate CA cert");
        Self { issuer }
    }

    fn ca_params(common_name: &str, is_expired: bool) -> CertificateParams {
        let mut params = CertificateParams::default();
        set_validity(&mut params, is_expired);
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
    }

    /// This CA's certificate, DER encoded.
    fn cert_der(&self) -> Vec<u8> {
        self.issuer.der().to_vec()
    }

    /// An end-entity TLS server certificate for `domain`, used as both the
    /// subject CN and a dNSName SAN.
    fn issue_server(&self, domain: &str, key_size: RsaKeySize, is_expired: bool) -> CertifiedKey {
        let cert_params = {
            let mut params = CertificateParams::new(vec![domain.to_string()]).expect("valid SAN");
            set_validity(&mut params, is_expired);
            params.distinguished_name.push(DnType::CommonName, domain);
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params
        };
        let key = generate_key(key_size);
        let cert = cert_params
            .signed_by(&key, &self.issuer)
            .expect("sign server cert");
        CertifiedKey {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }
}

fn set_validity(params: &mut CertificateParams, is_expired: bool) {
    let now = SystemTime::now();
    let (not_before, not_after) = match is_expired {
        false => (now - DAY, now + 30 * DAY),
        true => (now - 30 * DAY, now - DAY),
    };
    params.not_before = not_before.into();
    params.not_after = not_after.into();
}

fn generate_key(key_size: RsaKeySize) -> KeyPair {
    KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, key_size).expect("generate RSA key")
}

/// Encode DER certificates as a concatenated PEM bundle.
fn pem_bundle(certs_der: &[&[u8]]) -> Vec<u8> {
    certs_der
        .iter()
        .map(|der| pem::encode(&pem::Pem::new("CERTIFICATE", der.to_vec())))
        .collect::<String>()
        .into_bytes()
}

fn corrupt_der(der: &[u8]) -> Vec<u8> {
    der[..der.len() / 2].to_vec()
}
