use std::net::IpAddr;

// TODO: allow dead code and refact and share with cli config
#[allow(dead_code)]
/// Lightway endpoint details
#[derive(Clone)]
#[cfg_attr(mobile, derive(uniffi::Record))]
pub struct RustEndpointConfig {
    #[cfg(mobile)]
    pub server_ip: IpAddress,
    #[cfg(desktop)]
    pub server_ip: IpAddr,

    pub port: u16,
    pub server_dn: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth_token: Option<String>,
    pub ca_cert: String,
    pub use_tcp: bool,
    pub use_cha_cha_20: bool,
    pub outside_mtu: u32,
}

#[cfg(mobile)]
#[derive(Debug, thiserror::Error, uniffi::Error)]
// Some of the errors here are used in the iOS app only, so we are explicitly tagging them with dead code allowed
pub enum EndpointError {
    /// Invalid network protocol
    #[error("Invalid network protocol")]
    #[allow(dead_code)]
    InvalidProtocol,

    /// Unable to load certificate
    #[error("Unable to load certificate")]
    #[allow(dead_code)]
    InvalidCertificate,
}

// Ref: https://mozilla.github.io/uniffi-rs/0.27/proc_macro/index.html#the-unifficustom_type-and-unifficustom_newtype-macros
#[cfg(mobile)]
uniffi::custom_type!(IpAddress, String);

#[cfg(mobile)]
#[derive(Debug, Eq, PartialEq, Clone)]
/// Custom type  with `String` as the `Builtin` bridge
pub struct IpAddress {
    ip: IpAddr,
}

#[cfg(mobile)]
impl std::fmt::Display for IpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ip)
    }
}

#[cfg(mobile)]
impl crate::UniffiCustomTypeConverter for IpAddress {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        use std::str::FromStr;
        Ok(IpAddress {
            ip: IpAddr::from_str(val.as_str())?,
        })
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.ip.to_string()
    }
}

#[cfg(mobile)]
impl From<IpAddress> for IpAddr {
    fn from(val: IpAddress) -> Self {
        val.ip
    }
}
