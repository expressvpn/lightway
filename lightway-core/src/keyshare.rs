/// Key share group for post-quantum key exchange.
/// Client can choose one based on server compatibility.
#[derive(Copy, Clone, Debug, Default)]
pub enum KeyShare {
    /// P-521 + ML-KEM-1024
    #[default]
    P521MLKEM1024,

    /// X25519 + ML-KEM-768
    X25519MLKEM768,
}

impl KeyShare {
    /// Get the corresponding curve group
    pub fn as_curve_group(&self) -> wolfssl::CurveGroup {
        match self {
            KeyShare::P521MLKEM1024 => wolfssl::CurveGroup::P521MLKEM1024,
            KeyShare::X25519MLKEM768 => wolfssl::CurveGroup::X25519MLKEM768,
        }
    }
}
