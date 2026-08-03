//! Errors returned by the ExpressLane primitives.

/// Errors which can occur encrypting, decrypting or rekeying.
#[derive(Debug, thiserror::Error)]
pub enum ExpresslaneError {
    /// Creating the AEAD failed
    #[error("Creating new crypto failed")]
    NewCipherFailed,
    /// Installing the key into the AEAD failed
    #[error("Setting key failed")]
    SetKeyFailed,
    /// No key is installed for the direction being used
    #[error("No key installed")]
    NoKey,
    /// The AEAD refused to encrypt
    #[error("Encryption failed")]
    EncryptFailed,
    /// AEAD authentication failed
    #[error("Authentication failed")]
    AuthFailed,
    /// The plaintext does not fit the 16-bit wire length field
    #[error("Payload too large")]
    PayloadTooLarge,
    /// The packet was rejected by the replay window
    #[error("Replayed packet")]
    Replayed,
    /// The buffer was shorter than the wire format requires
    #[error("Insufficient data")]
    InsufficientData,
}

/// Result alias for the ExpressLane primitives.
pub type ExpresslaneResult<T> = Result<T, ExpresslaneError>;
