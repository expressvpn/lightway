#![cfg(feature = "debug")]

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use lightway_core::Tls13SecretCallbacks;

#[derive(Debug, Clone)]
pub(crate) struct WiresharkKeyLogger(pub(crate) PathBuf);

impl WiresharkKeyLogger {
    pub(crate) fn new(path: PathBuf) -> Arc<Self> {
        Arc::new(Self(path))
    }
}

impl Tls13SecretCallbacks for WiresharkKeyLogger {
    fn wireshark_keylog(&self, secret: String) {
        let Ok(mut keylog_file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
        else {
            return;
        };

        if let Err(e) = keylog_file.write_all(secret.as_bytes()) {
            tracing::error!("Failed to write in file {:?}", e);
        }
    }
}
