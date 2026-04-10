//! Mobile mod of inside io
//! A warpper for Tun which can be cloned for multiple connections
use crate::{ConnectionState, io::inside::Tun};

pub type TunnelState = Option<std::sync::Arc<Tun>>;

/// Inside IO which can be cloned by multiple parallel connections
///
/// The actual tunnel `InsideIO` is stored inside `ConnectionState::extended`
/// After a connection becomes active, it updates the connection state with tunnel `InsideIO`
#[derive(Clone)]
pub struct MobileInsideIo {
    pub mtu: usize,
}

impl lightway_core::InsideIOSendCallback<ConnectionState<TunnelState>> for MobileInsideIo {
    fn send(
        &self,
        buf: uniffi::deps::bytes::BytesMut,
        state: &mut ConnectionState<TunnelState>,
    ) -> lightway_core::IOCallbackResult<usize> {
        if let Some(tun) = state.extended.clone() {
            tun.send(buf, state)
        } else {
            // Fake it, but all tunnel traffic is dropped/blocked
            lightway_core::IOCallbackResult::Ok(buf.len())
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn if_index(&self) -> uniffi::Result<u32, std::io::Error> {
        Err(std::io::Error::other("unimplemented!"))
    }

    fn name(&self) -> uniffi::Result<String, std::io::Error> {
        Err(std::io::Error::other("unimplemented!"))
    }
}
