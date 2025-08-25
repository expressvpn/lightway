# Plugins

Plugins provides a way to control traffic flowing throught Lightway protocol.
Applications can create a custom plugin and attach it to client or server.

Plugins can be constructed by implementing the following trait (Ref: `lightway_core::Plugin`)

```rust
pub trait Plugin {
    /// Hook to run during packet ingress
    fn ingress(&self, data: &mut BytesMut) -> PluginResult;

    /// Hook to run during packet egress
    fn egress(&self, data: &mut BytesMut) -> PluginResult;
}
```


The following is an example plugin to drop packets to and from a particular IP address.

```rust
use std::net::Ipv4Addr;
use bytes::BytesMut;
use lightway_core::{Plugin, PluginType, PluginFactory, PluginResult, PluginFactoryError};
use pnet_packet::ipv4::Ipv4Packet;

#[derive(Clone, Debug)]
struct IpFilter(Ipv4Addr);

impl IpFilter {
    fn new(ip: Ipv4Addr) -> Self {
        Self(ip)
    }
}

impl Plugin for IpFilter {
    fn ingress(&self, data: &mut BytesMut) -> PluginResult {
        let Some(packet) = Ipv4Packet::new(data) else {
            return PluginResult::Accept;
        };
        if packet.get_destination() == self.0 {
            PluginResult::Drop
        } else {
            PluginResult::Accept
        }
    }

    fn egress(&self, data: &mut BytesMut) -> PluginResult {
        let Some(packet) = Ipv4Packet::new(data) else {
            return PluginResult::Accept;
        };
        if packet.get_source() == self.0 {
            PluginResult::Drop
        } else {
            PluginResult::Accept
        }
    }
}

pub struct IpFilterPluginFactory {
    filter: IpFilter
}

impl IpFilterPluginFactory {
    pub fn new(ip: Ipv4Addr) -> Self {
        let filter = IpFilter::new(ip);
        Self { filter }
    }
}

impl PluginFactory for IpFilterPluginFactory {
    fn build(&self) -> Result<PluginType, PluginFactoryError> {
        let filter = self.filter.clone();
        Ok(Box::new(filter))
    }
}

```

Pluginfactory's instance can be created and attached to a factory list `lightway_client::PluginFactoryList`

And this plugin factory list can be applied to a client or server by sending it as an argument:
`lightway_client::ClientConfig::inside_plugins` or `lightway_server:ServerConfig::inside_plugins`

to `lightway_client::client` or `lightway_server::server` api to filter traffic.
