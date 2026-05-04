use bytes::BytesMut;
use delegate::delegate;
use thiserror::Error;

/// Convenience type to use `Plugin` as function arguments
pub type PluginType = Box<dyn Plugin + Sync + Send>;

/// Lightway Plugin trait for inside and outside packets
///
/// These are the hooks which will be installed at the ingress and
/// egress of the inside and outside packets.
///
/// Inside:
///     Ingress -> Packets received from the tunnel interface
///     Egress -> Packet being sent to the tunnel interface
///
/// Outside:
///     Ingress -> Packet received from Lightway TCP/UDP socket
///     Egress -> Packet being sent to Lightway TCP/UDP socket
///
/// Applications can use this hooks to implement ACL etc
pub trait Plugin {
    /// Hook to run during packet ingress
    fn ingress(&self, data: &mut BytesMut) -> PluginResult;

    /// Hook to run during packet egress
    fn egress(&self, data: &mut BytesMut) -> PluginResult;
}

/// Stores the list of plugins
#[derive(Default)]
pub(crate) struct PluginList {
    plugins: Vec<PluginType>,
}

/// The result of an [`Plugin`].
#[derive(Error, Debug)]
pub enum PluginResult {
    /// [`Plugin`] accepted the packet
    #[error("Plugin accepts the packet")]
    Accept,
    /// [`Plugin`] dropped the packet
    #[error("Plugin drops the packet")]
    Drop,
    /// [`Plugin`] dropped the packet and returned a reply packet to send back
    /// This is useful only for Inside IO plugins. Outside plugins cannot
    /// drop a packet with reply
    #[error("Plugin drops the packet with reply packet")]
    DropWithReply(BytesMut),
    /// Internal [`Plugin`] error
    #[error("Plugin error")]
    Error(Box<dyn std::error::Error + Sync + Send>),
}

impl PluginList {
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    pub(crate) fn do_ingress(&self, data: &mut BytesMut) -> PluginResult {
        for plugin in self.plugins.iter() {
            let res = plugin.ingress(data);
            if !matches!(res, PluginResult::Accept) {
                return res;
            }
        }
        PluginResult::Accept
    }

    pub(crate) fn do_egress(&self, data: &mut BytesMut) -> PluginResult {
        for plugin in self.plugins.iter().rev() {
            let res = plugin.egress(data);
            if !matches!(res, PluginResult::Accept) {
                return res;
            }
        }
        PluginResult::Accept
    }
}

impl From<Vec<PluginType>> for PluginList {
    fn from(plugins: Vec<PluginType>) -> Self {
        Self { plugins }
    }
}

/// Convenience type to use as function arguments
pub type PluginFactoryType = Box<dyn PluginFactory + Sync + Send>;

/// The result of an [`Plugin`].
#[derive(Error, Debug)]
pub enum PluginFactoryError {
    /// Factory error during building
    #[error("Factory build error")]
    BuildError(Box<dyn std::error::Error + Sync + Send>),
}

/// Factory to build `Plugin`
/// This will be used to build a new instance of `Plugin` for every connection.
pub trait PluginFactory {
    /// Build a new instance of `Plugin`
    fn build(&self) -> Result<PluginType, PluginFactoryError>;
}

/// Stores the list of `PluginFactory`
#[derive(Default)]
pub struct PluginFactoryList(Vec<PluginFactoryType>);

impl PluginFactoryList {
    /// Create new `PluginFactoryList`
    pub fn new() -> Self {
        Self::default()
    }

    delegate! {
        to self.0 {
            /// Returns the number of plugins.
            pub fn len(&self) -> usize;

            /// Returns true if the plugin list contains no plugins.
            pub fn is_empty(&self) -> bool;
        }
    }

    /// Add [`PluginFactory`] to the [`PluginFactoryList`]
    pub fn add(&mut self, factory: PluginFactoryType) {
        self.0.push(factory);
    }

    // Build a PluginList
    pub(crate) fn build(&self) -> Result<PluginList, PluginFactoryError> {
        let plugins = self
            .0
            .iter()
            .map(|f| f.build())
            .collect::<Result<Vec<PluginType>, _>>()?;
        Ok(PluginList::from(plugins))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, BufMut};
    use test_case::test_case;

    struct PadPlugin {
        pad: Vec<u8>,
    }

    impl Default for PadPlugin {
        fn default() -> Self {
            Self {
                pad: Self::PAD.to_owned(),
            }
        }
    }

    impl PadPlugin {
        const PAD: &'static [u8] = b"PadPlugin";

        fn new(pad: Vec<u8>) -> Self {
            Self { pad }
        }
    }

    impl Plugin for PadPlugin {
        fn ingress(&self, data: &mut BytesMut) -> PluginResult {
            let pad = data.copy_to_bytes(self.pad.len());
            assert_eq!(&pad[..], self.pad);

            PluginResult::Accept
        }

        fn egress(&self, data: &mut BytesMut) -> PluginResult {
            let orig_data = BytesMut::from(&data[..]);
            data.clear();
            data.put(self.pad.as_ref());
            data.extend(orig_data);

            PluginResult::Accept
        }
    }

    // This plugin will drop data if the content len is odd
    struct DropPlugin;

    impl Plugin for DropPlugin {
        fn ingress(&self, data: &mut BytesMut) -> PluginResult {
            if data.len() % 2 == 1 {
                PluginResult::Drop
            } else {
                PluginResult::Accept
            }
        }

        fn egress(&self, data: &mut BytesMut) -> PluginResult {
            self.ingress(data)
        }
    }

    #[test]
    fn test_plugin_list_create() {
        let plugin_list = PluginList::default();
        assert_eq!(plugin_list.plugins.len(), 0);
    }

    #[test]
    fn test_plugin_from() {
        let plugin1 = Box::<PadPlugin>::default();
        let plugin2 = Box::<PadPlugin>::default();
        let plugin3 = Box::<PadPlugin>::default();
        let plugins: Vec<PluginType> = vec![plugin1, plugin2, plugin3];
        let plugin_list = PluginList::from(plugins);
        assert_eq!(plugin_list.plugins.len(), 3);
    }

    #[test]
    fn test_plugin_ingress() {
        let plugins: Vec<PluginType> = vec![Box::<PadPlugin>::default()];
        let plugin_list = PluginList::from(plugins);
        let orig_value = 32;

        let mut data = BytesMut::new();
        data.put(PadPlugin::PAD);
        data.put_u32(orig_value);

        let res = plugin_list.do_ingress(&mut data);
        assert!(matches!(res, PluginResult::Accept));
        let value = data.get_u32();
        assert_eq!(value, orig_value);
    }

    #[test]
    fn test_plugin_egress() {
        let plugins: Vec<PluginType> = vec![Box::<PadPlugin>::default()];
        let plugin_list = PluginList::from(plugins);
        let orig_value = 32;

        let mut data = BytesMut::new();
        data.put_u32(orig_value);

        let res = plugin_list.do_egress(&mut data);
        assert!(matches!(res, PluginResult::Accept));

        let pad = data.copy_to_bytes(PadPlugin::PAD.len());
        assert_eq!(pad, PadPlugin::PAD);
        assert_eq!(data.get_u32(), orig_value);
    }

    #[test]
    fn test_plugin_egress_and_ingress() {
        let plugins: Vec<PluginType> = vec![Box::<PadPlugin>::default()];
        let plugin_list = PluginList::from(plugins);

        let orig_value = 32;

        let mut data = BytesMut::new();
        data.put_u32(orig_value);
        plugin_list.do_egress(&mut data);

        plugin_list.do_ingress(&mut data);
        let value = data.get_u32();
        assert_eq!(value, orig_value);
    }

    #[test]
    fn test_plugin_chaining() {
        let plugin1 = Box::new(PadPlugin::new(b"plugin1".to_vec()));
        let plugin2 = Box::new(PadPlugin::new(b"plugin2".to_vec()));
        let plugin3 = Box::new(PadPlugin::new(b"plugin3".to_vec()));
        let plugins: Vec<PluginType> = vec![plugin1, plugin2, plugin3];
        let plugin_list = PluginList::from(plugins);

        let orig_value = 32;

        let mut data = BytesMut::new();
        data.put_u32(orig_value);
        plugin_list.do_egress(&mut data);

        plugin_list.do_ingress(&mut data);
        let value = data.get_u32();
        assert_eq!(value, orig_value);
    }

    #[test_case(b"odd", 32 => matches PluginResult::Drop)]
    #[test_case(b"even", 32 => matches PluginResult::Accept)]
    fn test_plugin_chaining_egress_drop(pad: &[u8], value: u16) -> PluginResult {
        let plugin1 = Box::new(DropPlugin);
        let plugin2 = Box::new(PadPlugin::new(pad.to_vec()));
        let plugins: Vec<PluginType> = vec![plugin1, plugin2];
        let plugin_list = PluginList::from(plugins);

        let mut data = BytesMut::new();
        data.put_u16(value);
        plugin_list.do_egress(&mut data)
    }

    #[test_case(1, 32 => matches PluginResult::Drop)]
    #[test_case(2, 32 => matches PluginResult::Accept)]
    fn test_plugin_chaining_ingress_drop(times: usize, value: u8) -> PluginResult {
        let pad = b"even";
        let plugin1 = Box::new(PadPlugin::new(pad.to_vec()));
        let plugin2 = Box::new(DropPlugin);
        let plugins: Vec<PluginType> = vec![plugin1, plugin2];
        let plugin_list = PluginList::from(plugins);

        let mut data = BytesMut::new();
        data.put(&pad[..]);
        for _ in 0..times {
            data.put_u8(value);
        }
        plugin_list.do_ingress(&mut data)
    }
}
