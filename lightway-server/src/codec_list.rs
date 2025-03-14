use lightway_core::{PacketDecoderType, PacketEncoderType};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Mutex, Weak},
};

// Maps client's internal IP (assigned by IPManager) to its connection's packet encoder
pub type InternalIPToEncoderMap = HashMap<Ipv4Addr, Weak<Mutex<PacketEncoderType>>>;

// List of Decoders of each connection
pub type DecoderList = Vec<Weak<Mutex<PacketDecoderType>>>;
