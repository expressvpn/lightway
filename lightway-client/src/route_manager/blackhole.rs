//! Linux blackhole route support. The `route_manager` crate cannot create
//! these: it hardcodes `RouteType::Unicast` when building netlink messages.

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::route::{
    RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use std::io;
use std::net::IpAddr;

fn route_message(destination: IpAddr, prefix: u8, metric: u32) -> RouteMessage {
    let mut msg = RouteMessage::default();
    msg.header.address_family = if destination.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    msg.header.destination_prefix_length = prefix;
    msg.header.protocol = RouteProtocol::Static;
    msg.header.scope = RouteScope::Universe;
    msg.header.kind = RouteType::BlackHole;
    msg.header.table = RouteHeader::RT_TABLE_MAIN;
    msg.attributes
        .push(RouteAttribute::Destination(destination.into()));
    msg.attributes.push(RouteAttribute::Priority(metric));
    msg
}

fn execute(msg: RouteNetlinkMessage, flags: u16) -> io::Result<()> {
    let mut hdr = NetlinkHeader::default();
    hdr.flags = flags;
    let mut packet = NetlinkMessage::new(hdr, NetlinkPayload::from(msg));
    packet.finalize();
    let mut buf = vec![0u8; packet.header.length as usize];
    packet.serialize(&mut buf);

    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    socket.send(&buf, 0)?;

    let mut recv_buf = vec![0u8; 4096];
    let mut recv_slice = &mut recv_buf[..];
    let len = socket.recv(&mut recv_slice, 0)?;
    let response = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[..len])
        .map_err(|e| io::Error::other(format!("{e:?}")))?;
    match response.payload {
        NetlinkPayload::Error(e) if e.code.is_some() => Err(e.to_io()),
        _ => Ok(()),
    }
}

pub(super) fn add(destination: IpAddr, prefix: u8, metric: u32) -> io::Result<()> {
    execute(
        RouteNetlinkMessage::NewRoute(route_message(destination, prefix, metric)),
        NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
    )
}

pub(super) fn delete(destination: IpAddr, prefix: u8, metric: u32) -> io::Result<()> {
    execute(
        RouteNetlinkMessage::DelRoute(route_message(destination, prefix, metric)),
        NLM_F_REQUEST | NLM_F_ACK,
    )
}
