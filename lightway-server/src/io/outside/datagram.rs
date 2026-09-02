//! Carrier-independent datagram dispatch.

use bytes::BytesMut;
use lightway_core::{
    ConnectionType, Header, OutsideIOSendCallbackArg, OutsidePacket, SessionId, Version,
};
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

use crate::{connection_manager::ConnectionManager, metrics};

/// Parse one wire packet, route it to its connection, and hand it over.
///
/// `mint` builds the send callback for a connection being created.
/// `reject` sends an already-encoded reject frame to a peer with no
/// connection.
pub(crate) fn data_received(
    conn_manager: &Arc<ConnectionManager>,
    buf: &mut BytesMut,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    mint: impl FnOnce() -> OutsideIOSendCallbackArg,
    reject: impl FnOnce(&[u8]),
) {
    let pkt = OutsidePacket::Wire(buf, ConnectionType::Datagram);
    let pkt = match conn_manager.parse_raw_outside_packet(pkt) {
        Ok(pkt) => pkt,
        Err(e) => {
            metrics::udp_parse_wire_failed();
            warn!("Extracting header from packet failed: {e}");
            return;
        }
    };
    let hdr = *pkt.header().expect("a parsed datagram carries a header");

    if !conn_manager.is_supported_version(hdr.version) {
        // If the protocol version is not supported then drop
        // the packet.
        metrics::udp_bad_packet_version(hdr.version);
        return;
    }

    // A peer-address hit delivers even when the session id in `hdr` does
    // not match, which `find_or_create_datagram_connection_with` would
    // reject. Do not fold this into the call below.
    let (conn, roamed) = match conn_manager.find_datagram_connection_with(peer_addr) {
        Some(conn) => (conn, false),
        None => match conn_manager.find_or_create_datagram_connection_with(
            peer_addr,
            hdr.version,
            hdr.session,
            local_addr,
            mint,
        ) {
            Ok(routed) => routed,
            Err(_e) => {
                send_reject(reject);
                return;
            }
        },
    };

    match conn.outside_data_received(pkt) {
        Ok(0) => {
            // We will hit this case when there is UDP packet duplication.
            // TLS library skips duplicate packets and thus no frames read.
            // It is also possible that adversary can capture the packet
            // and replay it. In any case, skip processing further
            if roamed {
                metrics::udp_session_rotation_attempted_via_replay();
            }
        }
        Ok(_) => {
            // NOTE: We wait until the first successful TLS
            // decrypt to protect against the case where a crafted
            // packet with a session ID causes us to change the
            // connection IP without verifying the SSL connection
            // first
            if roamed {
                metrics::udp_conn_recovered_via_session(hdr.session);
                // Address first: the rotation announce must go to the
                // address the client roamed to.
                conn_manager.set_peer_addr(&conn, peer_addr);
                conn.begin_session_id_rotation();
            }
        }
        Err(err) => {
            warn!("Failed to process outside data: {err}");
            let _ = conn.handle_outside_data_error(&err);
            // Fatal or not, we are done with this packet.
        }
    }
}

fn send_reject(reject: impl FnOnce(&[u8])) {
    metrics::udp_rejected_session();
    let msg = Header {
        version: Version::MINIMUM,
        aggressive_mode: false,
        session: SessionId::REJECTED,
        expresslane_data: false,
    };

    let mut buf = BytesMut::with_capacity(Header::WIRE_SIZE);
    msg.append_to_wire(&mut buf);

    reject(&buf);
}
