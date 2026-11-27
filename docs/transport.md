# Transports

A transport is the layer under a Lightway connection. It owns the secure
session. It turns Lightway frames into records, and records back into
frames. The connection owns the Lightway state machine and the outside
IO. It does not touch the secure session.

The built-in transport is `TlsTransport`. It runs TLS over TCP and DTLS
over UDP. An application can supply a different transport.

## Capabilities

Each transport reports `TransportCaps`. The connection reads them once,
when it is built, and uses them to select its framing, queueing and error
handling.

| Capability         | Meaning                                                                                                   | TLS      | DTLS       |
|--------------------|-----------------------------------------------------------------------------------------------------------|----------|------------|
| `delivery`         | `Stream`: frames arrive in order and are never lost. `Datagram`: one Lightway frame travels in each packet, and packets can be lost or reordered. | `Stream` | `Datagram` |
| `wire_header`      | Part of `Datagram`. Each packet starts with a Lightway header that carries the session ID. Expresslane needs it. A stream cannot carry the header. | no       | yes        |
| `supports_roaming` | The connection continues after a change of the local network.                                             | no       | yes        |

The connection does PMTU discovery only on a datagram transport. The server
rotates the session ID only on a transport with the wire header.

## The contract of a transport

The `Transport` trait is synchronous. If a method needs the outside path,
it returns `Pending`. The doc of each method states what the connection
does next.

- A transport never sends on the outside IO. Any method can make records.
  After each call, the connection takes the records with `poll_transmit`.
- Each call to `write` gets exactly one Lightway frame, and the transport
  consumes all of it. The connection calls `write` only after the
  handshake is `Ready`.
- The connection asks for ticks only while the link comes up or a key
  update is pending. On each tick, except while the client
  authenticates, it calls `has_timed_out`, so a transport retransmits
  there.
- Each `TransportError` states whether it ends the connection.

## Encapsulation

The connection gives each record to its encapsulation. If the transport
has the wire header, the encapsulation adds the Lightway header. It runs the egress
hooks of the outside plugins and sends the packet. On a received packet,
it runs the ingress hooks and reads the header before the transport sees
the record. A transport does not see the header or the plugins.

If the outside IO blocks, a datagram encapsulation drops the packet. A
stream encapsulation keeps its packets in order, and the connection writes
no new frame until they leave. Meanwhile the connection queues the frames
that nothing above retransmits: control frames and inner UDP.
