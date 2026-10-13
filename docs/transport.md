# Transports

A transport is the layer under a Lightway connection. It owns the secure
session and the framing between Lightway frames and the outside path. The
connection owns the Lightway state machine. It does not touch the secure
session or the socket.

The built-in transport is `TlsTransport`. It runs TLS over TCP and DTLS
over UDP. An application can supply a different transport.

## Capabilities

Each transport reports `TransportCaps`. The connection reads them once,
when it is built, and uses them to select its framing, queueing and error
handling.

| Capability             | Meaning                                                                                      | TLS | DTLS |
|------------------------|----------------------------------------------------------------------------------------------|-----|------|
| `lossy`                | One Lightway frame travels in each packet. Packets can be lost or reordered.                 | no  | yes  |
| `reliable_control`     | Control frames are not lost, also on a `lossy` transport. They queue when the path blocks.   | yes | no   |
| `wire_header`          | Each packet starts with a Lightway header that carries the session ID. Expresslane needs it. | no  | yes  |
| `supports_roaming`     | The connection continues after a change of the local network.                                | no  | yes  |

The connection does PMTU discovery only on a `lossy` transport. The server
rotates the session ID only on a `wire_header` transport.

## The contract of a transport

The `Transport` trait is synchronous. If a method needs the outside path,
it returns `Pending`. The doc of each method states what the connection
does next.

- Each call to `write` gets exactly one Lightway frame. If a write blocks,
  the connection retries it with the same buffer.
- The connection asks for ticks only while the link comes up or a key
  update is pending. On each tick, except while the client
  authenticates, it calls `has_timed_out`, so a transport retransmits
  there.
- Each `TransportError` states whether it ends the connection.
- The ingress hooks of the outside plugins run before the transport sees
  a packet. The transport runs only the egress hooks, on each packet that
  it sends. If a hook does not accept a packet, the transport does not
  send it.

## Client

To use a custom transport, set `ClientConnectionMode::Transport`. It
contains two items:

- `factory`: a `ClientTransportFactory`. For each connection attempt, the
  client calls `connect` with the `TransportArgs` and the
  `ClientTransportArgs`.
- `connector`: a function that connects the outside IO when the
  attempt starts.

`TransportArgs` contains the outside path and the outside MTU. It also
contains the protocol version, the session ID and the outside plugins.
`ClientTransportArgs` contains the peer checks and the key share. A
transport uses the items that apply to it.

After a network change, a client on a `supports_roaming` transport keeps
the connection and sends keepalives. On other transports, the client
disconnects and returns `ClientResult::NetworkChange`.
