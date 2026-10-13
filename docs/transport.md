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

## Client

To use a custom transport, set `ClientConnectionMode::Transport`. It
contains two items:

- `factory`: a `ClientTransportFactory`. For each connection attempt, the
  client calls `connect` with the `TransportArgs` and the
  `ClientTransportArgs`.
- `connector`: a function that connects the outside IO when the
  attempt starts.

`TransportArgs` contains the largest record that one outside packet can
carry. `ClientTransportArgs` contains the peer checks and the key share.
A transport uses the items that apply to it.

After a network change, a client on a `supports_roaming` transport keeps
the connection and sends keepalives. On other transports, the client
disconnects and returns `ClientResult::NetworkChange`.

## Server

To use a custom server, set `ServerConfig::mode` to
`ServerConnectionMode::Custom` with a boxed `Server`. The `server`
function calls `Server::run` with the `ConnectionManager`. When `run`
returns, `server` disconnects every connection and returns. A signal or
an exit of the inside IO also stops `server`. Then `server` drops the
`run` future and disconnects every connection. Thus a task that the
custom server spawns does not stop with `run`. When the connection of a
task is `Disconnected`, stop the task.

A custom server depends on `lightway-core` and `async-trait`. `Server`
uses `#[async_trait]`, and the connection methods take types from
`lightway_core`.

To add a connection, call `ConnectionManager::create_connection`. Give it
the protocol version of the client, the local address, the outside IO
callback and a builder for the transport. If the transport carries no
version, give `Version::MINIMUM`, as the TCP server does. The manager
calls the builder once with the `TransportArgs` of the new connection.
Thus the builder can move state into the transport, for example a peer
that the server accepted on its own socket.

The manager does not route by peer address. The custom server gives the
outside data of each connection to `Connection::outside_data_received`.

The outside IO callback owns the peer address of its connection. When
the peer moves, the custom server sends to the new address through that
callback and returns it from `OutsideIOSendCallback::peer_addr`. The
expresslane callback does not get the new address.

A custom server also does these steps for each connection:

- If `outside_data_received` returns an error, call
  `Connection::handle_outside_data_error`. If it returns `Break`, stop
  the delivery to that connection.
- When the outside path of a connection closes, call
  `Connection::disconnect`. If not, the connection keeps its inside IP
  until idle eviction.
- The manager can disconnect a connection, for example when the
  connection stays offline for too long. Check `Connection::state`, and
  stop the delivery to a connection that is `Disconnected`.
