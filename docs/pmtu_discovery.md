# Path MTU Discovery

`Lightway` protocol supports calculating the Path MTU between server and client dynamically.

`Lightway` implements the following RFC to Path MTU calculation:

[`Packetization Layer Path MTU Discovery for Datagram Transports (RFC 8899)`](https://datatracker.ietf.org/doc/html/rfc8899)

Please refer the above RFC for the state machine.

The implementation can be found here: [dplpmtud.rs](../lightway-core/src/connection/dplpmtud.rs)


The following are the things which is notable in Lightway's implementation:

- `Lightway` uses Ping/Pong message with id != 0 as PLPMTU probe message
- `Packetization Layer` defined in the RFC is `Lightway` itself (not including DTLS or lower layers)

After calculating Path MTU, `Lightway` uses it for handling inside packets (from tunnel):

1. Update TCP MSS value in TCP SYN packets based on the PMTU value
1. Fragment UDP packets inside lightway protocol if the size is larger than PMTU,
   which will be reassembled at the other end. Ref: `lightway_core::wire::DataFrag`

The application can observe the outcome of discovery. The connection emits
`Event::PmtudStateChanged(PmtudStatus)` on every state transition and whenever the PLPMTU
estimate changes, and `Connection::pmtud_status()` returns the current `PmtudStatus` (`None`
when PMTUD is not enabled). `PmtudStatus::max_packet_size` is the largest inside packet the
connection sends in a single `Data` frame at the discovered PLPMTU; it is `None` while there is
no estimate (`Disabled`, `Base`, `Error`). An application that sends packets outside the
`Connection` (an offloaded data plane) can use it to size its own packets and to clamp TCP MSS,
which is `max_packet_size - 40` for IPv4 (the IP and TCP headers), exactly as the connection
does for the packets it sends itself.

At present, PMTU discovery is only enabled on client side. In future, we may enable
it in Server.

