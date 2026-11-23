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
connection sends in a single `Data` frame at the discovered PLPMTU. In `Base`, before anything is
confirmed, it is the base PLPMTU. It is `None` while PMTUD is not running (`Disabled`) and in
`Error`, where even the base did not get through. An application that sends packets outside the
`Connection` (an offloaded data plane) can use it to size its own packets and to clamp TCP MSS,
which is `max_packet_size - 40` for IPv4 (the IP and TCP headers), exactly as the connection
does for the packets it sends itself.

Probes are sent with DF set (`OutsideIOSendCallback::enable_pmtud_probe`):

- If the socket cannot be switched into probe mode, PMTUD stops for the connection, since a probe
  that may be fragmented proves nothing about the path. It is tried again on the next path change.
- A probe the local interface refuses for its size (`EMSGSIZE`) fails that size at once.
- A probe that never leaves the host (an earlier write is pending, or the write blocks) is not
  counted as lost. Its timer sends it again.

Only probes carry DF. It is cleared again (`disable_pmtud_probe`) as soon as a probe is written, so
ordinary traffic goes without it, during discovery and after: a datagram larger than the path is
fragmented on the way instead of dropped where no ICMP "fragmentation needed" comes back. If DF
cannot be cleared, each later send tries again first. The client's UDP socket also clears DF for
ordinary traffic, since the Linux default (`IP_PMTUDISC_WANT`) sets it on every datagram.

In `Error` the base probe is retried once a minute.

The outside path can change under a running connection. The application reports it:

- `Connection::pmtud_path_changed()` when the device moves to another network: the estimate is
  dropped and discovery starts again from the base probe. `Connection::set_outside_io()` does the
  same for a new outside socket.
- `Connection::pmtud_path_lost()` when there is no usable path (e.g. the device is offline):
  discovery stops until the next `pmtud_path_changed()`, even if the outside socket is replaced
  or the connection comes online in the meantime.

At present, PMTU discovery is only enabled on client side. In future, we may enable
it in Server.

