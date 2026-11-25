# The TLS session writes records, and the connection sends them

The TLS session does not send on the outside IO. Its I/O callback puts
each record in a queue and always accepts all bytes. After each call to
the session, the connection takes the records and gives them to the
encapsulation, which adds the wire header, runs the outside plugins and
sends the packets.

We chose this because the wire header and the plugins then have one
owner for both directions, and the session ID, the PMTUD probe mode and
the GSO batch stay with the connection that controls them. A transport
other than TLS can plug in under the same contract.

## Consequences

- A blocked datagram is dropped. Before, the TLS library kept it and
  sent it again on the next write. DTLS sends lost handshake records
  again on its own timer.
- A blocked stream keeps its packets in order in the encapsulation. The
  connection writes a new frame only after the encapsulation is free.
- During the triple send of a DTLS client, the outside plugins run on
  each copy, because each copy is a separate record.
- Each record is copied once more than before, into one reused buffer.
