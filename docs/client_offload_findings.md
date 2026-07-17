# Client TUN offload: field findings (branch `client-tun-offload`)

Date: 2026-07-17. Client: Linux 6.8, wired multi-gig NIC (`enp34s0`),
speedtest via Ookla server 70128 (HK, ~2.9 ms RTT) against a production
server running a kernel offload datapath (no `--enable-tun-offload` on
the lightway-server side).

## What the branch adds

With `--enable-tun-offload` on a UDP connection the client enables, end
to end:

- **Upload (GSO):** TSO superpackets read from the TUN, segmented in
  userspace (SIMD checksums), shipped as `sendmsg(UDP_SEGMENT)` batches
  chunked to the kernel's 64 KiB single-send limit.
- **Download (GRO):** `UDP_GRO` on the outside socket so the kernel
  delivers coalesced datagram trains per `recvmsg`; decrypted TCP
  segments are then re-coalesced per flow (`TcpGroTable`, 8 flows) into
  TSO superpackets written to the TUN with a live `virtio_net_hdr`.

## Measured results

| Metric | Before branch | With offload |
|---|---|---|
| Upload | ~3.6 Gbps | **3.93 Gbps** |
| Download | ~1.6 Gbps | 1.72 Gbps |
| Client `UdpRcvbufErrors` during test | (2.24 M historical) | **0** |

Upload GSO is verified on the wire (pre-segmentation superframes,
`UDP, bad length 4008 > 1336`, visible at the egress tap).

## Why download did not improve: server sends UDP checksum 0

Mid-download wire sample on the client:

```
149.40.55.231.15254 > 10.2.51.17.48204: [no cksum] UDP, length 1406
```

Every inbound data packet carries UDP checksum 0. The kernel refuses to
GRO-coalesce zero-checksum UDP — the first check in
`udp_gro_receive()` (`net/ipv4/udp_offload.c`):

```c
	/* requires non zero csum, for symmetry with GSO */
	if (!uh->check) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}
```

This gate sits ahead of every UDP GRO path (including fraglist GRO), so
no client-side setting can work around it. Confirmed empirically: with
`UDP_GRO` enabled on the socket and `generic-receive-offload: on`,
91,616 packets/s arrived mid-download — uniform 1434-byte frames,
82% spaced 2–5 µs apart (ideal coalescing conditions) — yet the
post-GRO tap saw effectively zero frames above 1500 bytes.

**Fix (server side):** the kernel offload datapath must fill UDP
checksums on transmit. With NIC tx-checksum offload this is effectively
free, and it is what allows every receiver's GRO to engage. (Zero-
checksum UDP is also dropped outright by some middleboxes.) Once the
server fills checksums, the client's socket-GRO → TUN-GRO chain
activates with no further changes.

## Remaining observations

- The client receive path no longer drops: `UdpRcvbufErrors` delta was
  exactly 0 across the test at 91.6 kpps. The current download ceiling
  is upstream (server per-flow pacing or path loss), not the client.
- Ookla reported **61% packet loss** during the offload test run while
  client socket drops were zero — the loss is in the network/server
  direction, most plausibly the loss probes drowning during the
  3.9 Gbps upload phase. `sendmsg(UDP_SEGMENT)` emits up to 48
  back-to-back wire packets per call; TX pacing under congestion is a
  known follow-up from the server GSO work (PR #413) and now applies to
  the client too.
- Historical note for anyone re-running the analysis: a packet tap
  (tcpdump) sees ingress frames *after* the kernel GRO engine and
  egress frames *before* GSO segmentation — so working GRO shows up as
  >MTU inbound frames, and working GSO as >MTU outbound frames with a
  `bad length X > stride` annotation.
