# Logging and Metrics

## Logging

Lightway server and client support logging which is useful for both debugging and monitoring.

The logging levels can be configured using the cli argument: `log-level`

Example usage:
```bash
./lightway-server --config ./server.yaml --log-level info
```

In addition to that, lightway server also supports emitting logs in different formats like
`json`, `compact` and `pretty` and can be configured using `log-format` cli argument.

Example usage:
```bash
./lightway-server --config ./server.yaml --log-format json
```

## Metrics

Lightway server also supports metrics to monitor. The following are the metrics available:


| Metric Name | Source | Metric Type | Definition |
| ------------------------------------------------------------------- | ------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| conn_accept_failed | server | Counter | A new connection could not be accepted |
| connection_accept_proxy_header_failed | server | Counter | A new connection did cnot present a valid PROXY header |
| conn_create_failed | server | Counter | A new connection could not be created |
| conn_alloc_frag_map | core | Counter | A connection has used a fragmented data packet.<br>Therefore the 2M FragmentMap has been allocated |
| wolfssl_appdata | core | Counter | An AppData result occurred during a WolfSSL operation.<br><br>Given current configuration we do not expect this to be non-zero |
| session_id_mismatch | core | Counter | Server has received a mismatched session_id in the header after the packet content has been validated <br><br>Should generally be expected to happen rarely|
| received_encoding_req_non_online | core | Counter | Server received an encoding request when the Connection state is not Online |
| received_encoding_req_with_tcp | core | Counter | Server received an encoding request when the Connection type is TCP |
| received_encoding_res_as_server | core | Counter | Server received an encoding response |
| expresslane_encrypt_no_key | core | Counter | Server tried to send an expresslane packet, but no valid expresslane key to encrypt |
| expresslane_decrypt_no_key | core | Counter | Server received an expresslane packet, but no valid expresslane key to decrypt |
| expresslane_decrypt_failed | core | Counter | Server received an expresslane packet, but it cannot be decrypted by current/prev key |
| conn_created | server | Counter | The number of new connections created |
| conn_link_up | server | Counter | Counts connection which have reached the “link up” state (~(D)TLS connection established) |
| conn_online | server | Counter | Counts connection which have reached the “online” state after successful authentication |
| conn_rejected_no_free_ip | server | Counter | Counts connections which were rejected at auth time due to a lack of free IPs in the server pool<br><br>Should generally be expected to be 0 |
| conn_rejected_access_denied | server | Counter | Counts connections rejected due to invalid auth |
| conn_tls_error | server | Counter | Counts connections which failed due to a TLS failure from WolfSSL |
| conn_unknown_error | server | Counter | Counts connections which failed due to a non-TLS failure from WolfSSL |
| conn_aged_out | server | Counter | Counts connections which are disconnected due to being idle (after 1 day of inactivity) |
| user_auth_eviction | server | Counter | Counts connections which are disconnected due to their auth expiring |
| conn_client_closed | server | Counter | Counts connections which have been closed since client initiate Disconnect |
| conn_stale_closed | server | Counter | Counts connections which have been closed since it has not become ONLINE within STALE_AGE (60s) |
| conn_closed | server | Counter | Counts total connections which have been closed for any reason (including client_closed, stale_closed, etc.) |
| udp_conn_recovered_via_session | server | Counter | Counts UDP connections which have been recovered using the session ID (which indicates that the client’s IP address changed) |
| udp_session_rotation_attempted_via_replay | server | Counter | Counts UDP rotation attempted using duplicated packets. i.e An attack<br>ie. Some adversary capture and replay packets from different IP address.<br><br>There is also a possibility that counter is incremented due to aggressive connect.<br> |
| udp_recv_truncated | server | Counter | Counts occurrences of UDP packet truncation on receive |
| udp_recv_invalid_addr | server | Counter | Counts failures to retrieve a valid socket address from `recvmsg` syscall |
| udp_recv_missing_pktinfo | server | Counter | Counts failures to find a valid `PKTINFO` control message in `recvmsg` result |
| udp_bad_packet_version | server | Counter | Counts UDP packets where the the version in the wire protocol header was not a version supported by the server |
| udp_rejected_session | server | Counter | Counts UDP packets which were rejected due to the session id in the wire protocol header not being recognised |
| udp_parse_wire_failed | server | Counter | Counts UDP packets which could not be parsed. Indicates plugin ingress chain failed |
| udp_no_header | server | Counter | Counts UDP packets where the wire protocol header was not found/could not be found |
| udp_session_rotation_begin | server | Counter | Counts connections which started a session ID rotation |
| udp_session_rotation_finalized | server | Counter | Counts connections which completed a session ID rotation |
| to_link_up_time | server | Histogram | Measures time between a connection being started (on first packet) and the Link Up state (i.e. (D)TLS negotiation complete) |
| to_online_time | server | Histogram | Measures time between a connection being started (on first packet) and the connection being online (i.e. authenticated and passing data packets) |
| tun_rejected_packet_invalid_state | server | Counter | Counts packets received on the TUN device for a connection which is not in the Online state |
| tun_rejected_packet_invalid_inside_packet | server | Counter | Counts packets received on the TUN device which are invalid (e.g. too large, not an IPv4) |
| tun_rejected_packet_invalid_other | server | Counter | Counts packets received on the TUN device which are invalid for an uncategorised reason |
| tun_rejected_packet_no_connection | server | Counter | Counts packets received on the TUN device for which there is no corresponding connection |
| tun_from_client | server | Counter | Counts bytes sent on the TUN interface (i.e. which is data coming from a client) |
| tun_to_client | server | Counter | Counts bytes received on the TUN interface (i.e which is data going to a client) |
| sessions_current_online | server | Gauge | The number of connections which are currently in the Online state |
| sessions_lifetime_total | server | Gauge | The total number of connections which have been created over the entire lifetime of the server |
| sessions_pending_id_rotations | server | Gauge | The number of connections for which a session ID rotation is in progress |
| sessions_active_5m<br>sessions_active_15m<br>sessions_active_60m | server | Gauge | The number of connections which were “active” in most recent N minutes.<br>An “active” connection is one where traffic has been seen from the client to the Internet |
| sessions_standby_5m<br>sessions_standby_15m<br>sessions_standby_60m | server | Gauge | The number of connections which were “on standby” in most recent N minutes.<br>An “on standby” connection is one where traffic has been seen from the Internet to the client |
| sessions_encoding_enabled | server | Gauge | The number of connections which currently have encoding enabled |
| assigned_internal_ips | server | Gauge | The current number of IPs which are allocated to connections |


The actual implementation can be found in:
- [lightway-core/src/metrics.rs](../lightway-core/src/metrics.rs)
- [lightway-server/src/metrics.rs](../lightway-server/src/metrics.rs)
