# Policy Routing (Linux)

On Linux, Lightway uses firewall-mark-based policy routing to route VPN traffic.
This eliminates an encapsulation loop race condition that exists in the simpler
host-route approach.

## Background — The Race Condition

Without policy routing, Lightway keeps a `/32` host route for the VPN server in
the main routing table alongside the tunnel's catch-all routes (`0.0.0.0/1` and
`128.0.0.0/1`). The host route is maintained reactively by watching netlink
notifications.

During a Wi-Fi roam, the kernel removes the old default route **before** the new
one appears. In that window the server's `/32` also disappears. An outbound VPN
packet then matches the tunnel catch-all, gets re-encrypted, is read back off the
TUN device, re-encrypted again, and so on — an encapsulation loop that persists
until the new default route arrives.

## Solution — fwmark Policy Routing

The tunnel routes move out of the main table into a private routing table. The
outside UDP socket is stamped with a firewall mark (`SO_MARK=0x65436800`, Helium's
atomic symbol "He" encoded as a LE u32 — an uncommon value chosen to avoid clashes). Four `ip rule` entries then
steer packets by mark:

```
Rule MARKED          (default priority 100):  fwmark <MARK>      lookup main     # tunnel socket → WAN
Rule SERVER          (default priority 105):  to <SERVER_IP>/32  lookup main     # rp_filter fix
Rule MARKED_FALLBACK (default priority 107):  fwmark <MARK>      unreachable     # loop-breaker (roam guard)
Rule TUNNEL          (default priority 110):  (no condition)     lookup <TABLE>  # all other traffic → tunnel
```

The kernel manages the main table's default route on its own. Lightway no longer
needs a reactive server host route, and the race window is gone.

## The 4 Rules Explained

### Rule MARKED — Tunnel socket → WAN

```
ip rule add fwmark 0x65436800 lookup main priority 100
```

The outside UDP socket carries `SO_MARK=0x65436800` (set once at socket creation,
[`src/io/outside/udp.rs`](../lightway-client/src/io/outside/udp.rs)).
Every packet from that socket matches this rule and resolves through the main
table, which holds the kernel-managed WAN default route. No Lightway-owned server
route is needed.

### Rule SERVER — rp_filter fix

```
ip rule add to <SERVER_IP>/32 lookup main priority 105
```

Linux's strict reverse-path filter (`rp_filter=1`) validates incoming packets by
asking: *"If I were to send a packet to this source IP (with the incoming packet's
mark, which is 0), which interface would I use?"* After `Rule TUNNEL` is
installed, an unmarked lookup for the server IP falls to `Rule TUNNEL` →
tunnel table → `0.0.0.0/1 via lightway`. The rp_filter then sees the server's
reply arriving on `wlan0` but the route saying `lightway`, which is a mismatch —
the packet is silently dropped.

`Rule SERVER` intercepts that unmarked lookup and redirects it to main,
where the WAN default route resolves via the physical interface. The rp_filter sees
a consistent interface and accepts the packet.

This rule is **never hit by regular outbound traffic** — it only fires when the
kernel performs the internal rp_filter route lookup on an incoming server packet.

### Rule MARKED_FALLBACK — Loop-breaker (roam guard)

```
ip rule add fwmark 0x65436800 unreachable priority 107
```

`ip rule` falls through to the next rule when a table returns no matching route.
During a Wi-Fi roam the kernel briefly removes the old default route from main.
Marked packets find no route at `Rule MARKED`, skip
`Rule SERVER` (destination is not `SERVER_IP`), and without
`Rule MARKED_FALLBACK` would reach `Rule TUNNEL` — the tunnel
table — causing re-encapsulation.

`Rule MARKED_FALLBACK` catches them with a second fwmark match and
returns `ENETUNREACH`. The outside I/O send handler treats this as a transient
failure ([`src/io/outside/udp.rs`](../lightway-client/src/io/outside/udp.rs)) and
drops the packet cleanly instead of looping.

During normal operation `Rule MARKED_FALLBACK` is never reached —
marked packets always exit at `Rule MARKED`.

### Rule TUNNEL — VPN data → tunnel table

```
ip rule add lookup <TABLE> priority 110
```

Unmarked packets (decrypted VPN data from userspace) fall through
`Rule MARKED`, `Rule SERVER`, and `Rule MARKED_FALLBACK`
and hit this unconditional catch-all. They resolve through the private tunnel
table, which holds `0.0.0.0/1` and `128.0.0.0/1` via the TUN device, plus the
DNS route.

## Packet Lifetime — ping to 8.8.8.8

The following traces a single ICMP Echo Request from a local application through
the VPN and back.

### Outbound (application → 8.8.8.8)

```
1. APPLICATION (ICMP Echo Request)  src=10.x.x.x  dst=8.8.8.8  mark=0
   └─ kernel evaluates ip rules:
      Rule MARKED (100):          fwmark==0x65436800? NO  → skip
      Rule SERVER (105):          dst==server_ip? NO  → skip
      Rule MARKED_FALLBACK (107): fwmark==0x65436800? NO  → skip
      Rule TUNNEL (110):          catch-all → lookup tunnel table
                                           0.0.0.0/1 matches → route via lightway (TUN device)

2. TUN DEVICE receives packet  src=10.x.x.x  dst=8.8.8.8  mark=0
   └─ inside_io_task: inside_io.recv_buf(&mut buf)  [lib.rs:657]

3. IP SOURCE REWRITE  src=100.64.0.5  dst=8.8.8.8  mark=0
   └─ ipv4_update_source(buf, ip_config.client_ip)  [lib.rs:672]
      src 10.x.x.x → 100.64.0.5 (server-assigned client IP)

4. ENCRYPTION  src=100.64.0.5  dst=8.8.8.8  mark=0  →  DTLS record
   └─ conn.inside_data_received(&mut buf)  [lib.rs:683]
      lightway_core wraps plaintext into encrypted DTLS record

5. OUTSIDE UDP SOCKET sends  src=client_wan_ip  dst=server_ip  mark=0x65436800
   └─ Udp::send(encrypted_buf)  [udp.rs:199]
      SO_MARK=0x65436800 stamped by kernel on every packet from this socket  [udp.rs:50]
      kernel evaluates ip rules:
      Rule MARKED (100): fwmark==0x65436800? YES → lookup main → WAN default → out via wlan0

6. NIC (wlan0) emits packet  src=client_wan_ip  dst=server_ip  mark=0x65436800
   └─ encrypted UDP travels over internet to VPN server
      (VPN server decrypts, SNATs, forwards to 8.8.8.8; 8.8.8.8 replies to server)
```

### Inbound (8.8.8.8 → application)

```
7. NIC (wlan0) receives encrypted UDP  src=server_ip  dst=client_wan_ip  mark=0
   └─ kernel rp_filter check (mark=0): "how would I reach server_ip?"
      Rule MARKED (100):  fwmark==0x65436800? NO  → skip
      Rule SERVER (105):  dst==server_ip? YES → lookup main → WAN default → wlan0
      rp_filter: arrived on wlan0, route says wlan0 → MATCH → packet accepted ✓

8. OUTSIDE IO TASK reads encrypted packet  src=server_ip  dst=client_wan_ip  mark=0
   └─ outside_io.recv_buf(&mut bufs[0])  [lib.rs:612]

9. DECRYPTION  src=8.8.8.8  dst=100.64.0.5  mark=0
   └─ conn.multiple_outside_data_received(pkts)  [lib.rs:622]
      lightway_core decrypts DTLS record back to plaintext ICMP reply
      calls InsideIOSendCallback::send() → Tun::send()  [tun.rs:90]

10. IP DESTINATION REWRITE  src=8.8.8.8  dst=10.x.x.x  mark=0
    └─ ipv4_update_destination(buf, self.ip)  [tun.rs:61]
       dst 100.64.0.5 → 10.x.x.x (tun_local_ip)

11. TUN DEVICE delivers packet  src=8.8.8.8  dst=10.x.x.x  mark=0
    └─ tun.try_send(buf)  [tun.rs:73]
       kernel delivers ICMP Echo Reply to application socket ✓
```

### Which rules each packet hits

| Packet | `Rule MARKED` | `Rule SERVER` | `Rule MARKED_FALLBACK` | `Rule TUNNEL` |
|---|---|---|---|---|
| Outbound app traffic (mark=0) | skip | skip | skip | **HIT** → tunnel table |
| rp_filter check for server_ip (mark=0) | skip | **HIT** → main | — | — |
| Encrypted packet leaving client (mark=0x65436800) | **HIT** → WAN | — | — | — |
| Marked packet during roam (mark=0x65436800, no default route) | fall through | skip | **HIT** → ENETUNREACH | — |

## RouteMode

`RouteMode` is defined in [`src/route_manager.rs`](../lightway-client/src/route_manager.rs)
and controls how routes are installed. On Linux the default is `Fwmark`; all other
platforms default to `Default`.

| Mode | Server route | Tunnel routes in | Policy rules | Linux default |
|---|---|---|---|---|
| `Fwmark` | None — rules handle it | tunnel table | `Rule MARKED`, `Rule SERVER`, `Rule MARKED_FALLBACK`, `Rule TUNNEL` | ✓ |
| `Default` | /32 in main, reactively managed | main table | None | |
| `Lan` | /32 in main, reactively managed | main table + RFC 1918 + link-local | None | |
| `NoExec` | None | None installed | None | |

`Fwmark` is Linux-only (`#[cfg(linux)]`). It skips the server `/32` entirely;
`Rule MARKED` replaces it without the race window.

## Configuration

All parameters are in `FWMarkConfig`
([`src/policy_routing.rs`](../lightway-client/src/policy_routing.rs)) and are
user-configurable. Validation enforces the strict ordering:
`Rule MARKED < Rule SERVER < Rule TUNNEL` and `Rule MARKED_FALLBACK < Rule TUNNEL`.

| Field | Default | Constraint | Notes |
|---|---|---|---|
| `fwmark` | `1698916352` (`0x65436800`) | u32 | Helium's atomic symbol "He" encoded as a LE u32 — uncommon value avoids clashes |
| `fwmark_route_table` | `2` | 1–252 | Avoids reserved IDs: 253 (default), 254 (main), 255 (local) |
| `rule_priority_marked` | `100` | < `rule_priority_marked_fallback` | Tunnel socket → main; must precede the loop-breaker |
| `rule_priority_server` | `105` | < `rule_priority_tunnel` | rp_filter fix; must precede `Rule TUNNEL` |
| `rule_priority_marked_fallback` | `107` | < `rule_priority_tunnel` | Loop-breaker; must precede `Rule TUNNEL` |
| `rule_priority_tunnel` | `110` | > `rule_priority_marked` and `rule_priority_marked_fallback` | Catch-all; must be the last Lightway-owned rule |

The routing table is registered in `/etc/iproute2/rt_tables` as `lightway-tunnel`
so that `ip rule show` displays a human-readable name instead of a bare table ID.

## Key Source Files

| File | Role |
|---|---|
| [`lightway-client/src/policy_routing.rs`](../lightway-client/src/policy_routing.rs) | Installs/removes the 4 ip rules via netlink; manages rt_tables registration |
| [`lightway-client/src/route_manager.rs`](../lightway-client/src/route_manager.rs) | `RouteMode` enum; Fwmark routes go into the tunnel table instead of main |
| [`lightway-client/src/config.rs`](../lightway-client/src/config.rs) | `FWMarkConfig` builder and validation |
| [`lightway-client/src/lib.rs`](../lightway-client/src/lib.rs) | Wires it together: rules installed before routes, cleaned up after |
| [`lightway-client/src/io/outside/udp.rs`](../lightway-client/src/io/outside/udp.rs) | Applies `SO_MARK` to the outside socket and verifies it was accepted |

### Initialization order

Rules must be installed before routes, and removed after:

```
1. PolicyRouting::new()       open netlink handle, store server_ip
2. policy_routing.install()   add 4 ip rules  ← MUST be before routes
3. UdpSocket::new(fwmark)     create outside socket + SO_MARK + verify read-back
4. RouteManager::new()        configure with tunnel table ID
5. route_manager.apply()      install routes into tunnel table

Shutdown (reverse):
route_manager.stop()          remove tunnel routes
policy_routing.cleanup()      remove 4 rules, unregister table name
```
