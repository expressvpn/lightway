# Frequently Asked Questions

## Why do I need to sign a CLA before contributing to Lightway Core?
The reason we have a CLA is to be upfront and transparent about what happens when someone contributes code to the project. It is important to note that the author maintains ownership of the code at all times and that we will immediately release any contributions under the GPL 2.0 license. This helps to protect the project by ensuring that any code in the repository can be released under the GPL 2.0 license both now and in the future. This is why the Apache Foundation requires a CLA for all contributions—the intent is to protect everyone's interests.

As part of any code contribution, we will list the author's name and what was contributed so that the author will get full recognition for their work.

## Which TLS library does Lightway use?

Lightway uses wolfSSL by default, and it remains the main, recommended TLS
backend. BoringSSL is now also supported as an alternative backend, selected
at compile time via cargo features (the two are mutually exclusive). See
[TLS backends](./tls_backends.md) for how to enable each one.

## Does Lightway client/server applications support IPv6 ?

Lightway apps does not currently provide full IPv6 support on either the client or server.
The one supported piece is the outside connection: the encrypted transport between the
client and the server can run over IPv6 as well as IPv4. That is the extent of it.

 - The server can bind to an IPv6 address and the client can connect to one. The client
   uses the first address its configured server name resolves to, so on a dual-stack host
   that may be IPv6; there is no address-family preference setting yet
 - IPv6 traffic is not carried by the tunnel. Any IPv6 packet that still reaches the
   tunnel interface is rejected by lightway-core as an unsupported packet and dropped,
   so none is ever sent to the server
 - On desktop, in route modes `default` and `lan`, the client blocks all IPv6
   traffic, so IPv6 (including DNS queries to IPv6 resolvers) cannot bypass
   the tunnel. On Linux and macOS it adds unreachable routes, so IPv6
   connections fail straight away and applications fall back to IPv4; on
   Windows it routes IPv6 into the tunnel interface, where it is discarded.
   This is controlled by `block_ipv6`, which is on by default; in `lan` mode
   unique local addresses (`fc00::/7`) keep following the existing IPv6
   default route. Link-local and multicast traffic stays on its on-link
   routes. A host with no IPv6 stack has nothing to block and skips these
   routes; on Windows they are also skipped, with a warning, when IPv6 is not
   bound to the tunnel adapter.
 - On Linux hosts managed by systemd-networkd, its default
   `ManageForeignRoutes=yes` makes it remove these unreachable routes when it
   reconfigures a link (for example on `networkctl reload` or a restart of
   systemd-networkd), and the client does not add them back while connected.
   Set `ManageForeignRoutes=no` in the `[Network]` section of
   `networkd.conf` to keep them. NetworkManager leaves them in place.
 - Without `block_ipv6` (or in route mode `noexec`, or on mobile) IPv6
   firewalling and leak prevention are not handled by Lightway
 - Rate limiting is out of scope for the Lightway client at this time

Full IPv6 support for both the Lightway client and server is planned for a future release.
Until then, Lightway should be considered IPv4-focused, and deployments should be configured accordingly.

## Firewall Configuration

The Lightway server/client does not configure or manage firewall rules.
If you are using the Lightway server/client, you are responsible for ensuring that appropriate firewall rules are in place, including (but not limited to):

 - Applying any required rate limiting
 - Blocking or restricting IPv6 traffic
 - Preventing IPv6 traffic from bypassing the tunnel where `block_ipv6` does
   not apply (route mode `noexec`, `block_ipv6: false`, or mobile)

Without proper firewall configuration, traffic may bypass the tunnel depending on system and network settings.

