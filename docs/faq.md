# Frequently Asked Questions

## Why do I need to sign a CLA before contributing to Lightway Core?
The reason we have a CLA is to be upfront and transparent about what happens when someone contributes code to the project. It is important to note that the author maintains ownership of the code at all times and that we will immediately release any contributions under the GPL 2.0 license. This helps to protect the project by ensuring that any code in the repository can be released under the GPL 2.0 license both now and in the future. This is why the Apache Foundation requires a CLA for all contributions—the intent is to protect everyone's interests.

As part of any code contribution, we will list the author's name and what was contributed so that the author will get full recognition for their work.

## Does Lightway client/server applications support IPv6 ?

Lightway apps does not currently provide full IPv6 support on either the client or server.

 - IPv6 traffic handling is incomplete
 - IPv6 firewalling and leak prevention are not handled by Lightway
 - Rate limiting is out of scope for the Lightway client at this time

Full IPv6 support for both the Lightway client and server is planned for a future release.
Until then, Lightway should be considered IPv4-focused, and deployments should be configured accordingly.

## Firewall Configuration

The Lightway client does not configure or manage firewall rules.
If you are using the Lightway client, you are responsible for ensuring that appropriate firewall rules are in place, including (but not limited to):

 - Applying any required rate limiting
 - Blocking or restricting IPv6 traffic
 - Preventing IPv6 traffic from bypassing the tunnel

Without proper firewall configuration, traffic may bypass the tunnel depending on system and network settings.

