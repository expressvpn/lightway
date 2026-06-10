# Design Overview

## lightway-core

lightway-core is a small, multi-platform, Rust library that encapsulates the
encryption and processing of IP packets.

On its own, lightway-core is not an executable application. Instead, it is a
*purposefully* simple library. Intentionally, lightway-core is opinionated
about how it works and the scope it controls, and very agnostic about
everything else. The core use case of this library is as part of a
high-performance, always-on VPN application, which necessarily entails
deferring items like "how do I actually send UDP packets?" to the host
application, which can use the best API for the platform, be it a Windows
desktop or an iPhone.

## lightway-client

lightway-client is a fully working Lightway client implementation with TCP and UDP support across multiple platforms, including Windows, Linux, macOS, and mobile devices.

All client settings are centralized in a single [Config](/lightway-client/src/config.rs) struct, designed to cover multiple use cases simultaneously, please refer [General Config Design Rationale](/docs/general_config.md)

All clients possible work with mulitple server connections with different auth settings, and it still possible to set one auth for all connection, please refer [Connection Setting.](/docs/connection_setting.md)

## lightway-server

lightway-server is a Linux implementation for a fully working Lightway server with both TCP and UDP support.

All server settings are centralized in a single Config struct, please refer [General Config Design Rationale](/docs/general_config.md)

# Terminology

Some people may prefer to see these terms in context, see [What does it actually do?](#what-does-it-actually-do)

## Inside
Refers to data that will be wrapped or has already been unwrapped by lightway-core. This corresponds to data coming to / from the tun device.
## Outside
Refers to data wrapped by lightway-core. This corresponds to data coming to / from a network socket.
## Context
lightway-core attributes that may be shared across multiple connections
## Connection
lightway-core attributes that reflect a single wrapped data path between a client and server.

# What does it actually do?

At a very high-level, once a connection is established, lightway-core provides a bidirectional pathway for wrapping data in a way that can be securely sent over the internet.

One direction is the "inside path". The host application passes data to lightway-core for wrapping via `Connection.inside_data_received`, and then lightway-core will call the host application's `outside_io.send` one or more times with the appropriately encrypted data, which the host is then responsible for transmitting appropriately. Where "appropriately" normally means "send these packets over the internet, client->server or server->client depending on which side of the connection we are on."

The other direction is the "outside path". The host application passes data wrapped by lightway-core to the appropriate library function `Connection.outside_data_received`; lightway-core will then call the host application's `inside_io.send` one or more times with the appropriately unwrapped data, which the host can then deliver the data into the tun device.

Of course, the devil is in the details, and there are a lot of details here. For an example of how the above works you can see [IP Translation](./ip_translation.md#packet-flow-steps-as-marked-yellow-in-above-picture)
