# Connection Setting 

Multiple VPN connections are supported via the `servers` field (`Vec<ConnectionConfig>`). At the same time, Config is designed to work equally well with a single server connection in a straightforward and energy-efficient way — as is the case with the current android client implementation.
It is also common to share the same auth across multiple connections within a group of servers. The top-level fields in Config outside of servers are sufficient to set up a single connection, but this introduces complexity when the code needs to handle both single and multiple connection cases.
To address this, `Config` provides three helper methods that abstract over the `servers` field:

- `.len()` and `.is_empty()` — simple helpers to inspect how many servers are configured.
- `.take_servers()` — extracts the servers from the config, normalizing by promoting the top-level connection config into a single entry in servers if needed, and filling in any missing auth or certificate information in the process.

This makes it possible to specify a single auth or certificate at the top level and have it applied across all connections automatically.
The network initialization flow remains clean and consistent across clients, as illustrated in the following pseudo code. Note that the actual implementation differs due to asynchronous execution.
```rust
#[cfg(platform)]
fn client(mut config: Config) {
  let servers = config.take_servers();
  
  for server in servers.into_iter() {
    connect(server);
  }
}
```
