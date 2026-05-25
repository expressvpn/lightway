# General Config


## Current flow with mobile feature

**Desktop client flow (steps 0, 1, 2, 3, 4, 5, 6):**

Starting from default values (0), the config evolves through each step along the bold lines. Meanwhile, ConfigPatch plays a central role along the dot lines, generating patches by deserializing from a file, environment variables, and CLI options — each applied as a layered override in sequence.

**Mobile client flow (steps 0, 1, 2, 6):**

Mobile takes a shorter path, skipping the steps after **2.ConfigContent** in the flow chart. Rather than reading from a file, config content comes from a Dynamic UI. The Dynamic UI itself is driven by a JSON schema file generated at compile time from the same `Config` struct via the CLI client.
This means both desktop and mobile ultimately share the same `Config` source of truth, with the mobile flow being a streamlined subset of the desktop flow.

```mermaid
flowchart TB
    clientFn("client(config)")
    E0@{ shape: paper-tape, label: "SchemaFile" } --> A0
    0 -. "JsonSchema" .-> E0
    0 -. "Serialize" .-> E1

    subgraph "android (foreign)"
      A0@{ shape: manual-input, label: "Dynamic UI"}
    end

    A0 --"mobile"--> 2
    2  --"mobile shortcut" --> 6
    E1@{ shape: paper-tape, label: "ConfigFile" } --"cli"--> 2

    subgraph main.rs or mobile.rs
      1("1: Config::default()") ==> 2
      2("2: ConfigContent") ==> 3
      3("3:Envars(LW_CLIENT_*)") ==> 4
      4("4: CLI Option") ==> 5
      5("5: Special Envars(LW_CLIENT_RUST_LOG)") ==> 6
      6("6: Config (determined)")
    end

    subgraph config.rs
      0@{ shape: braces, label: "0: Config" } == "Default" ==>1
      0 -. "Patch" .-> 0.1
      0.1 -. "Deserialize" .-> 3
      0.1@{ shape: braces, label: "ConfigPatch" } -. "Parser" .-> 4
    end

    0.1 -. "Deserialize" .-> 2
    6 ==> clientFn
```


## Possibilities for all clients from a General Config

As shown, `Config` is the single source of truth for all clients — all user inputs, whether from a UI or a file,
flow through it. JSON schema generation from the CLI is designed to be a general-purpose mechanism for all client tooling.
The major clients are already implemented, so the existing clients do not use JSON schema and do not follow the current design.
When JSON schema support is needed for a new client, the Android implementation serves as a practical reference to follow,
even though the broader approach to consuming JSON schema remains an open question in the [discussion](https://github.com/expressvpn/lightway/pull/411#discussion_r3166422937).

When adding a platform-specific field, a feature gate is required — e.g. `#[cfg(feature = "...")]`
— with the platform intent communicated via `x-cfg` and `format` attributes in the JSON schema.
This makes it easy to tailor the schema on the client side while still being generatable from the CLI.
That said, introducing more feature gates alongside existing target gates risks making the repo harder to follow.
To keep things clean, the practical approach with the least friction is:

1. Feature gates belong on **fields** of the `Config` struct.
2. `cfg` target attributes belong on **functions**.

Following this pattern, the feature gate lives only in `Config` and is handed off to the target gate in the function layer.
A further benefit is that functions sharing the same signature with `#[cfg(target)]` selection at compile time means a Windows developer and an Android developer work in almost the same domain language:

```rust
struct Config {
   #[cfg(feature="windows")]
   #[schemars(extend("x-cfg" = "windows"))]
   win_only_field: usize,
   
   #[cfg(feature="android")]
   #[schemars(extend("x-cfg" = "android"))]
   android_only_field: usize,
   // ...
}

fn main () {
   let config = Config::load();
   client(config)
}

#[cfg(windows)]
fn client(config: Config) {
     let Config {
       win_only_field,
       ..
     } = config;
    if win_only_field > 256 {
       // ...
    }
}

#[cfg(android)]
fn client(config: Config) {
     let Config {
       android_only_field,
       ..
     } = config;
    let tun = Tun::new(android_only_field);
}
```
