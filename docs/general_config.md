# General Config Design Rationale

## Abstract

The config generation is unified on all clients and server. For the server part, it is quite simple as it only supports native builds on top of Linux. For the client side, we need to consider much more in real-world usage, especially generating JSON schema for any platform target from a macOS machine, which is a common working case for a start-up group. This document is not meant to set rules to restrict the development, but to address development pain points ahead of time by providing guides that help you leverage what we currently have.

## Use Cases with Personas

In our previous works, we rolled out different clients in a straightforward way by building the client on top of the target machines; these are the native development cases. When the mobile feature was added to the project and JSON schema was introduced, the scope of use cases became broader than before, including cross-compiling cases and the need for providing a general UI.

This extended the user personas from 1 (native developer only) to 3 (native developer, cross-platform developer, frontend / designer). Providing JSON schema is not a hard requirement when we are building tools ourselves, because we have all kinds of machines we need. However, this is key infrastructure for the Lightway community or external developers; even a small team of developers from different backgrounds can more easily leverage Lightway.

### Current State (Status 0): Only Mobile Clients Support JSON Schema

For now, we remain at `Status 0` — JSON schema generation is only supported for mobile clients, and we are not requiring all clients to adopt it.

- Native developer:
  - Windows: `cargo build`
  - macOS: `cargo build`
- Cross-platform developer:
  - Mobile from desktop: `cargo build --feature=mobile`
- Frontend / Designer:
  - Android schema from Linux: `cargo run -g jsonschema --all-features` (mobile only)
  - All schema from any desktop: **Not supported** (other clients still based on platform gate)

## Current Flow

**Desktop client flow (steps 0, 1, 2, 3, 4, 5, 6):**

Starting from default values (0), the config evolves through each step along the bold lines. Meanwhile, ConfigPatch plays a central role along the dot lines, generating patches by deserializing from a file, environment variables, and CLI options — each applied as a layered override in sequence.

**Mobile client flow (steps 0, 1, 2, 6):**

Mobile takes a shorter path, skipping the steps after **2.ConfigContent** in the flow chart. Rather than reading from a file, config content comes from a Dynamic UI. The Dynamic UI itself is driven by a JSON schema file generated at compile time from the same `Config` struct via the CLI client. This means both desktop and mobile ultimately share the same `Config` source of truth, with the mobile flow being a streamlined subset of the desktop flow.

**Server flow (steps 0, 1, 2, 3, 4, 5, 6):**

The flow is exactly the same as the CLI client, but all parameters use SERVER keywords, e.g.: `LW_CLIENT_*` will be `LW_SERVER_*`.

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

## General Config Design Principles

`Config` is the single source of truth for all clients — all user inputs, whether from a UI or a file, flow through it. JSON schema generation from the CLI is designed to be a general-purpose mechanism for all client tooling. The major clients are already implemented, so the existing clients do not use JSON schema and do not follow the current design. When JSON schema support is needed for a new client, the Android implementation serves as a practical reference to follow, even though the broader approach remains an open question in the [discussion](https://github.com/expressvpn/lightway/pull/411#discussion_r3166422937).

When adding a platform-specific field, a feature gate may be required — e.g. `#[cfg(feature = "...")]` — with the platform intent communicated via `x-cfg` and `format` attributes in the JSON schema. Critically, `#[cfg(target)]` must **not** be applied to fields: if it were, those fields would be absent when generating schema on a non-matching host, making it impossible to fulfill the goal of generating all schema from any desktop. This is what makes it easy to tailor the schema on the client side while still being generatable from the CLI. That said, introducing more feature gates alongside existing target gates risks making the repo harder to follow. To keep things clean, the practical approach with the least friction is:

1. Feature gates (if used) belong on **fields** of the `Config` struct — never with a target gate.
2. `cfg` target attributes belong on **functions**.

Following this pattern, the feature gate lives only in `Config` and is handed off to the target gate in the function layer. A further benefit is that functions sharing the same signature with `#[cfg(target)]` selection at compile time means a Windows developer and an Android developer work in almost the same domain language:

```rust
struct Config {
   #[cfg(feature="windows")] // optional
   #[schemars(extend("x-cfg" = "windows"))]
   win_only_field: usize,

   #[cfg(feature="android")] // optional
   #[schemars(extend("x-cfg" = "android"))]
   android_only_field: usize,
   // ...
}

fn main() {
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

## Future Plans

Both options below share a common goal: enabling developers, frontend engineers, and designers to generate and tailor the config or schema from any working branch without needing a specific target machine.

### Option 1: Align All Clients with Feature Gates in Config

- Native developer:
  - Windows: `cargo build --feature=windows`
  - macOS: `cargo build --feature=macos`
- Cross-platform developer:
  - Mobile from desktop: `cargo build --feature=mobile`
- Frontend / Designer:
  - All schema from any desktop: `cargo run -g jsonschema --all-features`

There are no extra fields compiled in for any use case — every field is exactly what the target needs. However, specifying both a feature and a target flag can be verbose. Since we already use Makefile to wrap build commands, this verbosity is easily managed there without affecting day-to-day usage. The design principle noted above (feature gates on fields, `cfg` targets on functions) applies specifically to this option.

### Option 2: Keep All Extra Fields in Config without Feature or Target Gates

- Native developer:
  - Windows: `cargo build`
  - macOS: `cargo build`
- Cross-platform developer:
  - Mobile from desktop: `cargo build --feature=mobile`
- Frontend / Designer:
  - All schema from any desktop: `cargo run -g jsonschema`

This approach always compiles extra fields into the config regardless of the target, and is syntactically inconsistent with the cross-build cases. It may appear simpler because native builds require no feature flag, but since we invoke builds through Makefile rather than calling `cargo build` directly, that surface simplicity does not translate into a real workflow benefit.
