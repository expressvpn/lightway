# General Config Design Rationale

## Introduction

The config generation is unified across all clients and the server. For the server, the scope is simple — it only supports native builds on Linux. For the client side, real-world usage is considerably broader, particularly when generating JSON schema for any platform target from a macOS machine, which is a common working scenario for a small team.

This document is not meant to impose restrictions on development. Instead, it addresses development pain points ahead of time by providing guides that help you leverage what is currently available.

---

## Methods

### Config as Single Source of Truth

`Config` is the single source of truth for all clients — all user inputs, whether from a UI or a file, flow through it. JSON schema generation from the CLI is designed to be a general-purpose mechanism for all client tooling.

`Config` derives both `ConfigPatch` and `JsonSchema`, which enables the layered override flow described below.

### Config Flow

**Desktop client flow (steps 0–6):**

Starting from default values (0), the config evolves through each step along the bold lines. `ConfigPatch` plays a central role along the dot lines, generating patches by deserializing from a file, environment variables, and CLI options — each applied as a layered override in sequence.

**Mobile client flow (steps 0, 1, 2, 6):**

Mobile takes a shorter path, skipping the intermediate steps after `2.ConfigContent`. Rather than reading from a file, config content comes from a Dynamic UI driven by a JSON schema file generated at compile time from the same `Config` struct via the CLI client. Both desktop and mobile ultimately share the same `Config` source of truth, with the mobile flow being a streamlined subset.

**Server flow (steps 0–6):**

Identical to the CLI client flow, but all parameters use `SERVER` keywords — e.g. `LW_CLIENT_*` becomes `LW_SERVER_*`.

```mermaid
flowchart TB
    clientFn("client(ClientConfig,...)")
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
    6 == "Config Lifecycle Methods" ==> clientFn
```

### Design Principles

When adding a platform-specific(possible platfom gate or cross compiling feature gate) field, platform intent is communicated via `x-cfg` and `format` attributes in the JSON schema. Critically, `#[cfg(target)]` must **not** be applied to fields: if it were, those fields would be absent when generating schema on a non-matching host, making it impossible to generate all schemas from any desktop machine.

To keep things clean, the practical approach with the least friction is:

1. Config fields carry **no** `#[cfg]` attributes — all fields compile on every target.
2. `cfg` target attributes belong on **functions**.

Because all fields compile on every target but only the matching platform's function consumes them, clippy will report unused-field warnings on the other targets. `#[allow(dead_code)]` on the `Config` struct suppresses these. Following this pattern, platform intent lives only in the schema annotations on `Config` fields and is enforced at runtime by the target-gated function layer. A further benefit is that functions sharing the same signature with `#[cfg(target)]` selection at compile time means a Windows developer and an Android developer work in almost the same domain language:

```rust
#[allow(dead_code)]
struct Config {
  #[schemars(extend("x-cfg" = "windows"))]
  win_only_field: usize,

  #[schemars(extend("x-cfg" = "macos"))]
  macos_only_field: usize,

  #[schemars(extend("x-cfg" = "mobile"))]
  mobile_only_field: usize,
  // ...
}

fn main() {
   let config = Config::load();
   client(config)
}

#[cfg(all(windows, not(feature = "mobile")))]
fn client(config: Config) {
    let Config { win_only_field, .. } = config;
    if win_only_field > 256 {
      // ...
    }
}

#[cfg(all(macosx, not(feature = "mobile")))]
fn client(config: Config) {
    let Config { macos_only_field, .. } = config;
    let tun = Tun::new(macos_only_field);
}

#[cfg(feature = "mobile")]
fn client(config: Config) {
    let Config { mobile_only_field, .. } = config;
    let tun = Tun::new(mobile_only_field);
}
```

One subtlety to be aware of: `mobile` is a **feature gate for cross-compilation**, not a platform gate. It is not mutually exclusive with platform targets — a Linux machine cross-compiling for Android still satisfies `#[cfg(linux)]`. Where a function must run only on native Linux desktop and be excluded from mobile cross-compilation builds, the correct predicate is:

```rust
#[cfg(all(linux, not(feature = "mobile")))]
fn client(config: Config) {
    // native Linux desktop only
}
```

or, if the intent is to cover all non-mobile desktop targets:

```rust
#[cfg(all(desktop, not(feature = "mobile")))]
fn client(config: Config) {
    // all desktop platforms, excluding mobile cross-compilation
}
```

This distinction matters only at the function layer; `Config` fields remain unconditionally compiled in either case.

### Config Lifecycle Methods

After the config is fully determined (step 6), three methods bridge it into the client runtime. `validate()` and `take_servers()` are methods on `Config`; `try_from_reload_sig_and_config()` is a constructor on `ClientConfig`.

Typical call site order in `main.rs`:

```rust
config.validate()?;                             // fail fast before logging or other setup
let servers = config.take_servers()?;           // normalize servers, transfer ownership
let client_config = ClientConfig::<()>::try_from_reload_sig_and_config(
    config_reload_signal,
    config,
)?;
// servers and client_config are then used independently
```

#### `validate()`

Checks the fully determined `Config` for conflicts and invalid values (mismatched socket-buffer or PMTUD settings on TCP, invalid Windows TUN parameters). Called independently in `main.rs` as the first step after config is determined, so validation fails fast before any further setup (logging, server normalization, runtime construction).

#### `take_servers()`

Must be called **before** constructing `ClientConfig`. It normalizes the config's flexible server representation — promoting single-server top-level fields, resolving CA certificates, and propagating auth credentials — and transfers ownership of the resulting `Vec<ConnectionConfig>` out of `Config`. All downstream consumers work against a uniform server list regardless of how the original config was expressed.

#### `try_from_reload_sig_and_config()`

The canonical constructor for `ClientConfig`. It consumes `config` (after `validate()` and `take_servers()` have been called), builds `TunConfig`, and wires up the optional `config_reload_signal` for hot-reload support.

---

## Results

### Current State (Status 0): Mobile Only

JSON schema generation is currently only supported for mobile clients. Existing clients do not use JSON schema and do not yet follow this design. When JSON schema support is needed for a new client, the Android implementation serves as a practical reference.

| Persona                  | Use Case                    | Command                                     |
|--------------------------|-----------------------------|---------------------------------------------|
| Native developer         | Windows build               | `cargo build`                               |
| Native developer         | macOS build                 | `cargo build`                               |
| Native developer         | Linux build                 | `cargo build`                               |
| Cross-platform developer | Mobile from desktop         | `cargo build --feature=mobile`              |
| Frontend / Designer      | Android schema from Linux   | `cargo run -g jsonschema --features=mobile` |
| Frontend / Designer      | All schema from any desktop | **Not yet supported**                       |

### Extended Personas

Previous clients were built in a straightforward native way. Introducing the mobile feature and JSON schema expanded the scope of use cases beyond native development, extending the user personas from 1 to 3:

- **Native developer** — builds on the target machine directly.
- **Cross-platform developer** — cross-compiles for a different target from their own machine.
- **Frontend / Designer** — generates JSON schema to build and design a dynamic UI, without needing a target-specific machine.

This broader scope is key infrastructure not just for internal use, but for the wider Lightway community and external developers.

---

## Discussion

### Future Plans

The goal is to enable developers, frontend engineers, and designers to generate and tailor the config or schema from any working branch without needing a specific target machine. All extra fields are kept in `Config` without feature or target gates:

| Persona                  | Use Case                    | Command                                       |
|--------------------------|-----------------------------|-----------------------------------------------|
| Native developer         | Windows build               | `cargo build`                                 |
| Native developer         | macOS build                 | `cargo build`                                 |
| Native developer         | Linux build                 | `cargo build`                                 |
| Cross-platform developer | Mobile from desktop         | `cargo build --feature=mobile`                |
| Frontend / Designer      | Android schema from Linux   | `cargo run -g jsonschema` (filter with x-cfg) |
| Frontend / Designer      | All schema from any desktop | `cargo run -g jsonschema`                     |

All fields are always compiled into `Config` regardless of the target. This keeps `Config` as a uniform type across all platforms, makes schema generation a single command with no flags, and removes the need for feature-flag management across the build matrix. Platform-specific intent is communicated entirely through schema annotations (`x-cfg`, `format`), while runtime behavior is enforced by target-gated functions. The design principles above — no `#[cfg]` on fields, `cfg` targets on functions — follow directly from this approach.

### Other Possibilities

#### Align All Clients with Feature Gates in Config

| Persona                  | Use Case                    | Command                                  |
|--------------------------|-----------------------------|------------------------------------------|
| Native developer         | Windows build               | `cargo build --feature=windows`          |
| Native developer         | macOS build                 | `cargo build --feature=macos`            |
| Native developer         | Linux build                 | `cargo build --feature=linux`            |
| Cross-platform developer | Mobile from desktop         | `cargo build --feature=mobile`           |
| Frontend / Designer      | All schema from any desktop | `cargo run -g jsonschema --all-features` |

No extra fields are compiled in for any use case — every field is exactly what the target needs. However, every build must explicitly specify a feature flag, and the `Config` type differs across targets, which adds friction when reasoning about cross-platform behaviour. While builds are wrapped in `Makefile.toml`, the added feature-flag surface still grows with each new client platform. See the [prior discussion](https://github.com/expressvpn/lightway/pull/411#discussion_r3166422937) for context.
