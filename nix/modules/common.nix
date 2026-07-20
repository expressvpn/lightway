# Common module - shared Rust toolchains and configuration
{
  perSystem =
    { pkgs, ... }:
    let
      cargoToml = builtins.fromTOML (builtins.readFile ../../Cargo.toml);
      msrv = cargoToml.workspace.package.rust-version;

      # Pinned stable version, shared with the Earthfile and local dev via rust-toolchain.toml.
      # rust-overlay does not read rust-toolchain.toml itself, so parse the channel and pin explicitly.
      rustToolchain = builtins.fromTOML (builtins.readFile ../../rust-toolchain.toml);
      rustStableVersion = rustToolchain.toolchain.channel;

      # Rust toolchains (shared across all modules)
      rustStable = pkgs.rust-bin.stable.${rustStableVersion};
      rustMsrv = pkgs.rust-bin.stable.${msrv};
      rustNightly = pkgs.rust-bin.nightly.latest;
    in
    {
      # Export via _module.args for use in other modules
      _module.args = {
        inherit rustStable rustMsrv rustNightly;
      };
    };
}
