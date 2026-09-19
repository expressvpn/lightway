# Checks module - Nix flake checks for CI/CD
{ inputs, ... }:
{
  perSystem =
    {
      config,
      lib,
      pkgs,
      rustStable,
      nativeSuffix,
      ...
    }:
    let
      # Source directory for all checks
      src = ../..;

      # Rust toolchain with rustfmt component
      rust = rustStable.default.override {
        extensions = [ "rustfmt" ];
      };

      # Format check - verifies Rust code formatting
      fmt =
        pkgs.runCommand "lightway-fmt-check"
          {
            nativeBuildInputs = [
              rust
              pkgs.cargo
            ];
            inherit src;
          }
          ''
            cd $src
            cargo fmt --check
            touch $out
          '';

      # The packages no longer run tests: their cargo flags select individual
      # binaries, and scoping the suite to those would silently drop every
      # workspace member outside them. Tests instead run once per system here,
      # over the whole workspace, reusing the package's toolchain and
      # environment but its own workspace-scoped dependency artifacts.
      craneLib = (inputs.crane.mkLib pkgs).overrideToolchain (_: rustStable.minimal);

      workspaceArgs = config.packages."lightway-${nativeSuffix}".craneArgs // {
        pname = "lightway-workspace";
        # uniffi-bindgen is excluded: its uniffi_bindgen dependency resolves
        # askama.toml relative to CARGO_MANIFEST_DIR, and crane's vendor layout
        # makes that relative walk land in a different store path.
        cargoExtraArgs = "--workspace --exclude uniffi-bindgen";
      };

      tests = craneLib.cargoTest (
        workspaceArgs
        // {
          cargoArtifacts = craneLib.buildDepsOnly workspaceArgs;
        }
      );
    in
    {
      checks = {
        inherit fmt tests;
      };
    };
}
