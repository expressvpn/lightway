{
  description = "Lightway flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      perSystem =
        {
          config,
          self',
          pkgs,
          lib,
          system,
          ...
        }:
        let
          cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          msrv = cargoToml.workspace.package.rust-version;

          # Rust toolchains
          rustLatest = pkgs.rust-bin.stable.latest;
          rustMsrv = pkgs.rust-bin.stable.${msrv};
          rustNightly = pkgs.rust-bin.nightly.latest;

          # Rust platforms for different variants
          rustPlatformLatest = pkgs.makeRustPlatform {
            cargo = rustLatest.minimal;
            rustc = rustLatest.minimal;
          };
          rustPlatformMsrv = pkgs.makeRustPlatform {
            cargo = rustMsrv.minimal;
            rustc = rustMsrv.minimal;
          };

          # Musl static builds (architecture-aware cross-compilation)
          # Uses pkgsCross to avoid rebuilding entire toolchain
          # Only supported on Linux systems
          muslConfig = {
            "x86_64-linux" = {
              pkgs = pkgs.pkgsCross.musl64;
              target = "x86_64-unknown-linux-musl";
            };
            "aarch64-linux" = {
              pkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
              target = "aarch64-unknown-linux-musl";
            };
          }.${system} or null;
          muslPkgs = if muslConfig != null then muslConfig.pkgs else null;
          muslTarget = if muslConfig != null then muslConfig.target else null;
          rustLatestMusl = rustLatest.minimal.override {
            targets = lib.optional (muslTarget != null) muslTarget;
          };
          rustPlatformMusl =
            if muslPkgs != null then
              muslPkgs.makeRustPlatform {
                cargo = rustLatestMusl;
                rustc = rustLatestMusl;
              }
            else
              null;
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.rust-overlay.overlays.default ];
          };

          packages =
            {
              default = self'.packages.lightway-client;

              # Regular builds with latest rust
              lightway-client = pkgs.callPackage ./nix {
                rustPlatform = rustPlatformLatest;
              };
              lightway-server = pkgs.callPackage ./nix {
                package = "lightway-server";
                rustPlatform = rustPlatformLatest;
              };

              # MSRV builds
              lightway-client-msrv = pkgs.callPackage ./nix {
                rustPlatform = rustPlatformMsrv;
              };
              lightway-server-msrv = pkgs.callPackage ./nix {
                package = "lightway-server";
                rustPlatform = rustPlatformMsrv;
              };
            }
            // lib.optionalAttrs pkgs.stdenv.isLinux {
              # Musl static builds (Linux only)
              lightway-client-musl = muslPkgs.callPackage ./nix {
                rustPlatform = rustPlatformMusl;
                isStatic = true;
              };
              lightway-server-musl = muslPkgs.callPackage ./nix {
                package = "lightway-server";
                rustPlatform = rustPlatformMusl;
                isStatic = true;
              };
            };

          devShells =
            {
              default = self'.devShells.stable;

              stable = pkgs.callPackage ./nix/shell.nix {
                rustc = rustLatest.default;
              };
              nightly = pkgs.callPackage ./nix/shell.nix {
                rustc = rustNightly.default;
              };
              msrv = pkgs.callPackage ./nix/shell.nix {
                rustc = rustMsrv.default;
              };
            }
            // lib.optionalAttrs pkgs.stdenv.isLinux {
              musl = muslPkgs.callPackage ./nix/shell.nix {
                rustc = rustLatestMusl.override {
                  extensions = [
                    "rust-src"
                    "rust-analyzer"
                  ];
                };
                isStatic = true;
                defaultTarget = muslTarget;
              };
            };

          formatter = pkgs.nixfmt-rfc-style;
        };
    };
}
