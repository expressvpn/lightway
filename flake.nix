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

          # Musl cross-compilation setup
          muslPkgs = pkgs.pkgsCross.musl64;
          rustLatestMusl = rustLatest.minimal.override {
            targets = [ "x86_64-unknown-linux-musl" ];
          };
          rustPlatformMusl = muslPkgs.makeRustPlatform {
            cargo = rustLatestMusl;
            rustc = rustLatestMusl;
          };
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.rust-overlay.overlays.default ];
          };

          packages = {
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

            # Musl static builds
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

          devShells = {
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
            musl = muslPkgs.callPackage ./nix/shell.nix {
              rustc = rustLatestMusl.override {
                extensions = [ "rust-src" "rust-analyzer" ];
              };
              isStatic = true;
            };
          };

          formatter = pkgs.nixfmt-rfc-style;
        };
    };
}
