{
  description = "Lightway flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = ["x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin"];
      perSystem = { config, self', pkgs, lib, system, ... }:
        let
          runtimeDeps = with pkgs; [  ];
          buildDeps = with pkgs; [
            pkg-config rustPlatform.bindgenHook openssl gnumake
            autoconf
            automake
            libtool libevent
            cargo-nextest
            cargo-deny
            cargo-outdated
          ];
          devDeps = with pkgs; [ gdb ];

          cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          cargoMemberToml = package: builtins.fromTOML (builtins.readFile  ./${package}/Cargo.toml);
          msrv = cargoToml.package.rust-version;

          rustPackage = package: features:
            (pkgs.makeRustPlatform {
              cargo = pkgs.rust-bin.stable.latest.minimal;
              rustc = pkgs.rust-bin.stable.latest.minimal;
            }).buildRustPackage {
              inherit ((cargoMemberToml package).package) name version;
              src = ./.;
              cargoLock.lockFile = ./Cargo.lock;
              buildFeatures = features;
              buildInputs = runtimeDeps;
              nativeBuildInputs = buildDeps;
              doCheck = false;
              cargoLock.outputHashes = {
                "wolfssl-3.0.0" = "sha256-mrQZ+zKwj3bMs3EXMU7Pdq8PgCcJejTPx6OhD+x29Bw=";
              };
            };

          mkDevShell = rustc:
            pkgs.mkShell {
              shellHook = ''
                export RUST_SRC_PATH=${pkgs.rustPlatform.rustLibSrc}
              '';
              buildInputs = runtimeDeps;
              nativeBuildInputs = buildDeps ++ devDeps ++ [ rustc ];
            };
        in {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ (import inputs.rust-overlay) ];
          };

          packages.default = self'.packages.lightway-client;
          devShells.default = self'.devShells.stable;

          packages.lightway-client = (rustPackage "lightway-client" "");
          packages.lightway-server = (rustPackage "lightway-server" "");
          packages.lightway-core = (rustPackage "lightway-core" "");

          devShells.stable = (mkDevShell pkgs.rust-bin.stable.latest.default);
          devShells.msrv = (mkDevShell pkgs.rust-bin.stable.${msrv}.default);

          formatter = pkgs.alejandra;
        };
    };
}
