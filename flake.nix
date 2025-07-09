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
          runtimeDeps = with pkgs; [ ];
          buildDeps = with pkgs; [
            autoconf
            automake
            libtool
            rustPlatform.bindgenHook
          ];
          devDeps = with pkgs; [
            cargo-deny
            cargo-nextest
            cargo-outdated
            rust-analyzer
          ];

          cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          cargoMemberToml = package: builtins.fromTOML (builtins.readFile ./${package}/Cargo.toml);
          msrv = cargoToml.workspace.package.rust-version;

          rustPackage =
            package: features:
            (pkgs.makeRustPlatform {
              cargo = pkgs.rust-bin.stable.latest.minimal;
              rustc = pkgs.rust-bin.stable.latest.minimal;
            }).buildRustPackage
              {
                inherit ((cargoMemberToml package).package) name version;
                src = ./.;
                cargoLock.lockFile = ./Cargo.lock;
                buildFeatures = features;
                buildInputs = runtimeDeps;
                nativeBuildInputs = buildDeps;
                cargoBuildFlags = "-p ${package}";
                # Some tests rely on debug_assert! and fail in release.
                checkType = "debug";
                cargoLock.outputHashes = {
                  "wolfssl-3.0.0" = "sha256-4nCoGOIhiGC7aTDvdXpVNTBzMl4dkNCJxtcuODumW2Q=";
                };
              };

          mkDevShell =
            rustc:
            pkgs.mkShell {
              shellHook = ''
                export RUST_SRC_PATH=${pkgs.rustPlatform.rustLibSrc}
              '';
              buildInputs = runtimeDeps;
              nativeBuildInputs = buildDeps ++ devDeps ++ [ rustc ];
            };
          clientFeatures = [ ] ++ lib.optional pkgs.stdenv.isLinux [ "io-uring" ];
          serverFeatures = [ ] ++ lib.optional pkgs.stdenv.isLinux [ "io-uring" ];
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.rust-overlay.overlays.default ];
          };

          packages.default = self'.packages.lightway-client;
          devShells.default = self'.devShells.stable;

          packages.lightway-client = rustPackage "lightway-client" clientFeatures;
          packages.lightway-server = rustPackage "lightway-server" serverFeatures;

          devShells.stable = mkDevShell pkgs.rust-bin.stable.latest.default;
          devShells.msrv = mkDevShell pkgs.rust-bin.stable.${msrv}.default;

          formatter = pkgs.nixfmt-rfc-style;
        };
    };
}
