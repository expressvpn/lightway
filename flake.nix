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
            cargo-make
            cargo-nextest
            cargo-outdated
            cargo-fuzz
            rust-analyzer
          ];

          cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          cargoMemberToml = package: builtins.fromTOML (builtins.readFile ./${package}/Cargo.toml);
          msrv = cargoToml.workspace.package.rust-version;

          rustPackage =
            rustVersion: package: features:
            (pkgs.makeRustPlatform {
              cargo = pkgs.rust-bin.stable.${rustVersion}.minimal;
              rustc = pkgs.rust-bin.stable.${rustVersion}.minimal;
            }).buildRustPackage
              {
                inherit ((cargoMemberToml package).package) name version;
                src = ./.;
                cargoLock.lockFile = ./Cargo.lock;
                buildFeatures = features;
                buildInputs = runtimeDeps;
                nativeBuildInputs = buildDeps;
                cargoBuildFlags = "-p ${package}";
                # Enable ARM crypto extensions, overrides the default stdenv.hostPlatform.gcc.arch.
                env.NIX_CFLAGS_COMPILE =
                  with pkgs.stdenv.hostPlatform;
                  lib.optionalString (isAarch && isLinux) "-march=${gcc.arch}+crypto";
                cargoLock.outputHashes = {
                  "wolfssl-3.0.0" = "sha256-kEVY/HLHTGFaIRSdLbVIomewUngUKEc9q11605n3I+Y=";
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
          serverStartScript = pkgs.writeShellScriptBin "server_start" (builtins.readFile ./samples/server_start.sh);
        in
        rec {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.rust-overlay.overlays.default ];
          };

          packages.default = self'.packages.lightway-client;
          devShells.default = self'.devShells.stable;

          packages.lightway-client = rustPackage "latest" "lightway-client" clientFeatures;
          packages.lightway-server = rustPackage "latest" "lightway-server" serverFeatures;
          packages.lightway-client-msrv = rustPackage msrv "lightway-client" clientFeatures;
          packages.lightway-server-msrv = rustPackage msrv "lightway-server" serverFeatures;

          devShells.stable = mkDevShell pkgs.rust-bin.stable.latest.default;
          devShells.nightly = mkDevShell pkgs.rust-bin.nightly.latest.default;
          devShells.msrv = mkDevShell pkgs.rust-bin.stable.${msrv}.default;
          devShells.quick-start = pkgs.mkShell {
            shellHook = ''
              export RUST_SRC_PATH=${pkgs.rustPlatform.rustLibSrc}
            '';
            buildInputs = runtimeDeps;
            nativeBuildInputs = buildDeps ++ devDeps ++ (with pkgs; [ 
              apacheHttpd
              iproute2
              iptables
              jq
              openssl
              yq
            ]) ++ [
              packages.lightway-server
              serverStartScript 
            ];
          };

          formatter = pkgs.nixfmt-rfc-style;
        };
    };
}
