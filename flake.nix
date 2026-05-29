{
  description = "Lightway flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay.url = "github:oxalica/rust-overlay";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
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

      imports = [
        inputs.treefmt-nix.flakeModule
        ./nix/modules/common.nix
        ./nix/modules/native.nix
        ./nix/modules/cross.nix
        ./nix/modules/devshells.nix
        ./nix/modules/checks.nix
      ];

      perSystem =
        {
          config,
          pkgs,
          system,
          nativeSuffix,
          ...
        }:
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              inputs.rust-overlay.overlays.default
              # Backport NixOS/nixpkgs#524985 (merged 2026-05-27): switch
              # `importCargoLock` to download crates from
              # `https://static.crates.io/crates` instead of the API endpoint
              # `https://crates.io/api/v1/crates/...`, which now returns HTTP 403
              # for `curl/*` User-Agents. See rust-lang/crates.io#13482 and
              # NixOS/nixpkgs#524979. Drop this overlay once `flake.lock` is
              # bumped to a `nixpkgs-unstable` revision containing the upstream
              # fix.
              #
              # Override `makeRustPlatform` (not `rustPlatform.importCargoLock`):
              # nixpkgs' `pkgs/development/compilers/rust/make-rust-platform.nix`
              # constructs a fresh `importCargoLock` from a hardcoded file path
              # via `buildPackages.callPackage`, so the top-level
              # `rustPlatform.importCargoLock` is ignored by both native.nix and
              # cross.nix (which both call `(pkgsCross.)makeRustPlatform`).
              (
                final: prev:
                let
                  patchedImportCargoLockFile = builtins.toFile "import-cargo-lock-static-crates-io.nix" (
                    builtins.replaceStrings [ "https://crates.io/api/v1/crates" ] [ "https://static.crates.io/crates" ]
                      (builtins.readFile (prev.path + "/pkgs/build-support/rust/import-cargo-lock.nix"))
                  );
                in
                {
                  makeRustPlatform =
                    args:
                    (prev.makeRustPlatform args).overrideScope (
                      _: _: {
                        importCargoLock = prev.buildPackages.callPackage patchedImportCargoLockFile {
                          inherit (args) cargo;
                        };
                      }
                    );
                }
              )
            ];
            config.allowUnfree = true;
            config.android_sdk.accept_license = true;
          };

          # Convenience aliases for native packages
          packages = {
            default = config.packages."lightway-client-${nativeSuffix}";
            lightway-client = config.packages."lightway-client-${nativeSuffix}";
            lightway-server = config.packages."lightway-server-${nativeSuffix}";
            lightway-client-msrv = config.packages."lightway-client-${nativeSuffix}-msrv";
            lightway-server-msrv = config.packages."lightway-server-${nativeSuffix}-msrv";
          };

          treefmt = {
            projectRootFile = "flake.nix";
            programs.nixfmt.enable = pkgs.lib.meta.availableOn pkgs.stdenv.buildPlatform pkgs.nixfmt.compiler;
            programs.nixfmt.package = pkgs.nixfmt;
          };
        };
    };
}
