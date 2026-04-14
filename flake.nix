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
            overlays = [ inputs.rust-overlay.overlays.default ];
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
