# Cross-compilation module - all cross-compilation targets
{
  perSystem =
    {
      lib,
      pkgs,
      system,
      rustLatest,
      ...
    }:
    let
      # Map system to its native architecture (only for Linux)
      # On Darwin, everything is cross-compilation
      nativeArch =
        if lib.hasSuffix "linux" system then
          {
            "x86_64-linux" = "x86_64";
            "aarch64-linux" = "aarch64";
          }
          .${system} or null
        else
          null;

      # Cross-compilation target configurations
      # Includes both true cross-compilation and musl static builds
      allTargets = {
        x86_64-linux-gnu = {
          pkgsCross = pkgs.pkgsCross.gnu64;
          rustTarget = "x86_64-unknown-linux-gnu";
          isStatic = false;
          arch = "x86_64";
          libc = "gnu";
        };
        x86_64-linux-musl = {
          pkgsCross = pkgs.pkgsCross.musl64;
          rustTarget = "x86_64-unknown-linux-musl";
          isStatic = true;
          arch = "x86_64";
          libc = "musl";
        };
        aarch64-linux-musl = {
          pkgsCross = pkgs.pkgsCross.aarch64-multiplatform-musl;
          rustTarget = "aarch64-unknown-linux-musl";
          isStatic = true;
          arch = "aarch64";
          libc = "musl";
        };
        aarch64-linux-gnu = {
          pkgsCross = pkgs.pkgsCross.aarch64-multiplatform;
          rustTarget = "aarch64-unknown-linux-gnu";
          isStatic = false;
          arch = "aarch64";
          libc = "gnu";
        };
      };

      # Filter out gnu targets for native architecture (already built in native.nix)
      # Keep all musl targets (including native arch) since they're static builds
      # On Darwin, include all targets as everything is cross-compilation
      crossTargets = lib.filterAttrs (
        name: config:
        nativeArch == null # Darwin: include everything
        || config.libc == "musl" # Linux: include all musl
        || config.arch != nativeArch # Linux: include cross-arch gnu
      ) allTargets;

      # Helper: Create cross-compilation toolchain
      mkCrossToolchain =
        targetName: config:
        let
          rust = rustLatest.minimal.override { targets = [ config.rustTarget ]; };
        in
        {
          inherit (config) pkgsCross rustTarget isStatic;
          inherit rust;
          rustPlatform = config.pkgsCross.makeRustPlatform {
            cargo = rust;
            rustc = rust;
          };
        };

      # Helper: Build package for a target
      mkPackage =
        package: toolchain:
        toolchain.pkgsCross.callPackage ../. {
          inherit package;
          rustPlatform = toolchain.rustPlatform;
          isStatic = toolchain.isStatic;
          # Don't pass platformSuffix - rustPlatform adds target triple automatically for cross-compilation
        };

      # Helper: Create both client and server for a target
      mkTargetPackages =
        targetName: config: toolchain:
        {
          "lightway-client-${targetName}" = mkPackage "lightway-client" toolchain;
          "lightway-server-${targetName}" = mkPackage "lightway-server" toolchain;
        };

      # All cross-compilation toolchains
      crossToolchains = lib.mapAttrs mkCrossToolchain crossTargets;

      # Generate all packages (includes native musl and cross-compilation)
      crossPackages = lib.foldl' lib.mergeAttrs { } (
        lib.mapAttrsToList (
          name: toolchain: mkTargetPackages name crossTargets.${name} toolchain
        ) crossToolchains
      );

      # Native musl configuration for devShell (if on native arch)
      nativeMuslConfig =
        if nativeArch != null then
          {
            "x86_64" = crossTargets.x86_64-linux-musl or null;
            "aarch64" = crossTargets.aarch64-linux-musl or null;
          }
          .${nativeArch} or null
        else
          null;

      nativeMuslToolchain =
        if nativeMuslConfig != null then
          crossToolchains.${
            if nativeArch == "x86_64" then "x86_64-linux-musl" else "aarch64-linux-musl"
          }
        else
          null;
    in
    {
      packages = crossPackages;

      devShells = lib.optionalAttrs (nativeMuslToolchain != null) {
        musl = nativeMuslToolchain.pkgsCross.callPackage ../shell.nix {
          rustc = nativeMuslToolchain.rust.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ];
          };
          isStatic = true;
          defaultTarget = nativeMuslToolchain.rustTarget;
        };
      };
    };
}
