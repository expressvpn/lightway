# Native builds module - platform-specific native builds
{
  perSystem =
    {
      lib,
      pkgs,
      system,
      rustStable,
      rustMsrv,
      ...
    }:
    let
      # Rust platforms
      rustPlatformStable = pkgs.makeRustPlatform {
        cargo = rustStable.minimal;
        rustc = rustStable.minimal;
      };
      rustPlatformMsrv = pkgs.makeRustPlatform {
        cargo = rustMsrv.minimal;
        rustc = rustMsrv.minimal;
      };

      # Helper: Build package with the default (wolfssl) backend
      mkPackage =
        package: pkgs: rustPlatform:
        pkgs.callPackage ../. {
          inherit package rustPlatform;
          isStatic = false;
          platformSuffix = nativeSuffix;
        };

      # Helper: Build package with the boringssl backend. Drops default
      # features (which include wolfssl) and lets the caller pass the
      # exact feature set — lightway-client opts into `postquantum`
      # explicitly, while lightway-server has no `postquantum` feature
      # (it pins lightway-core's postquantum on via its own Cargo.toml).
      # boring-sys handles BoringSSL's CMake build via the cmake/perl
      # nativeBuildInputs declared in nix/default.nix.
      mkBoringSslPackage =
        package: pkgs: rustPlatform: features:
        pkgs.callPackage ../. {
          inherit package rustPlatform features;
          isStatic = false;
          platformSuffix = "${nativeSuffix}-boringssl";
          noDefaultFeatures = true;
        };

      # Platform-specific package suffix for native builds
      nativeSuffix =
        if system == "x86_64-linux" then
          "x86_64-linux-gnu"
        else if system == "aarch64-linux" then
          "aarch64-linux-gnu"
        else if system == "x86_64-darwin" then
          "x86_64-darwin"
        else if system == "aarch64-darwin" then
          "aarch64-darwin"
        else
          throw "Unsupported system: ${system}";

      # Native packages for all platforms
      nativePackages = {
        # Pinned stable builds
        "lightway-client-${nativeSuffix}" = mkPackage "lightway-client" pkgs rustPlatformStable;
        "lightway-server-${nativeSuffix}" = mkPackage "lightway-server" pkgs rustPlatformStable;

        # MSRV builds (wolfssl backend)
        "lightway-client-${nativeSuffix}-msrv" = mkPackage "lightway-client" pkgs rustPlatformMsrv;
        "lightway-server-${nativeSuffix}-msrv" = mkPackage "lightway-server" pkgs rustPlatformMsrv;

        # BoringSSL backend builds
        "lightway-client-${nativeSuffix}-boringssl" =
          mkBoringSslPackage "lightway-client" pkgs rustPlatformStable
            [
              "boringssl"
              "postquantum"
            ];
        "lightway-server-${nativeSuffix}-boringssl" =
          mkBoringSslPackage "lightway-server" pkgs rustPlatformStable
            [ "boringssl" ];
      };
    in
    {
      packages = nativePackages;

      # Export nativeSuffix for use in flake.nix aliases
      _module.args.nativeSuffix = nativeSuffix;
    };
}
