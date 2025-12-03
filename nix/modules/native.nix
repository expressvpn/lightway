# Native builds module - platform-specific native builds
{
  perSystem =
    {
      lib,
      pkgs,
      system,
      rustLatest,
      rustMsrv,
      ...
    }:
    let
      # Rust platforms
      rustPlatformLatest = pkgs.makeRustPlatform {
        cargo = rustLatest.minimal;
        rustc = rustLatest.minimal;
      };
      rustPlatformMsrv = pkgs.makeRustPlatform {
        cargo = rustMsrv.minimal;
        rustc = rustMsrv.minimal;
      };

      # Helper: Build package
      mkPackage =
        package: pkgs: rustPlatform:
        pkgs.callPackage ../. {
          inherit package rustPlatform;
          isStatic = false;
          platformSuffix = nativeSuffix;
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
        # Latest stable builds
        "lightway-client-${nativeSuffix}" = mkPackage "lightway-client" pkgs rustPlatformLatest;
        "lightway-server-${nativeSuffix}" = mkPackage "lightway-server" pkgs rustPlatformLatest;

        # MSRV builds
        "lightway-client-${nativeSuffix}-msrv" = mkPackage "lightway-client" pkgs rustPlatformMsrv;
        "lightway-server-${nativeSuffix}-msrv" = mkPackage "lightway-server" pkgs rustPlatformMsrv;
      };
    in
    {
      packages = nativePackages;

      # Export nativeSuffix for use in flake.nix aliases
      _module.args.nativeSuffix = nativeSuffix;
    };
}
