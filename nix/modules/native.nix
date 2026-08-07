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
        packages: pkgs: rustPlatform:
        pkgs.callPackage ../. {
          inherit packages rustPlatform;
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
        # Pinned stable builds
        "lightway-client-${nativeSuffix}" = mkPackage [ "lightway-client" ] pkgs rustPlatformStable;
        "lightway-server-${nativeSuffix}" = mkPackage [ "lightway-server" ] pkgs rustPlatformStable;

        # Combined stable build - client+server in one derivation to compile deps once
        "lightway-${nativeSuffix}" = mkPackage [
          "lightway-client"
          "lightway-server"
        ] pkgs rustPlatformStable;

        # MSRV builds
        "lightway-client-${nativeSuffix}-msrv" = mkPackage [ "lightway-client" ] pkgs rustPlatformMsrv;
        "lightway-server-${nativeSuffix}-msrv" = mkPackage [ "lightway-server" ] pkgs rustPlatformMsrv;

        # Combined MSRV build - client+server in one derivation to compile deps once
        "lightway-${nativeSuffix}-msrv" = mkPackage [
          "lightway-client"
          "lightway-server"
        ] pkgs rustPlatformMsrv;

        # BoringSSL backend builds - combined client+server to compile the
        # shared dependency graph once. Client needs the `postquantum` feature
        # explicitly; server has no such feature (it enables postquantum in
        # lightway-core directly via its Cargo.toml dep spec).
        "lightway-${nativeSuffix}-boringssl-beta" = pkgs.callPackage ../. {
          packages = [
            "lightway-client"
            "lightway-server"
          ];
          rustPlatform = rustPlatformStable;
          isStatic = false;
          platformSuffix = "${nativeSuffix}-boringssl-beta";
          noDefaultFeatures = true;
          perPackageFeatures = {
            lightway-client = [
              "boringssl"
              "postquantum"
            ];
            lightway-server = [ "boringssl" ];
          };
        };
      };
    in
    {
      packages = nativePackages;

      # Export nativeSuffix for use in flake.nix aliases
      _module.args.nativeSuffix = nativeSuffix;
    };
}
