# Native builds module - platform-specific native builds
{
  perSystem =
    {
      lib,
      pkgs,
      system,
      rustStable,
      rustMsrv,
      crane,
      ...
    }:
    let
      # Rust platforms
      # A craneLib per toolchain. Artifacts are toolchain-bound, so stable and
      # MSRV get their own dependency derivations.
      craneStable = (crane.mkLib pkgs).overrideToolchain (_: rustStable.minimal);
      craneMsrv = (crane.mkLib pkgs).overrideToolchain (_: rustMsrv.minimal);

      # Helper: Build package with the default (wolfssl) backend
      mkPackage =
        packages: pkgs: craneLib:
        pkgs.callPackage ../. {
          inherit packages craneLib;
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
        "lightway-client-${nativeSuffix}" = mkPackage [ "lightway-client" ] pkgs craneStable;
        "lightway-server-${nativeSuffix}" = mkPackage [ "lightway-server" ] pkgs craneStable;

        # Combined stable build - client+server in one derivation to compile deps once
        "lightway-${nativeSuffix}" = mkPackage [
          "lightway-client"
          "lightway-server"
        ] pkgs craneStable;

        # MSRV builds
        "lightway-client-${nativeSuffix}-msrv" = mkPackage [ "lightway-client" ] pkgs craneMsrv;
        "lightway-server-${nativeSuffix}-msrv" = mkPackage [ "lightway-server" ] pkgs craneMsrv;

        # Combined MSRV build - client+server in one derivation to compile deps once
        "lightway-${nativeSuffix}-msrv" = mkPackage [
          "lightway-client"
          "lightway-server"
        ] pkgs craneMsrv;

        # BoringSSL backend builds - combined client+server to compile the
        # shared dependency graph once.
        "lightway-${nativeSuffix}-boringssl-beta" = pkgs.callPackage ../. {
          packages = [
            "lightway-client"
            "lightway-server"
          ];
          craneLib = craneStable;
          isStatic = false;
          platformSuffix = "${nativeSuffix}-boringssl-beta";
          noDefaultFeatures = true;
          perPackageFeatures = {
            lightway-client = [ "boringssl" ];
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
