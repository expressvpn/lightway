# Development shells module
{
  perSystem =
    {
      config,
      lib,
      pkgs,
      rustLatest,
      rustMsrv,
      rustNightly,
      system,
      ...
    }:
    {
      devShells = {
        default = config.devShells.stable;

        stable = pkgs.callPackage ../shell.nix {
          rustc = rustLatest.default;
        };
        nightly = pkgs.callPackage ../shell.nix {
          rustc = rustNightly.default;
        };
        msrv = pkgs.callPackage ../shell.nix {
          rustc = rustMsrv.default;
        };
      }
      // lib.optionalAttrs (lib.hasSuffix "linux" system) {
        android =
          let
            ANDROID_NDK_VERSION = androidConstants.NDK_VERSION;
            androidConstants = (import ./constants.nix).android;
            androidComposition = pkgs.androidenv.composeAndroidPackages {
              buildToolsVersions = [ androidConstants.BUILD_TOOL_VERSION ];
              includeNDK = true;
              includeSystemImages = false;
              ndkVersions = [ ANDROID_NDK_VERSION ];
              platformVersions = [ androidConstants.PLATFORM_VERSION ];
            };
            androidSdk = androidComposition.androidsdk;
            buildScript = pkgs.writeShellScriptBin "build" ''
              cargo make build-android
            '';
            pinned-cargo-ndk = pkgs.callPackage ../pkgs/cargo-ndk.nix { };
            pkgsCross =
              with pkgs.pkgsCross;
              {
                "aarch64-linux" = aarch64-multiplatform;
                "x86_64-linux" = gnu64;
              }
              .${system} or null;
          in
          pkgsCross.callPackage ../shell.nix ({
            rustc = rustLatest.minimal.override {
              targets = [
                "aarch64-linux-android"
                "armv7-linux-androideabi"
                "i686-linux-android"
                "x86_64-linux-android"
              ];
              extensions = [
                "rust-analyzer"
                "rust-src"
              ];
            };
            shellEnvVar = {
              inherit ANDROID_NDK_VERSION;
              ANDROID_HOME = "${androidSdk}/libexec/android-sdk";
              ANDROID_NDK_HOME = "${androidSdk}/libexec/android-sdk/ndk/${ANDROID_NDK_VERSION}";
              ANDROID_SDK_ROOT = "${androidSdk}/libexec/android-sdk";
            };
            extraBuildPkgs = with pkgs; [
              androidenv.androidPkgs.androidsdk
              androidenv.androidPkgs.ndk-bundle
              buildScript
              git-lfs
              ktlint
              pinned-cargo-ndk
              zulu
            ];
            extraShellHook = ''
              export GRADLE_OPTS="-Dorg.gradle.project.android.aapt2FromMavenOverride=${androidSdk}/libexec/android-sdk/build-tools/${androidConstants.BUILD_TOOL_VERSION}/aapt2 $GRADLE_OPTS"
            '';
          });
      };
      formatter = pkgs.nixfmt;
    };
}
