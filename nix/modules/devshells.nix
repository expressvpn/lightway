# Development shells module
{
  perSystem =
    {
      config,
      lib,
      pkgs,
      rustStable,
      rustMsrv,
      rustNightly,
      system,
      ...
    }:
    {
      devShells = {
        default = config.devShells.stable;

        stable = pkgs.callPackage ../shell.nix {
          rustc = rustStable.default;
          # BPF toolchain for lightway-bpf-steering (kp_lwt-style kernel offload
          # steering programs): clang/libclang to compile the programs, libbpf +
          # bpftools to load and inspect them, linuxHeaders for uapi/linux/bpf.h,
          # pkg-config + elfutils/zlib for libbpf-sys's vendored libbpf build.
          #
          # Linux-only, and gated rather than merely unused elsewhere: bpftools
          # and linuxHeaders have no Darwin build, so an unguarded reference
          # fails `nix flake check` at *evaluation* on the macOS runner.
          extraBuildPkgs = lib.optionals (lib.hasSuffix "linux" system) (
            with pkgs;
            [
              clang
              llvmPackages.libclang
              libbpf
              bpftools
              linuxHeaders
              pkg-config
              elfutils
              zlib
            ]
          );
          # cc-wrapper injects -fzero-call-used-regs=used-gpr by default, which
          # clang rejects for -target bpf ("unsupported option"). Only that one
          # flag is turned off; every other hardening default stays on.
          shellEnvVar = {
            hardeningDisable = [ "zerocallusedregs" ];
          };
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
              includeEmulator = false;
              includeNDK = true;
              includeSystemImages = false;
              ndkVersions = [ ANDROID_NDK_VERSION ];
              platformVersions = [ androidConstants.PLATFORM_VERSION ];
            };
            androidSdk = androidComposition.androidsdk;
            buildScript = pkgs.writeShellScriptBin "build" ''
              cd "$(git rev-parse --show-toplevel 2>/dev/null)"
              cargo make build-android
            '';
            cleanScript = pkgs.writeShellScriptBin "clean" ''
              cd "$(git rev-parse --show-toplevel 2>/dev/null)"
              cargo make clean-android
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
            rustc = rustStable.minimal.override {
              targets = [
                "aarch64-linux-android"
                "armv7-linux-androideabi"
                "i686-linux-android"
                "x86_64-linux-android"
              ];
            };
            shellEnvVar = {
              inherit ANDROID_NDK_VERSION;
              ANDROID_HOME = "${androidSdk}/libexec/android-sdk";
              ANDROID_NDK_HOME = "${androidSdk}/libexec/android-sdk/ndk-bundle";
              ANDROID_SDK_ROOT = "${androidSdk}/libexec/android-sdk";
            };
            extraBuildPkgs = with pkgs; [
              buildScript
              cleanScript
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
