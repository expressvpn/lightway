# Checks module - Nix flake checks for CI/CD
{
  perSystem =
    {
      lib,
      pkgs,
      rustLatest,
      rustNightly,
      ...
    }:
    let
      # Common configuration
      src = ../..;
      version = "0.1.0";

      cargoLock = {
        lockFile = ../../Cargo.lock;
        outputHashes = {
          "wolfssl-3.0.0" = "sha256-CNGs4M6kyzH9YtEkVWPMAjkxAVyT9plIo1fX3AWOiTw=";
        };
      };

      # Build tools needed for wolfssl dependency
      wolfsslBuildInputs = [
        pkgs.autoconf
        pkgs.automake
        pkgs.libtool
      ];

      # Rust toolchains
      rustFmt = rustLatest.default.override {
        extensions = [ "rustfmt" ];
      };

      rustWithClippy = rustLatest.default.override {
        extensions = [ "clippy" ];
      };

      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustWithClippy;
        rustc = rustWithClippy;
      };

      # Nightly Rust with miri for unsafe code testing
      rustNightlyWithMiri = rustNightly.default.override {
        extensions = [ "miri" "rust-src" ];
      };

      rustPlatformNightly = pkgs.makeRustPlatform {
        cargo = rustNightlyWithMiri;
        rustc = rustNightlyWithMiri;
      };

      # Helper to create check derivations with common defaults
      mkCheck =
        pname: attrs:
        rustPlatform.buildRustPackage ({
          inherit
            pname
            version
            src
            cargoLock
            ;
          installPhase = "touch $out";
          doCheck = false;
        } // attrs);

      # Helper for nightly checks
      mkNightlyCheck =
        pname: attrs:
        rustPlatformNightly.buildRustPackage ({
          inherit
            pname
            version
            src
            cargoLock
            ;
          installPhase = "touch $out";
          doCheck = false;
        } // attrs);

      # Format check - verifies Rust code formatting (doesn't need dependencies)
      fmt = pkgs.runCommand "lightway-fmt-check"
        {
          nativeBuildInputs = [
            rustFmt
            pkgs.cargo
          ];
          inherit src;
        }
        ''
          cd $src
          cargo fmt --check
          touch $out
        '';

      # Lint check - runs clippy, cargo doc, and shellcheck
      lint = mkCheck "lightway-lint-check" {
        nativeBuildInputs = wolfsslBuildInputs ++ [ pkgs.shellcheck ];
        RUSTDOCFLAGS = "-D warnings";
        buildPhase = ''
          cargo clippy -p lightway-client --no-default-features --all-targets -- -D warnings
          cargo doc --document-private-items
          find tests -name "*.sh" -print0 | xargs -r0 shellcheck
        '';
      };

      # Check dependencies - runs cargo deny
      check-dependencies = mkCheck "lightway-check-dependencies" {
        nativeBuildInputs = [ pkgs.cargo-deny ];
        buildPhase = ''
          cargo deny --all-features check --deny warnings bans license sources
        '';
      };

      # Coverage - generates code coverage reports
      # Note: cargo-llvm-cov is marked broken on Darwin, works on Linux
      coverage = mkCheck "lightway-coverage" {
        nativeBuildInputs = wolfsslBuildInputs ++ [ pkgs.cargo-llvm-cov ];
        buildPhase = ''
          cargo llvm-cov test --no-report
          mkdir -p $out
          cargo llvm-cov report --summary-only --output-path $out/summary.txt
          cargo llvm-cov report --json --output-path $out/coverage.json
          cargo llvm-cov report --html --output-dir $out/html
        '';
        installPhase = "echo 'Coverage reports generated in $out'";
      };

      # Build Miri sysroot separately using fixed-output derivation
      # This follows the standard Nix pattern for dependencies requiring network access
      # See: https://github.com/oxalica/rust-overlay/issues/100
      miriSysroot = pkgs.stdenv.mkDerivation {
        name = "miri-sysroot";

        nativeBuildInputs = [ rustNightlyWithMiri ];

        # Dummy source - we only need cargo/miri commands
        unpackPhase = "true";

        # Fixed-output derivation - allowed network access with known output hash
        outputHashMode = "recursive";
        outputHashAlgo = "sha256";
        # Use lib.fakeHash initially, then update with actual hash from build error
        outputHash = lib.fakeHash;

        buildPhase = ''
          export CARGO_HOME=$TMPDIR/.cargo
          export MIRI_SYSROOT=$out
          mkdir -p $CARGO_HOME $out

          # Build Miri sysroot (downloads stdlib dependencies from crates.io)
          cargo miri setup
        '';

        installPhase = ''
          echo "Miri sysroot built at $out"
        '';
      };

      # Test-miri - runs tests under Miri for unsafe code validation
      test-miri = mkNightlyCheck "lightway-test-miri" {
        nativeBuildInputs = wolfsslBuildInputs;

        # Use pre-built Miri sysroot from FOD
        MIRIFLAGS = "-Zmiri-permissive-provenance";
        MIRI_SYSROOT = "${miriSysroot}";

        buildPhase = ''
          # Test unsafe code in lightway-app-utils
          cargo miri test -p lightway-app-utils -- iouring sockopt

          # Test unsafe code in lightway-server
          cargo miri test -p lightway-server -- io::outside::udp
        '';
      };
    in
    {
      checks = {
        inherit
          fmt
          lint
          check-dependencies
          coverage
          test-miri
          ;
      };
    };
}
