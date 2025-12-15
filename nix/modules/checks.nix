# Checks module - Nix flake checks for CI/CD
{
  perSystem =
    {
      lib,
      pkgs,
      rustLatest,
      ...
    }:
    let
      # Source directory for all checks
      src = ../..;

      # Rust toolchains
      rustFmt = rustLatest.default.override {
        extensions = [ "rustfmt" ];
      };

      rustWithClippy = rustLatest.default.override {
        extensions = [ "clippy" ];
      };

      # Rust platform with clippy for lint check
      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustWithClippy;
        rustc = rustWithClippy;
      };

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
      lint = rustPlatform.buildRustPackage {
        pname = "lightway-lint-check";
        version = "0.1.0";
        inherit src;

        cargoLock = {
          lockFile = ../../Cargo.lock;
          outputHashes = {
            "wolfssl-3.0.0" = "sha256-CNGs4M6kyzH9YtEkVWPMAjkxAVyT9plIo1fX3AWOiTw=";
          };
        };

        # Build tools needed for wolfssl dependency
        nativeBuildInputs = [
          pkgs.autoconf
          pkgs.automake
          pkgs.libtool
          pkgs.shellcheck
        ];

        RUSTDOCFLAGS = "-D warnings";

        # Run checks instead of building
        buildPhase = ''
          cargo clippy -p lightway-client --no-default-features --all-targets -- -D warnings
          cargo doc --document-private-items
          find tests -name "*.sh" -print0 | xargs -r0 shellcheck
        '';

        # No artifacts to install
        installPhase = "touch $out";

        doCheck = false;
      };

      # Check dependencies - runs cargo deny to check for security issues and license compliance
      check-dependencies = rustPlatform.buildRustPackage {
        pname = "lightway-check-dependencies";
        version = "0.1.0";
        inherit src;

        cargoLock = {
          lockFile = ../../Cargo.lock;
          outputHashes = {
            "wolfssl-3.0.0" = "sha256-CNGs4M6kyzH9YtEkVWPMAjkxAVyT9plIo1fX3AWOiTw=";
          };
        };

        nativeBuildInputs = [ pkgs.cargo-deny ];

        # Run cargo deny checks
        buildPhase = ''
          cargo deny --all-features check --deny warnings bans license sources
        '';

        # No artifacts to install
        installPhase = "touch $out";

        doCheck = false;
      };

      # Coverage - generates code coverage reports
      # Note: Skips privileged tests since they can't run in Nix sandbox
      coverage = rustPlatform.buildRustPackage {
        pname = "lightway-coverage";
        version = "0.1.0";
        inherit src;

        cargoLock = {
          lockFile = ../../Cargo.lock;
          outputHashes = {
            "wolfssl-3.0.0" = "sha256-CNGs4M6kyzH9YtEkVWPMAjkxAVyT9plIo1fX3AWOiTw=";
          };
        };

        nativeBuildInputs = [
          pkgs.autoconf
          pkgs.automake
          pkgs.libtool
          pkgs.cargo-llvm-cov
        ];

        # Run tests with coverage and generate reports
        buildPhase = ''
          # Run tests with coverage collection (skip privileged tests)
          cargo llvm-cov test --no-report

          # Generate coverage reports
          mkdir -p $out
          cargo llvm-cov report --summary-only --output-path $out/summary.txt
          cargo llvm-cov report --json --output-path $out/coverage.json
          cargo llvm-cov report --html --output-dir $out/html
        '';

        # Coverage reports are in $out
        installPhase = "echo 'Coverage reports generated in $out'";

        doCheck = false;
      };
    in
    {
      checks = {
        inherit fmt lint check-dependencies coverage;
      };
    };
}
