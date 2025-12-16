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

      # Rust toolchain with rustfmt component
      rust = rustLatest.default.override {
        extensions = [ "rustfmt" ];
      };

      # Format check - verifies Rust code formatting
      fmt = pkgs.runCommand "lightway-fmt-check"
        {
          nativeBuildInputs = [
            rust
            pkgs.cargo
          ];
          inherit src;
        }
        ''
          cd $src
          cargo fmt --check
          touch $out
        '';
    in
    {
      checks = {
        inherit fmt;
      };
    };
}
