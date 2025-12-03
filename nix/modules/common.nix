# Common module - shared Rust toolchains and configuration
{
  perSystem =
    { pkgs, ... }:
    let
      cargoToml = builtins.fromTOML (builtins.readFile ../../Cargo.toml);
      msrv = cargoToml.workspace.package.rust-version;

      # Rust toolchains (shared across all modules)
      rustLatest = pkgs.rust-bin.stable.latest;
      rustMsrv = pkgs.rust-bin.stable.${msrv};
      rustNightly = pkgs.rust-bin.nightly.latest;
    in
    {
      # Export via _module.args for use in other modules
      _module.args = {
        inherit rustLatest rustMsrv rustNightly;
      };
    };
}
