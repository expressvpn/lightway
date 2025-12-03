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
      };

      formatter = pkgs.nixfmt-rfc-style;
    };
}
