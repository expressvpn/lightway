{
  lib,
  stdenv,
  buildPackages,
  mkShell,
  rustPlatform,
  autoconf,
  automake,
  libtool,
  cmake,
  git,
  cargo-deny,
  cargo-make,
  cargo-nextest,
  cargo-outdated,
  cargo-fuzz,
  rust-analyzer,
  rustc,
  isStatic ? false,
  defaultTarget ? null,
  shellEnvVar ? { },
  extraBuildPkgs ? [ ],
  extraShellHook ? "",
}:

let
  isCross = stdenv.hostPlatform.config != stdenv.buildPlatform.config;
  libclang = buildPackages.llvmPackages.libclang;
in
mkShell (
  {
    shellHook = ''
      export RUST_SRC_PATH=${rustPlatform.rustLibSrc}
      ${lib.optionalString (defaultTarget != null) ''
        export CARGO_BUILD_TARGET="${defaultTarget}"
        echo "Default cargo target set to: ${defaultTarget}"
      ''}
      ${lib.optionalString isStatic ''
        export RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-static"
        echo "Musl static build environment activated"
        echo "RUSTFLAGS: $RUSTFLAGS"
      ''}
      ${extraShellHook}
    '';

    nativeBuildInputs = [
      # Build dependencies
      autoconf
      automake
      libtool
      cmake
      git
    ]
    # For cross shells, bindgen env is set below (same as nix/default.nix)
    ++ lib.optionals (!isCross) [ rustPlatform.bindgenHook ]
    ++ [
      # Development tools
      cargo-deny
      cargo-make
      cargo-nextest
      cargo-outdated
      cargo-fuzz
      rust-analyzer

      # Rust toolchain
      rustc
    ]
    ++ extraBuildPkgs;
  }
  // lib.optionalAttrs isCross {
    LIBCLANG_PATH = "${lib.getLib libclang}/lib";
    BINDGEN_EXTRA_CLANG_ARGS = lib.concatStringsSep " " [
      "--target=${stdenv.hostPlatform.config}"
      "-isystem ${lib.getDev stdenv.cc.libc}/include"
      "-I${lib.getLib libclang}/lib/clang/${lib.versions.major libclang.version}/include"
    ];
  }
  // shellEnvVar
)
