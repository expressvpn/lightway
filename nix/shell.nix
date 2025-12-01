{
  lib,
  mkShell,
  rustPlatform,
  autoconf,
  automake,
  libtool,
  cargo-deny,
  cargo-make,
  cargo-nextest,
  cargo-outdated,
  cargo-fuzz,
  rust-analyzer,
  rustc,
  isStatic ? false,
  defaultTarget ? null,
}:

mkShell {
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
  '';

  nativeBuildInputs = [
    # Build dependencies
    autoconf
    automake
    libtool
    rustPlatform.bindgenHook

    # Development tools
    cargo-deny
    cargo-make
    cargo-nextest
    cargo-outdated
    cargo-fuzz
    rust-analyzer

    # Rust toolchain
    rustc
  ];
}
