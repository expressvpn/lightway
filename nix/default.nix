{
  lib,
  stdenv,
  rustPlatform,
  autoconf,
  automake,
  libtool,
  package ? "lightway-client",
  features ? [ ] ++ lib.optionals stdenv.isLinux [ "io-uring" ],
  isStatic ? false,
}:

let
  cargoToml = builtins.fromTOML (builtins.readFile ../${package}/Cargo.toml);

  # Package-specific metadata
  packageMeta = {
    lightway-client = {
      description = "Lightway VPN client";
      mainProgram = "lightway-client";
    };
    lightway-server = {
      description = "Lightway VPN server";
      mainProgram = "lightway-server";
    };
  };
in
rustPlatform.buildRustPackage {
  inherit (cargoToml.package) name version;

  src = ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "wolfssl-3.0.0" = "sha256-kEVY/HLHTGFaIRSdLbVIomewUngUKEc9q11605n3I+Y=";
    };
  };

  buildFeatures = features;
  cargoBuildFlags = "-p ${package}";

  nativeBuildInputs = [
    autoconf
    automake
    libtool
    rustPlatform.bindgenHook
  ];

  # Enable fully static linking for musl builds
  RUSTFLAGS = lib.optionalString isStatic "-C target-feature=+crt-static -C link-arg=-static";

  # Enable ARM crypto extensions
  env.NIX_CFLAGS_COMPILE =
    with stdenv.hostPlatform;
    lib.optionalString (isAarch && isLinux) "-march=${gcc.arch}+crypto";

  meta = {
    inherit (packageMeta.${package}) description mainProgram;
    platforms = lib.platforms.unix;
  };
}
