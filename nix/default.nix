{
  lib,
  stdenv,
  rustPlatform,
  autoconf,
  automake,
  libtool,
  buildPackages,
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

  nativeBuildInputs =
    [
      autoconf
      automake
      libtool
    ]
    ++ lib.optionals (stdenv.hostPlatform.system == stdenv.buildPlatform.system) [
      # For native builds, use bindgenHook normally
      rustPlatform.bindgenHook
    ];

  # For cross-compilation, manually configure bindgen
  # Use build platform's libclang but target platform's headers
  LIBCLANG_PATH = lib.optionalString (stdenv.hostPlatform.system != stdenv.buildPlatform.system) "${lib.getLib buildPackages.llvmPackages.libclang}/lib";

  BINDGEN_EXTRA_CLANG_ARGS = lib.optionalString (stdenv.hostPlatform.system != stdenv.buildPlatform.system) (
    lib.concatStringsSep " " ([
      "--target=${stdenv.hostPlatform.config}"
      "-isystem ${lib.getDev stdenv.cc.libc}/include"
      "-I${buildPackages.llvmPackages.clang}/resource-root/include"
    ] ++ lib.optionals (stdenv.cc ? nix-support) [
      "$(< ${stdenv.cc}/nix-support/libc-cflags)"
      "$(< ${stdenv.cc}/nix-support/cc-cflags)"
    ])
  );

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
