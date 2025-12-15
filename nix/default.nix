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
  platformSuffix ? null,
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

  # Construct package name with optional platform suffix
  packageName =
    if platformSuffix != null then
      "${cargoToml.package.name}-${platformSuffix}"
    else
      cargoToml.package.name;
in
rustPlatform.buildRustPackage {
  pname = packageName;
  inherit (cargoToml.package) version;

  src = ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "wolfssl-3.0.0" = "sha256-CNGs4M6kyzH9YtEkVWPMAjkxAVyT9plIo1fX3AWOiTw=";
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
  #
  # Note 1:
  # Use -static for maximum compatibility across architectures
  #
  # In aarch64 musl, With `-static`, the final binary  reports as dynamically
  # linked using file command. But it looks like cosmetic issue - binary is truly static
  #
  # OTOH, Both -static-pie and --no-dynamic-linker causes binaries which are reported
  # as statically linked. But SIGSEGV crashes on aarch64
  #
  # Tried to also disable PIE to make it statically linked without PIE, but it didn't work.
  # aarch64 musl always produces PIE binaries with PT_INTERP section
  #
  # Note 2:
  # For cross-compilation from macOS, disable lld and use gcc directly to
  # avoid platform_version flags
  RUSTFLAGS =
    lib.optionalString isStatic "-C target-feature=+crt-static -C link-arg=-static"
    + lib.optionalString (stdenv.hostPlatform.system != stdenv.buildPlatform.system && !isStatic)
      " -C linker=${stdenv.cc.targetPrefix}cc -C link-arg=-fuse-ld=bfd";

  # Enable ARM crypto extensions
  env.NIX_CFLAGS_COMPILE =
    with stdenv.hostPlatform;
    lib.optionalString (isAarch && isLinux) "-march=${gcc.arch}+crypto";

  meta = {
    inherit (packageMeta.${package}) description mainProgram;
    platforms = lib.platforms.unix;
  };
}
