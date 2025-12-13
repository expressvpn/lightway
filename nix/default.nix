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

  # RUSTFLAGS configuration for different build scenarios:
  #
  # 1. Static builds (musl):
  #    - Use -static for maximum compatibility across architectures
  #    - Note: On aarch64 musl, `file` command reports "dynamically linked" but
  #      the binary is truly static (cosmetic issue only)
  #    - Alternatives like -static-pie, --no-dynamic-linker cause SIGSEGV crashes on aarch64
  #    - Also tried to also disable PIE to make it statically linked without PIE,
  #      but it didn't work. aarch64 musl always produces PIE binaries with PT_INTERP section
  #
  # 2. Cross-compilation (all platforms):
  #    - Explicitly set linker to avoid host platform linker leaking into target
  #
  # 3. Cross-compilation to Linux:
  #    - Additionally force bfd linker to avoid macOS-specific platform_version
  #      flags when cross-compiling from Darwin to Linux
  #    - Darwin uses lld by default which can inject incompatible flags
  #
  # 4. Cross-compilation to Darwin:
  #    - Only set linker
  RUSTFLAGS =
    lib.optionalString isStatic "-C target-feature=+crt-static -C link-arg=-static"
    + lib.optionalString (
      !isStatic && stdenv.hostPlatform.system != stdenv.buildPlatform.system
    ) " -C linker=${stdenv.cc.targetPrefix}cc"
    + lib.optionalString (
      !isStatic && stdenv.hostPlatform.system != stdenv.buildPlatform.system && stdenv.hostPlatform.isLinux
    ) " -C link-arg=-fuse-ld=bfd";

  # Enable ARM crypto extensions
  env.NIX_CFLAGS_COMPILE =
    with stdenv.hostPlatform;
    lib.optionalString (isAarch && isLinux) "-march=${gcc.arch}+crypto";

  meta = {
    inherit (packageMeta.${package}) description mainProgram;
    platforms = lib.platforms.unix;
  };
}
