{
  lib,
  stdenv,
  rustPlatform,
  autoconf,
  automake,
  libtool,
  cmake,
  git,
  perl,
  buildPackages,
  packages ? [ "lightway-client" ],
  features ? [ ] ++ lib.optionals stdenv.isLinux [ "io-uring" ],
  # Per-package feature overrides: { "lightway-client" = ["boringssl" "postquantum"]; }.
  # A package listed here uses its own feature list instead of `features`.
  perPackageFeatures ? { },
  noDefaultFeatures ? false,
  isStatic ? false,
  platformSuffix ? null,
}:

let
  singlePackage = builtins.length packages == 1;
  cargoToml = builtins.fromTOML (builtins.readFile ../${builtins.head packages}/Cargo.toml);

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
  baseName = if singlePackage then cargoToml.package.name else "lightway";
  packageName = if platformSuffix != null then "${baseName}-${platformSuffix}" else baseName;
in
rustPlatform.buildRustPackage {
  pname = packageName;
  inherit (cargoToml.package) version;

  src = ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
    # boring is a git dependency, not a registry crate, so Cargo.lock has no
    # checksum for it. Nix's importCargoLock needs an explicit hash here.
    # One entry covers both `boring` and `boring-sys` since they share a git source.
    outputHashes = {
      "boring-5.1.0" = "sha256-4yrvuS2wk9R2IMztzSCaNOVJypXRRkcfwINbFrMZwXA=";
    };
  };

  # Features use the pkg/feature form: plain --features only applies to the
  # first -p package when several are selected. perPackageFeatures overrides
  # the uniform features list for specific packages.
  cargoBuildFlags = lib.concatStringsSep " " (
    map (p: "-p ${p}") packages
    ++ lib.optional noDefaultFeatures "--no-default-features"
    ++ (
      let
        featureFlags = lib.concatMap (
          p: map (f: "${p}/${f}") (perPackageFeatures.${p} or features)
        ) packages;
      in
      lib.optional (featureFlags != [ ]) ("--features " + lib.concatStringsSep "," featureFlags)
    )
  );

  nativeBuildInputs = [
    autoconf
    automake
    libtool
    # boring-sys's build script invokes `git init` and `cmake` to compile
    # BoringSSL from source. perl is required by some BoringSSL build steps.
    cmake
    git
    perl
  ]
  ++ lib.optionals (stdenv.hostPlatform.system == stdenv.buildPlatform.system) [
    # For native builds, use bindgenHook normally
    rustPlatform.bindgenHook
  ];

  # For cross-compilation, manually configure bindgen
  # Use build platform's libclang but target platform's headers
  LIBCLANG_PATH = lib.optionalString (
    stdenv.hostPlatform.system != stdenv.buildPlatform.system
  ) "${lib.getLib buildPackages.llvmPackages.libclang}/lib";

  BINDGEN_EXTRA_CLANG_ARGS =
    lib.optionalString (stdenv.hostPlatform.system != stdenv.buildPlatform.system)
      (
        lib.concatStringsSep " " (
          [
            "--target=${stdenv.hostPlatform.config}"
            "-isystem ${lib.getDev stdenv.cc.libc}/include"
            "-I${buildPackages.llvmPackages.clang}/resource-root/include"
          ]
          ++ lib.optionals (stdenv.cc ? nix-support) [
            "$(< ${stdenv.cc}/nix-support/libc-cflags)"
            "$(< ${stdenv.cc}/nix-support/cc-cflags)"
          ]
        )
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
      !isStatic
      && stdenv.hostPlatform.system != stdenv.buildPlatform.system
      && stdenv.hostPlatform.isLinux
    ) " -C link-arg=-fuse-ld=bfd";

  # Enable ARM crypto extensions
  env.NIX_CFLAGS_COMPILE =
    with stdenv.hostPlatform;
    lib.optionalString (isAarch && isLinux) "-march=${gcc.arch}+crypto";

  meta =
    (
      if singlePackage then
        { inherit (packageMeta.${builtins.head packages}) description mainProgram; }
      else
        { description = "Lightway VPN client and server"; }
    )
    // {
      platforms = lib.platforms.unix;
    };
}
