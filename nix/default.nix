{
  lib,
  stdenv,
  craneLib,
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
  # Per-package feature overrides: { "lightway-client" = ["boringssl"]; }.
  # A package listed here uses its own feature list instead of `features`.
  perPackageFeatures ? { },
  noDefaultFeatures ? false,
  isStatic ? false,
  platformSuffix ? null,
}:

let
  singlePackage = builtins.length packages == 1;

  # Compare full triples, not `.system`: musl and gnu on the same arch share a
  # `.system` string, and treating a musl host as native drags in a
  # musl-hosted LLVM that no binary cache serves.
  isCross = stdenv.hostPlatform.config != stdenv.buildPlatform.config;
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

  # Features use the pkg/feature form: plain --features only applies to the
  # first -p package when several are selected. perPackageFeatures overrides
  # the uniform features list for specific packages.
  cargoFlags =
    pkgList:
    lib.concatStringsSep " " (
      map (p: "-p ${p}") pkgList
      ++ lib.optional noDefaultFeatures "--no-default-features"
      ++ (
        let
          featureFlags = lib.concatMap (
            p: map (f: "${p}/${f}") (perPackageFeatures.${p} or features)
          ) pkgList;
        in
        lib.optional (featureFlags != [ ]) ("--features " + lib.concatStringsSep "," featureFlags)
      )
    );

  # Dependencies are always built for the whole workspace, whichever binaries
  # this package installs. Cargo unifies features per -p set, so a narrower set
  # does not reuse a wider one; building the superset once lets every package
  # sharing a toolchain, target and feature set hit the same artifacts.
  depsPackages = [
    "lightway-client"
    "lightway-server"
  ];

  # wolfssl-sys derives autotools --host by stripping the compiler suffix from
  # $CC, and crane points these at full store paths, which leaves a path rather
  # than a triple. The bare wrapper names are what configure expects.
  crossCc = "${stdenv.cc.targetPrefix}cc";
  crossCcVar = "CC_" + builtins.replaceStrings [ "-" ] [ "_" ] stdenv.hostPlatform.config;

  # cleanCargoSource keeps only Cargo manifests and Rust sources, which drops the
  # fixtures that tests read at runtime.
  src' =
    let
      root = ../.;
    in
    lib.fileset.toSource {
      inherit root;
      fileset = lib.fileset.unions [
        (craneLib.fileset.commonCargoSources root)
        # The whole tree, not selected extensions: lightway-client's config
        # tests read yaml from here and lightway-server's datagram tests read
        # certs, and filtering by extension just moves the next failure.
        ../tests
      ];
    };

  commonArgs = {
    src = src';
    strictDeps = true;
    inherit (cargoToml.package) version;

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
    ++ lib.optionals (!isCross) [
      # For native builds, use bindgenHook normally
      rustPlatform.bindgenHook
    ];

    # bindgenHook derives -frandom-seed from the derivation hash and passes it
    # through NIX_CFLAGS_COMPILE. Dependencies and package are separate
    # derivations here, so without a fixed seed bindgen rebuilds in the leaf and
    # the split buys nothing.
    NIX_OUTPATH_USED_AS_RANDOM_SEED = "aaaaaaaaaa";

    # For cross-compilation, manually configure bindgen
    # Use build platform's libclang but target platform's headers
    LIBCLANG_PATH = lib.optionalString isCross "${lib.getLib buildPackages.llvmPackages.libclang}/lib";

    BINDGEN_EXTRA_CLANG_ARGS = lib.optionalString isCross (
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
  }
  // lib.optionalAttrs isCross {
    ${crossCcVar} = crossCc;
    TARGET_CC = crossCc;
  };

  cargoArtifacts = craneLib.buildDepsOnly (
    commonArgs
    // {
      pname = "lightway-deps";
      cargoExtraArgs = cargoFlags depsPackages;
    }
  );
in
craneLib.buildPackage (
  commonArgs
  // {
    pname = packageName;
    inherit cargoArtifacts;
    cargoExtraArgs = cargoFlags packages;

    # Tests run once per system as the `tests` flake check, not here. Keeping
    # them in the package would force its cargo flags to cover the whole
    # workspace, and cargo unifies features per package set, so the dependency
    # artifacts built for these binaries would stop being reused.
    doCheck = false;

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

    # Consumed by nix/modules/checks.nix to build the workspace test derivation
    # against the same toolchain and environment as the package.
    passthru.craneArgs = commonArgs;
  }
)
