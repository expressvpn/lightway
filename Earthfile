VERSION 0.8
ARG --global debian = bookworm

# Using commit hash pinning because git tags can be changed
# Ref: https://github.com/earthly/lib/tree/3.0.3
IMPORT github.com/earthly/lib/rust:a49d2a0f4028cd15666d19904f8fc5fbd0b9ba87 AS lib-rust

install-build-dependencies:
    FROM rust:1.98.1-$debian
    WORKDIR /lightway
    RUN dpkg --add-architecture arm64
    RUN apt-get update -qq
    RUN apt-get install --no-install-recommends -qq \
        autoconf \
        autotools-dev \
        bsdmainutils \
        clang \
        cmake \
        g++-aarch64-linux-gnu \
        libc6:arm64 \
        libtool-bin \
        qemu-user-static \
        shellcheck \ 
        g++-riscv64-linux-gnu \ 
        gcc-riscv64-linux-gnu

    # Note this must be done before `lib-rust+INIT` overrides `$CARGO_HOME`.
    RUN rustup toolchain install nightly

    DO lib-rust+INIT --keep_fingerprints=true
    RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/refs/tags/v1.17.8/install-from-binstall-release.sh | bash
    DO lib-rust+CARGO --args="binstall --no-confirm cargo-deny cargo-llvm-cov cargo-make"
    RUN rustup component add clippy
    RUN rustup component add rustfmt
    RUN rustup component add llvm-tools-preview
    RUN rustup target add aarch64-unknown-linux-gnu
    RUN rustup target add riscv64gc-unknown-linux-gnu

    RUN rustup +nightly component add miri
    RUN rustup +nightly component add rust-src
    DO lib-rust+CARGO --args="+nightly miri setup"

source:
    FROM +install-build-dependencies
    COPY --keep-ts Cargo.toml Cargo.lock Makefile.toml ./
    COPY --keep-ts deny.toml ./
    COPY --keep-ts --dir lightway-core lightway-boring lightway-expresslane lightway-app-utils lightway-client uniffi-bindgen lightway-server tests ./

# build-wolfssl runs cargo to build native binaries for the host platform with the wolfssl backend.
# You may use `--platform linux/[amd64|arm64]` to override the host platform, to natively compile in emulation.
build-wolfssl:
    FROM +source

    DO lib-rust+CARGO --args="build --release --features io-uring" --output="release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/release/lightway-client AS LOCAL ./target/release/
    SAVE ARTIFACT ./target/release/lightway-server AS LOCAL ./target/release/

build-boringssl:
    FROM +source

    DO lib-rust+CARGO --args="build --release --no-default-features --features io-uring,boringssl" --output="release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/release/lightway-client AS LOCAL ./target/release/
    SAVE ARTIFACT ./target/release/lightway-server AS LOCAL ./target/release/

# build-backend builds client/server with a specified TLS backend, used by the e2e test containers.
build-backend:
    FROM +source
    ARG --required BACKEND
    ARG EXTRA_FEATURES=""
    LET client_features = "$BACKEND"
    LET server_features = "$BACKEND"
    IF [ -n "$EXTRA_FEATURES" ]
        SET client_features = "$client_features,$EXTRA_FEATURES"
        SET server_features = "$server_features,$EXTRA_FEATURES"
    END
    DO lib-rust+CARGO \
        --args="build --release -p lightway-client --no-default-features --features $client_features" \
        --output="release/lightway-client$"
    DO lib-rust+CARGO \
        --args="build --release -p lightway-server --no-default-features --features $server_features" \
        --output="release/lightway-server$"
    SAVE ARTIFACT ./target/release/lightway-client
    SAVE ARTIFACT ./target/release/lightway-server

build-cross-arm64-wolfssl:
    FROM +source
    LET target = "aarch64-unknown-linux-gnu"
    ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"

    DO lib-rust+CARGO --args="build --release --features io-uring --target=$target" --output="$target/release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/$target/release/lightway-client AS LOCAL ./target/$target/release/
    SAVE ARTIFACT ./target/$target/release/lightway-server AS LOCAL ./target/$target/release/

build-cross-arm64-boringssl:
    FROM +source
    ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
    ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64-static"

    LET target = "aarch64-unknown-linux-gnu"
    # boring-sys compiles BoringSSL's C/C++ via CMake without target-specific CC/CXX/AR,
    # CMake falls back to the host (x86_64) toolchain.
    ENV CC_aarch64_unknown_linux_gnu="aarch64-linux-gnu-gcc"
    ENV CXX_aarch64_unknown_linux_gnu="aarch64-linux-gnu-g++"
    ENV AR_aarch64_unknown_linux_gnu="aarch64-linux-gnu-ar"

    DO lib-rust+CARGO --args="build --release --target=$target --no-default-features --features boringssl" --output="$target/release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/$target/release/lightway-client AS LOCAL ./target/$target/release/
    SAVE ARTIFACT ./target/$target/release/lightway-server AS LOCAL ./target/$target/release/

build-cross-riscv64-boringssl:
    FROM +source
    ENV CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="riscv64-linux-gnu-gcc"
    ENV CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="qemu-riscv64-static -L /usr/riscv64-linux-gnu -cpu rv64"

    LET target = "riscv64gc-unknown-linux-gnu"
    ENV CC_riscv64gc_unknown_linux_gnu="riscv64-linux-gnu-gcc"
    ENV CXX_riscv64gc_unknown_linux_gnu="riscv64-linux-gnu-g++"
    ENV AR_riscv64gc_unknown_linux_gnu="riscv64-linux-gnu-ar"

    DO lib-rust+CARGO --args="build --release --target=$target --no-default-features --features boringssl" --output="$target/release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/$target/release/lightway-client AS LOCAL ./target/$target/release/
    SAVE ARTIFACT ./target/$target/release/lightway-server AS LOCAL ./target/$target/release/

build-cross-riscv64-wolfssl:
    FROM +source
    LET target = "riscv64gc-unknown-linux-gnu"
    ENV CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="riscv64-linux-gnu-gcc"

    DO lib-rust+CARGO --args="build --release --features io-uring --target=$target" --output="$target/release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/$target/release/lightway-client AS LOCAL ./target/$target/release/
    SAVE ARTIFACT ./target/$target/release/lightway-server AS LOCAL ./target/$target/release/

# test-wolfssl runs the unit/integration test suite with the wolfssl backend
# (the workspace default), natively for the host platform.
# You may use `--platform linux/[amd64|arm64]` to override the host platform, to natively compile in emulation.
test-wolfssl:
    FROM +source

    # Run all tests except privileged tests
    DO lib-rust+CARGO --args="test"

    # Run only privileged tests with sudo permissions
    RUN --privileged cargo test --package lightway-client test_privileged -- --ignored

# test-boringssl runs the unit/integration test suite with the boringssl backend.
# We test each backend-aware crate explicitly (workspace-level `cargo test` cannot
# both disable wolfssl defaults and enable boringssl in one invocation).
test-boringssl:
    FROM +source

    DO lib-rust+CARGO --args="test -p lightway-boring"
    DO lib-rust+CARGO --args="test -p lightway-app-utils --no-default-features --features tokio,boringssl"
    DO lib-rust+CARGO --args="test -p lightway-core --no-default-features --features boringssl"
    DO lib-rust+CARGO --args="test -p lightway-client --no-default-features --features boringssl"
    DO lib-rust+CARGO --args="test -p lightway-server --no-default-features --features boringssl"

    # Run only privileged tests with sudo permissions
    RUN --privileged cargo test --package lightway-client --no-default-features --features boringssl test_privileged -- --ignored

# test-miri runs tests for modules which make use of `unsafe` under Miri.
test-miri:
    FROM +source
    # The libc crate uses integer-to-pointer casts which are not compatible with "strict provenance"
    # (https://doc.rust-lang.org/nightly/std/ptr/index.html#strict-provenance).
    ENV MIRIFLAGS=-Zmiri-permissive-provenance
    # `lightway-app-utils`'s default features do not include a TLS backend
    # (its default is just `tokio`), so we must select one explicitly,
    # otherwise lightway-core's compile_error fires.
    DO lib-rust+CARGO --args="+nightly miri test -p lightway-app-utils --features wolfssl -- iouring sockopt"
    DO lib-rust+CARGO --args="+nightly miri test -p lightway-server --features wolfssl -- io::outside::udp"

# test-cross-arm64-wolfssl cross-compiles to arm64 from an amd64 host with the
# wolfssl backend. It then runs tests via QEMU.
test-cross-arm64-wolfssl:
    FROM +source
    ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
    ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64-static"

    LET target = "aarch64-unknown-linux-gnu"

    DO lib-rust+CARGO --args="test --target=$target -p lightway-core -p lightway-client -p lightway-server -p lightway-app-utils"

    # Run only privileged tests with sudo permissions
    RUN --privileged cargo test --package lightway-client --target=$target test_privileged -- --ignored

# test-cross-riscv64-wolfssl cross-compiles to riscv64 with the wolfssl backend.
test-cross-riscv64-wolfssl:
    FROM +source
    ENV CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="riscv64-linux-gnu-gcc"
    ENV CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="qemu-riscv64-static -L /usr/riscv64-linux-gnu -cpu rv64"

    LET target = "riscv64gc-unknown-linux-gnu"

    DO lib-rust+CARGO --args="test --target=$target -p lightway-core -p lightway-client -p lightway-server -p lightway-app-utils"

    # Run only privileged tests with sudo permissions
    RUN --privileged cargo test --package lightway-client --target=$target test_privileged -- --ignored

# e2e-wolfssl runs all end-to-end tests with the wolfSSL backend, must be run with `--allow-privileged`
e2e-wolfssl:
    BUILD ./tests+run-all-tests-wolfssl --debian=$debian

# e2e-boringssl runs all end-to-end tests with the boringssl backend, must be run with `--allow-privileged`
e2e-boringssl:
    BUILD ./tests+run-all-tests-boringssl --debian=$debian

# cross-compat runs cross-compatibility tests between TLS backends, must be run with `--allow-privileged`
cross-compat:
    BUILD ./tests+run-cross-compat-tests --debian=$debian

# coverage generates a report of code coverage by unit and integration tests via `cargo llvm-cov`
coverage:
    FROM +source
    RUN mkdir /tmp/coverage
    DO lib-rust+SET_CACHE_MOUNTS_ENV
    RUN --mount=$EARTHLY_RUST_CARGO_HOME_CACHE --mount=$EARTHLY_RUST_TARGET_CACHE \
        cargo llvm-cov test --no-report
    
    # Run privileged tests with sudo for coverage
    RUN --privileged --mount=$EARTHLY_RUST_CARGO_HOME_CACHE --mount=$EARTHLY_RUST_TARGET_CACHE \
        cargo llvm-cov test --package lightway-client test_privileged --no-report -- --ignored
    
    # Generate final coverage report including all tests
    RUN --mount=$EARTHLY_RUST_CARGO_HOME_CACHE --mount=$EARTHLY_RUST_TARGET_CACHE \
        cargo llvm-cov report --summary-only --output-path /tmp/coverage/summary.txt && \
        cargo llvm-cov report --json --output-path /tmp/coverage/coverage.json && \
        cargo llvm-cov report --html --output-dir /tmp/coverage/

    SAVE ARTIFACT /tmp/coverage/*

# fmt checks whether Rust code is formatted according to style guidelines
fmt:
    FROM +source
    DO lib-rust+CARGO --args="fmt --check"

# lint runs cargo clippy on the source code
lint:
    FROM +source
    # Lint each TLS backend separately. The crate::tls abstraction requires
    # exactly one of `wolfssl` or `boringssl` to be enabled, so we cannot
    # rely on a single --no-default-features pass.
    DO lib-rust+CARGO --args="clippy -p lightway-client --no-default-features --features wolfssl --all-targets -- -D warnings"
    DO lib-rust+CARGO --args="clippy -p lightway-client --no-default-features --features boringssl --all-targets -- -D warnings"
    # The point of lightway-expresslane is an offload engine that links no TLS
    # stack, so it has to keep building with every backend feature off.
    DO lib-rust+CARGO --args="check -p lightway-expresslane --no-default-features"
    ENV RUSTDOCFLAGS="-D warnings"
    DO lib-rust+CARGO --args="doc --document-private-items"
    # Run lint for shell scripts inside tests/ directory
    COPY --dir tests ./
    RUN find tests -name "*.sh" -print0 | xargs -r0 shellcheck

# check-dependencies lints our dependencies via `cargo deny`
check-dependencies:
    FROM +source
    DO lib-rust+CARGO --args="deny --all-features check --deny warnings bans licenses sources"
