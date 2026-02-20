VERSION 0.8
ARG --global debian = bookworm

# Using commit hash pinning because git tags can be changed
# Ref: https://github.com/earthly/lib/tree/3.0.3
IMPORT github.com/earthly/lib/rust:a49d2a0f4028cd15666d19904f8fc5fbd0b9ba87 AS lib-rust

install-build-dependencies:
    FROM rust:1.93.1-$debian
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
    DO lib-rust+CARGO --args="install --locked cargo-deny cargo-llvm-cov cargo-make"
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
    COPY --keep-ts --dir lightway-core lightway-app-utils lightway-client lightway-server tests ./

# build runs cargo to build native binaries for the host platform.
# You may use `--platform linux/[amd64|arm64]` to override the host platform, to natively compile in emulation.
build:
    FROM +source

    DO lib-rust+CARGO --args="build --release --features io-uring" --output="release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/release/lightway-client AS LOCAL ./target/release/
    SAVE ARTIFACT ./target/release/lightway-server AS LOCAL ./target/release/

# build-cross-arm64 cross-compiles to arm64 from an amd64 host.
build-cross-arm64:
    FROM +source
    LET target = "aarch64-unknown-linux-gnu"
    ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"

    DO lib-rust+CARGO --args="build --release --features io-uring --target=$target" --output="$target/release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/$target/release/lightway-client AS LOCAL ./target/$target/release/
    SAVE ARTIFACT ./target/$target/release/lightway-server AS LOCAL ./target/$target/release/

# build-cross-riscv64 cross-compiles to riscv64 from an amd64 or arm64 host.
build-cross-riscv64:
    FROM +source
    LET target = "riscv64gc-unknown-linux-gnu"
    ENV CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="riscv64-linux-gnu-gcc"

    DO lib-rust+CARGO --args="build --release --features io-uring --target=$target" --output="$target/release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/$target/release/lightway-client AS LOCAL ./target/$target/release/
    SAVE ARTIFACT ./target/$target/release/lightway-server AS LOCAL ./target/$target/release/

build-kyber-client:
    FROM +source
    DO lib-rust+CARGO --args="build --release --features kyber_only --bin lightway-client --target-dir ./lightway-client-kyber" --output="lightway-client-kyber/release/lightway-client"
    SAVE ARTIFACT ./lightway-client-kyber/release/lightway-client AS LOCAL ./target/release/lightway-client-kyber

# test runs cargo to compile all unit and integration tests, natively for the host platform.
# You may use `--platform linux/[amd64|arm64]` to override the host platform, to natively compile in emulation.
test:
    FROM +source

    # Run all tests except privileged tests
    DO lib-rust+CARGO --args="test"
    DO lib-rust+CARGO --args="test --features kyber_only"

    # Run only privileged tests with sudo permissions
    RUN --privileged cargo test --package lightway-client test_privileged -- --ignored

# test-miri runs tests for modules which make use of `unsafe` under Miri.
test-miri:
    FROM +source
    # The libc crate uses integer-to-pointer casts which are not compatible with "strict provenance"
    # (https://doc.rust-lang.org/nightly/std/ptr/index.html#strict-provenance).
    ENV MIRIFLAGS=-Zmiri-permissive-provenance
    DO lib-rust+CARGO --args="+nightly miri test -p lightway-app-utils -- iouring sockopt"
    DO lib-rust+CARGO --args="+nightly miri test -p lightway-server -- io::outside::udp"

# test-cross-arm64 cross-compiles to arm64 from an amd64 host. It then runs tests via QEMU.
test-cross-arm64:
    FROM +source
    LET target = "aarch64-unknown-linux-gnu"
    ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
    ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64-static"

    # Run all tests except privileged tests
    DO lib-rust+CARGO --args="test --target=$target"
    DO lib-rust+CARGO --args="test --features kyber_only --target=$target"

    # Run only privileged tests with sudo permissions
    RUN --privileged cargo test --package lightway-client --target=$target test_privileged -- --ignored

# test-cross-riscv64 cross-compiles to riscv64 from an amd64 or arm64 host. It then runs tests via QEMU.
test-cross-riscv64:
    FROM +source
    LET target = "riscv64gc-unknown-linux-gnu"
    ENV CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="riscv64-linux-gnu-gcc"
    ENV CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="qemu-riscv64-static -L /usr/riscv64-linux-gnu -cpu rv64"

    # Run all tests except privileged tests
    DO lib-rust+CARGO --args="test --target=$target"
    DO lib-rust+CARGO --args="test --features kyber_only --target=$target"

    # Run only privileged tests with sudo permissions
    RUN --privileged cargo test --package lightway-client --target=$target test_privileged -- --ignored

# e2e runs all end-to-end tests, must be run with `--allow-privileged`
e2e:
    BUILD ./tests+run-all-tests --debian=$debian

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
    DO lib-rust+CARGO --args="clippy -p lightway-client --no-default-features --all-targets -- -D warnings"
    ENV RUSTDOCFLAGS="-D warnings"
    DO lib-rust+CARGO --args="doc --document-private-items"
    # Run lint for shell scripts inside tests/ directory
    COPY --dir tests ./
    RUN find tests -name "*.sh" -print0 | xargs -r0 shellcheck

# check-dependencies lints our dependencies via `cargo deny`
check-dependencies:
    FROM +source
    DO lib-rust+CARGO --args="deny --all-features check --deny warnings bans license sources"
