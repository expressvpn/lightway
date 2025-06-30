VERSION 0.8
ARG --global debian = bookworm

# Using commit hash pinning because git tags can be changed
# Ref: https://github.com/earthly/lib/tree/3.0.3
IMPORT github.com/earthly/lib/rust:a49d2a0f4028cd15666d19904f8fc5fbd0b9ba87 AS lib-rust

install-build-dependencies:
    FROM rust:1.87.0-$debian
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
    DO lib-rust+CARGO --args="install --locked cargo-deny cargo-llvm-cov"
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
    COPY --keep-ts Cargo.toml Cargo.lock ./
    COPY --keep-ts deny.toml ./
    COPY --keep-ts --dir lightway-core lightway-app-utils lightway-client lightway-server lightway-man .cargo ./

# build builds with the Cargo release profile
build:
    FROM +source
    ARG ARCH=$(dpkg --print-architecture)
    LET target = "x86_64-unknown-linux-gnu"

    IF [ "$ARCH" = "arm64" ]
        SET target = "aarch64-unknown-linux-gnu"
    ELSE IF [ "$ARCH" = "riscv64" ]
        SET target = "riscv64gc-unknown-linux-gnu"
    END

    DO lib-rust+CARGO --args="build --release --features io-uring --target=$target" --output="$target/release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/$target/release/lightway-client AS LOCAL ./target/$target/release/
    SAVE ARTIFACT ./target/$target/release/lightway-server AS LOCAL ./target/$target/release/

# build-arm64 build for arm64. Support building from an amd64 or arm64 host
build-arm64:
    BUILD +build --ARCH="arm64"

build-riscv64:
    BUILD +build --ARCH="riscv64"

build-kyber-client:
    FROM +source
    ARG ARCH=$(dpkg --print-architecture)
    LET target = "x86_64-unknown-linux-gnu"

    IF [ "$ARCH" = "arm64" ]
        SET target = "aarch64-unknown-linux-gnu" 
    ELSE IF [ "$ARCH" = "riscv64" ]
        SET target = "riscv64gc-unknown-linux-gnu"
    END

    DO lib-rust+CARGO --args="build --release --features kyber_only --target=$target --bin lightway-client --target-dir ./lightway-client-kyber" --output="lightway-client-kyber/$target/release/lightway-client"
    SAVE ARTIFACT ./lightway-client-kyber/$target/release/lightway-client AS LOCAL ./target/$target/release/lightway-client-kyber

build-man:
    FROM +source
    DO lib-rust+CARGO --args="run --bin lightway-man"
    SAVE ARTIFACT ./man/lightway-client.1 AS LOCAL ./target/man/
    SAVE ARTIFACT ./man/lightway-server.1 AS LOCAL ./target/man/

# test executes all unit and integration tests via Cargo, in the host's native platform
test:
    FROM +source
    ARG ARCH=$(dpkg --print-architecture)
    LET target = "x86_64-unknown-linux-gnu"

    IF [ "$ARCH" = "arm64" ]
        SET target = "aarch64-unknown-linux-gnu" 
    ELSE IF [ "$ARCH" = "riscv64" ]
        SET target = "riscv64gc-unknown-linux-gnu"
    END

    DO lib-rust+CARGO --args="test --target=$target"
    DO lib-rust+CARGO --args="test --features kyber_only --target=$target"

# test-miri runs tests for modules which make use of `unsafe` under Miri.
test-miri:
    FROM +source
    # The libc crate uses integer-to-pointer casts which are not compatible with "strict provenance"
    # (https://doc.rust-lang.org/nightly/std/ptr/index.html#strict-provenance).
    ENV MIRIFLAGS=-Zmiri-permissive-provenance
    DO lib-rust+CARGO --args="+nightly miri test -p lightway-app-utils -- iouring sockopt"
    DO lib-rust+CARGO --args="+nightly miri test -p lightway-server -- io::outside::udp"

# test-arm64 executes all unit and integration tests via Cargo for arm64. Support running from an amd64 or arm64 host
test-arm64:
    BUILD +test --ARCH="arm64"

# test-riscv64 executes all unit and integration tests via Cargo for riscv64. Support running from an amd64 or arm64 host
test-riscv64:
    BUILD +test --ARCH="riscv64"

# e2e runs all end-to-end tests, must be run with `--allow-privileged`
e2e:
    BUILD ./tests+run-all-tests --debian=$debian

# coverage generates a report of code coverage by unit and integration tests via `cargo llvm-cov`
coverage:
    FROM +source
    RUN mkdir /tmp/coverage
    DO lib-rust+SET_CACHE_MOUNTS_ENV
    RUN --mount=$EARTHLY_RUST_CARGO_HOME_CACHE --mount=$EARTHLY_RUST_TARGET_CACHE \
        cargo llvm-cov test && \
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
    DO lib-rust+CARGO --args="clippy --all-features --all-targets -- -D warnings"
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
