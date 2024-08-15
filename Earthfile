VERSION 0.8
ARG --global debian = bookworm

# Using commit hash pinning because git tags can be changed
# Ref: https://github.com/earthly/lib/tree/3.0.3
IMPORT github.com/earthly/lib/rust:a49d2a0f4028cd15666d19904f8fc5fbd0b9ba87 AS lib-rust

install-build-dependencies:
    FROM rust:1.80.1-$debian
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
        shellcheck

    DO lib-rust+INIT --keep_fingerprints=true
    DO lib-rust+CARGO --args="install --locked cargo-deny cargo-llvm-cov"
    RUN rustup component add clippy
    RUN rustup component add rustfmt
    RUN rustup component add llvm-tools-preview
    RUN rustup target add aarch64-unknown-linux-gnu

source:
    FROM +install-build-dependencies
    COPY --keep-ts Cargo.toml Cargo.lock ./
    COPY --keep-ts deny.toml ./
    COPY --keep-ts --dir lightway-core lightway-app-utils lightway-client lightway-server .cargo ./

    RUN --no-cache date \
     && find lightway-core lightway-app-utils lightway-client lightway-server -ls
    RUN --no-cache grep -r ServerAuth .

# build builds with the Cargo release profile
build:
    FROM +source
    ARG ARCH=$(dpkg --print-architecture)
    LET target = "x86_64-unknown-linux-gnu"

    IF [ "$ARCH" = "arm64" ]
        SET target = "aarch64-unknown-linux-gnu" 
    END

    DO lib-rust+CARGO --args="build --release --target=$target" --output="$target/release/lightway-(client|server)$"

    SAVE ARTIFACT ./target/$target/release/lightway-client AS LOCAL ./target/$target/release/
    SAVE ARTIFACT ./target/$target/release/lightway-server AS LOCAL ./target/$target/release/

# build-arm64 build for arm64. Support building from an amd64 or arm64 host
build-arm64:
    BUILD +build --ARCH="arm64"

# test executes all unit and integration tests via Cargo, in the host's native platform
test:
    FROM +source
    ARG ARCH=$(dpkg --print-architecture)
    LET target = "x86_64-unknown-linux-gnu"

    IF [ "$ARCH" = "arm64" ]
        SET target = "aarch64-unknown-linux-gnu" 
    END

    DO lib-rust+CARGO --args="test --target=$target"

# test-arm64 executes all unit and integration tests via Cargo for arm64. Support running from an amd64 or arm64 host
test-arm64:
    BUILD +test --ARCH="arm64"

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
