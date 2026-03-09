# syntax=docker/dockerfile:1-labs
FROM rust:1.86 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    jq \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/ethereum/solidity/releases/download/v0.8.27/solc-static-linux -o /usr/local/bin/solc \
    && chmod +x /usr/local/bin/solc

# Copy workspace files and all crates EXCEPT net
COPY --exclude=crates/net . .

# Make the workspace container-safe when host-only absolute Noir paths are present.
# These crates are not needed by p2p_test, but Cargo still resolves workspace metadata.
RUN mkdir -p /app/.docker-noir-stubs/acir/src /app/.docker-noir-stubs/acvm/src /app/.docker-noir-stubs/bn254_blackbox_solver/src /app/.docker-noir-stubs/nargo/src /app/.docker-noir-stubs/noirc_abi/src && \
    printf '[package]\nname = "acir"\nversion = "0.0.0"\nedition = "2021"\n\n[lib]\npath = "src/lib.rs"\n' > /app/.docker-noir-stubs/acir/Cargo.toml && \
    printf '[package]\nname = "acvm"\nversion = "0.0.0"\nedition = "2021"\n\n[lib]\npath = "src/lib.rs"\n' > /app/.docker-noir-stubs/acvm/Cargo.toml && \
    printf '[package]\nname = "bn254_blackbox_solver"\nversion = "0.0.0"\nedition = "2021"\n\n[lib]\npath = "src/lib.rs"\n' > /app/.docker-noir-stubs/bn254_blackbox_solver/Cargo.toml && \
    printf '[package]\nname = "nargo"\nversion = "0.0.0"\nedition = "2021"\n\n[lib]\npath = "src/lib.rs"\n' > /app/.docker-noir-stubs/nargo/Cargo.toml && \
    printf '[package]\nname = "noirc_abi"\nversion = "0.0.0"\nedition = "2021"\n\n[lib]\npath = "src/lib.rs"\n' > /app/.docker-noir-stubs/noirc_abi/Cargo.toml && \
    touch /app/.docker-noir-stubs/acir/src/lib.rs /app/.docker-noir-stubs/acvm/src/lib.rs /app/.docker-noir-stubs/bn254_blackbox_solver/src/lib.rs /app/.docker-noir-stubs/nargo/src/lib.rs /app/.docker-noir-stubs/noirc_abi/src/lib.rs && \
    sed -i 's|/home/dev/repo/acvm-repo/acir|/app/.docker-noir-stubs/acir|g' ./crates/zk-prover/Cargo.toml && \
    sed -i 's|/home/dev/repo/acvm-repo/acvm|/app/.docker-noir-stubs/acvm|g' ./crates/zk-prover/Cargo.toml && \
    sed -i 's|/home/dev/repo/acvm-repo/bn254_blackbox_solver|/app/.docker-noir-stubs/bn254_blackbox_solver|g' ./crates/zk-prover/Cargo.toml && \
    sed -i 's|/home/dev/repo/tooling/nargo|/app/.docker-noir-stubs/nargo|g' ./crates/zk-prover/Cargo.toml && \
    sed -i 's|/home/dev/repo/tooling/noirc_abi|/app/.docker-noir-stubs/noirc_abi|g' ./crates/zk-prover/Cargo.toml

COPY ./crates/net/Cargo.toml ./crates/net/Cargo.toml
RUN mkdir -p ./crates/net/src/bin && \
    echo "fn main() {}" > ./crates/net/src/main.rs && \
    echo "fn main() {}" > ./crates/net/src/bin/p2p_test.rs

# Build dependencies
RUN cargo build --bin p2p_test

# Copy full net crate
COPY ./crates/net ./crates/net

RUN cargo build --bin p2p_test

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables ca-certificates iputils-ping netcat-traditional && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/debug/p2p_test .
