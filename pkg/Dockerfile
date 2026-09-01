# Dockerfile — distroless static image for the `atom` binary (G4 Foundry)
# Build context: repo root (where Cargo.toml lives)

# 1. Builder stage — compile in a full Rust toolchain
FROM rust:1.80-slim AS builder
WORKDIR /app

# Install musl for static linking
RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY cli cli
COPY sdk sdk
RUN mkdir -p cli/atom-cli/src && echo 'fn main() {}' > cli/atom-cli/src/main.rs
RUN cargo build --release -p atom-cli 2>&1 | tail -5 || true
RUN rm cli/atom-cli/src/main.rs

# Copy actual source and build
COPY . .
RUN cargo build --release -p atom-cli --locked

# 2. Runtime stage — distroless static
FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/target/release/atom /usr/local/bin/atom
# Durable ATOM HTTP control plane. Override the bind address with
# ATOM_SERVE_ADDR and mount /var/lib/atom so its SQLite ledger survives a
# container replacement. The signing identity is supplied at runtime.
EXPOSE 8420
VOLUME ["/var/lib/atom"]
ENTRYPOINT ["/usr/local/bin/atom"]
CMD ["serve", "--state-db", "/var/lib/atom/atom.sqlite"]
