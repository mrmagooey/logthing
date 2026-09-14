# Builds the `loadgen` load generator from the repo root, so the container
# drives the real wire formats the Rust crate emits rather than a Python
# re-implementation that could drift from them.
#
# Separate from the root Dockerfile (which builds the `logthing` server)
# because this image needs only the one binary from the `tools/loadgen`
# workspace member. COPY is selective for the same reason the root Dockerfile's
# is: cargo validates every workspace member and [[bench]] target path when it
# *parses* the manifest, so all of them must be present even though only
# -p loadgen is built. See tests/docker_build_context_integration.rs.
FROM rust:1.93-slim-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tools ./tools
COPY benches ./benches
RUN cargo build --release -p loadgen

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/loadgen /usr/local/bin/loadgen
ENTRYPOINT ["loadgen"]
