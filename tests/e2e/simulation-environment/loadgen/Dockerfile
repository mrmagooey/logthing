# Builds the `loadgen` load generator against the repo root, so the container
# drives the real wire formats the Rust crate emits rather than a Python
# re-implementation that could drift from them.
#
# Separate from the root Dockerfile (which builds the `logthing` server) because
# this image needs only the one binary from the `tools/loadgen` workspace member.
FROM rust:1.93-slim-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p loadgen && cp target/release/loadgen /loadgen

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /loadgen /usr/local/bin/loadgen
ENTRYPOINT ["loadgen"]
