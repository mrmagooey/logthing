FROM rust:1.93-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo files first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Cargo resolves workspace members and validates every declared target path
# when it *parses* Cargo.toml -- long before it decides what to compile. So
# `tools/` and `benches/` must be present even though `default-members = ["."]`
# means neither is built here. Omitting them fails the build at manifest parse:
#   error: failed to load manifest for workspace member `/app/tools/loadgen`
#   error: can't find `<name>` bench at `benches/<name>.rs`
# tests/docker_build_context_integration.rs enforces that this list stays in
# sync with Cargo.toml.
COPY tools ./tools
COPY benches ./benches

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/logthing /usr/local/bin/logthing

# Copy default config
COPY logthing.toml /etc/logthing/config.toml

# Create directory for certificates
RUN mkdir -p /etc/logthing/certs

# Expose ports
EXPOSE 5985 5986 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:5985/health || exit 1

# Run server
CMD ["logthing"]
