#!/bin/bash
# Script to run Logthing server with profiling

# Change to repo root (parent of scripts directory)
cd "$(dirname "$0")/.."

# Set environment variables
export RUST_LOG=info
export WEF__FORWARDING__DESTINATIONS__0__URL=s3://wef-events/archive
export WEF__FORWARDING__DESTINATIONS__0__PROTOCOL=http
export WEF__FORWARDING__DESTINATIONS__0__ENABLED=true
export WEF__FORWARDING__DESTINATIONS__0__HEADERS__ENDPOINT=http://minio:9000
export WEF__FORWARDING__DESTINATIONS__0__HEADERS__REGION=us-east-1
export WEF__FORWARDING__DESTINATIONS__0__HEADERS__ACCESS_KEY=miniouser
export WEF__FORWARDING__DESTINATIONS__0__HEADERS__SECRET_KEY=miniopassword
export WEF__FORWARDING__DESTINATIONS__0__HEADERS__MAX_SIZE_MB=100
export WEF__FORWARDING__DESTINATIONS__0__HEADERS__FLUSH_INTERVAL_SECS=60
export WEF__FORWARDING__BUFFER_SIZE=100000
export WEF__SYSLOG__ENABLED=false

# Create temp directory for buffers
mkdir -p /tmp/wef-events

# Run server with profiling
echo "Starting Logthing server with profiling..."
exec ./target/profiling/logthing
