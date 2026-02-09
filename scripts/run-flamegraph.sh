#!/bin/bash
# Run cargo flamegraph for profiling

cd /home/peter/projects/logthing

# Kill any existing server
pkill -f wef-server || true
sleep 1

echo "Running server with flamegraph profiling..."
echo "This will take about 70 seconds..."

# Run with cargo flamegraph - it will automatically profile and generate SVG
timeout 70 cargo flamegraph --profile profiling --root -- --config tests/e2e/simulation-environment/config/wef-server-10k-sustained.toml 2>&1 | tee /tmp/flamegraph-run.log &
SERVER_PID=$!

sleep 10

echo "Running performance test..."
cd tests/e2e/simulation-environment
docker compose run --rm performance-test-max-throughput 2>&1 | tail -20

echo "Waiting for flamegraph to complete..."
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "Flamegraph saved to: /home/peter/projects/logthing/flamegraph.svg"
