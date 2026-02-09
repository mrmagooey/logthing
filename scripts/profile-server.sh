#!/bin/bash
# Profile the WEF server during performance test

set -e

cd /home/peter/projects/logthing

echo "========================================"
echo "Starting WEF Server with CPU Profiling"
echo "========================================"

# Create profiling directory
mkdir -p profiling-results

# Start server with perf recording in background
echo "Starting server with perf record..."
perf record -g -- ./target/profiling/wef-server &
SERVER_PID=$!

echo "Server PID: $SERVER_PID"
echo "Waiting for server to start..."
sleep 5

echo ""
echo "========================================"
echo "Running Performance Test"
echo "========================================"

# Run performance test
cd tests/e2e/simulation-environment
docker compose run --rm performance-test-max-throughput 2>&1 | tee ../../../profiling-results/test-output.txt

echo ""
echo "========================================"
echo "Stopping Server and Generating Profile"
echo "========================================"

# Stop the server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

cd /home/peter/projects/logthing

# Generate flamegraph
echo "Generating flamegraph..."
perf script | ./target/release/inferno-collapse-perf 2>/dev/null | ./target/release/inferno-flamegraph > profiling-results/flamegraph.svg 2>/dev/null || \
    (echo "Generating report with perf..." && perf report --stdio --sort=dso,symbol | head -100 > profiling-results/perf-report.txt)

echo ""
echo "Profiling complete!"
echo "Results saved to profiling-results/"
