#!/bin/bash
# Test script for the Generic Event Parser
# This script demonstrates how the parser works with sample Windows events

echo "================================"
echo "Generic Event Parser Test Suite"
echo "================================"
echo ""

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found. Please install Rust."
    exit 1
fi

echo "1. Running parser tests..."
echo "   Testing Event 4624 (Successful Logon)"
echo "   Testing Event 4668 (S4U2Self)"
echo "   Testing edge cases (unsupported events, missing fields)"
echo ""

# Run the tests
cargo test --lib parser::tests -- --nocapture

echo ""
echo "================================"
echo "Test Results Summary"
echo "================================"
echo ""
echo "If all tests passed, the generic parser framework is working correctly!"
echo ""
echo "Configuration file location: config/event_parsers.yaml"
echo ""
echo "Supported Events:"
echo "  - 4624: Successful Logon"
echo "  - 4668: S4U2Self"
echo ""
echo "To add new event parsers, edit config/event_parsers.yaml"
echo "and add a new entry under 'event_parsers:'"