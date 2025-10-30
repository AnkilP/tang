#!/bin/bash
# Basic usage example for Tang server

set -e

echo "Tang Server - Basic Usage Example"
echo "================================="
echo

# Create a temporary directory for keys
KEYS_DIR=$(mktemp -d)
echo "Using keys directory: $KEYS_DIR"
echo

# Generate keys
echo "1. Generating keys..."
cargo run -q -- keygen -d "$KEYS_DIR" --signing
cargo run -q -- keygen -d "$KEYS_DIR"
echo

# List keys
echo "2. Listing active keys:"
cargo run -q -- list -d "$KEYS_DIR"
echo

# Start server in background
echo "3. Starting Tang server on port 9090..."
cargo run -q -- serve -d "$KEYS_DIR" -p 9090 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Test endpoints
echo "4. Testing health endpoint:"
curl -s http://localhost:9090/health
echo
echo

echo "5. Testing advertisement endpoint:"
curl -s http://localhost:9090/adv | jq '.'
echo

# Stop server
echo "6. Stopping server..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true

# Cleanup
rm -rf "$KEYS_DIR"

echo
echo "Example completed successfully!"
