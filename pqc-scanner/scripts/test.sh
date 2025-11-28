#!/bin/bash
# PQC Scanner - Test Script
#
# Runs all tests including unit tests and integration tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR/src/pqc-scanner"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    PQC Scanner Test Suite                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Run unit tests
echo "🧪 Running unit tests..."
cargo test --lib -- --nocapture
echo ""

# Run integration tests
echo "🔗 Running integration tests..."
cargo test --test '*' -- --nocapture
echo ""

# Run doc tests
echo "📚 Running documentation tests..."
cargo test --doc
echo ""

echo "✅ All tests passed!"
