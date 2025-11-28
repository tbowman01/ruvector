#!/bin/bash
# PQC Scanner - Quick Start Script
#
# Usage: ./scripts/start.sh [options]
#
# Options:
#   --build    Rebuild containers before starting
#   --logs     Follow container logs after starting
#   --dev      Start in development mode (local binary)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Parse arguments
BUILD=false
LOGS=false
DEV=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --build)
            BUILD=true
            shift
            ;;
        --logs)
            LOGS=true
            shift
            ;;
        --dev)
            DEV=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           PQC Scanner - Post-Quantum Crypto Scanner           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

if [ "$DEV" = true ]; then
    echo "🔧 Starting in development mode..."
    echo ""
    echo "Building PQC Scanner..."
    cd src/pqc-scanner
    cargo build --release
    echo ""
    echo "Starting PQC Scanner on port 8001..."
    RUST_LOG=info ./target/release/pqc-scanner &
    PQC_PID=$!
    echo "PQC Scanner PID: $PQC_PID"
    echo ""
    echo "Press Ctrl+C to stop"
    wait $PQC_PID
else
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        echo "❌ Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi

    # Determine docker-compose command
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        COMPOSE_CMD="docker-compose"
    fi

    if [ "$BUILD" = true ]; then
        echo "🔨 Building containers..."
        $COMPOSE_CMD build
        echo ""
    fi

    echo "🚀 Starting PQC Scanner stack..."
    $COMPOSE_CMD up -d

    echo ""
    echo "✅ PQC Scanner is starting up!"
    echo ""
    echo "Services:"
    echo "  • Open WebUI:        http://localhost:3000"
    echo "  • MCP Context Forge: http://localhost:4444"
    echo "  • PQC Scanner:       http://localhost:8001"
    echo ""
    echo "Health checks:"
    echo "  • PQC Scanner:       http://localhost:8001/health"
    echo ""

    if [ "$LOGS" = true ]; then
        echo "📋 Following logs (Ctrl+C to stop)..."
        echo ""
        $COMPOSE_CMD logs -f
    else
        echo "To view logs:  $COMPOSE_CMD logs -f"
        echo "To stop:       $COMPOSE_CMD down"
    fi
fi
