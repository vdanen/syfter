#!/bin/bash
# Run syfter tests
#
# Usage:
#   ./scripts/run-tests.sh              # Run local tests (default)
#   ./scripts/run-tests.sh local        # Run local tests only
#   ./scripts/run-tests.sh server       # Run server tests (requires running server)
#   ./scripts/run-tests.sh server-isolated  # Start test stack and run server tests
#   ./scripts/run-tests.sh all          # Run all tests
#   ./scripts/run-tests.sh quick        # Run quick tests (skip slow)
#   ./scripts/run-tests.sh stack-up     # Start test stack only
#   ./scripts/run-tests.sh stack-down   # Stop test stack

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PODMAN_DIR="$PROJECT_DIR/podman"

cd "$PROJECT_DIR"

# Default server URL for server tests
SERVER_URL="${SYFTER_TEST_SERVER:-http://localhost:8000}"

# Test server URL (isolated stack)
TEST_SERVER_URL="http://localhost:18000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Ensure the complete development environment is installed. The test suite
# imports server modules during collection, so [dev] alone is not sufficient.
ensure_test_dependencies() {
    echo_info "Installing test dependencies (.[all])..."
    python -m pip install -e ".[all]"
}

# Start the test stack
start_test_stack() {
    echo_info "Starting test stack on port 18000..."
    cd "$PODMAN_DIR"
    
    # Build and start
    podman-compose -f docker-compose.test.yml up -d --build
    
    # Wait for API to be ready
    echo_info "Waiting for API to be ready..."
    local max_attempts=30
    local attempt=1
    while [ $attempt -le $max_attempts ]; do
        if curl -sf "$TEST_SERVER_URL/health" > /dev/null 2>&1; then
            echo_info "Test stack is ready!"
            return 0
        fi
        echo "  Waiting... ($attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    echo_error "Test stack failed to start"
    podman-compose -f docker-compose.test.yml logs api-test
    return 1
}

# Stop the test stack
stop_test_stack() {
    echo_info "Stopping test stack..."
    cd "$PODMAN_DIR"
    podman-compose -f docker-compose.test.yml down -v
}

MODE="${1:-local}"

case "$MODE" in
    local)
        ensure_test_dependencies
        echo_info "Running local tests (SQLite)..."
        python -m pytest tests/ -m "not server_only" -v
        ;;
    
    server)
        ensure_test_dependencies
        echo_info "Running server tests against $SERVER_URL..."
        
        # Check if server is running
        if ! curl -sf "$SERVER_URL/health" > /dev/null 2>&1; then
            echo_error "Server not running at $SERVER_URL"
            echo_info "Start the server with: cd podman && podman-compose up -d"
            echo_info "Or use 'server-isolated' to start a separate test stack"
            exit 1
        fi
        
        SYFTER_TEST_SERVER="$SERVER_URL" python -m pytest tests/ -m "server_only" -v
        ;;
    
    server-isolated)
        ensure_test_dependencies
        echo_info "Running server tests with isolated test stack..."
        
        # Check if test stack is already running
        STACK_WAS_RUNNING=false
        if curl -sf "$TEST_SERVER_URL/health" > /dev/null 2>&1; then
            echo_info "Test stack already running at $TEST_SERVER_URL"
            STACK_WAS_RUNNING=true
        else
            start_test_stack
        fi
        
        # Run tests (with visible output for seeding)
        echo_info "Running tests (first run will scan a test container, ~1-2 min)..."
        SYFTER_TEST_SERVER="$TEST_SERVER_URL" python -m pytest tests/ -m "server_only" -v -s
        TEST_RESULT=$?
        
        # Clean up: stop the stack if we started it
        if [ "$STACK_WAS_RUNNING" = false ]; then
            echo ""
            echo_info "Cleaning up test stack..."
            stop_test_stack
        else
            echo ""
            echo_info "Test stack was already running, leaving it up."
            echo_info "Stop manually with: $0 stack-down"
        fi
        
        exit $TEST_RESULT
        ;;
    
    all)
        ensure_test_dependencies
        echo_info "Running ALL tests..."
        echo_info "  - Local tests first..."
        python -m pytest tests/ -m "not server_only" -v
        
        echo ""
        echo_info "  - Server tests against $SERVER_URL..."
        if curl -sf "$SERVER_URL/health" > /dev/null 2>&1; then
            SYFTER_TEST_SERVER="$SERVER_URL" python -m pytest tests/ -m "server_only" -v
        else
            echo_warn "Server not running, skipping server tests"
            echo_info "Use 'server-isolated' for isolated server testing"
        fi
        ;;
    
    quick)
        ensure_test_dependencies
        echo_info "Running quick tests (skipping slow)..."
        python -m pytest tests/ -m "not server_only and not slow" -v
        ;;
    
    coverage)
        ensure_test_dependencies
        echo_info "Running tests with coverage..."
        python -m pytest tests/ -m "not server_only" --cov=syfter --cov-report=html --cov-report=term -v
        echo_info "Coverage report: htmlcov/index.html"
        ;;
    
    stack-up)
        echo_info "Starting test stack..."
        start_test_stack
        echo ""
        echo_info "Test stack running at:"
        echo "  API:      $TEST_SERVER_URL"
        echo "  MinIO:    http://localhost:19001 (testadmin/testadmin123)"
        echo "  Postgres: localhost:15432 (syfter_test/syfter_test_secret)"
        echo ""
        echo_info "Run server tests with: $0 server-isolated"
        echo_info "Stop with: $0 stack-down"
        ;;
    
    stack-down)
        stop_test_stack
        echo_info "Test stack stopped"
        ;;
    
    *)
        echo "Usage: $0 [local|server|server-isolated|all|quick|coverage|stack-up|stack-down]"
        echo ""
        echo "Test Modes:"
        echo "  local            Run local tests only (default)"
        echo "  server           Run server tests against existing server"
        echo "  server-isolated  Start test stack and run server tests (port 18000)"
        echo "  all              Run all tests"
        echo "  quick            Run quick tests (skip slow)"
        echo "  coverage         Run with coverage report"
        echo ""
        echo "Stack Management:"
        echo "  stack-up         Start isolated test stack"
        echo "  stack-down       Stop isolated test stack"
        echo ""
        echo "Environment variables:"
        echo "  SYFTER_TEST_SERVER  Server URL for 'server' mode (default: http://localhost:8000)"
        echo ""
        echo "Test stack ports (isolated):"
        echo "  API:        18000"
        echo "  PostgreSQL: 15432"
        echo "  MinIO:      19000/19001"
        exit 1
        ;;
esac

echo ""
echo_info "Tests completed!"
