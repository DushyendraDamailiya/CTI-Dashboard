#!/usr/bin/env bash
set -euo pipefail

# Start the backend API and static frontend for local development.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BACKEND_PORT="${BACKEND_PORT:-5001}"
FRONTEND_PORT="${FRONTEND_PORT:-8000}"

echo "Starting Threat Intelligence Dashboard"
echo "Project: $SCRIPT_DIR"

if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

echo "Installing Python dependencies..."
pip install -r requirements.txt

if [ ! -f ".env" ]; then
    echo ".env not found. Creating it from .env.example."
    if [ -f ".env.example" ]; then
        cp .env.example .env
    else
        touch .env
    fi
    echo "Add your API keys to .env before using external threat-intel scans."
fi

cleanup() {
    echo ""
    echo "Stopping servers..."
    kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "Starting backend on http://localhost:${BACKEND_PORT}"
python backend.py > /tmp/threat_dashboard_backend.log 2>&1 &
BACKEND_PID=$!

sleep 2
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "Backend failed to start. Check /tmp/threat_dashboard_backend.log"
    exit 1
fi

echo "Starting frontend on http://localhost:${FRONTEND_PORT}"
python3 -m http.server "$FRONTEND_PORT" > /tmp/threat_dashboard_frontend.log 2>&1 &
FRONTEND_PID=$!

sleep 1
if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    echo "Frontend failed to start. Check /tmp/threat_dashboard_frontend.log"
    exit 1
fi

echo ""
echo "Dashboard is ready:"
echo "- Frontend: http://localhost:${FRONTEND_PORT}"
echo "- Backend:  http://localhost:${BACKEND_PORT}"
echo ""
echo "Press Ctrl+C to stop both servers."

wait "$BACKEND_PID" "$FRONTEND_PID"
