#!/bin/bash

# Threat Intelligence Dashboard - Startup Script
# This script starts both the backend and frontend servers

echo "🚀 Starting Threat Intelligence Dashboard..."

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
echo "📚 Installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Creating with default values..."
    cat > .env << 'EOF'
ABUSEIPDB_KEY=86a775e65f9962f4869a00066f96c463e7a1fcc116309b06f7815a1608bf27b39da8bad2ec78bf2f
VIRUSTOTAL_KEY=5d7a690b2e10fa0e60e1b614197dd4df2cb8eea8e1e1a0a05f97cd1c8e3d0a1b
ALIENVAULT_KEY=aa449386110c52ad8f44b1d87c3cbdac
GREYNOISE_KEY=566c39ce-81ba-47f1-b8d8-3e3f8a8c9d4e
EOF
fi

# Start backend in background
echo "🔧 Starting Backend Server (port 5001)..."
python backend.py > /tmp/threat_dashboard_backend.log 2>&1 &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 2

# Check if backend started successfully
if ! ps -p $BACKEND_PID > /dev/null; then
    echo "❌ Backend failed to start. Check /tmp/threat_dashboard_backend.log"
    exit 1
fi

echo "✅ Backend Server is running (PID: $BACKEND_PID)"

# Start frontend in background
echo "🌐 Starting Frontend Server (port 8000)..."
python3 -m http.server 8000 > /tmp/threat_dashboard_frontend.log 2>&1 &
FRONTEND_PID=$!

# Wait a moment for frontend to start
sleep 1

# Check if frontend started successfully
if ! ps -p $FRONTEND_PID > /dev/null; then
    echo "❌ Frontend failed to start. Check /tmp/threat_dashboard_frontend.log"
    kill $BACKEND_PID
    exit 1
fi

echo "✅ Frontend Server is running (PID: $FRONTEND_PID)"

echo ""
echo "============================================"
echo "✅ Dashboard is ready!"
echo "============================================"
echo ""
echo "🌍 Open in browser: http://localhost:8000"
echo ""
echo "📊 Backend API: http://localhost:5001"
echo ""
echo "To stop the servers, press Ctrl+C"
echo ""

# Keep script running
trap "kill $BACKEND_PID $FRONTEND_PID; exit" SIGINT SIGTERM

# Wait for both processes
wait $BACKEND_PID $FRONTEND_PID
