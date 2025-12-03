#!/bin/bash
# start.sh - Quick start script for development

echo "Starting NIDS in development mode..."

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "✓ Virtual environment activated"
else
    echo "✗ Virtual environment not found. Run deploy.sh first."
    exit 1
fi

# Start API in background
echo "Starting API server..."
uvicorn main:app --reload --host 0.0.0.0 --port 8000 &
API_PID=$!

# Wait for API to start
sleep 3

# Check if API is running
if curl -s http://localhost:8000/ > /dev/null; then
    echo "✓ API server running on http://localhost:8000"
    echo "✓ API docs available at http://localhost:8000/docs"
else
    echo "✗ Failed to start API server"
    kill $API_PID 2>/dev/null
    exit 1
fi

echo ""
echo "NIDS is running!"
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for interrupt
trap "kill $API_PID 2>/dev/null; echo 'Services stopped'; exit 0" INT
wait
