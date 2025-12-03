#!/bin/bash
# stop.sh - Stop all NIDS services

echo "Stopping NIDS services..."

# Stop Docker services
if [ -f "docker-compose.yml" ]; then
    docker-compose down
    echo "✓ Docker services stopped"
fi

# Stop any running Python processes
pkill -f "uvicorn main:app"
pkill -f "packet_analyzer.py"

echo "✓ All services stopped"
