#!/bin/bash
# update.sh - Update NIDS system

echo "Updating NIDS system..."

# Pull latest code
git pull origin main

# Update dependencies
source venv/bin/activate
pip install --upgrade -r requirements.txt

# Rebuild Docker images
docker-compose build

# Restart services
docker-compose down
docker-compose up -d

echo "✓ System updated successfully"
