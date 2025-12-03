#!/bin/bash
# test.sh - Run all tests

echo "Running NIDS test suite..."

# Activate virtual environment
source venv/bin/activate

# Run pytest with coverage
pytest tests/ -v --cov=. --cov-report=html --cov-report=term

echo ""
echo "Coverage report generated in htmlcov/index.html"
