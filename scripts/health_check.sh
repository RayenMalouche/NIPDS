#!/bin/bash
# health_check.sh - System health check

echo "NIDS System Health Check"
echo "========================"
echo ""

# Check API
echo -n "API Service: "
if curl -s http://localhost:8000/ > /dev/null; then
    echo "✓ Running"
else
    echo "✗ Not responding"
fi

# Check MongoDB
echo -n "MongoDB: "
if docker-compose exec -T mongodb mongo --eval "db.version()" > /dev/null 2>&1; then
    echo "✓ Running"
else
    echo "✗ Not running"
fi

# Check Redis
echo -n "Redis: "
if docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; then
    echo "✓ Running"
else
    echo "✗ Not running"
fi

# Check Prometheus
echo -n "Prometheus: "
if curl -s http://localhost:9090/-/healthy > /dev/null; then
    echo "✓ Running"
else
    echo "✗ Not responding"
fi

# Check Grafana
echo -n "Grafana: "
if curl -s http://localhost:3000/api/health > /dev/null; then
    echo "✓ Running"
else
    echo "✗ Not responding"
fi

# Check disk space
echo ""
echo "Disk Usage:"
df -h | grep -E "Filesystem|/$"

# Check memory
echo ""
echo "Memory Usage:"
free -h

echo ""
echo "Health check complete"