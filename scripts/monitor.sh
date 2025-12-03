#!/bin/bash
# monitor.sh - Real-time monitoring script

watch -n 2 '
echo "=== NIDS System Status ==="
echo ""
echo "API Status:"
curl -s http://localhost:8000/stats | python3 -m json.tool 2>/dev/null || echo "API not responding"
echo ""
echo "Docker Services:"
docker-compose ps 2>/dev/null || echo "Docker not running"
echo ""
echo "Recent Alerts (last 5):"
curl -s "http://localhost:8000/alerts?limit=5" | python3 -m json.tool 2>/dev/null | grep -A 3 "alert_type" | head -15
'
