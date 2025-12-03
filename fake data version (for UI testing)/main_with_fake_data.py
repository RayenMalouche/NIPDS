# main.py - FastAPI Backend for Network Intrusion Detection System

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict
import asyncio
from datetime import datetime
import json
import numpy as np
from collections import defaultdict, deque
import threading
import time


# ============= Models =============
class Alert(BaseModel):
    id: str
    timestamp: datetime
    alert_type: str
    severity: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_size: int
    description: str
    confidence: float
    blocked: bool


class SystemStats(BaseModel):
    total_packets: int
    threats_detected: int
    alerts_generated: int
    packets_blocked: int
    normal_traffic: int
    detection_rate: float
    false_positive_rate: float


class ThreatDistribution(BaseModel):
    threat_type: str
    count: int
    percentage: float


# ============= In-Memory Storage =============
class DataStore:
    def __init__(self):
        self.alerts = deque(maxlen=1000)
        self.stats = {
            'total_packets': 0,
            'threats_detected': 0,
            'alerts_generated': 0,
            'packets_blocked': 0,
            'normal_traffic': 0,
            'detection_rate': 0.0,
            'false_positive_rate': 0.05
        }
        self.threat_distribution = defaultdict(int)
        self.traffic_history = deque(maxlen=100)
        self.is_monitoring = True


store = DataStore()

# ============= FastAPI App =============
app = FastAPI(title="NIDS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============= API Endpoints =============

@app.get("/")
async def root():
    return {
        "service": "Network Intrusion Detection System",
        "version": "1.0.0",
        "status": "operational",
        "monitoring": store.is_monitoring
    }


@app.get("/stats", response_model=SystemStats)
async def get_stats():
    """Get current system statistics"""
    return SystemStats(**store.stats)


@app.get("/alerts", response_model=List[Alert])
async def get_alerts(limit: int = 50, severity: Optional[str] = None):
    """Get recent alerts with optional severity filter"""
    alerts = list(store.alerts)
    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    return alerts[:limit]


@app.get("/threats/distribution", response_model=List[ThreatDistribution])
async def get_threat_distribution():
    """Get distribution of detected threats"""
    total = sum(store.threat_distribution.values())
    if total == 0:
        return []

    return [
        ThreatDistribution(
            threat_type=threat_type,
            count=count,
            percentage=(count / total) * 100
        )
        for threat_type, count in store.threat_distribution.items()
    ]


@app.get("/traffic/history")
async def get_traffic_history():
    """Get recent traffic history"""
    return list(store.traffic_history)


@app.post("/monitoring/start")
async def start_monitoring():
    """Start packet capture and monitoring"""
    store.is_monitoring = True
    return {"status": "monitoring_started"}


@app.post("/monitoring/stop")
async def stop_monitoring():
    """Stop packet capture and monitoring"""
    store.is_monitoring = False
    return {"status": "monitoring_stopped"}


@app.get("/monitoring/status")
async def get_monitoring_status():
    """Get current monitoring status"""
    return {"monitoring": store.is_monitoring}


@app.delete("/alerts/clear")
async def clear_alerts():
    """Clear all alerts"""
    store.alerts.clear()
    return {"status": "alerts_cleared"}


# ============= Background Monitoring Task =============

async def background_monitoring():
    """Simulates packet capture and analysis"""
    while True:
        if store.is_monitoring:
            # Simulate packet capture
            await asyncio.sleep(2)

            # Generate realistic traffic data
            packets_captured = np.random.randint(100, 500)
            threats_detected = np.random.randint(0, 15)

            # Update statistics
            store.stats['total_packets'] += packets_captured
            store.stats['threats_detected'] += threats_detected
            store.stats['normal_traffic'] += (packets_captured - threats_detected)

            # Update detection rate
            if store.stats['total_packets'] > 0:
                store.stats['detection_rate'] = (
                                                        store.stats['threats_detected'] / store.stats['total_packets']
                                                ) * 100

            # Add traffic history
            store.traffic_history.append({
                'timestamp': datetime.now().isoformat(),
                'packets': packets_captured,
                'threats': threats_detected,
                'normal': packets_captured - threats_detected
            })

            # Generate alerts for detected threats
            if threats_detected > 0:
                threat_types = [
                    'Port Scan', 'DDoS Attempt', 'SQL Injection',
                    'Brute Force', 'Malware Traffic', 'ARP Spoofing',
                    'DNS Tunneling', 'Man-in-the-Middle'
                ]
                severities = ['Low', 'Medium', 'High', 'Critical']
                protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']

                for _ in range(min(threats_detected, 5)):
                    threat_type = np.random.choice(threat_types)
                    severity = np.random.choice(severities, p=[0.1, 0.3, 0.4, 0.2])

                    alert = Alert(
                        id=f"alert_{int(time.time() * 1000)}_{np.random.randint(1000)}",
                        timestamp=datetime.now(),
                        alert_type=threat_type,
                        severity=severity,
                        source_ip=f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                        dest_ip=f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                        source_port=np.random.randint(1024, 65535),
                        dest_port=np.random.choice([80, 443, 22, 21, 3389, 8080]),
                        protocol=np.random.choice(protocols),
                        packet_size=np.random.randint(64, 1500),
                        description=f"Suspicious {threat_type} activity detected",
                        confidence=np.random.uniform(0.7, 0.99),
                        blocked=severity in ['High', 'Critical']
                    )

                    store.alerts.appendleft(alert.dict())
                    store.threat_distribution[threat_type] += 1
                    store.stats['alerts_generated'] += 1

                    if alert.blocked:
                        store.stats['packets_blocked'] += 1
        else:
            await asyncio.sleep(1)


@app.on_event("startup")
async def startup_event():
    """Start background monitoring on startup"""
    asyncio.create_task(background_monitoring())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)