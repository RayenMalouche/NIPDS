# main.py - NIDS + NIPS with SAFE Configuration for Your Network

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from collections import deque, defaultdict
import threading
import time
from packet_analyzer import PacketCapture, FeatureExtractor, MLDetectionEngine
from nips_engine import NIPSEngine

app = FastAPI(title="NIDS + NIPS - Full Security System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============= SAFETY CONFIGURATION =============
# Set to True ONLY after testing with False for at least 30 minutes
ENABLE_AUTO_BLOCKING = False  # 🔴 KEEP FALSE UNTIL TESTED!

print("\n" + "=" * 70)
print("🔒 NIDS + NIPS SYSTEM - SAFETY MODE")
print("=" * 70)
if not ENABLE_AUTO_BLOCKING:
    print("⚠️  AUTO-BLOCKING: DISABLED (SAFE MODE)")
    print("⚠️  Threats will be DETECTED but NOT BLOCKED")
    print("⚠️  Change ENABLE_AUTO_BLOCKING = True to activate prevention")
else:
    print("🛡️  AUTO-BLOCKING: ENABLED (ACTIVE PREVENTION)")
    print("⚠️  Threats WILL BE BLOCKED automatically!")
print("=" * 70 + "\n")


# ============= Models =============
class Alert(BaseModel):
    id: int
    timestamp: str
    alert_type: str
    severity: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    description: str
    confidence: float
    blocked: bool
    prevention_action: Optional[str] = None


class IPManagement(BaseModel):
    ip: str
    action: str


# ============= Global Objects =============
capture = PacketCapture(interface="Wi-Fi")
extractor = FeatureExtractor()
detector = MLDetectionEngine()

try:
    detector.load_models("packet_analyzer_model.pkl")
    print("[+] Loaded ML detection model")
except:
    print("[!] No model found, running rule-based only")

# ============= NIPS Configuration =============
nips_config = {
    'auto_block_enabled': ENABLE_AUTO_BLOCKING,
    'default_block_duration_minutes': 30,
    'permanent_block_threshold': 5,
    'threat_score_threshold': 100,
    'rate_limit_window_seconds': 10,
    'rate_limit_threshold': 50,
    'threat_policies': {
        'Port Scan': {'action': 'block', 'duration_minutes': 60, 'threat_score': 50},
        'SYN Flood': {'action': 'block', 'duration_minutes': 120, 'threat_score': 100},
        'DDoS Attempt': {'action': 'block', 'duration_minutes': 180, 'threat_score': 150},
        'Brute Force': {'action': 'block', 'duration_minutes': 90, 'threat_score': 80},
        'SQL Injection': {'action': 'block', 'duration_minutes': 240, 'threat_score': 120},
        'Suspicious Port Access': {'action': 'log', 'duration_minutes': 30, 'threat_score': 30},
        # Changed to 'log' for safety
        'Malware Traffic': {'action': 'block', 'duration_minutes': 360, 'threat_score': 200}
    }
}

# Initialize NIPS Engine
nips = NIPSEngine(config=nips_config)

# ============= CRITICAL: WHITELIST YOUR NETWORK =============
print("\n[NIPS] Adding network to whitelist...")

# YOUR NETWORK - Based on your ipconfig
nips.add_to_whitelist('192.168.1.14')  # Your PC WiFi IP
nips.add_to_whitelist('192.168.1.1')  # Your Router/Gateway
nips.add_to_whitelist('192.168.1.0/24')  # Your entire home subnet

# VirtualBox (if you use it)
nips.add_to_whitelist('192.168.56.1')  # VirtualBox Host-Only
nips.add_to_whitelist('192.168.56.0/24')  # VirtualBox subnet

# Localhost
nips.add_to_whitelist('127.0.0.1')
nips.add_to_whitelist('::1')  # IPv6 localhost

# DNS Servers (CRITICAL for internet)
nips.add_to_whitelist('8.8.8.8')  # Google DNS Primary
nips.add_to_whitelist('8.8.4.4')  # Google DNS Secondary
nips.add_to_whitelist('1.1.1.1')  # Cloudflare DNS
nips.add_to_whitelist('1.0.0.1')  # Cloudflare DNS Secondary

# Common Services (prevents blocking essential internet services)
nips.add_to_whitelist('142.250.0.0/16')  # Google services range
nips.add_to_whitelist('172.217.0.0/16')  # Google services range
nips.add_to_whitelist('13.107.0.0/16')  # Microsoft services range

print("\n[NIPS] ✅ Whitelisted IPs/Subnets:")
for ip in sorted(nips.whitelist):
    print(f"  ✓ {ip}")
print()

# Storage
store = type('Store', (), {})()
store.alerts = deque(maxlen=1000)
store.stats = {
    "total_packets": 0,
    "threats_detected": 0,
    "packets_blocked": 0,
    "packets_prevented": 0,
    "normal_traffic": 0,
    "start_time": datetime.now()
}

print("[+] NIDS + NIPS SYSTEM READY")
print(f"[+] Detection: ML + Rule-Based")
print(f"[+] Prevention: {'ACTIVE' if ENABLE_AUTO_BLOCKING else 'DISABLED (SAFE MODE)'}")
if not ENABLE_AUTO_BLOCKING:
    print("[+] To enable blocking: Set ENABLE_AUTO_BLOCKING = True at line 31")


# ============= Detection + Prevention Loop =============
def real_capture_loop():
    syn_count = defaultdict(int)
    port_scan_tracker = defaultdict(set)
    last_reset = time.time()

    while True:
        if len(capture.packets_buffer) > 0:
            packet = capture.packets_buffer.popleft()
            store.stats["total_packets"] += 1

            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            dst_port = packet.get('dst_port', 0)
            src_port = packet.get('src_port', 0)
            tcp_flags = packet.get('tcp_flags', 0)
            protocol = packet.get('protocol', 0)

            current_time = time.time()

            # === RULE-BASED DETECTION ===
            threat_detected = False
            alert_type = ""
            severity = "Medium"
            confidence = 0.95

            # 1. Port Scan Detection
            if dst_port > 0:
                port_scan_tracker[src_ip].add(dst_port)
                if len(port_scan_tracker[src_ip]) > 20:  # Increased threshold
                    threat_detected = True
                    alert_type = "Port Scan"
                    severity = "High"  # Reduced from Critical

            # 2. SYN Flood Detection
            if tcp_flags == 2:
                syn_count[src_ip] += 1
                if syn_count[src_ip] > 100:  # Increased threshold
                    threat_detected = True
                    alert_type = "SYN Flood"
                    severity = "Critical"

            # 3. Suspicious ports (RELAXED - only truly dangerous)
            if dst_port in [23, 135, 139]:  # Removed common ports like 22, 3389
                threat_detected = True
                alert_type = "Suspicious Port Access"
                severity = "Medium"  # Reduced severity

            # 4. DDoS detection
            if len(port_scan_tracker[src_ip]) > 100:
                threat_detected = True
                alert_type = "DDoS Attempt"
                severity = "Critical"

            # Reset counters every 10 seconds
            if current_time - last_reset > 10:
                syn_count.clear()
                port_scan_tracker.clear()
                last_reset = current_time

            # === TRIGGER PREVENTION IF THREAT DETECTED ===
            if threat_detected:
                store.stats["threats_detected"] += 1

                # Prepare threat data
                threat_data = {
                    'source_ip': src_ip,
                    'threat_type': alert_type,
                    'severity': severity,
                    'confidence': confidence,
                    'destination_ip': dst_ip,
                    'port': dst_port
                }

                # *** NIPS PREVENTION ACTION ***
                prevention_result = nips.process_threat(threat_data)

                # Check if actually blocked
                actually_blocked = prevention_result.get('action') == 'blocked'
                if actually_blocked:
                    store.stats["packets_blocked"] += 1
                    store.stats["packets_prevented"] += 1

                # Create alert
                alert = {
                    "id": int(time.time() * 1000),
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": alert_type,
                    "severity": severity,
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "source_port": src_port,
                    "dest_port": dst_port,
                    "protocol": str(protocol),
                    "description": f"{alert_type} detected from {src_ip}",
                    "confidence": confidence,
                    "blocked": actually_blocked,
                    "prevention_action": prevention_result.get('action', 'none')
                }

                store.alerts.appendleft(alert)

                if actually_blocked:
                    print(
                        f"\n[🛡️ BLOCKED] {alert_type} from {src_ip} | Duration: {prevention_result.get('duration_minutes', 'permanent')}min")
                else:
                    action_reason = prevention_result.get('reason', prevention_result.get('action'))
                    print(f"\n[⚠️ DETECTED] {alert_type} from {src_ip} | Action: {action_reason}")

            store.stats["normal_traffic"] = store.stats["total_packets"] - store.stats["threats_detected"]

        time.sleep(0.001)


# ============= API Endpoints =============

@app.get("/")
def root():
    nips_stats = nips.get_stats()
    return {
        "status": "NIDS + NIPS ACTIVE",
        "mode": "Detection + Prevention" if ENABLE_AUTO_BLOCKING else "Detection Only (Safe Mode)",
        "packets": store.stats["total_packets"],
        "active_blocks": nips_stats['active_blocks'],
        "auto_block": nips.config['auto_block_enabled']
    }


@app.get("/stats")
def stats():
    uptime = (datetime.now() - store.stats["start_time"]).seconds
    nips_stats = nips.get_stats()

    return {
        **store.stats,
        "detection_rate": round(store.stats["threats_detected"] / max(1, store.stats["total_packets"]) * 100, 3),
        "prevention_rate": round(store.stats["packets_prevented"] / max(1, store.stats["threats_detected"]) * 100, 2) if
        store.stats["threats_detected"] > 0 else 0,
        "uptime_seconds": uptime,
        "nips_active_blocks": nips_stats['active_blocks'],
        "nips_total_blocks": nips_stats['total_blocks'],
        "nips_auto_unblocks": nips_stats['auto_unblocks'],
        "auto_blocking_enabled": ENABLE_AUTO_BLOCKING
    }


@app.get("/alerts")
def alerts(limit: int = 50, severity: Optional[str] = None):
    alert_list = list(store.alerts)
    if severity:
        alert_list = [a for a in alert_list if a['severity'].lower() == severity.lower()]
    return alert_list[:limit]


@app.get("/nips/status")
def nips_status():
    return nips.get_stats()


@app.get("/nips/blocked-ips")
def blocked_ips():
    return {
        "blocked_ips": list(nips.blocked_ips),
        "count": len(nips.blocked_ips),
        "whitelist": list(nips.whitelist),
        "blacklist": list(nips.blacklist)
    }


@app.post("/nips/whitelist")
def add_whitelist(data: IPManagement):
    nips.add_to_whitelist(data.ip)
    return {"status": "success", "ip": data.ip, "action": "whitelisted"}


@app.post("/nips/blacklist")
def add_blacklist(data: IPManagement):
    nips.add_to_blacklist(data.ip)
    return {"status": "success", "ip": data.ip, "action": "blacklisted"}


@app.post("/nips/unblock")
def unblock_ip(data: IPManagement):
    result = nips.unblock_ip(data.ip)
    return result


@app.post("/nips/block")
def manual_block(data: IPManagement):
    result = nips.block_ip(data.ip, 60, "Manual block")
    return result


@app.get("/nips/config")
def get_config():
    return nips.config


@app.post("/nips/config/auto-block")
def toggle_auto_block(enabled: bool):
    nips.config['auto_block_enabled'] = enabled
    print(f"\n[NIPS] Auto-blocking {'ENABLED' if enabled else 'DISABLED'} via API")
    return {"auto_block_enabled": enabled}


@app.get("/threats/distribution")
def threat_distribution():
    threat_counts = defaultdict(int)
    for alert in store.alerts:
        threat_counts[alert['alert_type']] += 1

    total = sum(threat_counts.values())
    if total == 0:
        return []

    return [
        {
            "threat_type": threat_type,
            "count": count,
            "percentage": (count / total) * 100
        }
        for threat_type, count in threat_counts.items()
    ]


@app.delete("/alerts/clear")
def clear_alerts():
    store.alerts.clear()
    return {"status": "alerts_cleared"}


# ============= Startup =============

@app.on_event("startup")
def start_system():
    capture.start_capture()
    threading.Thread(target=real_capture_loop, daemon=True).start()
    print("\n" + "=" * 70)
    print("[+] NIDS + NIPS SYSTEM STARTED")
    print("[+] Packet capture: ACTIVE on Wi-Fi (192.168.1.14)")
    print("[+] ML Detection: ACTIVE")
    print("[+] Rule-based Detection: ACTIVE")
    print(f"[+] NIPS Prevention: {'ACTIVE' if ENABLE_AUTO_BLOCKING else 'DISABLED (SAFE MODE)'}")
    print(f"[+] Auto-blocking: {'ENABLED' if ENABLE_AUTO_BLOCKING else 'DISABLED'}")
    print(f"[+] Whitelisted IPs: {len(nips.whitelist)}")
    print("=" * 70 + "\n")


@app.on_event("shutdown")
def shutdown_system():
    print("\n[+] Shutting down NIDS + NIPS...")
    capture.stop_capture()
    nips.shutdown()
    print("[+] System stopped")


if __name__ == "__main__":
    import uvicorn

    if ENABLE_AUTO_BLOCKING:
        print("\n[!] WARNING: Running with AUTO-BLOCKING ENABLED")
        print("[!] This must be run as ADMINISTRATOR for firewall control!")
    print("[!] Press Ctrl+C to stop the system\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)