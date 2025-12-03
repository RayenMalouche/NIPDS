# packet_analyzer.py - Packet Capture and ML-based Detection Engine

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import pickle
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json


class PacketCapture:
    """Real-time packet capture and preprocessing"""

    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packets_buffer = deque(maxlen=10000)
        self.is_running = False
        self.capture_thread = None

    def start_capture(self):
        """Start packet capture in background thread"""
        self.is_running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        print(f"[+] Started packet capture on {self.interface}")

    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        print("[+] Stopped packet capture")

    def _capture_loop(self):
        """Background packet capture loop"""
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            print(f"[!] Capture error: {e}")

    def _process_packet(self, packet):
        """Process and store captured packet"""
        if IP in packet:
            packet_info = self._extract_features(packet)
            self.packets_buffer.append(packet_info)

    def _extract_features(self, packet):
        """Extract features from packet for ML analysis"""
        features = {
            'timestamp': time.time(),
            'src_ip': packet[IP].src if IP in packet else None,
            'dst_ip': packet[IP].dst if IP in packet else None,
            'protocol': packet[IP].proto if IP in packet else None,
            'length': len(packet),
            'ttl': packet[IP].ttl if IP in packet else 0,
            'flags': 0,
            'src_port': 0,
            'dst_port': 0,
            'tcp_flags': 0,
            'window_size': 0,
            'urgent_pointer': 0
        }

        if TCP in packet:
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['tcp_flags'] = int(packet[TCP].flags)
            features['window_size'] = packet[TCP].window
            features['urgent_pointer'] = packet[TCP].urgptr

        elif UDP in packet:
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport

        return features

    def get_recent_packets(self, n=100):
        """Get n most recent packets"""
        return list(self.packets_buffer)[-n:]


class FeatureExtractor:
    """Extract statistical features for ML models"""

    def __init__(self, window_size=100):
        self.window_size = window_size
        self.ip_tracker = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'ports': set(), 'last_seen': 0})

    def extract_flow_features(self, packets):
        """Extract flow-based features from packet sequence"""
        if not packets:
            return None

        df = pd.DataFrame(packets)

        features = {
            # Basic statistics
            'packet_count': len(packets),
            'avg_packet_size': df['length'].mean(),
            'std_packet_size': df['length'].std(),
            'max_packet_size': df['length'].max(),
            'min_packet_size': df['length'].min(),

            # Protocol distribution
            'tcp_ratio': (df['protocol'] == 6).sum() / len(packets),
            'udp_ratio': (df['protocol'] == 17).sum() / len(packets),
            'icmp_ratio': (df['protocol'] == 1).sum() / len(packets),

            # Port analysis
            'unique_dst_ports': df['dst_port'].nunique(),
            'unique_src_ports': df['src_port'].nunique(),
            'common_ports': self._check_common_ports(df),

            # TTL statistics
            'avg_ttl': df['ttl'].mean(),
            'std_ttl': df['ttl'].std(),

            # TCP flags (if applicable)
            'syn_count': (df['tcp_flags'] & 0x02).sum(),
            'ack_count': (df['tcp_flags'] & 0x10).sum(),
            'fin_count': (df['tcp_flags'] & 0x01).sum(),
            'rst_count': (df['tcp_flags'] & 0x04).sum(),

            # Timing features
            'time_window': df['timestamp'].max() - df['timestamp'].min() if len(df) > 1 else 0,
            'packet_rate': len(packets) / max((df['timestamp'].max() - df['timestamp'].min()), 1),
        }

        return features

    def _check_common_ports(self, df):
        """Check if common service ports are being accessed"""
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3389, 8080]
        return df['dst_port'].isin(common_ports).sum() / len(df)

    def update_ip_statistics(self, packet):
        """Update per-IP statistics for anomaly detection"""
        src_ip = packet.get('src_ip')
        if src_ip:
            stats = self.ip_tracker[src_ip]
            stats['packets'] += 1
            stats['bytes'] += packet.get('length', 0)
            stats['ports'].add(packet.get('dst_port', 0))
            stats['last_seen'] = packet.get('timestamp', 0)


class MLDetectionEngine:
    """Machine Learning based intrusion detection"""

    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.feature_names = []
        self.is_trained = False

    def train_models(self, X_train, y_train):
        """Train multiple ML models for detection"""
        print("[+] Training detection models...")

        # Scale features
        X_scaled = self.scaler.fit_transform(X_train)

        # Random Forest for classification
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.models['random_forest'].fit(X_scaled, y_train)

        # Isolation Forest for anomaly detection
        self.models['isolation_forest'] = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        self.models['isolation_forest'].fit(X_scaled)

        self.is_trained = True
        print("[+] Models trained successfully")

    def predict(self, features):
        """Predict if traffic is malicious"""
        if not self.is_trained:
            return {'threat': False, 'confidence': 0.0, 'type': 'Unknown'}

        # Convert features to array
        feature_vector = self._features_to_vector(features)
        feature_scaled = self.scaler.transform([feature_vector])

        # Random Forest prediction
        rf_pred = self.models['random_forest'].predict(feature_scaled)[0]
        rf_proba = self.models['random_forest'].predict_proba(feature_scaled)[0]

        # Isolation Forest anomaly score
        if_pred = self.models['isolation_forest'].predict(feature_scaled)[0]
        if_score = self.models['isolation_forest'].score_samples(feature_scaled)[0]

        # Combine predictions
        is_threat = (rf_pred == 1) or (if_pred == -1)
        confidence = max(rf_proba) if rf_pred == 1 else abs(if_score)

        # Determine threat type based on features
        threat_type = self._classify_threat_type(features) if is_threat else 'Normal'

        return {
            'threat': bool(pred[0] == 1),
            'type': 'ML Anomaly',
            'confidence': float(prob[0][1]),
            'prediction': pred,
            'probabilities': prob
        }

    def _features_to_vector(self, features):
        """Convert feature dict to vector"""
        return [
            features['packet_count'],
            features['avg_packet_size'],
            features['std_packet_size'],
            features['max_packet_size'],
            features['tcp_ratio'],
            features['udp_ratio'],
            features['unique_dst_ports'],
            features['unique_src_ports'],
            features['avg_ttl'],
            features['syn_count'],
            features['packet_rate']
        ]

    def _classify_threat_type(self, features):
        """Classify type of threat based on features"""
        # Port scanning detection
        if features['unique_dst_ports'] > 50:
            return 'Port Scan'

        # DDoS detection
        if features['packet_rate'] > 1000:
            return 'DDoS Attempt'

        # Brute force detection
        if features['syn_count'] > features['packet_count'] * 0.8:
            return 'Brute Force'

        # SQL injection (common ports)
        if features.get('dst_port') in [3306, 5432, 1433]:
            return 'SQL Injection Attempt'

        return 'Suspicious Activity'

    def save_models(self, filepath='models/nids_model.pkl'):
        """Save trained models to disk"""
        model_data = {
            'models': self.models,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"[+] Models saved to {filepath}")

    def load_models(self, filepath='models/nids_model.pkl'):
        """Load trained models from disk"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            self.models = model_data['models']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.is_trained = True
            print(f"[+] Models loaded from {filepath}")
        except Exception as e:
            print(f"[!] Error loading models: {e}")


class RuleBasedDetector:
    """Rule-based detection for known attack patterns"""

    def __init__(self):
        self.rules = self._initialize_rules()
        self.connection_tracker = defaultdict(lambda: {'count': 0, 'first_seen': 0})

    def _initialize_rules(self):
        """Define detection rules"""
        return {
            'port_scan': {
                'description': 'Multiple ports accessed from single source',
                'threshold': 20,
                'time_window': 60
            },
            'syn_flood': {
                'description': 'Excessive SYN packets without ACK',
                'threshold': 100,
                'time_window': 10
            },
            'ping_flood': {
                'description': 'ICMP flood attack',
                'threshold': 50,
                'time_window': 5
            },
            'suspicious_port': {
                'description': 'Access to commonly exploited ports',
                'ports': [23, 135, 139, 445, 3389, 5900]
            }
        }

    def detect(self, packets):
        """Apply rule-based detection"""
        alerts = []

        if not packets:
            return alerts

        # Port scan detection
        src_ips = defaultdict(set)
        for pkt in packets:
            src_ips[pkt.get('src_ip', '')].add(pkt.get('dst_port', 0))

        for src_ip, ports in src_ips.items():
            if len(ports) > self.rules['port_scan']['threshold']:
                alerts.append({
                    'type': 'Port Scan',
                    'severity': 'High',
                    'source': src_ip,
                    'description': f'Port scan detected: {len(ports)} ports accessed',
                    'confidence': 0.95
                })

        # SYN flood detection
        syn_count = sum(1 for pkt in packets if pkt.get('tcp_flags', 0) & 0x02)
        if syn_count > self.rules['syn_flood']['threshold']:
            alerts.append({
                'type': 'SYN Flood',
                'severity': 'Critical',
                'description': f'SYN flood detected: {syn_count} SYN packets',
                'confidence': 0.90
            })

        return alerts


# Example usage and testing
if __name__ == "__main__":
    print("[+] NIDS Packet Analyzer Initialized")
    print("[+] Components:")
    print("    - Packet Capture Engine")
    print("    - Feature Extractor")
    print("    - ML Detection Engine")
    print("    - Rule-Based Detector")
    print("\n[!] Note: Run with sudo/root privileges for packet capture")