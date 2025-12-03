#!/usr/bin/env python3
# generate_report.py - Generate security report

import requests
import json
from datetime import datetime
import matplotlib.pyplot as plt
from collections import Counter


def generate_report():
    """Generate comprehensive security report"""

    print("Generating NIDS Security Report...")
    print("=" * 50)

    # Fetch data from API
    try:
        stats = requests.get("http://localhost:8000/stats").json()
        alerts = requests.get("http://localhost:8000/alerts?limit=100").json()
        threats = requests.get("http://localhost:8000/threats/distribution").json()
    except Exception as e:
        print(f"Error fetching data: {e}")
        return

    # Generate report
    report_file = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(report_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("NETWORK INTRUSION DETECTION SYSTEM - SECURITY REPORT\n")
        f.write("=" * 70 + "\n\n")

        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Summary Statistics
        f.write("SUMMARY STATISTICS\n")
        f.write("-" * 70 + "\n")
        f.write(f"Total Packets Analyzed:  {stats['total_packets']:,}\n")
        f.write(f"Threats Detected:        {stats['threats_detected']:,}\n")
        f.write(f"Packets Blocked:         {stats['packets_blocked']:,}\n")
        f.write(f"Detection Rate:          {stats['detection_rate']:.2f}%\n")
        f.write(f"False Positive Rate:     {stats['false_positive_rate']:.2f}%\n\n")

        # Threat Distribution
        f.write("THREAT DISTRIBUTION\n")
        f.write("-" * 70 + "\n")
        for threat in threats:
            f.write(f"{threat['threat_type']:<25} {threat['count']:>5} ({threat['percentage']:.1f}%)\n")
        f.write("\n")

        # Recent Alerts
        f.write("RECENT CRITICAL ALERTS\n")
        f.write("-" * 70 + "\n")
        critical_alerts = [a for a in alerts if a.get('severity') == 'Critical'][:10]
        for alert in critical_alerts:
            f.write(f"[{alert['timestamp']}] {alert['alert_type']}\n")
            f.write(f"  Source: {alert['source_ip']} → {alert['dest_ip']}\n")
            f.write(f"  {alert['description']}\n\n")

        # Recommendations
        f.write("RECOMMENDATIONS\n")
        f.write("-" * 70 + "\n")
        if stats['detection_rate'] > 10:
            f.write("⚠ High threat detection rate - Consider reviewing network policies\n")
        if stats['false_positive_rate'] > 10:
            f.write("⚠ High false positive rate - Model retraining recommended\n")
        f.write("\n")

    print(f"✓ Report generated: {report_file}")

    # Generate visualizations
    if threats:
        plt.figure(figsize=(10, 6))
        threat_types = [t['threat_type'] for t in threats]
        threat_counts = [t['count'] for t in threats]

        plt.bar(threat_types, threat_counts)
        plt.xlabel('Threat Type')
        plt.ylabel('Count')
        plt.title('Threat Distribution')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()

        chart_file = f"reports/threat_distribution_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(chart_file)
        print(f"✓ Chart generated: {chart_file}")


if __name__ == "__main__":
    import os

    os.makedirs("reports", exist_ok=True)
    generate_report()
