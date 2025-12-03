# nips_engine.py - Network Intrusion Prevention System Engine

import subprocess
import platform
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Set, Optional
import logging
import json

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class NIPSEngine:
    """Network Intrusion Prevention System - Active threat blocking and mitigation"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize NIPS Engine

        Args:
            config: Configuration dictionary with prevention policies
        """
        self.config = config or self._default_config()
        self.platform = platform.system().lower()

        # Tracking structures
        self.blocked_ips: Set[str] = set()
        self.whitelist: Set[str] = set(['127.0.0.1', 'localhost'])
        self.blacklist: Set[str] = set()
        self.temp_blocks: Dict[str, datetime] = {}  # IP -> unblock_time
        self.block_history: deque = deque(maxlen=1000)
        self.threat_scores: Dict[str, int] = defaultdict(int)  # IP -> threat score

        # Rate limiting
        self.connection_tracker: Dict[str, List[float]] = defaultdict(list)

        # Statistics
        self.stats = {
            'total_blocks': 0,
            'active_blocks': 0,
            'auto_unblocks': 0,
            'manual_blocks': 0,
            'prevented_attacks': defaultdict(int)
        }

        # Auto-unblock thread
        self.is_running = True
        self.unblock_thread = threading.Thread(target=self._auto_unblock_loop, daemon=True)
        self.unblock_thread.start()

        logger.info(f"[NIPS] Initialized on {self.platform.upper()}")
        logger.info(f"[NIPS] Auto-blocking: {self.config['auto_block_enabled']}")
        logger.info(f"[NIPS] Block duration: {self.config['default_block_duration_minutes']} minutes")

    def _default_config(self) -> Dict:
        """Default NIPS configuration"""
        return {
            'auto_block_enabled': True,
            'default_block_duration_minutes': 30,
            'permanent_block_threshold': 5,  # After 5 blocks, make it permanent
            'threat_score_threshold': 100,  # Block when score exceeds this
            'rate_limit_window_seconds': 10,
            'rate_limit_threshold': 50,  # Max connections per window

            # Per-threat-type policies
            'threat_policies': {
                'Port Scan': {
                    'action': 'block',
                    'duration_minutes': 60,
                    'threat_score': 50
                },
                'SYN Flood': {
                    'action': 'block',
                    'duration_minutes': 120,
                    'threat_score': 100
                },
                'DDoS Attempt': {
                    'action': 'block',
                    'duration_minutes': 180,
                    'threat_score': 150
                },
                'Brute Force': {
                    'action': 'block',
                    'duration_minutes': 90,
                    'threat_score': 80
                },
                'SQL Injection': {
                    'action': 'block',
                    'duration_minutes': 240,
                    'threat_score': 120
                },
                'Suspicious Port Access': {
                    'action': 'rate_limit',
                    'duration_minutes': 30,
                    'threat_score': 30
                },
                'Malware Traffic': {
                    'action': 'block',
                    'duration_minutes': 360,
                    'threat_score': 200
                }
            }
        }

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist (supports CIDR notation)"""
        if ip in self.whitelist:
            return True

        # Check CIDR ranges
        try:
            from ipaddress import ip_address, ip_network
            ip_obj = ip_address(ip)
            for whitelist_entry in self.whitelist:
                if '/' in whitelist_entry:  # CIDR notation
                    try:
                        network = ip_network(whitelist_entry, strict=False)
                        if ip_obj in network:
                            return True
                    except:
                        continue
        except:
            pass

        return False

    def process_threat(self, threat_data: Dict) -> Dict:
        """
        Process detected threat and take prevention action

        Args:
            threat_data: {
                'source_ip': str,
                'threat_type': str,
                'severity': str,
                'confidence': float,
                'destination_ip': str,
                'port': int
            }

        Returns:
            Action result dictionary
        """
        if not self.config['auto_block_enabled']:
            return {'action': 'none', 'reason': 'auto_block_disabled'}

        source_ip = threat_data.get('source_ip')
        threat_type = threat_data.get('threat_type', 'Unknown')
        severity = threat_data.get('severity', 'Medium')

        # Check whitelist (with CIDR support)
        if self._is_whitelisted(source_ip):
            logger.warning(f"[NIPS] Threat from WHITELISTED IP {source_ip} - NOT blocking")
            return {'action': 'none', 'reason': 'whitelisted'}

        # Check if already blocked
        if source_ip in self.blocked_ips:
            logger.debug(f"[NIPS] IP {source_ip} already blocked")
            return {'action': 'already_blocked', 'reason': 'already_blocked'}

        # Get threat policy
        policy = self.config['threat_policies'].get(
            threat_type,
            {'action': 'log', 'duration_minutes': 30, 'threat_score': 50}
        )

        # Update threat score
        self.threat_scores[source_ip] += policy['threat_score']
        current_score = self.threat_scores[source_ip]

        logger.info(f"[NIPS] Threat detected: {threat_type} from {source_ip} | Score: {current_score}")

        # Decide action based on score and policy
        action_taken = None

        if current_score >= self.config['threat_score_threshold'] or policy['action'] == 'block':
            # BLOCK the IP
            duration_minutes = policy['duration_minutes']

            # Check for permanent block
            block_count = self._get_block_count(source_ip)
            if block_count >= self.config['permanent_block_threshold']:
                duration_minutes = None  # Permanent block
                logger.warning(f"[NIPS] PERMANENT BLOCK for {source_ip} (blocked {block_count} times)")

            result = self.block_ip(source_ip, duration_minutes, threat_type)
            action_taken = result

        elif policy['action'] == 'rate_limit':
            # RATE LIMIT the IP
            result = self.rate_limit_ip(source_ip)
            action_taken = result

        else:
            # Just LOG
            logger.info(f"[NIPS] Logging threat from {source_ip} (no active prevention)")
            action_taken = {'action': 'log', 'ip': source_ip}

        # Update statistics
        if action_taken and action_taken.get('action') == 'blocked':
            self.stats['prevented_attacks'][threat_type] += 1

        return action_taken

    def block_ip(self, ip: str, duration_minutes: Optional[int] = None, reason: str = "") -> Dict:
        """
        Block an IP address using system firewall

        Args:
            ip: IP address to block
            duration_minutes: Block duration (None = permanent)
            reason: Reason for blocking

        Returns:
            Result dictionary
        """
        if self._is_whitelisted(ip):
            logger.warning(f"[NIPS] Cannot block WHITELISTED IP: {ip}")
            return {'action': 'error', 'reason': 'ip_whitelisted'}

        if ip in self.blocked_ips:
            return {'action': 'error', 'reason': 'already_blocked'}

        # Execute platform-specific block command
        success = False
        if self.platform == 'windows':
            success = self._block_ip_windows(ip)
        elif self.platform == 'linux':
            success = self._block_ip_linux(ip)
        elif self.platform == 'darwin':  # macOS
            success = self._block_ip_macos(ip)

        if success:
            self.blocked_ips.add(ip)
            self.stats['total_blocks'] += 1
            self.stats['active_blocks'] += 1

            # Set auto-unblock time
            if duration_minutes:
                unblock_time = datetime.now() + timedelta(minutes=duration_minutes)
                self.temp_blocks[ip] = unblock_time
                logger.info(f"[NIPS] ✅ BLOCKED {ip} for {duration_minutes}min | Reason: {reason}")
            else:
                logger.warning(f"[NIPS] 🔒 PERMANENTLY BLOCKED {ip} | Reason: {reason}")

            # Add to history
            self.block_history.append({
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'duration_minutes': duration_minutes,
                'reason': reason,
                'permanent': duration_minutes is None
            })

            return {
                'action': 'blocked',
                'ip': ip,
                'duration_minutes': duration_minutes,
                'permanent': duration_minutes is None
            }
        else:
            logger.error(f"[NIPS] ❌ Failed to block {ip}")
            return {'action': 'error', 'reason': 'firewall_command_failed'}

    def _block_ip_windows(self, ip: str) -> bool:
        """Block IP on Windows using netsh"""
        try:
            rule_name = f"NIPS_Block_{ip.replace('.', '_')}"

            # Check if rule already exists
            check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
            result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)

            if "No rules match" not in result.stdout:
                logger.debug(f"[NIPS] Firewall rule already exists for {ip}")
                return True

            # Create inbound block rule
            cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            # Create outbound block rule
            cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip}'

            result_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
            result_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True)

            return "Ok." in result_in.stdout and "Ok." in result_out.stdout

        except Exception as e:
            logger.error(f"[NIPS] Windows block error: {e}")
            return False

    def _block_ip_linux(self, ip: str) -> bool:
        """Block IP on Linux using iptables"""
        try:
            # Add to INPUT chain (incoming)
            cmd_in = f"sudo iptables -I INPUT -s {ip} -j DROP"
            # Add to OUTPUT chain (outgoing)
            cmd_out = f"sudo iptables -I OUTPUT -d {ip} -j DROP"

            result_in = subprocess.run(cmd_in, shell=True, capture_output=True)
            result_out = subprocess.run(cmd_out, shell=True, capture_output=True)

            return result_in.returncode == 0 and result_out.returncode == 0

        except Exception as e:
            logger.error(f"[NIPS] Linux block error: {e}")
            return False

    def _block_ip_macos(self, ip: str) -> bool:
        """Block IP on macOS using pfctl"""
        try:
            # Add to pf table
            cmd = f"echo 'block drop from {ip} to any' | sudo pfctl -a nips -f -"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            return result.returncode == 0

        except Exception as e:
            logger.error(f"[NIPS] macOS block error: {e}")
            return False

    def unblock_ip(self, ip: str) -> Dict:
        """
        Unblock an IP address

        Args:
            ip: IP address to unblock

        Returns:
            Result dictionary
        """
        if ip not in self.blocked_ips:
            return {'action': 'error', 'reason': 'not_blocked'}

        success = False
        if self.platform == 'windows':
            success = self._unblock_ip_windows(ip)
        elif self.platform == 'linux':
            success = self._unblock_ip_linux(ip)
        elif self.platform == 'darwin':
            success = self._unblock_ip_macos(ip)

        if success:
            self.blocked_ips.remove(ip)
            if ip in self.temp_blocks:
                del self.temp_blocks[ip]
            self.stats['active_blocks'] -= 1

            logger.info(f"[NIPS] 🔓 UNBLOCKED {ip}")
            return {'action': 'unblocked', 'ip': ip}
        else:
            return {'action': 'error', 'reason': 'firewall_command_failed'}

    def _unblock_ip_windows(self, ip: str) -> bool:
        """Unblock IP on Windows"""
        try:
            rule_name = f"NIPS_Block_{ip.replace('.', '_')}"
            cmd_in = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"'

            subprocess.run(cmd_in, shell=True, capture_output=True)
            subprocess.run(cmd_out, shell=True, capture_output=True)
            return True

        except Exception as e:
            logger.error(f"[NIPS] Windows unblock error: {e}")
            return False

    def _unblock_ip_linux(self, ip: str) -> bool:
        """Unblock IP on Linux"""
        try:
            cmd_in = f"sudo iptables -D INPUT -s {ip} -j DROP"
            cmd_out = f"sudo iptables -D OUTPUT -d {ip} -j DROP"

            subprocess.run(cmd_in, shell=True, capture_output=True)
            subprocess.run(cmd_out, shell=True, capture_output=True)
            return True

        except Exception as e:
            logger.error(f"[NIPS] Linux unblock error: {e}")
            return False

    def _unblock_ip_macos(self, ip: str) -> bool:
        """Unblock IP on macOS"""
        try:
            cmd = f"echo 'pass from {ip} to any' | sudo pfctl -a nips -f -"
            subprocess.run(cmd, shell=True, capture_output=True)
            return True

        except Exception as e:
            logger.error(f"[NIPS] macOS unblock error: {e}")
            return False

    def rate_limit_ip(self, ip: str) -> Dict:
        """
        Apply rate limiting to an IP

        Args:
            ip: IP address to rate limit

        Returns:
            Action result
        """
        now = time.time()
        window = self.config['rate_limit_window_seconds']
        threshold = self.config['rate_limit_threshold']

        # Clean old entries
        self.connection_tracker[ip] = [
            t for t in self.connection_tracker[ip]
            if now - t < window
        ]

        # Add current connection
        self.connection_tracker[ip].append(now)

        # Check if exceeds threshold
        if len(self.connection_tracker[ip]) > threshold:
            logger.warning(f"[NIPS] Rate limit exceeded for {ip} - BLOCKING")
            return self.block_ip(ip, 15, "Rate limit exceeded")

        return {'action': 'rate_limited', 'ip': ip, 'count': len(self.connection_tracker[ip])}

    def _auto_unblock_loop(self):
        """Background thread to auto-unblock IPs after duration expires"""
        while self.is_running:
            try:
                now = datetime.now()
                to_unblock = []

                for ip, unblock_time in list(self.temp_blocks.items()):
                    if now >= unblock_time:
                        to_unblock.append(ip)

                for ip in to_unblock:
                    self.unblock_ip(ip)
                    self.stats['auto_unblocks'] += 1
                    logger.info(f"[NIPS] Auto-unblocked {ip} after timeout")

                time.sleep(5)  # Check every 5 seconds

            except Exception as e:
                logger.error(f"[NIPS] Auto-unblock error: {e}")
                time.sleep(10)

    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist (never block)"""
        self.whitelist.add(ip)
        # Unblock if currently blocked
        if ip in self.blocked_ips:
            self.unblock_ip(ip)
        logger.info(f"[NIPS] Added {ip} to WHITELIST")

    def add_to_blacklist(self, ip: str):
        """Add IP to blacklist (always block permanently)"""
        self.blacklist.add(ip)
        self.block_ip(ip, None, "Manual blacklist")
        logger.warning(f"[NIPS] Added {ip} to BLACKLIST (permanent)")

    def remove_from_whitelist(self, ip: str):
        """Remove IP from whitelist"""
        if ip in self.whitelist:
            self.whitelist.remove(ip)
            logger.info(f"[NIPS] Removed {ip} from WHITELIST")

    def remove_from_blacklist(self, ip: str):
        """Remove IP from blacklist"""
        if ip in self.blacklist:
            self.blacklist.remove(ip)
            self.unblock_ip(ip)
            logger.info(f"[NIPS] Removed {ip} from BLACKLIST")

    def _get_block_count(self, ip: str) -> int:
        """Get number of times IP has been blocked"""
        return sum(1 for entry in self.block_history if entry['ip'] == ip)

    def get_stats(self) -> Dict:
        """Get NIPS statistics"""
        return {
            **self.stats,
            'blocked_ips': list(self.blocked_ips),
            'temp_blocks': {
                ip: time.isoformat()
                for ip, time in self.temp_blocks.items()
            },
            'whitelist': list(self.whitelist),
            'blacklist': list(self.blacklist),
            'recent_blocks': list(self.block_history)[-20:]
        }

    def shutdown(self):
        """Shutdown NIPS engine"""
        logger.info("[NIPS] Shutting down...")
        self.is_running = False
        if self.unblock_thread.is_alive():
            self.unblock_thread.join(timeout=2)


# Example usage
if __name__ == "__main__":
    # Initialize NIPS
    nips = NIPSEngine()

    # Simulate threat detection
    threat = {
        'source_ip': '192.168.1.100',
        'threat_type': 'Port Scan',
        'severity': 'High',
        'confidence': 0.95,
        'destination_ip': '10.0.0.1',
        'port': 22
    }

    result = nips.process_threat(threat)
    print(f"Action taken: {result}")

    # Get stats
    stats = nips.get_stats()
    print(f"NIPS Stats: {json.dumps(stats, indent=2)}")