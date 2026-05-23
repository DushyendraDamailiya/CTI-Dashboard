#!/usr/bin/env python3
"""
Real-Time Attack Detector
Monitors system logs for suspicious activity and sends alerts to the dashboard.
"""

import os
import re
import time
import socket
import threading
from collections import defaultdict
from datetime import datetime, timedelta

import requests

BACKEND_URL = os.getenv("ATTACK_BACKEND_URL", "http://localhost:5001")
SCAN_INTERVAL = int(os.getenv("ATTACK_SCAN_INTERVAL", "2"))
IPV4_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
BEACON_WINDOW = timedelta(minutes=1)
BEACON_THRESHOLD = 3

# Default to syslog for network attacks (Port Scan, Ping Sweep, etc.)
DEFAULT_LOG_FILE = (
    os.getenv("ATTACK_LOG_FILE")
    or (
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack_detector.log")
        if os.name == "nt"
        else "/var/log/syslog"
    )
)

ATTACK_PATTERNS = {
    "ssh_root_bruteforce": {
        "pattern": rf"Failed password for root from (?P<attacker_ip>{IPV4_PATTERN})",
        "name": "SSH Root Brute Force Attack",
        "severity": "critical",
    },
    "ssh_bruteforce": {
        "pattern": rf"Failed password for (?:invalid user )?\S+ from (?P<attacker_ip>{IPV4_PATTERN})",
        "name": "SSH Brute Force Attack",
        "severity": "high",
    },
    "port_scan": {
        # Detects UFW BLOCK or iptables BLOCK
        "pattern": rf"(UFW BLOCK|iptables.*BLOCK).*SRC=(?P<attacker_ip>{IPV4_PATTERN})",
        "name": "Port Scan Detected",
        "severity": "medium",
    },
    "ping_sweep": {
        # Detects ICMP echo requests in firewall/syslog formats.
        "pattern": r"(ICMP echo request|PROTO=ICMP)",
        "name": "Ping Sweep Detected",
        "severity": "medium",
    },
    "login_flood": {
        # Generic failed login (web, ftp, etc.)
        "pattern": r"(Failed|Invalid).*(login|authentication|user|password)",
        "name": "Login Flood Detected",
        "severity": "high",
    },
    "dns_flood": {
        # Detects high frequency DNS queries
        "pattern": r"(query:|query\[|named\[\d+\])",
        "name": "DNS Flood Detected",
        "severity": "medium",
    },
}


class AttackDetector:
    def __init__(self, log_file=DEFAULT_LOG_FILE):
        self.log_file = log_file
        self.last_position = 0
        self.attack_counts = defaultdict(int)
        self.attacks = []

        # Beaconing tracking
        self.beacon_history = defaultdict(list)
        self.beacon_lock = threading.Lock()

        self.lock = threading.Lock()

    def get_local_ip(self):
        """Get the primary local IPv4 address."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    def extract_attacker_ip(self, line, match):
        """Extract the source IPv4 address from common log formats."""
        groupdict = match.groupdict()
        if groupdict.get("attacker_ip"):
            return groupdict["attacker_ip"]

        for group in match.groups():
            if group and re.fullmatch(IPV4_PATTERN, group):
                return group

        source_match = re.search(
            rf"\b(?:SRC|src|from|client|rip|rhost|remote)=?\s*(?P<ip>{IPV4_PATTERN})\b",
            line,
            re.IGNORECASE,
        )
        if source_match:
            return source_match.group("ip")

        ip_match = re.search(rf"\b(?P<ip>{IPV4_PATTERN})\b", line)
        return ip_match.group("ip") if ip_match else None

    def parse_log_line(self, line, local_ip):
        """Parse a log line and return attack metadata when matched."""
        for attack_type, config in ATTACK_PATTERNS.items():
            match = re.search(config["pattern"], line, re.IGNORECASE)
            if not match:
                continue

            attacker_ip = self.extract_attacker_ip(line, match)
            if not attacker_ip or attacker_ip in {local_ip, "127.0.0.1"}:
                continue

            return {
                "type": attack_type,
                "name": config["name"],
                "severity": config["severity"],
                "attacker_ip": attacker_ip,
                "timestamp": datetime.now().isoformat(),
                "target_ip": local_ip,
                "log_line": line.strip()[:200],
            }
        return None

    def read_logs(self):
        """Read only new log entries since the last scan."""
        if not os.path.exists(self.log_file):
            return []

        try:
            file_size = os.path.getsize(self.log_file)
            if self.last_position > file_size:
                self.last_position = 0

            with open(self.log_file, "r", encoding="utf-8", errors="ignore") as handle:
                handle.seek(self.last_position)
                new_lines = handle.readlines()
                self.last_position = handle.tell()
                return new_lines
        except PermissionError:
            print(f"[warn] Permission denied reading {self.log_file}")
        except OSError as exc:
            print(f"[warn] Failed to read log file: {exc}")
        return []

    def detect_beaconing(self, attacker_ip):
        """Detect periodic connections from the same IP."""
        now = datetime.now()
        with self.beacon_lock:
            self.beacon_history[attacker_ip] = [
                t for t in self.beacon_history[attacker_ip]
                if now - t < BEACON_WINDOW
            ]

            self.beacon_history[attacker_ip].append(now)

            if len(self.beacon_history[attacker_ip]) > BEACON_THRESHOLD:
                self.beacon_history[attacker_ip] = []
                return True
        return False

    def process_attack(self, attack_data):
        """Track repeated attempts and send alert."""
        with self.lock:
            key = f"{attack_data['attacker_ip']}_{attack_data['type']}"
            self.attack_counts[key] += 1
            attack_data["attempt_count"] = self.attack_counts[key]
            self.attacks.append(attack_data)
            self.attacks = self.attacks[-100:]

        if self.detect_beaconing(attack_data["attacker_ip"]):
            beacon_alert = {
                "type": "beaconing",
                "name": "Beaconing Detected (Periodic Traffic)",
                "severity": "critical",
                "attacker_ip": attack_data["attacker_ip"],
                "timestamp": datetime.now().isoformat(),
                "target_ip": attack_data["target_ip"],
                "log_line": "Periodic connection pattern detected",
                "attempt_count": 99,
            }
            self.send_alert(beacon_alert)

        self.send_alert(attack_data)

    def send_alert(self, attack_data):
        """Send alert payload to the backend."""
        try:
            response = requests.post(
                f"{BACKEND_URL}/api/receive-alert",
                json=attack_data,
                timeout=5,
            )
            if response.status_code == 200:
                print(f"[ok] {attack_data['name']} from {attack_data['attacker_ip']}")
            else:
                print(f"[error] Failed to send alert: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print("[error] Cannot connect to backend")
        except Exception as exc:
            print(f"[error] Error sending alert: {exc}")

    def start_monitoring(self):
        """Run the monitoring loop."""
        print("[info] Starting Attack Detection Monitor")
        print(f"[info] Monitoring: {self.log_file}")
        print(f"[info] Backend: {BACKEND_URL}")
        local_ip = self.get_local_ip()
        print(f"[info] Local IP: {local_ip}")
        print("=" * 50)

        while True:
            try:
                for line in self.read_logs():
                    attack = self.parse_log_line(line.strip(), local_ip)
                    if attack:
                        self.process_attack(attack)

                time.sleep(SCAN_INTERVAL)
            except KeyboardInterrupt:
                print("\n[info] Stopping Attack Detector")
                break
            except Exception as exc:
                print(f"[warn] Detector loop error: {exc}")
                time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    AttackDetector().start_monitoring()
