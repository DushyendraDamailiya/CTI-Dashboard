#!/usr/bin/env python3
"""
Real-Time Attack Detector
Monitors system logs for suspicious activity and sends alerts to the dashboard.
"""

import ipaddress
import os
import re
import socket
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv

# Load environment configuration if present
load_dotenv()

BACKEND_URL = os.getenv("ATTACK_BACKEND_URL", "http://localhost:5001")
ALERT_INGEST_TOKEN = os.getenv("ALERT_INGEST_TOKEN")
SCAN_INTERVAL = int(os.getenv("ATTACK_SCAN_INTERVAL", "2"))
ALLOW_PRIVATE_IPS = os.getenv("ATTACK_ALLOW_PRIVATE_IPS", "true").lower() in ("1", "true", "yes")
IPV4_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
BEACON_WINDOW = timedelta(minutes=1)
BEACON_THRESHOLD = 3

# Default to attack_detector.log on Windows or syslog on Linux/macOS
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
    "win_failed_login": {
        # Windows Security Event 4625 failed logons & syslog equivalents
        "pattern": rf"(?:Event ID 4625|An account failed to log on|Logon Failure).*?(?:Source Network Address:\s*|from\s+)(?P<attacker_ip>{IPV4_PATTERN})",
        "name": "Windows Failed Logon Burst",
        "severity": "high",
    },
    "rdp_bruteforce": {
        # RDP connection failure / brute force
        "pattern": rf"(?:RDP|Terminal Server|TermDD).*?(?:failed|rejected|error|invalid).*?(?:from\s+|ip\s+)?(?P<attacker_ip>{IPV4_PATTERN})",
        "name": "RDP Brute Force Attempt",
        "severity": "high",
    },
    "port_scan": {
        # Detects UFW BLOCK or iptables BLOCK
        "pattern": rf"(UFW BLOCK|iptables.*BLOCK).*SRC=(?P<attacker_ip>{IPV4_PATTERN})",
        "name": "Port Scan Detected",
        "severity": "medium",
    },
    "nmap_scan": {
        # Detects Nmap stealth / SYN scan signatures
        "pattern": rf"(?:Nmap scan|SYN stealth scan|portscan|SCAN).*?(?:from|SRC=)?\s*(?P<attacker_ip>{IPV4_PATTERN})",
        "name": "Nmap Network Scan Detected",
        "severity": "medium",
    },
    "ping_sweep": {
        # Detects ICMP echo requests in firewall/syslog formats
        "pattern": r"(ICMP echo request|PROTO=ICMP)",
        "name": "Ping Sweep Detected",
        "severity": "medium",
    },
    "web_sqli": {
        # SQL injection attempts in web/access logs
        "pattern": r"(?:UNION(?:\s+ALL)?\s+SELECT|\bOR\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?|\bOR\s+1=1\b|SLEEP\(\d+\)|WAITFOR DELAY|BENCHMARK\(\d+)",
        "name": "SQL Injection Attempt",
        "severity": "critical",
    },
    "web_traversal": {
        # Directory / path traversal attempts
        "pattern": r"(?:\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|win\.ini|boot\.ini)",
        "name": "Directory Traversal Attack",
        "severity": "high",
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

    def is_valid_attacker_ip(self, value):
        """Validate attacker IPv4 addresses before alerting."""
        try:
            parsed = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return False
        if parsed.version != 4:
            return False
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast or parsed.is_reserved:
            return False
        return ALLOW_PRIVATE_IPS or parsed.is_global

    def is_valid_public_ipv4(self, value):
        """Alias for backwards compatibility."""
        return self.is_valid_attacker_ip(value)

    def extract_attacker_ip(self, line, match, local_ip=None):
        """Extract the source IPv4 address from common log formats."""
        groupdict = match.groupdict() if match else {}
        if groupdict.get("attacker_ip") and self.is_valid_attacker_ip(groupdict["attacker_ip"]):
            return groupdict["attacker_ip"]

        if match:
            for group in match.groups():
                if (
                    group
                    and isinstance(group, str)
                    and self.is_valid_attacker_ip(group)
                    and (not local_ip or group != local_ip)
                ):
                    return group

        source_match = re.search(
            rf"\b(?:SRC|src|from|client|rip|rhost|remote|address|ip)=?\s*(?P<ip>{IPV4_PATTERN})\b",
            line,
            re.IGNORECASE,
        )
        if (
            source_match
            and self.is_valid_attacker_ip(source_match.group("ip"))
            and (not local_ip or source_match.group("ip") != local_ip)
        ):
            return source_match.group("ip")

        # Fallback: scan all IPs in the line, picking the first non-local, valid IP
        all_ips = re.findall(rf"\b{IPV4_PATTERN}\b", line)
        for ip in all_ips:
            if (not local_ip or ip != local_ip) and self.is_valid_attacker_ip(ip):
                return ip

        return None

    def parse_log_line(self, line, local_ip):
        """Parse a log line and return attack metadata when matched."""
        if not line or not line.strip():
            return None

        clean_line = line.strip()
        for attack_type, config in ATTACK_PATTERNS.items():
            match = re.search(config["pattern"], clean_line, re.IGNORECASE)
            if not match:
                continue

            attacker_ip = self.extract_attacker_ip(clean_line, match, local_ip)
            if not attacker_ip or attacker_ip in {local_ip, "127.0.0.1"}:
                continue

            return {
                "type": attack_type,
                "name": config["name"],
                "severity": config["severity"],
                "attacker_ip": attacker_ip,
                "timestamp": datetime.now().isoformat(),
                "target_ip": local_ip,
                "log_line": clean_line[:200],
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
            headers = {}
            if ALERT_INGEST_TOKEN:
                headers["X-Alert-Token"] = ALERT_INGEST_TOKEN
            response = requests.post(
                f"{BACKEND_URL}/api/receive-alert",
                json=attack_data,
                headers=headers,
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
        print(f"[info] Lab/Private IP Alerts: {'Enabled' if ALLOW_PRIVATE_IPS else 'Disabled (Public Only)'}")
        print("=" * 50)

        # Ensure local log file exists on Windows so users can append test lines easily
        if not os.path.exists(self.log_file):
            try:
                with open(self.log_file, "a", encoding="utf-8"):
                    pass
            except OSError:
                pass

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
