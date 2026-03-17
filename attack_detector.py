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
from datetime import datetime

import requests

BACKEND_URL = os.getenv("ATTACK_BACKEND_URL", "http://localhost:5001")
SCAN_INTERVAL = int(os.getenv("ATTACK_SCAN_INTERVAL", "2"))

DEFAULT_LOG_FILE = (
    os.getenv("ATTACK_LOG_FILE")
    or (
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack_detector.log")
        if os.name == "nt"
        else "/var/log/auth.log"
    )
)

ATTACK_PATTERNS = {
    "ssh_bruteforce": {
        "pattern": r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)",
        "name": "SSH Brute Force Attack",
        "severity": "high",
    },
    "ssh_root_bruteforce": {
        "pattern": r"Failed password for root from (\d+\.\d+\.\d+\.\d+)",
        "name": "SSH Root Brute Force Attack",
        "severity": "critical",
    },
    "multiple_failures": {
        "pattern": r"Failed password for",
        "name": "Multiple Authentication Failures",
        "severity": "medium",
    },
}


class AttackDetector:
    def __init__(self, log_file=DEFAULT_LOG_FILE):
        self.log_file = log_file
        self.last_position = 0
        self.attack_counts = defaultdict(int)
        self.attacks = []
        self.lock = threading.Lock()

    def get_local_ip(self):
        """Get the primary local IPv4 address."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except OSError:
            return "127.0.0.1"

    def parse_log_line(self, line, local_ip):
        """Parse a log line and return attack metadata when matched."""
        for attack_type, config in ATTACK_PATTERNS.items():
            match = re.search(config["pattern"], line)
            if not match:
                continue

            attacker_ip = match.group(2) if (match.lastindex or 0) >= 2 else match.group(1)
            if attacker_ip in {local_ip, "127.0.0.1"}:
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

    def detect_windows_attacks(self):
        """Optional Windows Event Log support when pywin32 is installed."""
        try:
            import win32evtlog  # type: ignore

            server = "localhost"
            logtype = "Security"
            handle = win32evtlog.OpenEventLog(server, logtype)
            flags = (
                win32evtlog.EVENTLOG_SEQUENTIAL_READ
                | win32evtlog.EVENTLOG_BACKWARDS_READ
            )
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            local_ip = self.get_local_ip()

            for event in events[:10]:
                if event.EventType != 10:
                    continue
                message = str(event.StringInserts) if event.StringInserts else ""
                if "failed" not in message.lower() and "logon failure" not in message.lower():
                    continue
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
                if not ip_match:
                    continue
                attacker_ip = ip_match.group(1)
                if attacker_ip == local_ip:
                    continue
                return {
                    "type": "windows_logon_failure",
                    "name": "Windows Logon Failure",
                    "severity": "high",
                    "attacker_ip": attacker_ip,
                    "timestamp": datetime.now().isoformat(),
                    "target_ip": local_ip,
                    "log_line": message[:200],
                }
        except ImportError:
            return None
        except Exception:
            return None
        return None

    def process_attack(self, attack_data):
        """Track repeated attempts and send the alert upstream."""
        with self.lock:
            key = f"{attack_data['attacker_ip']}_{attack_data['type']}"
            self.attack_counts[key] += 1
            attack_data["attempt_count"] = self.attack_counts[key]
            self.attacks.append(attack_data)
            self.attacks = self.attacks[-100:]

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
                print(
                    f"[ok] Alert sent: {attack_data['name']} from {attack_data['attacker_ip']}"
                )
            else:
                print(f"[error] Failed to send alert: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print("[error] Cannot connect to backend. Is it running?")
        except Exception as exc:
            print(f"[error] Error sending alert: {exc}")

    def start_monitoring(self):
        """Run the monitoring loop."""
        print("[info] Starting Attack Detection Monitor")
        print(f"[info] Monitoring: {self.log_file}")
        print(f"[info] Backend: {BACKEND_URL}")
        local_ip = self.get_local_ip()
        print(f"[info] Local IP: {local_ip}")

        while True:
            try:
                for line in self.read_logs():
                    attack = self.parse_log_line(line.strip(), local_ip)
                    if attack:
                        self.process_attack(attack)

                time.sleep(SCAN_INTERVAL)
            except KeyboardInterrupt:
                print("[info] Stopping Attack Detector")
                break
            except Exception as exc:
                print(f"[warn] Detector loop error: {exc}")
                time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    AttackDetector().start_monitoring()
