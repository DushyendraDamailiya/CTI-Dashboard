#!/usr/bin/env python3
"""
AegisX Windows Endpoint Agent

Collects endpoint heartbeat, process, network, file, registry, scheduled-task,
USB, RDP, failed-login, and optional login telemetry, then sends it to the
Flask backend.
"""

import argparse
import csv
import getpass
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


AGENT_VERSION = "0.1.0"
INTERESTING_FILE_EXTENSIONS = {
    ".exe", ".dll", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".bat", ".cmd", ".scr", ".lnk", ".hta"
}
REGISTRY_RUN_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
]


def powershell_single_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def utc_now():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def stable_id(prefix, *values):
    seed = json.dumps([str(value or "") for value in values], sort_keys=True)
    return f"{prefix}-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:40]}"


def local_eventlog_time(value):
    return value.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%S")


def run_command(command, timeout=12):
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def run_powershell(script, timeout=15):
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    return run_command(command, timeout=timeout)


def parse_json_output(output):
    if not output:
        return []
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    return []


def get_primary_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return ""


def endpoint_id():
    host = socket.gethostname()
    node = uuid.getnode()
    return f"{host}-{node:x}"


def endpoint_payload():
    return {
        "endpoint_id": endpoint_id(),
        "hostname": socket.gethostname(),
        "ip_address": get_primary_ip(),
        "user": getpass.getuser(),
        "os": platform.platform(),
        "agent_version": AGENT_VERSION,
        "timestamp": utc_now(),
    }


class BackendClient:
    def __init__(self, backend_url, token=""):
        self.backend_url = backend_url.rstrip("/")
        self.token = token

    def post(self, path, payload):
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Agent-Token"] = self.token
        request = Request(f"{self.backend_url}{path}", data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=15) as response:
                return response.status, response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except URLError as exc:
            return 0, str(exc)

    def heartbeat(self):
        return self.post("/api/edr/heartbeat", endpoint_payload())

    def send_events(self, events):
        if not events:
            return 204, "no events"
        payload = endpoint_payload()
        payload["events"] = events
        return self.post("/api/edr/ingest", payload)


class WindowsCollector:
    def __init__(self, include_login_events=False, failed_login_threshold=5):
        self.include_login_events = include_login_events
        self.failed_login_threshold = max(1, int(failed_login_threshold or 5))
        self.process_seen = {}
        self.latest_process_names = {}
        self.network_seen = set()
        self.file_snapshot = {}
        self.registry_snapshot = {}
        self.task_snapshot = set()
        self.usb_snapshot = set()
        self.signature_cache = {}
        self.last_login_check = datetime.now() - timedelta(minutes=5)
        self.auth_seen = set()
        self.failed_burst_seen = set()
        self.watch_dirs = self.default_watch_dirs()

    def default_watch_dirs(self):
        user_profile = Path(os.environ.get("USERPROFILE", str(Path.home())))
        startup = user_profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        candidates = [
            user_profile / "Downloads",
            user_profile / "Desktop",
            user_profile / "Documents",
            Path(tempfile.gettempdir()),
            startup,
        ]
        return [path for path in candidates if path.exists()]

    def get_signature_info(self, path):
        if not path:
            return {}

        normalized_path = str(path)
        if normalized_path in self.signature_cache:
            return self.signature_cache[normalized_path]

        if not Path(normalized_path).exists():
            result = {"signature_status": "MissingFile", "is_signed": False}
            self.signature_cache[normalized_path] = result
            return result

        script = (
            f"$path={powershell_single_quote(normalized_path)}; "
            "$sig=Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue; "
            "if ($null -eq $sig) { "
            "[PSCustomObject]@{signature_status='Unknown'; is_signed=$false} "
            "} else { "
            "[PSCustomObject]@{"
            "signature_status=$sig.Status.ToString();"
            "signature_subject=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{''};"
            "signature_issuer=if($sig.SignerCertificate){$sig.SignerCertificate.Issuer}else{''};"
            "signature_thumbprint=if($sig.SignerCertificate){$sig.SignerCertificate.Thumbprint}else{''};"
            "is_signed=($null -ne $sig.SignerCertificate)"
            "} } | ConvertTo-Json -Depth 3"
        )
        parsed = parse_json_output(run_powershell(script, timeout=10))
        result = parsed[0] if parsed else {"signature_status": "Unknown", "is_signed": False}
        self.signature_cache[normalized_path] = result
        return result

    def is_agent_collector_process(self, process):
        name = (process.get("process_name") or "").lower()
        command_line = (process.get("command_line") or "").lower()
        collector_markers = (
            "get-ciminstance win32_process",
            "get-nettcpconnection",
            "get-winevent -filterhashtable",
            "get-scheduledtask",
            "get-authenticodesignature",
            "win32_pnpentity",
        )
        if name in {"powershell.exe", "pwsh.exe"} and any(marker in command_line for marker in collector_markers):
            return True
        if name == "conhost.exe" and "\\system32\\conhost.exe 0x4" in command_line:
            return True
        return False

    def calculate_sha256(self, path):
        try:
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError:
            return ""

    def collect_processes(self):
        script = (
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | "
            "ConvertTo-Json -Depth 3"
        )
        rows = parse_json_output(run_powershell(script, timeout=20))
        processes = {}
        for row in rows:
            pid = row.get("ProcessId")
            if pid is None:
                continue
            processes[int(pid)] = {
                "pid": int(pid),
                "parent_pid": row.get("ParentProcessId"),
                "process_name": row.get("Name") or "",
                "image_path": row.get("ExecutablePath") or "",
                "command_line": row.get("CommandLine") or "",
            }
        self.latest_process_names = {
            pid: process.get("process_name") or ""
            for pid, process in processes.items()
        }

        events = []
        for pid, process in processes.items():
            command_line = process.get("command_line") or ""
            image_path = process.get("image_path") or ""
            if self.is_agent_collector_process(process):
                self.process_seen.pop(pid, None)
                continue
            previous = self.process_seen.get(pid)
            signature = (
                process.get("process_name"),
                process.get("parent_pid"),
                image_path,
                command_line,
            )
            if previous == signature:
                continue
            parent = processes.get(int(process.get("parent_pid") or 0), {})
            signature_info = self.get_signature_info(image_path) if image_path else {}
            self.process_seen[pid] = signature
            events.append({
                "event_type": "process",
                "timestamp": utc_now(),
                "pid": pid,
                "parent_pid": process.get("parent_pid"),
                "parent_process": parent.get("process_name") or "",
                "process_name": process.get("process_name") or "",
                "image_path": image_path,
                "command_line": command_line,
                **signature_info,
            })

        live_pids = set(processes)
        for pid in list(self.process_seen):
            if pid not in live_pids:
                self.process_seen.pop(pid, None)

        return events

    def collect_network(self):
        script = (
            "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
            "Select-Object OwningProcess,RemoteAddress,RemotePort,LocalAddress,LocalPort,State | "
            "ConvertTo-Json -Depth 3"
        )
        rows = parse_json_output(run_powershell(script, timeout=15))

        events = []
        current = set()
        for row in rows:
            remote_address = str(row.get("RemoteAddress") or "")
            remote_port = row.get("RemotePort")
            pid = row.get("OwningProcess")
            if not remote_address or remote_address in {"0.0.0.0", "::", "127.0.0.1", "::1"}:
                continue
            key = (pid, remote_address, remote_port)
            current.add(key)
            if key in self.network_seen:
                continue
            events.append({
                "event_type": "network",
                "timestamp": utc_now(),
                "pid": pid,
                "process_name": self.latest_process_names.get(int(pid or 0)) or "",
                "destination_ip": remote_address,
                "destination_port": remote_port,
                "protocol": "tcp",
                "local_address": row.get("LocalAddress") or "",
                "local_port": row.get("LocalPort"),
            })

        self.network_seen = current
        return events

    def collect_process_snapshot(self):
        script = (
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,Name | ConvertTo-Json -Depth 2"
        )
        rows = parse_json_output(run_powershell(script, timeout=10))
        return [
            {"pid": row.get("ProcessId"), "process_name": row.get("Name") or ""}
            for row in rows
        ]

    def collect_files(self):
        events = []
        current_snapshot = {}
        for root in self.watch_dirs:
            try:
                files = root.rglob("*")
            except (OSError, PermissionError):
                continue
            scanned = 0
            for path in files:
                if scanned >= 2500:
                    break
                scanned += 1
                if not path.is_file() or path.suffix.lower() not in INTERESTING_FILE_EXTENSIONS:
                    continue
                try:
                    stat = path.stat()
                except (OSError, PermissionError):
                    continue
                key = str(path)
                value = (stat.st_mtime_ns, stat.st_size)
                current_snapshot[key] = value
                previous = self.file_snapshot.get(key)
                if previous is None:
                    signature_info = self.get_signature_info(key) if path.suffix.lower() in {".exe", ".dll"} else {}
                    events.append({
                        "event_type": "file",
                        "timestamp": utc_now(),
                        "file_action": "created",
                        "file_path": key,
                        "file_hash": self.calculate_sha256(key),
                        **signature_info,
                    })
                elif previous != value:
                    signature_info = self.get_signature_info(key) if path.suffix.lower() in {".exe", ".dll"} else {}
                    events.append({
                        "event_type": "file",
                        "timestamp": utc_now(),
                        "file_action": "modified",
                        "file_path": key,
                        "file_hash": self.calculate_sha256(key),
                        **signature_info,
                    })
        self.file_snapshot = current_snapshot
        return events

    def collect_registry(self):
        events = []
        current = {}
        for key in REGISTRY_RUN_KEYS:
            output = run_command(["reg.exe", "query", key], timeout=8)
            current[key] = output
            previous = self.registry_snapshot.get(key)
            if previous is not None and previous != output:
                events.append({
                    "event_type": "registry",
                    "timestamp": utc_now(),
                    "registry_action": "modified",
                    "registry_key": key,
                    "registry_value": output[-1000:],
                })
        self.registry_snapshot = current
        return events

    def collect_scheduled_tasks(self):
        output = run_command(["schtasks.exe", "/Query", "/FO", "CSV", "/V"], timeout=25)
        if not output:
            return []

        events = []
        current = set()
        try:
            rows = csv.DictReader(output.splitlines())
            for row in rows:
                task_name = row.get("TaskName") or row.get("Task Name") or ""
                task_to_run = row.get("Task To Run") or row.get("Task To Run:") or ""
                if not task_name:
                    continue
                signature = f"{task_name}|{task_to_run}"
                current.add(signature)
                if self.task_snapshot and signature not in self.task_snapshot:
                    events.append({
                        "event_type": "scheduled_task",
                        "timestamp": utc_now(),
                        "task_name": task_name,
                        "command_line": task_to_run,
                    })
        except csv.Error:
            return []

        self.task_snapshot = current
        return events

    def collect_usb_devices(self):
        script = (
            "Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | "
            "Where-Object { $_.PNPDeviceID -like 'USB*' -and $_.Status -eq 'OK' } | "
            "Select-Object Name,Manufacturer,PNPDeviceID,Service,DeviceID | "
            "ConvertTo-Json -Depth 3"
        )
        rows = parse_json_output(run_powershell(script, timeout=15))
        current = {}
        for row in rows:
            device_id = row.get("PNPDeviceID") or row.get("DeviceID") or row.get("Name")
            if not device_id:
                continue
            current[str(device_id)] = {
                "device_name": row.get("Name") or "USB Device",
                "manufacturer": row.get("Manufacturer") or "",
                "device_id": str(device_id),
                "service": row.get("Service") or "",
            }

        events = []
        previous_ids = set(self.usb_snapshot)
        current_ids = set(current)
        for device_id in sorted(current_ids - previous_ids):
            device = current[device_id]
            events.append({
                "event_type": "usb",
                "timestamp": utc_now(),
                "usb_action": "inserted",
                **device,
            })

        for device_id in sorted(previous_ids - current_ids):
            events.append({
                "event_type": "usb",
                "timestamp": utc_now(),
                "usb_action": "removed",
                "device_id": device_id,
            })

        self.usb_snapshot = current_ids
        return events

    def collect_authentication_events(self):
        start_time = local_eventlog_time(self.last_login_check)
        script = (
            "$start=[datetime]::Parse('%s'); "
            "$events=Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=$start} "
            "-MaxEvents 100 -ErrorAction SilentlyContinue; "
            "$events | ForEach-Object { "
            "$xml=[xml]$_.ToXml(); $data=@{}; "
            "foreach($d in $xml.Event.EventData.Data){ $data[$d.Name]=$d.'#text' }; "
            "[PSCustomObject]@{"
            "TimeCreated=$_.TimeCreated.ToString('o');"
            "Id=$_.Id;"
            "TargetUserName=$data.TargetUserName;"
            "IpAddress=$data.IpAddress;"
            "LogonType=$data.LogonType;"
            "WorkstationName=$data.WorkstationName;"
            "Status=$data.Status;"
            "SubStatus=$data.SubStatus"
            "} } | ConvertTo-Json -Depth 4"
        ) % start_time
        self.last_login_check = datetime.now()

        rows = parse_json_output(run_powershell(script, timeout=20))
        events = []
        failed_groups = {}

        for row in rows:
            event_id = row.get("Id")
            logon_type = str(row.get("LogonType") or "")
            username = row.get("TargetUserName") or ""
            source_ip = row.get("IpAddress") or ""
            timestamp = row.get("TimeCreated") or utc_now()
            is_failed = str(event_id) == "4625"
            auth_event_id = stable_id(
                "auth",
                event_id,
                timestamp,
                username,
                source_ip,
                logon_type,
                row.get("Status"),
                row.get("SubStatus"),
            )

            if auth_event_id in self.auth_seen:
                continue
            self.auth_seen.add(auth_event_id)

            if is_failed:
                key = (username, source_ip or "local")
                failed_groups.setdefault(key, []).append(row)

            if logon_type == "10":
                events.append({
                    "event_type": "rdp_login",
                    "event_id": stable_id("rdp", auth_event_id),
                    "timestamp": timestamp,
                    "windows_event_id": event_id,
                    "rdp_result": "failed" if is_failed else "successful",
                    "logon_type": logon_type,
                    "target_user": username,
                    "source_ip": source_ip,
                    "workstation": row.get("WorkstationName") or "",
                    "status_code": row.get("Status") or "",
                    "sub_status_code": row.get("SubStatus") or "",
                })

            if self.include_login_events:
                events.append({
                    "event_type": "login",
                    "event_id": stable_id("login", auth_event_id),
                    "timestamp": timestamp,
                    "windows_event_id": event_id,
                    "login_result": "failed" if is_failed else "successful",
                    "logon_type": logon_type,
                    "target_user": username,
                    "source_ip": source_ip,
                    "workstation": row.get("WorkstationName") or "",
                })

        for (username, source_ip), attempts in failed_groups.items():
            if len(attempts) >= self.failed_login_threshold:
                window_start = attempts[-1].get("TimeCreated") or ""
                window_end = attempts[0].get("TimeCreated") or ""
                burst_id = stable_id(
                    "failed-burst",
                    username,
                    source_ip,
                    len(attempts),
                    window_start,
                    window_end,
                    self.failed_login_threshold,
                )
                if burst_id in self.failed_burst_seen:
                    continue
                self.failed_burst_seen.add(burst_id)
                events.append({
                    "event_type": "failed_login_burst",
                    "event_id": burst_id,
                    "timestamp": window_end or utc_now(),
                    "target_user": username,
                    "source_ip": source_ip,
                    "failed_count": len(attempts),
                    "window_start": window_start,
                    "window_end": window_end,
                    "threshold": self.failed_login_threshold,
                })

        if len(self.auth_seen) > 5000:
            self.auth_seen = set(list(self.auth_seen)[-2500:])
        if len(self.failed_burst_seen) > 1000:
            self.failed_burst_seen = set(list(self.failed_burst_seen)[-500:])

        return events

    def collect_login_events(self):
        if not self.include_login_events:
            return []

        start_time = local_eventlog_time(self.last_login_check)
        script = (
            "$start=[datetime]::Parse('%s'); "
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=$start} "
            "-MaxEvents 20 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json -Depth 3"
        ) % start_time
        self.last_login_check = datetime.now()
        rows = parse_json_output(run_powershell(script, timeout=15))
        events = []
        for row in rows:
            event_id = stable_id("winlog", row.get("Id"), row.get("TimeCreated"), row.get("Message"))
            events.append({
                "event_type": "login",
                "timestamp": row.get("TimeCreated") or utc_now(),
                "source": row.get("ProviderName") or "Windows Security",
                "event_id": event_id,
                "windows_event_id": row.get("Id"),
                "message": (row.get("Message") or "")[:2000],
            })
        return events

    def bootstrap(self):
        self.process_seen = {}
        self.network_seen = set()
        self.file_snapshot = {}
        self.registry_snapshot = {}
        self.task_snapshot = set()
        self.usb_snapshot = set()
        self.collect_processes()
        self.collect_network()
        self.collect_files()
        self.collect_registry()
        self.collect_scheduled_tasks()
        self.collect_usb_devices()

    def collect_once(self, include_slow_checks=False):
        events = []
        events.extend(self.collect_processes())
        events.extend(self.collect_network())
        if include_slow_checks:
            events.extend(self.collect_files())
            events.extend(self.collect_registry())
            events.extend(self.collect_scheduled_tasks())
            events.extend(self.collect_usb_devices())
            events.extend(self.collect_authentication_events())
        return events


def main():
    parser = argparse.ArgumentParser(description="AegisX Windows Endpoint Agent")
    parser.add_argument("--backend", default=os.environ.get("EDR_BACKEND_URL", "http://localhost:5001"))
    parser.add_argument("--token", default=os.environ.get("EDR_AGENT_TOKEN", ""))
    parser.add_argument("--interval", type=int, default=int(os.environ.get("EDR_AGENT_INTERVAL", "2")))
    parser.add_argument("--heartbeat-interval", type=int, default=int(os.environ.get("EDR_HEARTBEAT_INTERVAL", "5")))
    parser.add_argument("--slow-interval", type=int, default=int(os.environ.get("EDR_SLOW_INTERVAL", "30")))
    parser.add_argument("--failed-login-threshold", type=int, default=int(os.environ.get("EDR_FAILED_LOGIN_THRESHOLD", "5")))
    parser.add_argument("--include-login-events", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--no-bootstrap", action="store_true")
    args = parser.parse_args()

    client = BackendClient(args.backend, args.token)
    collector = WindowsCollector(
        include_login_events=args.include_login_events,
        failed_login_threshold=args.failed_login_threshold,
    )

    if not args.no_bootstrap:
        collector.bootstrap()

    last_heartbeat = 0
    last_slow_check = 0

    while True:
        now = time.time()
        if now - last_heartbeat >= args.heartbeat_interval:
            status, message = client.heartbeat()
            print(f"[heartbeat] status={status} {message[:160]}")
            last_heartbeat = now

        include_slow = now - last_slow_check >= args.slow_interval
        events = collector.collect_once(include_slow_checks=include_slow)
        if include_slow:
            last_slow_check = now

        if events:
            status, message = client.send_events(events)
            print(f"[events] sent={len(events)} status={status} {message[:160]}")

        if args.once:
            break
        time.sleep(max(1, args.interval))


if __name__ == "__main__":
    if platform.system().lower() != "windows":
        print("This agent is designed for Windows endpoint telemetry.", file=sys.stderr)
    main()
