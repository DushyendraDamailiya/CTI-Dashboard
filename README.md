# Threat Intelligence and EDR Dashboard

A local security dashboard for malicious IP intelligence, real-time alert tracking, and basic Windows endpoint telemetry.

The project has three main parts:

- A Flask backend API on `http://localhost:5001`
- A browser dashboard served from `http://localhost:8000`
- Optional collectors:
  - `attack_detector.py` for log-based attack alerts
  - `windows_endpoint_agent.py` for Windows EDR telemetry

## Features

- Manual scan for IPs, domains, and file hashes
- Threat intelligence lookups through configured APIs
- Real-time alert storage and alert stats
- Global map and threat logs
- IP block/unblock API with optional firewall support
- EDR dashboard on the front page
- Windows endpoint heartbeat and online/offline status
- EDR process, network, file, registry, scheduled task, USB, RDP, and failed-login telemetry
- EDR alert queue with clickable details
- Safe dry-run EDR response actions

## Requirements

- Python 3.10 or newer
- A modern browser
- Optional: MySQL for persistent storage
- Optional for Windows EDR: run PowerShell or VS Code as Administrator for best event-log access

Install Python packages:

```powershell
pip install -r requirements.txt
```

## Configuration

Create `.env` from the example file:

```powershell
copy .env.example .env
```

Then edit `.env` and add only the keys you use:

```env
ABUSEIPDB_KEY=
VIRUSTOTAL_KEY=
ALIENVAULT_KEY=
GREYNOISE_KEY=
IPQUALITYSCORE_KEY=

MYSQL_ENABLED=false
EDR_HEARTBEAT_TIMEOUT_SECONDS=20
EDR_RESPONSE_DRY_RUN=true
```

MySQL is optional. If `MYSQL_ENABLED=false`, the app still runs with in-memory data.

## Run The Project

Open three terminals from the project folder.

### 1. Backend

```powershell
python backend.py
```

Backend URL:

```text
http://localhost:5001
```

### 2. Frontend

```powershell
python -m http.server 8000
```

Open:

```text
http://localhost:8000
```

### 3. Windows EDR Agent

For best results, run this terminal as Administrator:

```powershell
python windows_endpoint_agent.py --backend http://localhost:5001 --include-login-events
```

The agent should print heartbeat and event send messages:

```text
[heartbeat] status=200 ...
[events] sent=... status=200 ...
```

If the agent stops, the dashboard should mark the endpoint offline after about 20 seconds.

## EDR Dashboard

The EDR dashboard is shown on the Real-Time Monitoring page.

It shows:

- Endpoints online/offline
- Open and critical EDR alerts
- Events today
- Endpoint list
- Alert queue
- Recent endpoint events
- Process context
- Response history

The EDR dashboard auto-refreshes every 5 seconds. The Refresh button also works manually. Event rows are clickable and open full details.

Current EDR detections include:

- Failed login bursts
- Failed and successful RDP logins
- USB insertion/removal
- Suspicious PowerShell activity
- Suspicious process paths
- Unsigned or invalidly signed executables
- Network connections to high-risk ports
- Scheduled task persistence
- Registry Run key persistence

## Real-Time Attack Alerts

Run the log-based detector in a separate terminal:

```powershell
python attack_detector.py
```

By default on Windows it reads:

```text
attack_detector.log
```

You can point it at another log file:

```powershell
$env:ATTACK_LOG_FILE="C:\path\to\your.log"
python attack_detector.py
```

It sends alerts to:

```text
POST /api/receive-alert
```

## Firewall Blocking

Application-level IP blocking works from the dashboard.

System firewall blocking needs privileges:

- Windows: run backend as Administrator
- Linux/macOS: run `sudo bash setup-firewall-blocking.sh`

Test firewall support:

```powershell
python test-firewall-blocking.py
```

## Useful Checks Before Commit

```powershell
python -m py_compile backend.py attack_detector.py windows_endpoint_agent.py test-firewall-blocking.py
node --check script.js
```

Optional backend smoke test:

```powershell
$env:MYSQL_ENABLED="false"
python -c "import backend; c=backend.app.test_client(); print(c.get('/health').status_code); print(c.get('/api/edr/dashboard').status_code)"
```

## Current Limitations

- This is a local project, not a full enterprise EDR product.
- The Windows agent runs while the terminal is open; it is not installed as a Windows service yet.
- EDR response actions are dry-run by default.
- Some Windows login/RDP events require Administrator privileges.
- Browser charts and map libraries are loaded from CDN, so the dashboard needs internet access for those assets.

