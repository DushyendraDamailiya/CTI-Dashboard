# Threat Intelligence and Response Framework for Malicious IPs Dashboard

A real-time alert generation, monitoring, investigation, and response dashboard for malicious IP activity. The project combines a browser dashboard, a Flask backend, a log-based attack detector, optional MySQL persistence, map-based attack visualization, and response actions such as app-level and firewall-level IP blocking.

The main purpose of this project is real-time attack detection and alert generation. Manual threat-intelligence provider lookups are included only as a secondary investigation feature for analysts who want extra reputation context after an alert or during manual review.

## Table of Contents

- [Overview](#overview)
- [Core Features](#core-features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Runtime Flow](#runtime-flow)
- [Requirements](#requirements)
- [Installation](#installation)
- [Environment Configuration](#environment-configuration)
- [MySQL Setup](#mysql-setup)
- [Running the Project](#running-the-project)
- [Attack Detector](#attack-detector)
- [Dashboard Features](#dashboard-features)
- [Manual Scan Enrichment](#manual-scan-enrichment)
- [Backend Endpoint Reference](#backend-endpoint-reference)
- [Database Schema](#database-schema)
- [IP Blocking](#ip-blocking)
- [Testing Real-Time Alerts](#testing-real-time-alerts)
- [Firewall Blocking Setup](#firewall-blocking-setup)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Verification Commands](#verification-commands)
- [Future Improvements](#future-improvements)
<img width="1919" height="910" alt="Screenshot 2026-05-23 150655" src="https://github.com/user-attachments/assets/ccb86e94-1305-4623-bc74-77abac65f4f7" />

<img width="1919" height="1079" alt="5" src="https://github.com/user-attachments/assets/0b792f4c-e8b1-4922-935c-a07c0d3ce584" />

<img width="1919" height="1079" alt="4" src="https://github.com/user-attachments/assets/1542366e-df42-4951-a0b7-6feb46a43c9a" />

<img width="1919" height="1079" alt="3" src="https://github.com/user-attachments/assets/3d72d65c-6604-44d2-b4ff-92d73fd97a63" />

<img width="1919" height="1079" alt="1" src="https://github.com/user-attachments/assets/80783c64-b3f4-4810-87b2-da1c011bd882" />

<img width="1919" height="1079" alt="2" src="https://github.com/user-attachments/assets/93e0c097-43be-4d16-bcf2-a23661a0b3f7" />

## Overview

This project detects suspicious activity from logs, converts detections into structured alerts, sends alerts to a backend service, stores them when MySQL is enabled, and displays them in a live dashboard with charts, alert history, response controls, and map representation.

It is designed for cybersecurity labs, academic demonstrations, SOC-style workflows, and learning how log monitoring, alert generation, visualization, investigation, and response systems fit together.

The primary workflow is:

```text
Kali/Linux Test Traffic
  -> Target System Logs
  -> attack_detector.py
  -> Flask Backend /api/receive-alert
  -> MySQL or Runtime Memory
  -> Dashboard Alerts, Charts, Logs, Map Representation
  -> Investigation and IP Blocking
```

## Core Features

- Real-time log monitoring with `attack_detector.py`.
- Detection of SSH brute force, root brute force, port scan, ping sweep, login flood, DNS flood indicators, and beaconing-like behavior.
- Structured alert generation with attacker IP, target IP, severity, timestamp, log line, and attempt count.
- Flask backend for alert ingestion, validation, persistence, statistics, dashboard data, and response actions.
- Browser dashboard with monitoring, generated alerts, global map representation, threat logs, and manual investigation tabs.
- Optional MySQL persistence for alerts and scan history.
- Alert deduplication and severity escalation based on repeated attempts.
- Global map visualization for geographic representation of detected or scanned threat sources.
- Manual scan enrichment using external providers is secondary to the real-time alert workflow.
- Public IPv4 validation for scan and block actions.
- Optional alert-ingest token for detector-to-backend protection.
- App-level blocklist and optional operating-system firewall blocking.
- CSV and PDF-style export support from frontend tables.
- CORS configuration through environment variables.
- Graceful behavior when manual-scan provider keys or MySQL are disabled.

## Architecture

```text
+----------------------+       +---------------------+
| Authorized Test/Lab  |       | Monitored System    |
| Traffic Generator    | ----> | Logs                |
+----------------------+       +----------+----------+
                                         |
                                         v
                              +----------+----------+
                              | attack_detector.py |
                              | Pattern Detection  |
                              +----------+----------+
                                         |
                              POST /api/receive-alert
                                         |
                                         v
                              +----------+----------+
                              | backend.py          |
                              | Flask Backend       |
                              +----------+----------+
                                         |
                     +-------------------+-------------------+
                     |                                       |
                     v                                       v
             +-------+--------+                      +-------+--------+
             | MySQL Optional |                      | Browser UI     |
             | alerts/logs    |                      | index.html     |
             +----------------+                      +----------------+
```

## Technology Stack

### Frontend

- HTML5
- CSS3
- Vanilla JavaScript
- Chart.js
- Leaflet.js
- Font Awesome

### Backend

- Python
- Flask
- Flask-CORS
- Flask-Caching
- Requests
- ThreadPoolExecutor
- python-dotenv
- mysql-connector-python

### Database

- MySQL, optional
- Schema file: `mysql_schema.sql`

## Project Structure

| File | Purpose |
|------|---------|
| `index.html` | Main dashboard UI. |
| `style.css` | Dashboard styling, layout, dark theme, cards, tables, modals, and responsive rules. |
| `script.js` | Frontend logic for navigation, generated alerts, charts, map representation, manual scans, logs, exports, and block actions. |
| `backend.py` | Flask backend, alert receiver, alert storage, MySQL setup, dashboard endpoints, manual-scan enrichment proxy, validation, and blocking logic. |
| `attack_detector.py` | Real-time log monitor and attack alert sender. |
| `requirements.txt` | Python dependencies. |
| `.env.example` | Example environment configuration. |
| `mysql_schema.sql` | MySQL database schema. |
| `SETUP_GUIDE.md` | Setup-focused documentation. |
| `PROJECT_DESCRIPTION.md` | High-level project explanation. |
| `setup-firewall-blocking.sh` | Linux helper script for firewall blocking setup. |
| `test-firewall-blocking.py` | Firewall blocking capability test script. |
| `start.sh` | Shell helper for Unix-like startup workflows. |
| `diagram-1-ip-blocking-flow.mmd` | Mermaid diagram for IP blocking flow. |
| `diagram-2-three-blocking-options.mmd` | Mermaid diagram for blocking options. |
| `attack_detector.log` | Default local Windows test log file when present. |

## Runtime Flow

1. Start the Flask backend.
2. Open the dashboard in a browser.
3. Start the attack detector.
4. The detector tails the configured log file.
5. Suspicious log lines are matched against known attack patterns.
6. The detector sends an alert to `POST /api/receive-alert`.
7. The backend validates and stores the alert when MySQL is enabled.
8. The dashboard fetches generated alerts, statistics, logs, and map data from the backend.
9. Analysts review alert details, map representation, timeline, severity, and related log data.
10. Analysts can optionally block suspicious public IPs.
11. Manual scans can enrich IPs, domains, and hashes using external providers as a secondary feature.

## Requirements

- Python 3.10 or newer
- pip
- A modern browser such as Chrome, Edge, or Firefox
- MySQL Server, optional
- Git, optional
- Administrator or sudo privileges only if firewall-level blocking is required

## Installation

Clone or open the project folder, then install Python dependencies:

```bash
pip install -r requirements.txt
```

Using a virtual environment is recommended:

```bash
python -m venv venv
```

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Linux/macOS:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

## Environment Configuration

Create a `.env` file in the project root using `.env.example` as the template.

Example:

```env
ABUSEIPDB_KEY=your_abuseipdb_key_here
VIRUSTOTAL_KEY=your_virustotal_key_here
ALIENVAULT_KEY=your_alienvault_key_here
GREYNOISE_KEY=your_greynoise_key_here
IPQUALITYSCORE_KEY=your_ipqualityscore_key_here

MYSQL_ENABLED=false
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password_here
MYSQL_DATABASE=threat_dashboard
MYSQL_POOL_SIZE=5
ALERT_DEDUP_WINDOW_MINUTES=10
ALERT_INGEST_TOKEN=

CORS_ORIGINS=http://localhost:5500,http://127.0.0.1:5500,http://localhost:5173,http://localhost:3000
```

### Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `ABUSEIPDB_KEY` | No | Provider key for optional AbuseIPDB manual-scan enrichment. |
| `VIRUSTOTAL_KEY` | No | Provider key for optional VirusTotal manual-scan enrichment. |
| `ALIENVAULT_KEY` | No | Provider key for optional AlienVault OTX manual-scan enrichment. |
| `GREYNOISE_KEY` | No | Provider key for optional GreyNoise manual-scan enrichment. |
| `IPQUALITYSCORE_KEY` | No | Provider key for optional IPQualityScore manual-scan enrichment. |
| `MYSQL_ENABLED` | No | Set `true` to enable MySQL persistence. |
| `MYSQL_HOST` | If MySQL enabled | MySQL host. |
| `MYSQL_PORT` | If MySQL enabled | MySQL port. |
| `MYSQL_USER` | If MySQL enabled | MySQL username. |
| `MYSQL_PASSWORD` | If MySQL enabled | MySQL password. |
| `MYSQL_DATABASE` | If MySQL enabled | Database name. |
| `MYSQL_POOL_SIZE` | No | MySQL connection pool size. |
| `ALERT_DEDUP_WINDOW_MINUTES` | No | Time window used to group repeated alerts. |
| `ALERT_INGEST_TOKEN` | No | Optional shared token required by `/api/receive-alert`. |
| `CORS_ORIGINS` | No | Comma-separated list of allowed browser origins. |
| `ATTACK_BACKEND_URL` | No | Backend URL used by `attack_detector.py`. |
| `ATTACK_LOG_FILE` | No | Log file monitored by `attack_detector.py`. |
| `ATTACK_SCAN_INTERVAL` | No | Detector polling interval in seconds. |

External provider keys are optional and are not required for real-time alert generation. Without those keys, the detector, alert receiver, alert dashboard, map view, and response workflow can still run; only manual scan enrichment will show provider-specific offline or missing-key responses.

## MySQL Setup

MySQL is optional. If disabled, the backend still runs, but alerts and scan logs are not permanently stored.

To disable MySQL:

```env
MYSQL_ENABLED=false
```

To enable MySQL:

```env
MYSQL_ENABLED=true
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password
MYSQL_DATABASE=threat_dashboard
```

The backend creates the database and required tables automatically on startup when MySQL is enabled.

You can also import the schema manually:

```bash
mysql -u root -p < mysql_schema.sql
```

Windows PowerShell:

```powershell
Get-Content .\mysql_schema.sql | mysql -u root -p
```

## Running the Project

### 1. Start the Backend

```bash
python backend.py
```

Default backend address:

```text
http://localhost:5001
```

Useful backend URLs:

| URL | Purpose |
|-----|---------|
| `http://localhost:5001/` | Service metadata. |
| `http://localhost:5001/health` | Health check. |
| `http://localhost:5001/api/status` | Backend, MySQL, manual-scan provider, and blocklist status. |

### 2. Open the Dashboard

Open `index.html` in a browser.

If your browser blocks local-file requests, serve the folder with a simple local server:

```bash
python -m http.server 5500
```

Then open:

```text
http://localhost:5500/index.html
```

### 3. Start the Attack Detector

```bash
python attack_detector.py
```

Default detector behavior:

- Windows: monitors `attack_detector.log` in the project folder.
- Linux/macOS: monitors `/var/log/syslog` unless overridden.

Custom detector settings:

```env
ATTACK_LOG_FILE=attack_detector.log
ATTACK_BACKEND_URL=http://localhost:5001
ATTACK_SCAN_INTERVAL=2
```

If you set `ALERT_INGEST_TOKEN` in the backend `.env`, set the same value for the detector environment.

## Attack Detector

`attack_detector.py` is the main detection component.

It reads only new log lines after each polling interval. It resets safely if the log file is rotated or truncated.

Detected patterns include:

| Attack Type | Example Pattern |
|-------------|-----------------|
| SSH root brute force | `Failed password for root from <ip>` |
| SSH brute force | `Failed password for <user> from <ip>` |
| Port scan | `UFW BLOCK` or `iptables BLOCK` with `SRC=<ip>` |
| Ping sweep | `ICMP echo request` or `PROTO=ICMP` |
| Login flood | Generic failed login/authentication patterns |
| DNS flood indicator | Repeated DNS query log patterns |
| Beaconing | Repeated activity from the same IP within a short window |

The detector ignores local, private, reserved, loopback, and malformed IPs before sending alerts.

Alert payload fields include:

- `type`
- `name`
- `severity`
- `attacker_ip`
- `timestamp`
- `target_ip`
- `log_line`
- `attempt_count`

## Dashboard Features

### Real-Time Monitoring

Shows:

- KPI cards
- Live malicious IP activity
- Search and refresh controls
- Threat trend chart
- Attack type distribution chart
- Block and details actions

### Manual Scan

Manual scan is not the main detection engine. It is a secondary investigation tool that lets an analyst look up a suspicious public IP, domain, or hash after an alert is generated or during a separate manual review.

Allows investigation of:

- Public IPv4 addresses
- Domain names
- MD5, SHA1, and SHA256 hashes

The frontend and backend reject private/reserved IP scans because manual provider lookups are intended for public routable IPs.

### Global Map

The map representation is an important dashboard view. It uses Leaflet to visualize where suspicious activity or enriched scan results are associated geographically.

The map view helps show:

- Approximate country or region of attack sources.
- Marker colors based on threat level.
- Previously scanned public IPs with available geolocation.
- A quick visual summary of where suspicious activity is coming from.

The map depends on available country/geolocation data. If no geolocation can be resolved, the alert still appears in the alert and log views.

### Alerts

Shows real-time alerts from the backend with:

- Severity filtering
- Search
- Sorting
- Critical alert banner
- Details modal
- Block action
- CSV/PDF export
- Clear alerts action

### Threat Logs

Shows stored manual scan history with:

- Search
- Status filtering
- Date and score sorting
- Pagination
- Expandable details
- CSV/PDF export

## Manual Scan Enrichment

Manual scan enrichment is a secondary feature. The real-time detection and alert-generation system does not depend on these external providers. They are used only to add reputation context when an analyst manually scans a public IP, domain, or hash.

| Provider | Supported Targets | Notes |
|----------|-------------------|-------|
| AbuseIPDB | Public IPv4 | Abuse confidence, reports, ISP, usage type. |
| VirusTotal | Public IPv4, domain, hash | Detection and reputation data. |
| AlienVault OTX | Public IPv4, domain, hash | Pulses, reputation, ASN, country. |
| GreyNoise | Public IPv4 | Internet scanner classification. |
| IPQualityScore | Public IPv4 | Fraud score, VPN/proxy/TOR/bot/abuse indicators. |

When a provider key is missing, the backend returns a safe offline response instead of crashing.

## Backend Endpoint Reference

Base URL:

```text
http://localhost:5001
```

### `GET /`

Returns service metadata and endpoint list.

### `GET /health`

Returns backend health and MySQL status.

Example response:

```json
{
  "status": "healthy",
  "mysql": "enabled",
  "timestamp": "2026-05-23T12:00:00"
}
```

### `POST /api/validate`

Validates an IP, domain, or hash.

Request:

```json
{
  "target": "example.com",
  "type": "domain"
}
```

`type` can be:

- `auto`
- `ip`
- `domain`
- `hash`

### `POST /api/scan`

Runs a secondary manual enrichment scan against supported external providers. This endpoint is for investigation and does not perform the real-time alert detection.

Request:

```json
{
  "target": "8.8.8.8",
  "type": "ip"
}
```

For IP scans, the target must be a public, globally routable IPv4 address.

### `POST /api/scan/<service>`

Runs one provider-specific manual enrichment scan.

Supported service names:

- `abuseipdb`
- `virustotal`
- `alienvault`
- `greynoise`

Example:

```text
POST /api/scan/virustotal
```

### `GET /api/alerts`

Fetches stored real-time alerts generated by the detector.

Optional query:

```text
/api/alerts?limit=100
```

### `DELETE /api/alerts`

Clears stored alerts.

### `GET /api/alert-stats`

Returns chart-ready statistics for detector-generated alerts.

### `POST /api/receive-alert`

Receives real-time alerts from `attack_detector.py`. This is the central endpoint in the project.

Request:

```json
{
  "type": "ssh_bruteforce",
  "name": "SSH Brute Force Attack",
  "severity": "high",
  "attacker_ip": "8.8.8.8",
  "target_ip": "192.168.1.10",
  "timestamp": "2026-05-23T12:00:00",
  "log_line": "Failed password for admin from 8.8.8.8 port 22 ssh2",
  "attempt_count": 5
}
```

If `ALERT_INGEST_TOKEN` is configured, include one of:

```text
X-Alert-Token: your_token
```

or:

```text
Authorization: Bearer your_token
```

### `GET /api/threat-logs`

Fetches stored manual scan logs.

Optional query:

```text
/api/threat-logs?limit=500
```

### `POST /api/block-ip`

Blocks a public IPv4 address in the application blocklist and optionally in the system firewall.

Request:

```json
{
  "ip": "8.8.8.8",
  "reason": "manual_block",
  "firewall": false
}
```

### `POST /api/unblock-ip`

Unblocks an IP from the runtime blocklist and removes firewall rules if the backend created them.

Request:

```json
{
  "ip": "8.8.8.8"
}
```

### `GET /api/blocked-ips`

Lists currently blocked IPs.

### `GET /api/cache-stats`

Returns cache and rate-limit information.

### `GET /api/status`

Returns backend status, MySQL status, manual-scan provider status labels, and blocklist count.

## Database Schema

The database contains two main tables.

### `alerts`

Stores real-time attack alerts.

Important columns:

- `id`
- `alert_type`
- `source`
- `ip_address`
- `severity`
- `description`
- `target_ip`
- `log_line`
- `attempt_count`
- `raw_payload`
- `created_at`
- `updated_at`

Alert deduplication groups recent alerts by:

- `source`
- `ip_address`
- `alert_type`

### `threat_logs`

Stores manual IP scan history.

Important columns:

- `id`
- `ip_address`
- `country`
- `country_code`
- `threat_score`
- `api_sources`
- `status`
- `scan_results`
- `overall_data`
- `last_scanned_at`
- `created_at`
- `updated_at`

`ip_address` is unique, so repeated scans update the existing row.

## IP Blocking

The project supports two blocking modes.

### App-Level Blocking

Stores the IP in the backend runtime `blocked_ips` dictionary.

Limitations:

- Not persistent after backend restart.
- Does not affect operating-system network traffic.

### Firewall-Level Blocking

Attempts to add operating-system firewall rules.

Supported platforms:

| OS | Method |
|----|--------|
| Windows | `netsh advfirewall` |
| Linux | `sudo iptables` |
| macOS | `sudo route` |

Firewall blocking may require administrator or sudo privileges.

For safety, block actions accept only public, globally routable IPv4 addresses.

## Testing Real-Time Alerts

For local Windows-style testing, start the backend and detector, then append this line to `attack_detector.log`:

```text
Failed password for root from 8.8.8.8 port 22 ssh2
```

Expected result:

1. `attack_detector.py` detects the SSH root brute force pattern.
2. It sends an alert to `/api/receive-alert`.
3. The backend validates and stores the alert when MySQL is enabled.
4. The dashboard displays the alert in the Alerts tab.

Linux systems can test with authorized SSH failed-login events or controlled lab traffic that writes to `/var/log/syslog` or the configured `ATTACK_LOG_FILE`.

## Firewall Blocking Setup

Linux helper:

```bash
sudo bash setup-firewall-blocking.sh
```

Test firewall capability:

```bash
python test-firewall-blocking.py
```

Only run firewall tests on systems where you understand and accept the network changes being made.

## Security Notes

- Use this project only in authorized environments.
- Do not scan or attack systems without permission.
- Keep `.env` private and never commit real provider keys or tokens.
- Configure `CORS_ORIGINS` narrowly for your frontend host.
- Set `ALERT_INGEST_TOKEN` if the backend is reachable outside your local machine.
- Firewall blocking can affect real connectivity; use carefully.
- The current app-level blocklist is runtime memory only.
- Authentication and role-based access control are not yet implemented.
- The Flask development server is not a production WSGI deployment.

## Troubleshooting

### Backend Does Not Start

Check dependencies:

```bash
pip install -r requirements.txt
```

Check `.env` values, especially MySQL settings if `MYSQL_ENABLED=true`.

### Dashboard Cannot Reach Backend

Confirm the backend is running:

```text
http://localhost:5001/health
```

If serving the frontend from a different origin, add that origin to `CORS_ORIGINS`.

### Alerts Do Not Appear

Check:

- `backend.py` is running.
- `attack_detector.py` is running.
- `ATTACK_BACKEND_URL` points to the correct backend.
- `ATTACK_LOG_FILE` points to the log being updated.
- The log line contains a supported pattern.
- The attacker IP is public and valid.
- If `ALERT_INGEST_TOKEN` is set, the detector has the same token.

### Manual Scan Enrichment Returns No Useful Results

Check:

- External provider keys are configured.
- The target type is correct.
- IP targets are public IPv4 addresses.
- Network access is available.
- Provider quota has not been exceeded.

### MySQL Errors

Check:

- MySQL Server is running.
- Credentials are correct.
- The configured user can create and use the database.
- `mysql-connector-python` is installed.

### Firewall Blocking Fails

Check:

- You are running with administrator or sudo privileges.
- The target IP is public IPv4.
- Required firewall tools are installed.
- On Linux, `iptables` is available.
- On Windows, PowerShell or terminal is running as Administrator.

## Verification Commands

Python syntax check:

```bash
python -m py_compile backend.py attack_detector.py test-firewall-blocking.py
```

JavaScript syntax check:

```bash
node --check script.js
```

Backend smoke checks:

```bash
python -c "import backend; c=backend.app.test_client(); print(c.get('/health').status_code); print(c.get('/api/status').status_code)"
```

Manual scan validation smoke check:

```bash
python -c "import backend; c=backend.app.test_client(); print(c.post('/api/scan', json={'target':'8.8.8.8','type':'ip'}).status_code)"
```

## Current Limitations

- No user login or role-based access control.
- Runtime app-level blocklist is not persistent.
- Live updates use polling rather than WebSockets.
- Some monitoring-table data is still demo/fallback data when backend data is unavailable.
- Firewall blocking behavior depends on OS permissions and installed tools.
- Manual enrichment quality depends on provider keys, provider availability, and quota.
- Flask development server should be replaced with a production WSGI server for deployment.

## Future Improvements

- Add authentication and role-based permissions.
- Persist blocklist entries in MySQL.
- Add block/unblock audit history.
- Add WebSocket-based real-time updates.
- Add background scan queue with retry and status tracking.
- Add provider health and quota dashboard.
- Add scheduled scans.
- Add SIEM integrations.
- Add Docker Compose for backend and MySQL.
- Add automated unit and integration tests.
- Add rule-based automated response playbooks.
- Add richer domain and hash enrichment.
- Add production deployment documentation.

## Ethical Use

This project is intended for defensive cybersecurity education, authorized lab testing, monitoring, and response. Use the detector, simulator, scanning, and blocking features only on systems and networks where you have explicit permission.
