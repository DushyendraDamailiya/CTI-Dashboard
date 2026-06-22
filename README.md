# Threat Intelligence and Response Dashboard

## Project Introduction

The Threat Intelligence and Response Dashboard is a cybersecurity project designed to detect, monitor, and respond to suspicious attack activity in real time. The project uses a Flask backend, a browser-based dashboard, a real-time attack detector, and an important Windows endpoint/EDR monitoring module to provide a complete security monitoring workflow.
In this project, Kali Linux is used as the attacker machine and Windows is used as the target/monitored machine in a controlled lab environment. Different authorized attacks are performed from Kali Linux against the Windows system. These activities create log entries on the Windows machine. The attack detector reads those logs, identifies suspicious patterns, and sends real-time alerts to the backend. The dashboard then displays these alerts with useful details such as attacker IP, target IP, attack type, severity, timestamp, attempt count, and related log information.
The project also includes EDR monitoring, which collects endpoint-level activity from the Windows machine, such as process activity, network connections, login events, USB activity, registry changes, scheduled tasks, and other suspicious behavior. This makes the project more powerful because it does not only show network attack alerts, but also provides endpoint visibility for better investigation.
The main purpose of this project is to show how real-time threat detection, alert generation, endpoint monitoring, visualization, and response actions work together in a security dashboard. Manual scanning using external threat intelligence APIs is also included as an additional feature, allowing users to check IPs, domains, and hashes for more reputation details during investigation.

<img width="1919" height="910" alt="1" src="https://github.com/user-attachments/assets/b83935d2-3250-47e6-94c6-5199fc1e1f67" />

<img width="1919" height="1079" alt="2" src="https://github.com/user-attachments/assets/4e12596c-16e9-4a3e-9424-ea600e0daebf" />

<img width="1919" height="1079" alt="3" src="https://github.com/user-attachments/assets/70792986-c257-48cf-9814-449933a9db02" />

<img width="1679" height="1042" alt="8" src="https://github.com/user-attachments/assets/323892ad-87ac-431f-b714-5e1ac9173501" />

<img width="1870" height="1051" alt="7" src="https://github.com/user-attachments/assets/024b2688-f93a-467f-ba48-003e169fbfb0" />

<img width="1874" height="1040" alt="9" src="https://github.com/user-attachments/assets/92b00531-d626-449d-bae8-fe2106f4ffd7" />

<img width="1919" height="1079" alt="4" src="https://github.com/user-attachments/assets/79a12c7c-74c4-4590-9c6a-e14935ed86ea" />

<img width="1919" height="1079" alt="5" src="https://github.com/user-attachments/assets/66c1b1bb-3a9f-419d-a742-8ce2a1902d32" />

<img width="1919" height="1079" alt="6" src="https://github.com/user-attachments/assets/fc60e212-98ef-4e71-8838-06db25b8c8ca" />

The main goal of this project is simple:

```text
Detect suspicious activity -> Generate alerts -> Show alerts on dashboard -> Help the user investigate and respond
```

This project is useful for cybersecurity learning, college projects, SOC-style demos, lab testing, and understanding how threat monitoring systems work.

Use it only in systems and networks where you have permission.

In our lab demonstration, Kali Linux is used as the attacker machine and Windows is used as the target/monitored machine. We perform controlled and authorized test attacks from Kali Linux to Windows. The Windows system records the activity in logs, `attack_detector.py` detects the suspicious patterns, and the dashboard generates real-time attack and threat alerts with further details for investigation.

In our lab demonstration, Kali Linux is used as the attacker machine and Windows is used as the target/monitored machine. We perform controlled and authorized test attacks from Kali Linux to Windows. The Windows system records the activity in logs, `attack_detector.py` detects the suspicious patterns, and the dashboard generates real-time attack and threat alerts with further details for investigation.

- [Main Features](#main-features)
- [How the Project Works](#how-the-project-works)
- [Lab Demonstration Workflow](#lab-demonstration-workflow)
- [Technology Used](#technology-used)
- [Project Files](#project-files)
- [Requirements](#requirements)
- [Setup](#setup)
- [Environment Variables](#environment-variables)
- [How to Run](#how-to-run)
- [Testing Real-Time Alerts](#testing-real-time-alerts)
- [Important Backend APIs](#important-backend-apis)
- [Database Support](#database-support)
- [Security Notes](#security-notes)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)

## Main Features

### 1. Real-Time Attack Detection

The file `attack_detector.py` checks new log entries and looks for suspicious patterns.

It can detect activity such as:

- SSH root brute force attempts
- SSH failed login attacks
- Port scan indicators
- Ping sweep indicators
- Login flood patterns
- DNS flood indicators
- Beaconing-like repeated activity

When a suspicious log line is found, the detector creates an alert and sends it to the backend.

### 2. Real-Time Alert Generation

The detector sends alerts to:

```text
POST /api/receive-alert
```

Each alert can include:

- Attack type
- Attacker IP address
- Target IP address
- Severity level
- Timestamp
- Attempt count
- Matched log line

These alerts are then shown inside the dashboard.

### 3. Live Dashboard

The dashboard is opened in the browser using `index.html`.

It shows:

- Real-time threat monitoring
- Alert cards
- KPI counters
- Charts
- Threat activity tables
- Search and filter options
- Details modals
- Response buttons

The dashboard helps the user quickly understand what happened, which IP was involved, and how serious the alert is.

### 4. Alerts Page

The Alerts page shows security alerts received from the backend.

It supports:

- Severity filters
- Search
- Sorting
- Alert details
- Block IP action
- Clear alerts action
- CSV export
- Printable PDF-style export

### 5. Windows Endpoint / EDR Monitoring

EDR monitoring is an important part of this project. The Windows endpoint agent collects system activity from the Windows machine and sends it to the backend:

```text
windows_endpoint_agent.py
```

This agent sends endpoint data to the backend and helps the dashboard show endpoint activity.

It can collect:

- Endpoint heartbeat
- Process activity
- Network connections
- File activity
- Registry Run key changes
- Scheduled task changes
- USB device activity
- RDP login activity
- Failed login bursts
- Optional login events

The dashboard shows endpoint status, EDR alerts, recent events, process context, and response history. This helps connect attack alerts with endpoint-level activity on the monitored Windows machine.

### 6. Global Map View

The Global Map page uses Leaflet.js to show threat locations on a map.

It can display:

- Country-based threat locations
- Marker colors based on threat score
- Scanned IP locations when geolocation is available
- Basic map statistics

This gives a visual idea of where suspicious activity may be coming from.

### 7. Threat Logs

The Threat Logs page stores and displays scan history.

It supports:

- Search by IP, country, or API source
- Status filtering
- Sorting by date or threat score
- Pagination
- Expandable details
- CSV export
- Printable PDF-style export

If MySQL is enabled, this history can be stored permanently.

### 8. IP Blocking and Unblocking

The dashboard can block suspicious public IPv4 addresses.

There are two blocking modes:

- Application-level blocking: stores the blocked IP in backend memory.
- Firewall-level blocking: tries to block the IP using the operating system firewall.

Firewall blocking may require Administrator or sudo permission.

Supported firewall methods:

| System | Method |
| --- | --- |
| Windows | Windows Firewall using `netsh advfirewall` |
| Linux | `iptables` |
| macOS | `route` |

For safety, private, local, reserved, and invalid IP addresses are rejected for scan and block actions.

### 9. Optional MySQL Storage

MySQL is optional.

If MySQL is enabled, the backend can store:

- Real-time alerts
- Threat scan logs
- Endpoint details
- Endpoint events
- EDR alerts
- Response actions
- IOC cache data
- Cases and audit-style data

If MySQL is disabled, the project can still run, but some data will only stay in memory while the backend is running.

### 10. Search, Filters, Charts, and Exports

The frontend includes useful investigation features:

- Search boxes
- Severity filters
- Status filters
- Sorting
- Chart.js graphs
- CSV exports
- Printable report exports
- Refresh buttons
- Toast notifications

These features make the dashboard easier to use during analysis.

### 11. Manual Scan Using APIs

Manual Scan is an additional investigation feature. It is not the main detection engine.

The main detection engine is:

```text
attack_detector.py -> /api/receive-alert -> backend.py -> dashboard alerts
```

Manual Scan is used when the user wants to check an IP, domain, or file hash against external threat intelligence services.

Supported scan targets:

- Public IPv4 addresses
- Domain names
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

Supported external APIs:

| API | Purpose |
| --- | --- |
| AbuseIPDB | Checks IP abuse reports and confidence score |
| VirusTotal | Checks IP, domain, and hash reputation |
| AlienVault OTX | Checks pulses, reputation, ASN, and country data |
| GreyNoise | Checks whether an IP is related to internet scanning activity |
| IPQualityScore | Checks fraud score, proxy, VPN, TOR, bot, and abuse indicators |

API keys are configured in `.env`.

If API keys are missing, the main real-time alert system still works. Only manual scan enrichment will have limited results.

## How the Project Works

The normal project flow is:

```text
Log activity
  -> attack_detector.py
  -> Flask backend
  -> MySQL or memory
  -> Browser dashboard
  -> Investigation and response
```

In a lab setup, the flow can look like this:

```text
Kali Linux test traffic
  -> Target system logs
  -> attack_detector.py
  -> POST /api/receive-alert
  -> backend.py
  -> Dashboard alerts
  -> Block or investigate IP
```

## Lab Demonstration Workflow

To show that the project is working in real time, it can be tested in a controlled lab using two machines:

- Kali Linux as the attacker/test machine
- Windows as the target and monitored machine

From Kali Linux, different authorized test activities can be performed against the Windows machine. These activities create security-related log entries on the Windows side. The detector reads those logs, identifies attack or threat patterns, and sends alerts to the backend.

The dashboard then shows:

- Real-time attack alerts
- Attacker IP address
- Target IP address
- Attack type
- Severity level
- Timestamp
- Attempt count
- Related log details
- Further investigation and block options

Example lab flow:

```text
Kali Linux attacker machine
  -> Controlled test activity against Windows
  -> Windows logs
  -> attack_detector.py
  -> Flask backend
  -> Real-time dashboard alert
  -> Alert details and response action
```

This lab setup proves that the dashboard is not only showing static data. It can receive real-time threat activity, generate alerts, and provide useful details for analysis.

## Technology Used

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

## Project Files

| File | Purpose |
| --- | --- |
| `index.html` | Main dashboard page |
| `style.css` | Dashboard design and responsive styling |
| `script.js` | Frontend logic, charts, map, alerts, scans, exports, and UI actions |
| `backend.py` | Flask backend API, alert storage, scan logic, EDR APIs, and blocking logic |
| `attack_detector.py` | Real-time log monitor and alert sender |
| `windows_endpoint_agent.py` | Important Windows endpoint/EDR telemetry agent |
| `mysql_schema.sql` | MySQL database schema |
| `.env.example` | Example environment configuration |
| `requirements.txt` | Python dependencies |
| `setup-firewall-blocking.sh` | Linux/macOS helper for firewall blocking setup |
| `test-firewall-blocking.py` | Firewall blocking test helper |
| `start.sh` | Linux/macOS helper to start backend and frontend |
| `diagram-1-ip-blocking-flow.mmd` | Mermaid diagram for IP blocking flow |
| `diagram-2-three-blocking-options.mmd` | Mermaid diagram for blocking options |

## Requirements

- Python 3.10 or newer
- pip
- A modern browser such as Chrome, Edge, or Firefox
- MySQL, optional
- Administrator or sudo permission only if firewall-level blocking is needed
- Internet access for CDN assets and external API scans

## Setup

Create and activate a virtual environment.

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create your local environment file:

```powershell
copy .env.example .env
```

On Linux/macOS:

```bash
cp .env.example .env
```

Then edit `.env` based on your setup.

## Environment Variables

Common settings:

```env
MYSQL_ENABLED=false
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password_here
MYSQL_DATABASE=threat_dashboard
MYSQL_POOL_SIZE=5
ALERT_DEDUP_WINDOW_MINUTES=10
ALERT_INGEST_TOKEN=
```

Manual scan API keys:

```env
ABUSEIPDB_KEY=your_abuseipdb_key_here
VIRUSTOTAL_KEY=your_virustotal_key_here
ALIENVAULT_KEY=your_alienvault_key_here
GREYNOISE_KEY=your_greynoise_key_here
IPQUALITYSCORE_KEY=your_ipqualityscore_key_here
```

Windows endpoint agent settings:

```env
EDR_AGENT_TOKEN=
EDR_HEARTBEAT_TIMEOUT_SECONDS=20
EDR_RESPONSE_DRY_RUN=true
EDR_AGENT_INTERVAL=2
EDR_HEARTBEAT_INTERVAL=5
EDR_SLOW_INTERVAL=30
EDR_FAILED_LOGIN_THRESHOLD=5
```

CORS settings:

```env
CORS_ORIGINS=http://localhost:5500,http://127.0.0.1:5500,http://localhost:8000,http://127.0.0.1:8000
```

## How to Run

### 1. Start the Backend

```bash
python backend.py
```

Default backend URL:

```text
http://localhost:5001
```

Useful backend checks:

```text
http://localhost:5001/
http://localhost:5001/health
http://localhost:5001/api/status
```

### 2. Start the Frontend

From the project folder:

```bash
python -m http.server 8000
```

Open:

```text
http://localhost:8000
```

You can also open `index.html` directly, but using a local server is usually smoother.

### 3. Start the Real-Time Attack Detector

In another terminal:

```bash
python attack_detector.py
```

Default log file:

- Windows: `attack_detector.log`
- Linux/macOS: `/var/log/syslog`

To use a custom log file:

Windows PowerShell:

```powershell
$env:ATTACK_LOG_FILE="C:\path\to\your.log"
python attack_detector.py
```

Linux/macOS:

```bash
ATTACK_LOG_FILE=/path/to/your.log python attack_detector.py
```

### 4. Start the Windows Endpoint Agent for EDR Monitoring

For best results, run the terminal as Administrator.

```powershell
python windows_endpoint_agent.py --backend http://localhost:5001 --include-login-events
```

To send only one collection cycle:

```powershell
python windows_endpoint_agent.py --backend http://localhost:5001 --once
```

### 5. Optional: Use the Startup Script

On Linux/macOS:

```bash
bash start.sh
```

This starts the backend and a local frontend server.

## Testing Real-Time Alerts

Start the backend and the attack detector first.

For local Windows-style testing, add this line to `attack_detector.log`:

```text
Failed password for root from 8.8.8.8 port 22 ssh2
```

Expected result:

1. `attack_detector.py` detects the pattern.
2. It sends an alert to `/api/receive-alert`.
3. The backend stores the alert.
4. The dashboard shows the alert on the Alerts page.

For Linux lab testing, you can generate authorized test traffic that creates log entries in `/var/log/syslog` or your configured log file.

## Important Backend APIs

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Backend service information |
| `/health` | GET | Backend health check |
| `/api/status` | GET | Backend, MySQL, API, and blocklist status |
| `/api/validate` | POST | Validates IP, domain, or hash input |
| `/api/receive-alert` | POST | Receives real-time alerts from `attack_detector.py` |
| `/api/alerts` | GET | Returns stored alerts |
| `/api/alerts` | DELETE | Clears stored alerts |
| `/api/alert-stats` | GET | Returns chart statistics |
| `/api/threat-logs` | GET | Returns manual scan history |
| `/api/block-ip` | POST | Blocks a public IPv4 address |
| `/api/unblock-ip` | POST | Unblocks an IP address |
| `/api/blocked-ips` | GET | Lists blocked IPs |
| `/api/edr/dashboard` | GET | Returns EDR dashboard data |
| `/api/edr/heartbeat` | POST | Receives Windows agent heartbeat |
| `/api/edr/ingest` | POST | Receives Windows endpoint events |
| `/api/edr/events` | GET | Returns endpoint events |
| `/api/edr/alerts` | GET | Returns EDR alerts |
| `/api/edr/respond` | POST | Records EDR response actions |
| `/api/scan` | POST | Runs manual scan using selected APIs |
| `/api/scan/<service>` | POST | Runs one specific manual scan service |

## Database Support

MySQL is optional.

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

The backend can create the required database and tables automatically.

You can also import the schema manually:

```bash
mysql -u root -p < mysql_schema.sql
```

Windows PowerShell:

```powershell
Get-Content .\mysql_schema.sql | mysql -u root -p
```

## Security Notes

- Use this project only for defensive learning and authorized testing.
- Do not scan, attack, or test systems without permission.
- Keep `.env` private.
- Do not commit real API keys.
- Use `ALERT_INGEST_TOKEN` if the backend is exposed outside your machine.
- Use `EDR_AGENT_TOKEN` to protect endpoint agent ingestion.
- Firewall blocking can affect real network traffic, so use it carefully.
- The Flask development server is not a production deployment.

## Limitations

- No user login or role-based access control is included.
- Application-level IP blocklist is stored in memory.
- Live updates use polling, not WebSockets.
- Manual scan quality depends on API keys, network access, and provider limits.
- Windows endpoint telemetry works best with Administrator permission.
- Some frontend data may use fallback values if the backend has no stored data yet.
- Production deployment needs extra hardening.

## Future Improvements

- Add user login and roles
- Add WebSocket-based live updates
- Store blocklist entries permanently
- Add more detection rules
- Add SIEM integrations
- Add Docker Compose setup
- Add automated tests
- Add better reporting
- Add case management workflow
- Add automated response playbooks

## Ethical Use

This project is made for defensive cybersecurity education, lab testing, monitoring, and response. Use it only where you have clear permission.
