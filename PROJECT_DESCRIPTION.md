# Project Description: Threat Intelligence and Response Framework for Malicious IPs Dashboard

## 1. Project Overview

The **Threat Intelligence and Response Framework for Malicious IPs Dashboard** is mainly a **real-time threat intelligence and alert generation system**. Its primary purpose is to continuously monitor log activity, detect suspicious attack patterns, generate real-time alerts, store those alerts, and display them on a live dashboard for quick investigation and response.

The project uses a browser-based dashboard, a Flask backend API, a real-time attack detector, an attack simulator running from Kali Linux, optional MySQL storage, and response actions such as IP blocking. External threat intelligence APIs are included as a **secondary supporting feature**. They enrich scanned IPs, domains, and hashes with reputation details, but the core functionality of the project is real-time detection, alert creation, alert storage, and alert visualization.

## 2. Project Objectives

- Monitor system or application logs in real time.
- Generate controlled test attacks from Kali Linux in a lab environment.
- Detect suspicious behavior such as brute force attacks, port scans, ping sweeps, login floods, DNS flood indicators, and beaconing.
- Generate real-time alerts whenever suspicious activity is detected.
- Send alerts from the detector to the backend automatically.
- Store and display alerts for investigation and later review.
- Show alert severity, attacker IP, target IP, attempt count, timestamp, and related log details.
- Provide live dashboard views, charts, filters, and threat history.
- Support response actions such as blocking and unblocking suspicious IP addresses.
- Use external APIs as a secondary feature to enrich manual scans with reputation and threat intelligence data.
- Store alerts and scan history in MySQL when enabled.

## 3. Technology Stack

### Frontend

- **HTML5** for the dashboard structure.
- **CSS3** for styling, responsive layout, dark cybersecurity theme, cards, tables, modals, and animations.
- **Vanilla JavaScript** for live alert display, dashboard logic, scan workflows, charts, map updates, filtering, pagination, and response actions.
- **Chart.js** for threat trend and attack distribution charts.
- **Leaflet.js** for interactive global map visualization.
- **Font Awesome** for dashboard icons.

### Backend

- **Python Flask** for REST API endpoints.
- **Flask-CORS** for browser-to-backend communication.
- **Flask-Caching** for simple in-memory caching support.
- **Requests** for alert delivery and external API enrichment.
- **ThreadPoolExecutor** for parallel threat intelligence scans.
- **python-dotenv** for environment variable loading.
- **mysql-connector-python** for optional MySQL persistence.

### Database

- **MySQL** is used when enabled through environment variables.
- The project includes `mysql_schema.sql`.
- Main tables:
  - `alerts`: stores real-time attack alerts.
  - `threat_logs`: stores manual IP scan history and results.

## 4. Main Project Files

| File | Purpose |
|------|---------|
| `index.html` | Main dashboard user interface. |
| `style.css` | Complete dashboard styling and responsive layout. |
| `script.js` | Frontend logic, API calls, charts, map, logs, alerts, and UI interactions. |
| `backend.py` | Flask backend server, alert receiver, alert storage, dashboard APIs, MySQL handling, API enrichment, and blocking logic. |
| `attack_detector.py` | Core real-time log monitor that detects attacks and sends alerts to the backend. |
| Kali Linux attack simulator | External lab machine used to generate controlled attack traffic for testing real-time alerts. |
| `mysql_schema.sql` | MySQL database schema for alerts and threat logs. |
| `.env.example` | Example configuration for API keys, MySQL, CORS, and alert deduplication. |
| `requirements.txt` | Python dependencies required to run the backend. |
| `setup-firewall-blocking.sh` | Helper script for firewall blocking setup on Linux. |
| `test-firewall-blocking.py` | Test helper for firewall blocking behavior. |

## 5. Core Project Features

### Kali Linux Attack Simulator

The attack simulator is an important part of the project testing workflow. It runs from a Kali Linux machine and generates controlled attack traffic against the monitored target system. This simulator is used only in a lab or authorized environment to verify that the real-time detector can identify attack patterns and generate alerts.

Example simulated activities include:

- SSH failed login attempts.
- Port scanning.
- Ping sweep testing.
- Repeated connection attempts.
- Other safe lab traffic that creates detectable log entries.

The simulator does not replace the detector. Its purpose is to create test events. The real-time detection work is still performed by `attack_detector.py`, which reads logs, matches suspicious patterns, and sends alerts to the backend.

The simulator flow is:

```text
Kali Linux Attack Simulator -> Target System Logs -> attack_detector.py -> Backend -> Dashboard Alerts
```

### Real-Time Threat Detection

The main working module of this project is `attack_detector.py`. It continuously monitors the configured log file and checks new log entries for suspicious patterns. Instead of only depending on manual scanning, the system actively watches activity and reacts when attack-like behavior appears.

Detected activity includes:

- SSH root brute force attacks.
- SSH brute force attempts.
- Port scans.
- Ping sweeps.
- Login floods.
- DNS flood indicators.
- Beaconing or repeated periodic traffic.

### Real-Time Alert Generation

When suspicious activity is detected, the attack detector immediately creates an alert containing the attacker IP, attack type, severity, target IP, timestamp, attempt count, and a short copy of the matched log line. This alert is then sent to the backend through:

```text
POST /api/receive-alert
```

The backend validates the alert, stores it when MySQL is enabled, and makes it available to the dashboard. This real-time alert generation workflow is the central function of the project.

### Live Alert Dashboard

The dashboard displays real-time alerts received from the attack detector. Alerts can be filtered by severity and reviewed by analysts. The dashboard helps the user quickly understand what attack occurred, which IP was involved, how severe it is, and when it happened.

### Real-Time Monitoring

The real-time monitoring page includes KPI cards, threat tables, search functionality, manual refresh, and charts. It shows important security metrics such as total requests, malicious IPs, high-severity alerts, and system/API health.

### Response Actions

The dashboard supports response actions such as blocking and unblocking IP addresses. Blocking can be handled in memory through the backend, and optional system firewall blocking is available for supported operating systems.

## 6. Supporting Dashboard Features

### Manual Scan

Manual scanning is a secondary feature of this project. It helps analysts investigate suspicious IPs, domains, and hashes after alerts are generated or during manual analysis.

Users can manually scan:

- IP addresses
- Domain names
- File hashes

The scan result includes overall threat score, risk level, API-wise enrichment results, malicious status, reputation details, geolocation when available, and scan timestamp.

### Global Map

The global map uses Leaflet.js to visualize attack sources geographically. Markers represent detected or scanned threats, and marker colors indicate severity levels such as low, medium, high, and critical.

### Threat Logs

The threat logs page stores and displays scan and alert-related history. It supports:

- Search by IP, country, or API source.
- Filtering by status.
- Sorting by date or threat score.
- Pagination.
- Export and clear actions in the frontend.

## 7. Backend API Features

The Flask backend provides REST endpoints for the dashboard and detector.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Backend service information. |
| `/health` | GET | Health check and MySQL status. |
| `/api/validate` | POST | Validates an IP, domain, or hash target. |
| `/api/scan` | POST | Secondary feature: scans a target using configured threat intelligence APIs. |
| `/api/scan/<service>` | POST | Secondary feature: scans a target using one specific service. |
| `/api/alerts` | GET | Fetches stored alerts. |
| `/api/alerts` | DELETE | Clears stored alerts. |
| `/api/alert-stats` | GET | Returns alert statistics for charts. |
| `/api/receive-alert` | POST | Main alert ingestion endpoint. Receives alerts from `attack_detector.py`. |
| `/api/threat-logs` | GET | Fetches stored manual scan logs. |
| `/api/block-ip` | POST | Blocks an IP in memory and optionally at firewall level. |
| `/api/unblock-ip` | POST | Unblocks an IP. |
| `/api/blocked-ips` | GET | Lists currently blocked IPs. |
| `/api/cache-stats` | GET | Shows cache and rate limit information. |
| `/api/status` | GET | Shows backend, MySQL, API, and blocklist status. |

## 8. Secondary Feature: Threat Intelligence API Enrichment

The backend supports external threat intelligence services as an enrichment layer. These APIs are useful for manual investigation and reputation checking, but they are not the main detection engine of the project. The main detection engine is the real-time attack detector and alert generation pipeline.

Supported enrichment services:

- **AbuseIPDB**: IP abuse confidence and report data.
- **VirusTotal**: IP/domain/hash reputation and detection information.
- **AlienVault OTX**: Pulse count, reputation, ASN, and threat intelligence.
- **GreyNoise**: Internet scanner classification such as benign, suspicious, or malicious.
- **IPQualityScore**: Fraud, proxy, VPN, TOR, bot, abuse velocity, and risk score details for IPv4 addresses.

API keys are configured in `.env` using the names shown in `.env.example`. If an API key is missing, the system can still run its real-time alert generation functionality.

## 9. Attack Detector

`attack_detector.py` is the core module of the project. It monitors a log file and detects suspicious patterns such as:

- SSH root brute force attacks.
- SSH brute force attempts.
- Port scans.
- Ping sweeps.
- Login floods.
- DNS flood indicators.
- Beaconing or repeated periodic traffic.

When an attack pattern is found, the detector sends an alert payload to:

```text
POST /api/receive-alert
```

The backend then stores the alert and makes it available to the dashboard. This creates the real-time threat intelligence flow: log monitoring, attack detection, alert generation, backend ingestion, database storage, dashboard display, and response.

## 10. Database Design

The MySQL schema contains two main tables.

### `alerts`

Stores real-time attack alerts, including:

- Alert type
- Source
- IP address
- Severity
- Description
- Target IP
- Log line
- Attempt count
- Raw payload
- Created and updated timestamps

### `threat_logs`

Stores manual IP scan history, including:

- IP address
- Country and country code
- Threat score
- API sources
- Status
- Full scan results as JSON
- Overall result data as JSON
- Scan timestamps

The `threat_logs.ip_address` field is unique, so repeated scans update the existing record instead of creating duplicate entries.

## 11. Security and Reliability Features

- Input validation for IPs, domains, and hashes.
- Rate limiting with a request limit per client IP.
- CORS origin configuration through environment variables.
- API keys stored in environment variables instead of source code.
- Real-time alerting can continue even when external enrichment API keys are missing.
- Graceful handling when API keys are missing.
- Timeout handling for external APIs.
- Alert deduplication window support.
- Optional MySQL persistence.
- Optional firewall-level blocking.
- Defensive error handling in backend routes and detector loop.

## 12. Basic Workflow

1. The user opens the dashboard in the browser.
2. The dashboard communicates with the Flask backend.
3. The Kali Linux attack simulator generates controlled test activity in a lab environment.
4. The target system records this activity in its logs.
5. `attack_detector.py` monitors the configured log file continuously.
6. A suspicious log entry is matched against attack patterns.
7. The detector creates a real-time alert with attack details.
8. The detector sends the alert to the backend through `/api/receive-alert`.
9. The backend validates, stores, and deduplicates the alert when configured.
10. The dashboard displays the alert, statistics, charts, logs, and severity information.
11. The user reviews the alert and can block the suspicious IP address.
12. As a secondary workflow, the user can manually scan an IP, domain, or hash using external APIs for extra reputation intelligence.

## 13. How to Start and Use This Project

Follow these steps to run and use the project.

1. Install Python dependencies:

```bash
pip install -r requirements.txt
```

2. Create a `.env` file using `.env.example` as a reference.

3. Configure MySQL if you want alert and scan history to be saved permanently:

```env
MYSQL_ENABLED=true
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_password
MYSQL_DATABASE=threat_dashboard
```

If MySQL is not required, set:

```env
MYSQL_ENABLED=false
```

4. Add API keys only if manual scan enrichment is required:

```env
ABUSEIPDB_KEY=your_key
VIRUSTOTAL_KEY=your_key
ALIENVAULT_KEY=your_key
GREYNOISE_KEY=your_key
IPQUALITYSCORE_KEY=your_key
```

5. Start the backend:

```bash
python backend.py
```

6. Open `index.html` in a browser.

7. Start the attack detector for the main real-time alert generation workflow:

```bash
python attack_detector.py
```

8. Use the dashboard:

- Open the **Real-Time Monitoring** page to view live threat status.
- Open the **Alerts** page to review alerts generated by the detector.
- Open the **Threat Logs** page to review stored history.
- Use **Block IP** actions when a suspicious IP needs a response.
- Use **Manual Scan** only when you want extra reputation details from external APIs.

The main project flow is:

```text
Kali Linux Simulator -> Target Logs -> attack_detector.py -> /api/receive-alert -> Backend -> MySQL/Memory -> Dashboard Alerts -> Response Action
```

## 14. Project Outcome

This project delivers a complete real-time malicious IP threat detection and alert generation dashboard. Its main achievement is the live monitoring pipeline that detects suspicious log activity, generates alerts, sends them to the backend, stores them, and displays them for investigation and response. Manual scanning with external threat intelligence APIs is included as a useful side feature for enrichment and deeper analysis. The project is suitable for cybersecurity demonstrations, academic submission, learning real-time threat monitoring workflows, and as a base for further production hardening.

## 15. Future Scope

- Add user authentication and role-based access control.
- Add WebSocket-based live updates.
- Add PDF/CSV reporting.
- Add advanced correlation between alerts and scan history.
- Add machine learning based anomaly detection.
- Add SIEM integrations.
- Add Docker deployment.
- Add production-grade persistent blocklists.
- Add scheduled scans and automated response playbooks.
