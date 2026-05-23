# Setup Guide

## Project Name

Threat Intelligence and Response Framework for Malicious IPs Dashboard

## 1. Requirements

Before starting the project, make sure the following are installed:

- Python 3.10 or newer
- pip
- A modern browser such as Chrome, Edge, or Firefox
- MySQL Server, only if you want permanent alert and scan storage
- Git, if you are cloning the project from a repository

## 2. Project Files

Important files used during setup:

| File | Purpose |
|------|---------|
| `backend.py` | Starts the Flask backend API server. |
| `attack_detector.py` | Starts the real-time log monitoring and alert generation module. |
| Kali Linux attack simulator | External lab machine used to generate controlled attack traffic. |
| `index.html` | Opens the dashboard in the browser. |
| `.env.example` | Template for environment variables. |
| `.env` | Local private configuration file. Do not publish this file. |
| `requirements.txt` | Python package dependencies. |
| `mysql_schema.sql` | MySQL schema for alerts and threat logs. |

## 3. Install Dependencies

Open a terminal in the project folder and run:

```bash
pip install -r requirements.txt
```

If you are using a virtual environment, activate it first and then install the dependencies.

## 4. Create Environment File

Create a `.env` file in the project root by using `.env.example` as a reference.

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

CORS_ORIGINS=http://localhost:5500,http://127.0.0.1:5500,http://localhost:5173,http://localhost:3000,null
```

The external API keys are optional for the main real-time alert system. They are required only for manual scan enrichment.

## 5. MySQL Setup

MySQL is optional. Enable it only if you want alerts and scan logs to be stored permanently.

To enable MySQL, set this in `.env`:

```env
MYSQL_ENABLED=true
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password
MYSQL_DATABASE=threat_dashboard
```

The backend can create the required database tables automatically on startup.

You can also import the schema manually:

```bash
mysql -u root -p < mysql_schema.sql
```

On Windows PowerShell:

```powershell
Get-Content .\mysql_schema.sql | mysql -u root -p
```

If you do not want MySQL, keep:

```env
MYSQL_ENABLED=false
```

## 6. Start the Backend

Run:

```bash
python backend.py
```

The backend starts the Flask API server. By default, the frontend expects the backend to be available locally.

Useful backend URLs:

| URL | Purpose |
|-----|---------|
| `http://localhost:5001/` | Backend service information. |
| `http://localhost:5001/health` | Backend health check. |
| `http://localhost:5001/api/status` | API, MySQL, and blocklist status. |

## 7. Open the Dashboard

Open `index.html` in a browser.

You can use the dashboard to:

- View real-time monitoring.
- Review generated alerts.
- Check threat logs.
- Run manual scans.
- View map-based threat visualization.
- Block or unblock suspicious IP addresses.

## 8. Start Real-Time Alert Generation

The main function of this project is real-time threat detection and alert generation.

Start the detector with:

```bash
python attack_detector.py
```

The detector monitors the configured log file, detects suspicious patterns, and sends alerts to:

```text
POST http://localhost:5001/api/receive-alert
```

Default behavior:

- On Windows, it uses `attack_detector.log` in the project folder.
- On Linux, it uses `/var/log/syslog` unless changed.

You can change the monitored log file using:

```env
ATTACK_LOG_FILE=path_to_log_file
```

You can change the backend URL using:

```env
ATTACK_BACKEND_URL=http://localhost:5001
```

## 9. Use the Kali Linux Attack Simulator

The Kali Linux attack simulator is used to generate controlled security events in a lab environment. These events create log entries on the target system. `attack_detector.py` reads those logs, detects suspicious patterns, and sends alerts to the backend.

Use the simulator only on systems that you own or have permission to test.

Recommended lab setup:

```text
Kali Linux Machine -> Target/Monitored Machine -> attack_detector.py -> backend.py -> Dashboard
```

Example simulator activities:

- Try a few failed SSH login attempts from Kali to the target machine.
- Run a small port scan against the target machine in the lab.
- Run a ping sweep against a private lab subnet.
- Generate repeated connection attempts to test beaconing-style detection.

Example safe lab commands:

```bash
ping <target-ip>
```

```bash
nmap -sS <target-ip>
```

For SSH failed-login testing, connect from Kali to the target and intentionally enter a wrong password a few times:

```bash
ssh testuser@<target-ip>
```

These actions should create log entries on the target system. If the detector patterns match those logs, alerts will appear in the dashboard.

## 10. Test Real-Time Alerts

For Windows or local testing, add a sample suspicious log line to `attack_detector.log` while `attack_detector.py` is running.

Example log line:

```text
Failed password for root from 8.8.8.8 port 22 ssh2
```

If the backend and detector are running correctly, an alert should be sent to the backend and displayed in the dashboard alerts section.

## 11. Manual Scan Usage

Manual scan is a secondary feature used for enrichment.

Use it when you want to check an IP, domain, or hash against external threat intelligence services.

Supported services include:

- AbuseIPDB
- VirusTotal
- AlienVault OTX
- GreyNoise
- IPQualityScore

Manual scanning works best when the related API keys are configured in `.env`.

## 12. IP Blocking

The dashboard supports blocking and unblocking IP addresses.

Two blocking modes exist:

- App-level blocking: stores the blocked IP in backend memory.
- Firewall-level blocking: attempts to block the IP using the operating system firewall.

Firewall-level blocking may require administrator or sudo permission.

## 13. Common Problems

### Backend Not Starting

Check that dependencies are installed:

```bash
pip install -r requirements.txt
```

Also check the `.env` file for invalid MySQL settings.

### Alerts Not Showing

Make sure:

- `backend.py` is running.
- `attack_detector.py` is running.
- `ATTACK_BACKEND_URL` points to the correct backend URL.
- The monitored log file contains matching attack patterns.

### Manual Scan Has No API Results

Make sure the required API keys are added in `.env`.

The real-time alert system can still work without API keys.

### MySQL Errors

Make sure:

- MySQL Server is running.
- Username and password are correct.
- The configured user has permission to create/use the database.
- `mysql-connector-python` is installed from `requirements.txt`.

## 14. Main Runtime Flow

```text
Kali Linux Attack Simulator
  -> Target System Logs
  -> attack_detector.py
  -> Flask Backend /api/receive-alert
  -> MySQL or Memory Storage
  -> Dashboard Alerts and Monitoring
  -> Response Action
```

## 15. Recommended Start Order

1. Configure `.env`.
2. Start MySQL if enabled.
3. Run `python backend.py`.
4. Open `index.html`.
5. Run `python attack_detector.py`.
6. Use Kali Linux to generate authorized lab test traffic.
7. Review alerts in the dashboard.
