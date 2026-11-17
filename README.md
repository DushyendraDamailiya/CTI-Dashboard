# 🛡️ Threat Intelligence & EDR Dashboard

A modern, easy-to-use cybersecurity dashboard for detecting attacks, investigating threats, monitoring endpoints, and blocking malicious IPs in real time.

---

## 📖 Welcome & Overview

Welcome to the **Threat Intelligence and Response Dashboard**!

This project was built to help students, developers, and security enthusiasts understand how modern **Security Operations Centers (SOC)** and **Threat Intelligence (CTI)** systems work in the real world.

Here is the basic idea of how it works:
1. **Activity Happens**: A machine receives network requests, login attempts, or scan traffic.
2. **Detection**: The background detector (`attack_detector.py`) watches the logs for suspicious patterns (like brute-force attacks or port scans).
3. **Alerting**: Real-time alerts are sent to the Python Flask backend server.
4. **Visualization**: Everything appears instantly on your browser dashboard with interactive charts, threat levels, and details.
5. **Investigation & Response**: You can look up suspicious IPs against 5 threat intelligence APIs (VirusTotal, AbuseIPDB, GreyNoise, AlienVault, IPQS), view Windows telemetry with the EDR agent, and block malicious IPs with one click.

> 💡 **Lab Setup Tip**: In a typical home or college lab demo, you can use **Kali Linux** as the attacking machine and **Windows** as the monitored target machine. When test attacks are launched from Kali, the dashboard immediately picks them up and shows live alerts!

---

## ✨ Features at a Glance

- **🔴 Live Attack Detection**: Spots SSH brute force, Windows logon failures, RDP attempts, port scans, Nmap scans, SQL injection, directory traversal, and traffic beaconing.
- **📊 Interactive Dashboard**: Clean web UI with live threat graphs, attack breakdown charts, KPI counters, and real-time popups.
- **🖥️ Windows EDR Telemetry**: Gathers process trees, active network sockets, file modifications, registry changes, scheduled tasks, and USB plug-in events via `windows_endpoint_agent.py`.
- **🔍 Multi-Source Threat Scans**: Check any public IP, domain, or file hash with 5 popular threat intelligence APIs:
  - **AbuseIPDB**: Abuse reports and confidence rating
  - **VirusTotal**: Antivirus vendor scan consensus
  - **AlienVault OTX**: Threat pulses and community indicators
  - **GreyNoise**: Internet background noise and scanner classification
  - **IPQualityScore**: Fraud score, VPN, TOR, and bot detection
- **🗺️ Global Threat Map**: Visual Leaflet.js world map showing attack origins with threat severity pins.
- **🛡️ 1-Click IP Blocking**: Block malicious IPs in dashboard memory or at the OS firewall level (`netsh` on Windows, `iptables` on Linux, `route` on macOS).
- **💾 Flexible Storage**: Runs out of the box in zero-setup **in-memory mode** or connects to **MySQL** for permanent history.
- **📑 Easy Data Export**: Export alerts and threat history to CSV or printable reports with a single click.

---

## 📁 Project Structure

Here are the main files in the project and what each one does:

| File | What it does |
| --- | --- |
| `start.bat` | **Easiest way to start on Windows (Command Prompt or double-click)** |
| `start.ps1` | **PowerShell startup script for Windows** |
| `start.sh` | **Easiest way to start on Linux / macOS** |
| `index.html` | The web dashboard user interface |
| `style.css` | Styling and responsive dark-theme design |
| `script.js` | Frontend logic for live updates, charts, maps, and modals |
| `backend.py` | Python Flask backend server handling APIs, storage, and EDR |
| `attack_detector.py` | Real-time log watcher that detects attacks and sends alerts |
| `windows_endpoint_agent.py` | Windows agent that collects process, network, and system activity |
| `test-firewall-blocking.py` | Quick test to see if your computer can block IPs at the firewall |
| `mysql_schema.sql` | Optional database schema if you choose to use MySQL |
| `.env.example` | Example settings file for your API keys |
| `requirements.txt` | List of required Python packages |

---

## 🚀 How to Run (Step-by-Step)

You have two simple ways to run the project:

---

### Option 1: The Quick 1-Click Method (Recommended)

This starts everything automatically: the **Backend**, the **Web Dashboard**, the **Windows EDR Agent**, and the **Attack Detector**!

#### On Windows:
You can simply **double-click `start.bat`** in File Explorer, or open your terminal in the project folder:

**In Windows PowerShell:**
```powershell
.\start.ps1
# or
.\start.bat
```
> 💡 *PowerShell Tip*: If you type just `start.bat`, PowerShell shows an error saying it does not search the current folder by default. Always add `.\` at the start: `.\start.ps1` or `.\start.bat`!

**In Command Prompt (cmd):**
```cmd
start.bat
```

**What starts automatically in separate windows:**
1. **Flask Backend**: Runs on `http://localhost:5001` (with in-memory store or MySQL).
2. **Frontend UI**: Runs on `http://localhost:8000`.
3. **Windows EDR Agent**: Gathers live process, network, and endpoint telemetry.
4. **Attack Detector**: Monitors logs in real time for brute force, scans, and attacks.
5. **Browser**: Automatically opens `http://localhost:8000` so you can view your dashboard right away!

*To stop everything later*: Simply close the opened command prompt or PowerShell windows.

#### On Linux or macOS:
Open your terminal in the project folder and run:
```bash
bash start.sh
```
Both the backend (`:5001`) and frontend (`:8000`) will start up together.

---

### Option 2: Running Step-by-Step Manually

If you prefer to run each part yourself in separate terminal windows, follow these easy steps:

#### Step 1: Start the Backend Server
Open a terminal in the project folder and run:
```bash
# Optional: activate your virtual environment first if you made one
python backend.py
```
You should see:
```text
 * Running on http://127.0.0.1:5001
```
> 💡 *Note*: If MySQL is not running on your computer, don't worry! The backend automatically uses in-memory mode, so everything works smoothly without any database setup.

#### Step 2: Open the Web Dashboard
Open a second terminal in the project folder and run:
```bash
python -m http.server 8000
```
Now open your web browser and visit:
👉 **[http://localhost:8000](http://localhost:8000)**

You will see the live Threat Intelligence Dashboard ready to go!

#### Step 3: Start the Attack Detector
Open a third terminal and run:
```bash
python attack_detector.py
```
This script will begin watching for attacks:
- On Windows, it watches `attack_detector.log`.
- On Linux, it watches `/var/log/syslog`.

#### Step 4 (Optional): Start the Windows EDR Agent
If you want to test live Windows endpoint telemetry (processes, network connections, USB events):
Open PowerShell (as Administrator for best results) and run:
```powershell
python windows_endpoint_agent.py
```
Now click on the **Endpoint Detection & Response (EDR)** section on your dashboard to see your machine's live telemetry!

---

## 🧪 Quick 10-Second Test (See an Alert Pop Up!)

Want to test if alerts work without waiting for an actual network attack? It takes 10 seconds:

1. Make sure `backend.py`, the web dashboard (`http://localhost:8000`), and `attack_detector.py` are running.
2. Open the file **`attack_detector.log`** in Notepad or any text editor.
3. Paste this test line at the bottom and save the file:
   ```text
   Failed password for root from 192.168.1.50 port 22 ssh2
   ```
4. **Watch your dashboard**:
   - The detector immediately spots the SSH brute-force pattern.
   - A live toast notification appears in the dashboard.
   - Go to the **Alerts** tab to inspect the alert details and click **Block IP**!

---

## ⚙️ Configuration & API Keys (`.env`)

You can run the project immediately with zero configuration.

If you want to use the **Manual Scan** tab to check external threat databases, copy `.env.example` to `.env` and add your free API keys:

```bash
# On Windows:
copy .env.example .env

# On Linux / macOS:
cp .env.example .env
```

Open `.env` in any editor:
```env
# Free Threat Intelligence API Keys (optional for manual scans)
ABUSEIPDB_KEY=your_key_here
VIRUSTOTAL_KEY=your_key_here
ALIENVAULT_KEY=your_key_here
GREYNOISE_KEY=your_key_here
IPQUALITYSCORE_KEY=your_key_here

# Database (optional - leave false for easy in-memory mode)
MYSQL_ENABLED=false
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_password
MYSQL_DATABASE=threat_dashboard
```

> 🎁 **Where to get free API keys**:
> - [AbuseIPDB](https://www.abuseipdb.com/) (Free 1,000 checks/day)
> - [VirusTotal](https://www.virustotal.com/) (Free 500 requests/day)
> - [AlienVault OTX](https://otx.alienvault.com/) (Free community access)
> - [GreyNoise](https://www.greynoise.io/) (Free community account)
> - [IPQualityScore](https://www.ipqualityscore.com/) (Free 5,000 queries/month)

---

## 🗄️ Optional MySQL Setup

By default, the dashboard runs in **in-memory mode**—meaning you don't have to install or configure MySQL.

If you'd like to save alerts and scan logs permanently across restarts:
1. Make sure MySQL server is installed and running.
2. Set `MYSQL_ENABLED=true` in your `.env` file with your username and password.
3. The backend will automatically create the database and tables on its first run!
4. (Optional) You can also import the schema manually:
   ```bash
   mysql -u root -p < mysql_schema.sql
   ```

---

## 📡 API Reference

The backend provides simple REST endpoints:

| Endpoint | Method | Description |
| --- | --- | --- |
| `/health` | GET | Health check and server status |
| `/api/status` | GET | Connection status for MySQL and external APIs |
| `/api/receive-alert` | POST | Ingests real-time alerts from `attack_detector.py` |
| `/api/alerts` | GET / DELETE | Fetch recent alerts or clear all alerts |
| `/api/alert-stats` | GET | Hourly chart statistics and top attack types |
| `/api/scan` | POST | Query an IP, domain, or hash against all configured APIs |
| `/api/scan/<service>` | POST | Query an indicator with a specific API service |
| `/api/block-ip` | POST | Block a suspicious IP address |
| `/api/unblock-ip` | POST | Unblock an IP address |
| `/api/blocked-ips` | GET | List currently blocked IPs |
| `/api/threat-logs` | GET | View saved threat scan history |
| `/api/edr/dashboard` | GET | Returns live Windows endpoint overview and alerts |
| `/api/edr/heartbeat` | POST | Receives agent keep-alive heartbeats |
| `/api/edr/ingest` | POST | Ingests endpoint telemetry events |

---

## 🤝 Responsible Use & Learning

This project was created for educational purposes, cybersecurity coursework, and defensive lab simulations. Please remember to test only on your own systems or within dedicated virtual machines and authorized home labs.
