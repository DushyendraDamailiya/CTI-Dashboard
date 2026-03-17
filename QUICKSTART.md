# ⚡ Quick Start Guide

## 🎯 Your Project is Ready to Use!

### What Was Wrong?
1. ❌ Missing `config.js` reference in HTML - **FIXED**
2. ❌ Missing `.env` file with API keys - **FIXED**
3. ❌ Python dependencies not installed - **FIXED**
4. ❌ Frontend server stopping - **FIXED**

---

## 🚀 Run the Project Now

### Option 1: Automatic (Recommended)
```bash
cd /Users/pankajkumarrana/Downloads/major-project-main
chmod +x start.sh
./start.sh
```

### Option 2: Manual Setup
```bash
# Terminal 1: Backend
cd /Users/pankajkumarrana/Downloads/major-project-main
source venv/bin/activate
python backend.py

# Terminal 2: Frontend (in same directory)
python3 -m http.server 8000
```

---

## 🌍 Access Your Dashboard

### Open in Browser
👉 **http://localhost:8000**

---

## ✨ Features Available

✅ **Real-Time Monitoring**
- Live threat KPIs
- Threat charts
- Auto-refresh table

✅ **Manual Scan**
- Scan any IP address
- Scan domains
- Scan file hashes

✅ **Threat Intelligence**
- 4 threat APIs integrated
- Real-time analysis
- Color-coded threats

✅ **Alerts & Logs**
- Security alerts
- Threat history
- Action tracking

---

## 🔧 Backend API (http://localhost:5001)

Try these API calls:

```bash
# Health check
curl http://localhost:5001/health

# Validate input
curl -X POST http://localhost:5001/api/validate \
  -H "Content-Type: application/json" \
  -d '{"target":"8.8.8.8"}'

# Scan an IP (may take 10-30 seconds)
curl -X POST http://localhost:5001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.1"}'
```

---

## ⚙️ Configuration

### API Keys Location
File: `.env`

```
ABUSEIPDB_KEY=your-key-here
VIRUSTOTAL_KEY=your-key-here
ALIENVAULT_KEY=your-key-here
GREYNOISE_KEY=your-key-here
IPQUALITYSCORE_KEY=your-key-here
MYSQL_ENABLED=true
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your-mysql-password
MYSQL_DATABASE=threat_dashboard
```

To get real API keys:
1. **AbuseIPDB**: https://www.abuseipdb.com
2. **VirusTotal**: https://www.virustotal.com
3. **AlienVault OTX**: https://otx.alienvault.com
4. **GreyNoise**: https://www.greynoise.io

---

## 📊 Server Status

| Service | Port | Status |
|---------|------|--------|
| Frontend | 8000 | ✅ Running |
| Backend | 5001 | ✅ Running |

---

## 📝 Documentation

- **BUG_FIXES.md** - Detailed bug fixes
- **PROJECT_STATUS.md** - Full project status
- **README.md** - Original documentation
- **SETUP_GUIDE.md** - Detailed setup instructions

---

## ❓ Troubleshooting

### Port Already in Use?
```bash
# Find what's using the port
lsof -i :8000
lsof -i :5001

# Kill the process
kill -9 <PID>
```

### Backend Not Responding?
```bash
# Check if backend is running
curl http://localhost:5001/health

# If not, restart it
python backend.py
```

### Frontend Shows 404?
```bash
# Make sure you're in the right directory
cd /Users/pankajkumarrana/Downloads/major-project-main

# Restart frontend
python3 -m http.server 8000
```

---

## 🎉 You're All Set!

Your Threat Intelligence Dashboard is now:
- ✅ Fully operational
- ✅ All bugs fixed
- ✅ Ready to scan threats
- ✅ Running on localhost

**Open http://localhost:8000 and start using it now!**

---

## 💡 Tips

- Mock data is provided for demonstration
- Real API calls will be made with real keys
- Scans typically take 10-30 seconds
- Responses are cached for 1 hour
- You can scan up to 100 targets per hour

Enjoy! 🚀
