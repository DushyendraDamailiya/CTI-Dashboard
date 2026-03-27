# Threat Intelligence Dashboard - Setup & Deployment Guide

## Overview
This guide explains how to run the complete Threat Intelligence Dashboard with the Python backend proxy.

---

## Project Structure

```
MajorProject/
├── index.html                 # Frontend HTML
├── style.css                  # Frontend CSS
├── script.js                  # Frontend JavaScript (updated)
├── config.js                  # Frontend config (optional, for reference)
├── backend.py                 # Python Flask backend (NEW - CRITICAL)
├── requirements.txt           # Python dependencies (NEW)
├── .env                       # Environment variables with API keys (NEW)
├── .gitignore                # Git ignore file (updated)
├── API_RESPONSE_GUIDE.md     # API response documentation
├── IMPROVEMENT_ROADMAP.md    # Improvement suggestions
├── COMPLETION_REPORT.md      # Project completion report
├── QUICKSTART.md             # Quick start guide
└── README.md                 # Main documentation
```

---

## What's New

### 1. **backend.py** (Python Flask Server)
- ✅ CORS proxy for all 4 APIs
- ✅ Input validation (IP, domain, hash)
- ✅ Rate limiting (100 requests/hour per IP)
- ✅ Response caching (1 hour)
- ✅ Error handling
- ✅ Logging

### 2. **requirements.txt**
- Lists all Python dependencies
- Use `pip install -r requirements.txt`

### 3. **.env**
- Contains API keys (KEEP PRIVATE!)
- Already in .gitignore

### 4. **Updated script.js**
- ✅ Input validation functions
- ✅ Backend integration
- ✅ Real API response handling
- ✅ Error handling with retry

---

## Setup Instructions

### Prerequisites
- Python 3.7+ installed
- pip package manager
- Node.js (optional, for serving frontend)

### Step 1: Install Python Dependencies

```bash
# Navigate to project directory
cd /Users/pankajkumarrana/Desktop/MajorProject

# Create virtual environment (recommended)
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Verify .env File

Check that `.env` contains your API keys:
```bash
cat .env
```

You should see:
```
ABUSEIPDB_KEY=86a775e65...
VIRUSTOTAL_KEY=5d7a690b...
ALIENVAULT_KEY=aa44938611...
GREYNOISE_KEY=566c39ce...
```

### Step 3: Start the Backend Server

**Option A: Development Mode**
```bash
python backend.py
```

Output should show:
```
 * Running on http://0.0.0.0:5000
 * Debug mode: off
```

**Option B: Production Mode** (with Gunicorn)
```bash
gunicorn -w 4 -b 0.0.0.0:5000 backend:app
```

### Step 4: Serve Frontend in Another Terminal

**Option A: Python HTTP Server**
```bash
# In new terminal, keep backend running
cd /Users/pankajkumarrana/Desktop/MajorProject
python3 -m http.server 8000
```

**Option B: Node.js HTTP Server**
```bash
npm install -g http-server  # If not installed
http-server -p 8000
```

**Option C: Use VS Code Live Server**
- Install "Live Server" extension in VS Code
- Right-click `index.html` → "Open with Live Server"

### Step 5: Access the Dashboard

Open in browser:
```
http://localhost:8000
```

---

## Testing the Setup

### 1. Test Backend Health
```bash
curl http://localhost:5000/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2025-12-05T14:22:00"
}
```

### 2. Test Input Validation
```bash
curl -X POST http://localhost:5000/api/validate \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "type": "auto"}'
```

### 3. Test Full Scan
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.105"}'
```

### 4. Test in Dashboard
1. Open http://localhost:8000
2. Go to "Manual Scan" tab
3. Enter a test IP: `192.168.1.105`
4. Click "Scan Now"
5. Should show results from all 4 APIs

---

## How It Works

### Data Flow

```
User Input (Frontend)
        ↓
Input Validation (Frontend)
        ↓
POST /api/scan (Backend)
        ↓
Server-side Validation
        ↓
Check Cache
        ├─ Cache Hit → Return cached result ✓
        └─ Cache Miss → Query APIs
                ↓
        Query 4 APIs in parallel:
        ├─ AbuseIPDB
        ├─ VirusTotal
        ├─ AlienVault OTX
        └─ GreyNoise
                ↓
        Combine results & calculate consensus
        ↓
        Cache result (1 hour)
        ↓
Display Results (Frontend)
```

### Security Features

1. **CORS Proxy**: Browser can't bypass backend
2. **API Key Protection**: Keys never exposed to frontend
3. **Input Validation**: Both frontend + backend
4. **Rate Limiting**: 100 requests/hour per IP
5. **Error Handling**: Graceful failure handling
6. **Timeout Protection**: 10-second timeout per API
7. **Caching**: Reduces API calls and costs

---

## Production Deployment

### Deploy to Heroku

1. **Create Heroku account**: https://www.heroku.com

2. **Install Heroku CLI**:
```bash
brew tap heroku/brew && brew install heroku
```

3. **Create Procfile**:
```
web: gunicorn -w 4 -b 0.0.0.0:$PORT backend:app
```

4. **Deploy**:
```bash
heroku login
heroku create your-app-name
git push heroku main
```

### Deploy to AWS EC2

1. **Launch EC2 instance** (Ubuntu 20.04)

2. **Install dependencies**:
```bash
sudo apt-get update
sudo apt-get install python3-pip nginx
pip install -r requirements.txt
```

3. **Configure Nginx** as reverse proxy:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
    }
}
```

4. **Run with Gunicorn**:
```bash
gunicorn -w 4 -b 127.0.0.1:5000 backend:app
```

### Deploy to Docker

1. **Create Dockerfile**:
```dockerfile
FROM python:3.9
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "backend:app"]
```

2. **Build & Run**:
```bash
docker build -t threat-dashboard .
docker run -p 5000:5000 threat-dashboard
```

---

## Environment Variables

### Development
```bash
FLASK_ENV=development
FLASK_DEBUG=False
ABUSEIPDB_KEY=your_key
VIRUSTOTAL_KEY=your_key
ALIENVAULT_KEY=your_key
GREYNOISE_KEY=your_key
```

### Production
Use environment management:
- Heroku: Config Vars
- AWS: Systems Manager Parameter Store
- Docker: .env file or docker-compose.yml
- Linux: /etc/environment or systemd service file

---

## Troubleshooting

### "CORS error" in browser console
- Backend not running
- Backend URL wrong (check script.js line 5)
- Backend not listening on 0.0.0.0:5000

**Fix**:
```bash
# Check if backend is running
curl http://localhost:5000/health

# Restart backend
python backend.py
```

### "Invalid input" for valid IPs
- Input validation regex might be too strict
- Extra spaces in input

**Fix**:
```bash
# Test validation endpoint
curl -X POST http://localhost:5000/api/validate \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
```

### API keys not working
- Keys expired or revoked
- Wrong API key format
- API rate limit exceeded

**Fix**:
1. Verify keys in `.env` file
2. Check API service website for key status
3. Wait before retrying (rate limits)

### Backend crashes
- Check error logs:
```bash
# If running with: python backend.py
# See output directly

# If running with gunicorn:
tail -f gunicorn.log
```

### Slow responses
- APIs are slow (normal)
- Rate limit approaching
- Network connection issue

**Check cache**:
```bash
curl http://localhost:5000/api/cache-stats
```

---

## API Endpoints

### Health Check
```
GET /health
Response: { "status": "healthy", "timestamp": "..." }
```

### Validate Input
```
POST /api/validate
Body: { "target": "192.168.1.1", "type": "auto" }
Response: { "success": true, "type": "ip" }
```

### Full Scan (All 4 APIs)
```
POST /api/scan
Body: { "target": "192.168.1.1" }
Response: { 
  "target": "...",
  "results": [ {...}, {...}, {...}, {...} ],
  "overall": { "averageScore": 80, "consensus": "MALICIOUS" }
}
```

### Scan Specific Service
```
POST /api/scan/abuseipdb
Body: { "target": "192.168.1.1" }
Response: { "result": {...} }
```

### Cache Stats
```
GET /api/cache-stats
Response: { "cache_type": "simple", "cache_timeout": 3600 }
```

### Status
```
GET /api/status
Response: { "status": "operational", "apis": {...} }
```

---

## Rate Limiting

- **Limit**: 100 requests per hour per IP
- **Reset**: Automatically at start of each hour
- **Error**: HTTP 429 (Too Many Requests)

```bash
# This will be rejected after 100 requests
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
# HTTP 429: Rate limit exceeded
```

---

## Caching

- **Duration**: 1 hour
- **Type**: In-memory (simple)
- **Key**: Same scan parameters
- **Benefits**: Faster response, lower API costs

```bash
# First request: hits APIs (slow)
curl -X POST http://localhost:5000/api/scan \
  -d '{"target": "192.168.1.1"}'

# Second request (within 1 hour): cached (fast)
curl -X POST http://localhost:5000/api/scan \
  -d '{"target": "192.168.1.1"}'
```

---

## Monitoring & Logging

Backend logs all API calls:
```
2025-12-05 14:22:00 INFO: Scanning target: 192.168.1.105
2025-12-05 14:22:01 INFO: AbuseIPDB response received
2025-12-05 14:22:02 INFO: VirusTotal response received
...
```

---

## Performance Tips

1. **Enable Caching**: Already enabled (1 hour)
2. **Use Gunicorn**: 4+ workers for production
3. **Add Redis**: For distributed caching
4. **Use CDN**: For frontend assets
5. **Monitor APIs**: Track response times

---

## Next Steps

1. ✅ Setup backend locally
2. ✅ Test with sample IPs
3. ✅ Verify all 4 APIs working
4. ✅ Deploy to production
5. ⏭️ Add more features (real-time feed, WebSocket, etc.)

---

## Support

For issues:
1. Check troubleshooting section
2. Review backend logs
3. Test with curl
4. Check API service status websites

---

## Security Reminders

⚠️ **IMPORTANT**:
- ✅ Never commit `.env` file (it's in .gitignore)
- ✅ Never share API keys
- ✅ Use HTTPS in production
- ✅ Set strong authentication for admin endpoints
- ✅ Monitor rate limiting for abuse

---

Last Updated: December 5, 2025
