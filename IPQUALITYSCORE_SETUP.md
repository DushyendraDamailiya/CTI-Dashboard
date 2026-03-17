# 🆕 IPQualityScore Integration Guide

**Status**: ✅ **Now integrated into your dashboard**

---

## 📊 What is IPQualityScore?

IPQualityScore is a fraud detection API that helps identify:
- **VPN/Proxy usage** - Detect users hiding their location
- **Bot traffic** - Identify automated attacks
- **Fraud patterns** - Suspicious behavior analysis
- **Geolocation** - Precise IP location data

Perfect for enhancing your threat detection with proxy/VPN detection!

---

## 🚀 Quick Setup (5 minutes)

### Step 1: Get Your Free API Key

1. Go to: https://www.ipqualityscore.com/
2. Click "Start Free"
3. Sign up or log in
4. Go to Dashboard → **API Keys**
5. Copy your free tier API key

### Step 2: Add to .env File

Open `.env` in your project folder and update:

```bash
# Before:
IPQUALITYSCORE_KEY=your_ipqualityscore_api_key_here

# After:
IPQUALITYSCORE_KEY=your_actual_api_key_here
```

### Step 3: Restart Backend

```bash
# Stop current backend (Ctrl+C)
# Then restart:
python backend.py
```

### Step 4: Test It!

1. Open dashboard: http://localhost:8000
2. Go to "Manual Scan"
3. Enter an IP address (e.g., `8.8.8.8`)
4. You'll now see **5 results** including IPQualityScore!

---

## 📈 What You Get

### IPQualityScore Data Displayed

When you scan an IP, you'll see:

```json
{
  "name": "IPQualityScore",
  "fraud_score": 15,           // 0-100 fraud risk
  "is_vpn": false,             // Using VPN?
  "is_proxy": false,           // Using Proxy?
  "is_bot": false,             // Automated traffic?
  "is_crawler": false,         // Search engine crawler?
  "threat_types": [],          // What threats detected
  "country": "US",             // Country code
  "latitude": 37.386,          // Geo coordinates
  "longitude": -122.084,       // Geo coordinates
}
```

### Example Results

**Clean IP (Google DNS - 8.8.8.8)**:
```
Fraud Score: 15/100 ✅
No VPN, No Proxy, No Bot
Country: United States
Latitude/Longitude: Provided
```

**Suspicious IP**:
```
Fraud Score: 82/100 ⚠️
Is Proxy: YES
Is VPN: YES
Is Bot: YES
Country: China
Latitude/Longitude: Provided
```

---

## 📊 API Details

### Endpoint
```
GET https://api.ipqualityscore.com/api/json/ip
```

### Parameters
```
?ip=<target>
&key=<your_api_key>
&strictness=1
```

**Strictness levels**:
- 0 = Relaxed (fewer false positives)
- 1 = Normal (balanced)
- 2 = Strict (more detections)

### Response Fields

| Field | Type | Meaning |
|-------|------|---------|
| `fraud_score` | 0-100 | Fraud risk percentage |
| `is_vpn` | boolean | VPN/Proxy detected |
| `is_proxy` | boolean | Proxy service |
| `is_bot` | boolean | Automation/Bot traffic |
| `is_crawler` | boolean | Search engine crawler |
| `country_code` | string | ISO country code |
| `country_name` | string | Full country name |
| `isp` | string | Internet Service Provider |
| `latitude` | float | Geographic latitude |
| `longitude` | float | Geographic longitude |

---

## 🎯 Free Tier Limits

| Feature | Free Tier | Paid |
|---------|-----------|------|
| Queries/Month | 5,000 | Unlimited |
| Cost | **FREE** | $0.001/query |
| VPN Detection | ✅ Yes | ✅ Yes |
| Geolocation | ✅ Yes | ✅ Yes |
| Bot Detection | ✅ Yes | ✅ Yes |
| Proxy Detection | ✅ Yes | ✅ Yes |

**5,000 queries = ~166 queries/day** 

Perfect for testing and moderate use!

---

## 💡 Use Cases

### 1. Proxy/VPN Detection
```
Block users accessing through VPN/Proxy
→ Enhances security
→ Detects data center IPs
```

### 2. Bot Detection
```
Identify automated attack traffic
→ Distinguish bots from humans
→ Alert on suspicious patterns
```

### 3. Geographic Enrichment
```
Get precise coordinates for map display
→ Better threat visualization
→ More accurate geolocation than basic IP lookup
```

### 4. Fraud Prevention
```
Combined fraud score from multiple factors
→ Holistic threat assessment
→ Combined with AbuseIPDB + VirusTotal
```

---

## 🔍 Real-World Examples

### Example 1: Data Center IP (Malicious)
```
Input: 192.0.2.1 (AWS Data Center)

Response:
{
  "fraud_score": 92,          // High fraud risk
  "is_proxy": false,
  "is_vpn": false,
  "is_bot": true,             // Automated traffic
  "country": "US",
  "threat_score": "CRITICAL"
}

→ Alert: Automated attack from cloud infrastructure
```

### Example 2: Home Network IP (Safe)
```
Input: 203.0.113.45

Response:
{
  "fraud_score": 5,           // Low fraud risk ✅
  "is_proxy": false,
  "is_vpn": false,
  "is_bot": false,
  "country": "IN",
  "isp": "Airtel",
  "threat_score": "LOW"
}

→ Safe: Residential ISP connection
```

### Example 3: VPN Exit Node (Suspicious)
```
Input: 192.0.2.50 (NordVPN Exit Node)

Response:
{
  "fraud_score": 88,          // High fraud risk
  "is_proxy": true,           // Proxy detected
  "is_vpn": true,             // VPN detected ⚠️
  "is_bot": false,
  "country": "NL",
  "threat_score": "HIGH"
}

→ Alert: Anonymous access via VPN
```

---

## 🔧 How It's Integrated

### Backend Changes

**1. Added to API_CONFIG** (backend.py):
```python
'ipqualityscore': {
    'endpoint': 'https://api.ipqualityscore.com/api/json/ip',
    'key': get_required_env('IPQUALITYSCORE_KEY'),
    'method': 'GET',
    'timeout': 10
}
```

**2. Query Function** (backend.py):
```python
def query_ipqualityscore(target):
    # Validates IP format
    # Extracts fraud score, VPN, proxy, bot info
    # Returns formatted response
```

**3. Integrated in Scans** (backend.py):
```python
def get_scan_tasks(target, target_type):
    # Only run for IPs (not domains/hashes)
    if target_type == 'ip':
        tasks['IPQualityScore'] = query_ipqualityscore(target)
```

---

## 🎨 Frontend Display

When you scan an IP, the dashboard shows:

```
┌─────────────────────────┐
│  IPQualityScore         │
├─────────────────────────┤
│ Fraud Score: 15/100     │
│ VPN: ❌ No              │
│ Proxy: ❌ No            │
│ Bot: ❌ No              │
│ Country: United States  │
│ Latitude: 37.386°N      │
│ Longitude: -122.084°W   │
└─────────────────────────┘
```

---

## ⚠️ Troubleshooting

### "Missing IPQUALITYSCORE_KEY"
```bash
Error: Missing required environment variable: IPQUALITYSCORE_KEY

Solution:
1. Add key to .env file
2. Restart backend: python backend.py
```

### "IPQualityScore only supports IPv4"
```bash
Error when scanning domain/hash

Expected: IPQualityScore only runs for IP addresses
Solution: Use Manual Scan with an IP address
```

### "API Error: Exceeded Rate Limit"
```bash
Error: Free tier limit reached

Solution:
1. Upgrade to paid plan
2. Or wait until monthly reset
3. Or use combo with other free APIs only
```

### "Invalid API Key"
```bash
Error: Invalid API key

Solution:
1. Check key in .env file
2. Verify key from dashboard at https://www.ipqualityscore.com/
3. Ensure no extra spaces
4. Restart backend
```

---

## 📈 Dashboard Integration

### Scan with IPQualityScore

**From Dashboard UI**:
1. Click "Manual Scan"
2. Enter IP: `192.168.1.1`
3. Click "Scan"
4. See results including IPQualityScore
5. Review VPN/Proxy status
6. Check fraud score

**From API**:
```bash
curl -X POST http://localhost:5001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"8.8.8.8"}'
```

Response includes IPQualityScore data:
```json
{
  "results": [
    {
      "name": "IPQualityScore",
      "fraud_score": 15,
      "is_vpn": false,
      "is_proxy": false,
      ...
    }
  ]
}
```

---

## 🚀 Next Steps

1. ✅ **Get API key** - https://www.ipqualityscore.com/
2. ✅ **Add to .env** - Copy key to file
3. ✅ **Restart backend** - `python backend.py`
4. ✅ **Test it** - Scan an IP from dashboard
5. ✅ **Monitor usage** - Check your monthly quota

---

## 📞 Support

**IPQualityScore Documentation**:
- https://www.ipqualityscore.com/documentation/ip-reputation-api

**Your Backend**:
- Logs available in terminal when backend runs
- Check for errors: `tail -f your_log.txt`

---

## 🎉 Summary

You now have **5 threat intelligence sources**:

1. ✅ **AbuseIPDB** - Abuse reports
2. ✅ **VirusTotal** - Malware analysis
3. ✅ **AlienVault OTX** - Threat pulses
4. ✅ **GreyNoise** - Internet noise
5. ✨ **IPQualityScore** - Fraud + VPN/Proxy detection (NEW!)

**Combined coverage = Much better threat detection!** 🛡️

---

## 📊 Feature Comparison

| Feature | AbuseIPDB | VT | OTX | GreyNoise | IPQuality |
|---------|-----------|----|----|-----------|-----------|
| Abuse Reports | ✅ | ❌ | ✅ | ❌ | ❌ |
| Malware | ❌ | ✅ | ✅ | ❌ | ❌ |
| VPN/Proxy | ❌ | ❌ | ❌ | ❌ | ✅ |
| Geolocation | ❌ | ❌ | ❌ | ❌ | ✅ |
| Bot Detection | ❌ | ❌ | ❌ | ❌ | ✅ |
| Free Tier | ✅ | ✅ | ✅ | ✅ | ✅ |

---

**Status**: 🟢 Ready to use!

Get your API key and start detecting VPNs and proxies! 🚀
