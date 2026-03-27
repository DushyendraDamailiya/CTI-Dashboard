# 🔧 IPQualityScore DNS Error - Troubleshooting Guide

## ❌ Error You're Getting

```
HTTPSConnectionPool(host='api.ipqualityscore.com', port=443):
Failed to resolve 'api.ipqualityscore.com' ([Errno 8] nodename nor servname provided, or not known)
```

**Root Cause**: DNS resolution is failing - system can't find the IP address for `api.ipqualityscore.com`

---

## 🛠️ Troubleshooting Steps

### **Step 1: Check Internet Connection** (30 seconds)

```bash
# Test if your internet works
ping google.com

# If this fails: No internet → Fix your connection first
# If this works: Continue to Step 2
```

### **Step 2: Check DNS Resolution** (30 seconds)

```bash
# Can your system resolve the domain?
nslookup api.ipqualityscore.com

# Expected output:
# Server: 8.8.8.8
# Address: 8.8.8.8#53
# Non-authoritative answer:
# Name: api.ipqualityscore.com
# Address: xxx.xxx.xxx.xxx

# If error "can't find api.ipqualityscore.com": DNS is broken
```

### **Step 3: Check DNS Server** (1 minute)

```bash
# Try using Google's DNS
# Edit /etc/resolv.conf or use system settings

# For macOS:
# System Preferences → Network → Wi-Fi → Advanced → DNS
# Add: 8.8.8.8 (Google's public DNS)

# For Linux:
# Edit /etc/resolvconf/resolv.conf.d/head
# Add: nameserver 8.8.8.8

# For Windows:
# Settings → Network & Internet → Change adapter options
# Add DNS: 8.8.8.8
```

### **Step 4: Test Website Direct** (1 minute)

```bash
# Open in browser:
https://www.ipqualityscore.com

# If it loads in your browser, DNS is working
# If not, network/firewall issue
```

### **Step 5: Check Firewall/VPN** (1 minute)

```bash
# If using VPN, try:
1. Disconnect VPN
2. Retry the scan
3. If it works → VPN is blocking it

# Check firewall:
# macOS: System Preferences → Security & Privacy → Firewall
# Windows: Settings → Windows Security → Firewall & network protection
```

---

## ✅ Solutions by Cause

### **Problem: No Internet Connection**

```bash
# Solution: Reconnect to WiFi or ethernet
# Verify with: ping google.com
# Should show: bytes from xxx: icmp_seq=1 ttl=52 time=xx.xxx ms
```

### **Problem: DNS Not Working**

**macOS:**
```bash
# Try flushing DNS cache
sudo dscacheutil -flushcache

# Verify with:
nslookup api.ipqualityscore.com
```

**Linux:**
```bash
# Check DNS
cat /etc/resolv.conf

# Add Google DNS if missing:
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
```

**Windows:**
```powershell
# Clear DNS cache
ipconfig /flushdns

# Verify:
nslookup api.ipqualityscore.com
```

### **Problem: Firewall/VPN Blocking**

```bash
# Solution 1: Disconnect VPN
# Solution 2: Add exception in firewall
# Solution 3: Use different DNS (8.8.8.8 or 1.1.1.1)
```

---

## 🎯 Quick Fix (Try These First)

### **Option 1: Restart Network** (30 seconds)
```bash
# macOS
sudo ifconfig en0 down && sudo ifconfig en0 up

# Linux
sudo systemctl restart networking

# Or just: Turn WiFi off/on
```

### **Option 2: Change DNS** (2 minutes)
```bash
# macOS - Open Terminal
echo "nameserver 8.8.8.8" | sudo tee /etc/resolver/ipqualityscore.com

# Then test:
nslookup api.ipqualityscore.com
```

### **Option 3: Use Public DNS** (2 minutes)
```bash
# Use Cloudflare DNS instead of default
# System Preferences → Network → Wi-Fi → Advanced → DNS
# Add: 1.1.1.1 (Cloudflare)
# Add: 8.8.8.8 (Google)
```

---

## 🧪 Test After Fix

```bash
# 1. Start backend
python backend.py

# 2. Open dashboard
# http://localhost:8000

# 3. Try Manual Scan with an IP
# Should now work!
```

---

## ❓ Common Scenarios

### **Scenario 1: At Home/Office with WiFi**
- Try: Disconnect/Reconnect WiFi
- Try: Restart router
- Try: Use mobile hotspot instead

### **Scenario 2: Behind Corporate Firewall**
- Try: Connect to home internet
- Try: Ask IT to whitelist `api.ipqualityscore.com`
- Try: Use VPN to public network

### **Scenario 3: Using VPN**
- Try: Disconnect VPN
- Try: Use different VPN server
- Try: Switch to system DNS (not VPN DNS)

---

## 📊 Diagnostic Command

Run this to check everything:

```bash
#!/bin/bash
echo "=== Network Diagnostics ==="

echo "1. Internet Connection:"
ping -c 1 google.com > /dev/null && echo "✅ Connected" || echo "❌ No internet"

echo ""
echo "2. DNS Resolution:"
nslookup api.ipqualityscore.com > /dev/null 2>&1 && echo "✅ DNS Working" || echo "❌ DNS Failed"

echo ""
echo "3. API Reachability:"
curl -I https://api.ipqualityscore.com 2>/dev/null | head -1 && echo "✅ API Reachable" || echo "❌ Cannot reach API"

echo ""
echo "4. Current DNS Servers:"
cat /etc/resolv.conf 2>/dev/null || echo "Check System Settings → Network → DNS"

echo ""
echo "=== Test Complete ==="
```

Save as `test-network.sh`, then:
```bash
bash test-network.sh
```

---

## 🔗 API Endpoint Verification

The backend is correctly using:
```
https://api.ipqualityscore.com/api/json/ip
```

This is correct. The issue is just DNS resolution.

---

## ⚠️ If All Else Fails

### **Workaround: Disable IPQualityScore Temporarily**

Edit `backend.py`:

```python
def get_scan_tasks(target, target_type):
    tasks = {
        'AbuseIPDB': lambda: query_abuseipdb(target),
        'VirusTotal': lambda: query_virustotal(target),
        'AlienVault': lambda: query_alienvault(target),
        'GreyNoise': lambda: query_greynoise(target)
        # 'IPQualityScore': lambda: query_ipqualityscore(target)  # ← Comment out
    }
    return tasks
```

This lets the dashboard work with the other 4 APIs while you fix IPQualityScore.

---

## 📞 Next Steps

1. **Run diagnostics** - Use command above
2. **Identify cause** - WiFi? DNS? Firewall?
3. **Apply fix** - One of the solutions above
4. **Test again** - Restart backend and scan

**Report back with:**
- Result of `ping google.com`
- Result of `nslookup api.ipqualityscore.com`
- Are you behind a firewall/VPN/corporate network?

Then I can help further! 🚀
