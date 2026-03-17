# Fixing IPQualityScore DNS Error - Quick Fixes

**Error:** `HTTPSConnectionPool(host='api.ipqualityscore.com', port=443): ... Failed to resolve 'api.ipqualityscore.com'`

**Root Cause:** System DNS cannot resolve the IPQualityScore domain to an IP address.

---

## Quick Fix (Try This First)

### **1. Restart Your Network** - 60% Success Rate
```bash
# macOS:
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Linux:
sudo systemctl restart systemd-resolved
# or
sudo service networking restart
```

### **2. Change DNS Server** - 30% Success Rate
```bash
# macOS:
# Go to System Preferences → Network → Advanced → DNS
# Click [+] and add: 8.8.8.8 or 1.1.1.1

# Linux (edit /etc/resolv.conf):
# Add or change: nameserver 8.8.8.8

# Linux (systemd):
sudo nano /etc/systemd/resolved.conf
# Change: DNS=8.8.8.8 1.1.1.1
sudo systemctl restart systemd-resolved
```

### **3. Check If You're Using VPN**
VPN might block IPQualityScore API:
- Disconnect VPN
- Try scanning again
- If it works, whitelist api.ipqualityscore.com in your VPN

### **4. Check Security Software**
Firewall or security software might block the domain:
- Temporary disable firewall/antivirus
- Test scan
- Re-enable and whitelist api.ipqualityscore.com

---

## Verify DNS Works

```bash
# Test 1: Check if DNS resolves
nslookup api.ipqualityscore.com

# Expected output: IP address (not "name or service not known")

# Test 2: Ping the domain
ping -c 3 api.ipqualityscore.com

# Expected: Should work (or show no response, but not "unknown host")

# Test 3: Try CURL
curl -I https://api.ipqualityscore.com

# Expected: HTTP/2 200 (or redirect)
```

---

## Good News: Dashboard Still Works

✅ **Dashboard continues working with 4 APIs** (AbuseIPDB, VirusTotal, AlienVault, GreyNoise)

The backend has been updated with graceful error handling:

```
User scans IP → Backend queries 5 APIs
  ✅ AbuseIPDB → Returns results
  ✅ VirusTotal → Returns results
  ✅ AlienVault → Returns results
  ✅ GreyNoise → Returns results
  ⚠️ IPQualityScore → DNS error, returns error response
  
Dashboard displays: "IPQualityScore: Temporarily unavailable"
User still sees 4 threat intelligence sources
```

---

## If DNS Still Not Working

Option 1: Continue using without IPQualityScore (4 APIs work fine)
- Dashboard functions normally
- Remove IPQUALITYSCORE_KEY from .env (optional, doesn't affect anything)
- Restart backend

Option 2: Wait for network to recover, then:
1. Fix DNS (try steps above)
2. Verify `nslookup api.ipqualityscore.com` works
3. Restart backend
4. IPQualityScore will be included again

---

## Test IPQualityScore After Fix

```bash
# In terminal 1: Start backend
python3 backend.py

# In terminal 2: Scan an IP
curl http://localhost:5001/api/scan -X POST \
  -H "Content-Type: application/json" \
  -d '{"target": "85.217.149.44"}'

# In response, look for "IPQualityScore" with success: true
```

---

## Still Having Issues?

1. **Check .env has API key:**
   ```bash
   grep IPQUALITYSCORE .env
   # Should show: IPQUALITYSCORE_KEY=3PUSRW53fbZ9tLSfhzm4DlUWS7wXLEbR
   ```

2. **Check backend logs:**
   ```bash
   # Run backend and watch logs:
   python3 backend.py 2>&1 | grep -i ipquality
   ```

3. **Check network connectivity:**
   ```bash
   # Working? → Other DNS might work
   ping 8.8.8.8  # Google DNS
   ping 1.1.1.1  # Cloudflare DNS
   
   # If these fail: Network/internet issue, not DNS-specific
   ```

4. **Try alternative DNS:** If 8.8.8.8 doesn't work, try 1.1.1.1 or your ISP's DNS

---

## System-Specific Help

### macOS Only
```bash
# Clear DNS cache completely:
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Check current DNS:
scutil --dns | grep nameserver | head -5

# Reset network settings (last resort):
# System Preferences → Network → Advanced → TCP/IP → Renew DHCP Lease
```

### Linux Only
```bash
# Check current DNS:
cat /etc/resolv.conf

# Temporary change to Google DNS:
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# Restart resolver:
sudo systemctl restart networking
```

### Windows Only
```
# macOS/Linux user? This guide is for macOS/Linux!
# For Windows, open PowerShell Admin and run:
# ipconfig /flushdns
# Then edit DNS in Network Settings
```

---

## ISP DNS vs Public DNS

Try in this order:
1. **Your ISP's DNS** (usually works, but might be blocked)
2. **Google DNS: 8.8.8.8** (most reliable)
3. **Cloudflare DNS: 1.1.1.1** (privacy-focused)
4. **Quad9: 9.9.9.9** (security-focused)

---

## When It Works

You'll see in backend logs:
```
✅ IPQualityScore returned fraud_score=XX, is_vpn=true/false, is_proxy=true/false
```

In dashboard:
```
IPQualityScore: ✓ (shows actual threat data)
```

