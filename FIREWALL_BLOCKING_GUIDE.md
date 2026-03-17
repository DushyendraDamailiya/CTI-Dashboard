# 🔒 Firewall IP Blocking Guide

## Overview

Your dashboard now supports **3 levels of IP blocking**:

1. **Application-Level Blocking** (In-Memory) - Stores blocked IPs in the app
2. **System-Level Firewall Blocking** (Recommended) - Prevents actual network access
3. **Hybrid Approach** - Both in-memory + firewall

---

## Option 1: Application-Level Only (Current Default)

### How It Works
- Blocked IPs are stored in the backend's in-memory dictionary
- Dashboard marks them as "blocked" in the threat table
- Doesn't prevent actual system access (passive)
- Good for logging and UI display

### When to Use
- ✅ Logging and auditing
- ✅ Non-critical threats
- ✅ Testing without system changes

### No Setup Required ✓

---

## Option 2: System-Level Firewall Blocking 🔥 (RECOMMENDED)

### How It Works

Your backend can now add IPs to the system firewall:

- **macOS**: Uses `route` command to block traffic
- **Linux**: Uses `iptables` to drop packets
- **Windows**: Uses `netsh` Windows Firewall

### Prerequisites

#### macOS
```bash
# Requires sudo (passwordless recommended)
# Test firewall rule:
sudo route add -net 8.8.8.8 127.0.0.1
# Remove it:
sudo route delete -net 8.8.8.8
```

#### Linux (Ubuntu/Debian)
```bash
# Install iptables if needed
sudo apt-get install iptables

# Test firewall rule:
sudo iptables -I INPUT 1 -s 8.8.8.8 -j DROP
# Remove it:
sudo iptables -D INPUT -s 8.8.8.8 -j DROP

# Make permanent (optional):
sudo apt-get install iptables-persistent
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

#### Windows
```powershell
# Requires admin privileges in PowerShell

# Test firewall rule:
netsh advfirewall firewall add rule name="BlockIP_8_8_8_8" dir=in action=block remoteip=8.8.8.8 protocol=any

# Remove it:
netsh advfirewall firewall delete rule name="BlockIP_8_8_8_8"
```

### Setup for Production

#### macOS - Enable Passwordless Sudo

Edit sudoers file:
```bash
sudo visudo
```

Add this line at the end:
```
# Allow python to use route without password
%admin ALL=(ALL) NOPASSWD: /sbin/route
```

#### Linux - Enable Passwordless Sudo for iptables

Edit sudoers file:
```bash
sudo visudo
```

Add this line:
```
# Allow python to use iptables without password
%sudo ALL=(ALL) NOPASSWD: /sbin/iptables
```

#### Windows - Run Python as Admin

The backend must run with administrator privileges.

---

## How to Use Firewall Blocking

### From Dashboard UI

1. **Click "Block" button** on any threat IP
2. **Confirmation dialog appears**:
   ```
   Block IP 192.168.1.105?
   
   Choose:
   OK = Block in app + firewall
   Cancel = Block in app only
   ```
3. **Result shows status**:
   - ✅ In-memory blocked (always)
   - 🔒 Firewall blocked (if you chose OK and have permissions)
   - ⚠️ Warning if firewall blocking failed

### From API

#### Block with Firewall
```bash
curl -X POST http://localhost:5001/api/block-ip \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.105",
    "reason": "suspicious_activity",
    "firewall": true
  }'
```

Response (macOS/Linux):
```json
{
  "success": true,
  "message": "IP 192.168.1.105 blocked",
  "firewall_status": {
    "success": true,
    "message": "IP 192.168.1.105 blocked via iptables"
  },
  "totalBlocked": 1
}
```

#### Unblock IP
```bash
curl -X POST http://localhost:5001/api/unblock-ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.105"}'
```

#### View All Blocked IPs
```bash
curl http://localhost:5001/api/blocked-ips
```

Response:
```json
{
  "success": true,
  "blocked_ips": [
    {
      "ip": "192.168.1.105",
      "reason": "manual_block",
      "blockedAt": "2026-03-10T10:30:45.123456",
      "firewall_blocked": true
    }
  ],
  "total_blocked": 1
}
```

---

## What Actually Happens When You Block an IP

### On macOS
```bash
# Backend runs:
sudo route add -net 192.168.1.105 127.0.0.1

# This means:
# - Packets to 192.168.1.105 are routed to localhost (127.0.0.1)
# - Effectively blocks incoming and outgoing traffic to that IP
```

### On Linux
```bash
# Backend runs:
sudo iptables -I INPUT 1 -s 192.168.1.105 -j DROP

# This means:
# - All incoming packets from 192.168.1.105 are DROPPED
# - The IP cannot establish any connection to your device
```

### On Windows
```powershell
# Backend runs:
netsh advfirewall firewall add rule name="BlockIP_192_168_1_105" ^
  dir=in action=block remoteip=192.168.1.105 protocol=any

# This creates a Windows Firewall inbound rule
# - Blocks all traffic from that IP
```

---

## Important Notes ⚠️

### 1. ISP-Level Blocking
**Cannot be done from your device.** ISPs use routing at their infrastructure level.

To block at ISP level, you'd need:
- ❌ ISP control panel (if they provide one)
- ❌ BGP route filtering (enterprise only)
- ❌ Contact ISP support

Your device-level blocking only works on **your network**.

### 2. VPN & Proxy Bypass
If the attacker uses a VPN:
- Your firewall blocks **one exit node**
- They can use a **different exit node**
- Recommend: Blocking by geolocation or threat signatures instead

### 3. Firewall Rule Persistence
**Important**: Firewall rules don't survive system restart by default.

To make rules persistent:

#### macOS
```bash
# Edit /etc/pfctl.conf or create a startup script
# Or use a network management tool
```

#### Linux
```bash
# Install iptables-persistent
sudo apt-get install iptables-persistent
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

#### Windows
Rules persist by default in Windows Firewall.

### 4. Performance Impact
- Firewall rules add ~1-5ms per packet check
- Negligible on modern systems
- No performance issues expected

---

## Testing the Firewall Blocking

### Test macOS Firewall
```bash
# Block a test IP
curl -X POST http://localhost:5001/api/block-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8","firewall":true}'

# Check route was added
netstat -rn | grep 8.8.8.8

# Verify blocking works
ping 8.8.8.8  # Should not reach

# Unblock
curl -X POST http://localhost:5001/api/unblock-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}'
```

### Test Linux Firewall
```bash
# Block a test IP
curl -X POST http://localhost:5001/api/block-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8","firewall":true}'

# Check iptables rule was added
sudo iptables -L -n | grep 8.8.8.8

# Verify blocking works
ping 8.8.8.8  # Should not reach

# Unblock
curl -X POST http://localhost:5001/api/unblock-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}'
```

### Test Windows Firewall
```powershell
# Block a test IP
curl -X POST http://localhost:5001/api/block-ip `
  -H "Content-Type: application/json" `
  -d '{"ip":"8.8.8.8","firewall":true}'

# Check Windows Firewall rules
netsh advfirewall firewall show rule name=all | findstr "BlockIP"

# Verify blocking works
ping 8.8.8.8  # Should not reach

# Unblock
curl -X POST http://localhost:5001/api/unblock-ip `
  -H "Content-Type: application/json" `
  -d '{"ip":"8.8.8.8"}'
```

---

## Option 3: Docker Containerization

For enterprise use with automatic rule persistence:

Create `docker-compose.yml`:
```yaml
version: '3.8'
services:
  backend:
    image: your-threat-dashboard:latest
    cap_add:
      - NET_ADMIN
    volumes:
      - /etc/iptables:/etc/iptables
    ports:
      - "5001:5001"
```

This gives the container firewall permissions while isolating changes.

---

## Recommended Security Practices

1. **Block at threshold** - Only block High/Critical threats
2. **Log everything** - Keep audit trail of blocked IPs
3. **Set expiration** - Auto-unblock after 24-48 hours
4. **Monitor false positives** - Review blocked IPs weekly
5. **Use with IDS/IPS** - Combine with Snort/Suricata for better detection

---

## Troubleshooting

### "Permission denied" error
**Solution**: Run backend with sudo/admin privileges
```bash
# macOS/Linux
sudo python backend.py

# Windows (run PowerShell as Admin)
python backend.py
```

### Firewall rule not working
**Solution**: Check if rule was actually added
```bash
# macOS
netstat -rn

# Linux
sudo iptables -L -n -v

# Windows
netsh advfirewall firewall show rule name=all
```

### Cannot unblock IP
**Solution**: IP might have multiple rules, delete manually
```bash
# macOS
sudo route delete -net 192.168.1.105

# Linux
sudo iptables -D INPUT -s 192.168.1.105 -j DROP

# Windows
netsh advfirewall firewall delete rule name="BlockIP_192_168_1_105"
```

---

## Summary

| Feature | App-Only | + Firewall | + Persistence |
|---------|----------|-----------|----------------|
| Block in Dashboard | ✅ | ✅ | ✅ |
| Prevent Access | ❌ | ✅ | ✅ |
| Survive Reboot | ❌ | ❌ | ✅ |
| Requires Sudo | ❌ | ✅ | ✅ |
| Recommended | Demo | Production | High-Security |

---

## Next Steps

1. Choose your blocking level
2. Set up firewall permissions (if needed)
3. Test with a non-critical IP first
4. Enable in production when ready
5. Monitor blocked IPs regularly

Your dashboard is now a **functional security tool** with real protective capabilities! 🎉
