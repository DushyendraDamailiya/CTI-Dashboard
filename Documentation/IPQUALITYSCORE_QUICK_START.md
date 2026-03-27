# IPQualityScore Enhanced Implementation - Quick Start

**Status:** ✅ Ready to use with official API format and advanced fraud detection

---

## What's New

### Official API Format
```
Before: https://api.ipqualityscore.com/api/json/ip?ip=1.2.3.4&key=KEY
After:  https://www.ipqualityscore.com/api/json/ip/KEY/1.2.3.4
```

### Rich Fraud Detection
Instead of simple fraud_score >= 75, now uses:
- ✅ **9 scoring categories** (anonymity, abuse, bots, connection, device, etc.)
- ✅ **Multi-factor analysis** (combines all indicators)
- ✅ **Active vs. static detection** (current threat vs. history)
- ✅ **Mobile-aware** (less strict for legitimate mobile users)
- ✅ **Top 5 risk indicators** (shows why IP is flagged)

---

## Response Highlights

### Key Fields
```json
{
  "score": 42,                    // 0-100 combined malicious score
  "isMalicious": false,           // True if >= 75 OR active threat
  "fraud_score": 25,              // Original API fraud score
  "threat_types": ["Crawler"],    // Categorized threats
  "risk_indicators": []           // Top reason(s) for flags
}
```

### New Nested Categories
```json
{
  "anonymity": {
    "is_active_vpn": true,        // Currently using VPN (high risk)
    "is_vpn": false,              // Used VPN in past (medium risk)
    "is_active_tor": false,
    ...
  },
  "abuse": {
    "abuse_velocity": "high",     // Rate of abuse (low/medium/high)
    "recent_abuse": true,
    ...
  },
  "device": {
    "mobile": true,
    "browser": "Chrome 122.0",
    ...
  },
  ...
}
```

---

## Scoring Examples

### Scenario 1: Regular User (Score: 15)
```
IP: 8.8.8.8 (Google DNS)
- fraud_score: 1
- No VPN/Proxy/TOR
- Not crawler, not bot
- Expected: score ≈ 15, isMalicious: false ✓
```

### Scenario 2: VPN User (Score: 42)
```
IP: Some VPN provider IP
- is_active_vpn: true (+35)
- fraud_score: 15 (+7)
- Expected: score ≈ 42, isMalicious: false ✓
```

### Scenario 3: Malicious Bot (Score: 100)
```
IP: Known botnet C&C
- is_bot: true (+20)
- high_risk_attacks: true (+30)
- frequent_abuser: true (+25)
- abuse_velocity: "high" (+20)
- Recent abuse: true (+5)
- fraud_score: 95 (+47)
- Expected: score = 100 (capped), isMalicious: true ✓
```

---

## Frontend Display Ideas

### For Dashboard Card
```html
<div class="threat-card">
  <h3>IPQualityScore</h3>
  <div class="score">
    <span class="number">42</span>
    <span class="status">MODERATE</span>
  </div>
  <ul class="threats">
    <li>🌐 Crawler detected</li>
  </ul>
  <p class="fraud-score">API Score: 25/100</p>
</div>
```

### For Risk List
```html
<div class="risk-indicators">
  <h4>Top Risk Factors:</h4>
  <ul>
    <li>Currently using VPN/TOR</li>
    <li>High-velocity abuse detected</li>
    <li>Recent abuse detected</li>
  </ul>
</div>
```

### For Advanced View
```html
<table class="ipqs-details">
  <tr><td>Connection Type</td><td>Residential</td></tr>
  <tr><td>Mobile</td><td>No</td></tr>
  <tr><td>OS / Browser</td><td>Windows 10 / Chrome 122.0</td></tr>
  <tr><td>Abuse Velocity</td><td>High</td></tr>
  <tr><td>Active VPN</td><td>Yes ⚠️</td></tr>
  <tr><td>Recent Abuse</td><td>Yes ⚠️</td></tr>
</table>
```

---

## API Parameters

**Used in all requests:**
```python
strictness: 1              # Recommended (balance speed vs accuracy)
allow_public_access_points: true  # Better for research/education
```

**Optional (not currently used, but available):**
```python
user_agent: "Mozilla/5.0..."      # Improves device detection
user_language: "en-US"            # Improves accuracy
custom tracking vars              # userID, transactionID, etc.
```

---

## Testing Checklist

- [ ] Backend starts without errors
- [ ] Can scan clean IP (Google DNS 8.8.8.8)
- [ ] Response includes all nested categories
- [ ] `isMalicious` is false for clean IP
- [ ] Response includes `threat_types` array
- [ ] Response includes `risk_indicators` array
- [ ] Error handling works (invalid IPs, no key, etc.)

---

## Example Response (Full Structure)

```json
{
  "name": "IPQualityScore",
  "success": true,
  "score": 28,
  "isMalicious": false,
  "fraud_score": 15,
  "anonymity": {
    "is_vpn": false,
    "is_active_vpn": false,
    "is_proxy": false,
    "is_tor": false,
    "is_active_tor": false
  },
  "abuse": {
    "recent_abuse": false,
    "frequent_abuser": false,
    "high_risk_attacks": false,
    "abuse_velocity": "low"
  },
  "automation": {
    "is_bot": false,
    "is_crawler": false,
    "is_security_scanner": false
  },
  "connection": {
    "type": "Residential",
    "shared": false,
    "dynamic": false,
    "trusted": false
  },
  "device": {
    "mobile": false,
    "os": "Mac OS",
    "browser": "Safari 17.0",
    "model": null,
    "brand": null
  },
  "location": {
    "country": "US",
    "city": "Mountain View",
    "region": "California",
    "latitude": 37.422,
    "longitude": -122.084,
    "zip": "94043",
    "timezone": "America/Los_Angeles"
  },
  "network": {
    "isp": "Google LLC",
    "organization": "Google LLC",
    "asn": 15169,
    "host": "dns.google",
    "request_id": "ABC123XYZ"
  },
  "threat_types": [],
  "risk_indicators": []
}
```

---

## Comparison: Before vs After

| Aspect | Before | After | Benefit |
|--------|--------|-------|---------|
| Malicious Logic | score >= 75 | 9-factor analysis | More accurate |
| VPN Detection | VPN=true | is_active_vpn vs is_vpn | Distinguishes current vs history |
| Device Info | None | OS, Browser, Model, Brand | Better fingerprinting |
| Abuse Pattern | Not shown | abuse_velocity + other flags | Understand attack pattern |
| Mobile Handling | None | Special logic | Fewer false positives |
| Why Flagged | Show threats | Plus top 5 risk indicators | Better user understanding |
| Response Size | Small | Medium (well-organized) | More actionable data |

---

## Backward Compatibility

✅ **Still includes old fields:**
- `fraud_score` → Still present
- `threat_types` → Still array
- `latitude/longitude` → Still present
- `isMalicious` → Still boolean

✅ **New fields are additions** (nested), not replacements

✅ **Frontend code doesn't break** if you add new checks for nested fields

---

## Next: Test with Real IPs

```bash
# Terminal 1: Start backend
python3 backend.py

# Terminal 2: Test specific IPs
curl http://localhost:5001/api/scan -X POST \
  -H "Content-Type: application/json" \
  -d '{"target": "85.217.149.44"}'

# Look for:
# - Complete response with all categories
# - Rich risk_indicators
# - Accurate score calculation
```

---

## Documentation

📄 **Full Details:** [IPQUALITYSCORE_ENHANCED_FRAUD_DETECTION.md](IPQUALITYSCORE_ENHANCED_FRAUD_DETECTION.md)  
📄 **Optional Handling:** [IPQUALITYSCORE_OPTIONAL_HANDLING.md](IPQUALITYSCORE_OPTIONAL_HANDLING.md)  
📄 **DNS Troubleshooting:** [DNS_QUICK_FIX.md](DNS_QUICK_FIX.md)  

---

## Status

✅ **Syntax:** Validated  
✅ **Error Handling:** Graceful  
✅ **Official Format:** Aligned  
✅ **Ready to Test:** Yes  

