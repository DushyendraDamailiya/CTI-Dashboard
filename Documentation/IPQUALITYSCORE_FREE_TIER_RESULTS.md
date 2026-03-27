# IPQualityScore Free-Tier Results - Easy Access Guide

**Status:** ✅ Updated to show all important free-tier fields clearly

---

## What Changed

The API response now includes an **`important_results`** section at the top level with all free-tier data users care about:

```json
{
  "name": "IPQualityScore",
  "success": true,
  "score": 95,
  "isMalicious": true,
  "request_id": "fFppVuqAdQ",
  
  "important_results": {
    "fraud_score": 100,
    "fraud_severity": "Critical (90+)",
    "country": "GB",
    "city": "London",
    "region": "England",
    "timezone": "Europe/London",
    "latitude": 51.51,
    "longitude": -0.09,
    "hostname": "185.93.89.48",
    "isp": "Limited Network",
    "organization": "Limited Network",
    "asn": 213790,
    "proxy_status": true,
    "vpn_status": false,
    "tor_status": false,
    "bot_activity": true,
    "recent_abuse": true,
    "threat_summary": {
      "overall_threat_level": "Critical",
      "threat_types": ["Proxy", "High-Risk-Attacks", "Bot"],
      "risk_indicators": [
        "Proxy detected",
        "Bot traffic detected",
        "Critical fraud score: 100",
        "Recent abuse detected"
      ]
    }
  },
  
  // ... additional detailed data below
}
```

---

## Free-Tier Fields Available

✅ **All of these are FREE (no premium needed):**

| Field | Equivalent to | Example |
|-------|--------|---------|
| `fraud_score` | Fraud Score | 100 |
| `fraud_severity` | 75+ = suspicious \| 85+ = risky \| 90+ = high risk | "Critical (90+)" |
| `country` | Country | "GB" |
| `city` | City | "London" |
| `region` | Region | "England" |
| `timezone` | Time Zone | "Europe/London" |
| `latitude` | Latitude | 51.51 |
| `longitude` | Longitude | -0.09 |
| `hostname` | Hostname | "185.93.89.48" |
| `isp` | ISP | "Limited Network" |
| `organization` | Organization | "Limited Network" |
| `asn` | ASN | 213790 |
| `proxy_status` | Proxy Status | true |
| `vpn_status` | VPN Status | false |
| `tor_status` | TOR Status | false |
| `bot_activity` | Bot Activity | true |
| `recent_abuse` | Recent Abuse | true |
| `request_id` | Request ID | "fFppVuqAdQ" |

---

## How to Display in Dashboard

### **Simple JavaScript Access:**

```javascript
// Get the IPQualityScore results
const results = response.find(r => r.name === 'IPQualityScore');

if (results && results.important_results) {
    const imp = results.important_results;
    
    // Display location
    console.log(`📍 ${imp.city}, ${imp.region}, ${imp.country} (${imp.timezone})`);
    console.log(`   Coordinates: ${imp.latitude}, ${imp.longitude}`);
    
    // Display network info
    console.log(`🔗 ${imp.hostname}`);
    console.log(`   ISP: ${imp.isp}`);
    console.log(`   Organization: ${imp.organization}`);
    console.log(`   ASN: ${imp.asn}`);
    
    // Display threat status
    console.log(`⚠️ Fraud Score: ${imp.fraud_score} (${imp.fraud_severity})`);
    console.log(`🛡️ Overall Threat: ${imp.threat_summary.overall_threat_level}`);
    
    // Display abuse indicators
    if (imp.proxy_status) console.log("🚫 Proxy detected");
    if (imp.vpn_status) console.log("🚫 VPN detected");
    if (imp.tor_status) console.log("🚫 TOR detected");
    if (imp.bot_activity) console.log("🤖 Bot activity detected");
    if (imp.recent_abuse) console.log("⚡ Recent abuse");
    
    // Display top risk reasons
    console.log("\n⚠️ Risk Reasons:");
    imp.threat_summary.risk_indicators.forEach(r => {
        console.log(`   • ${r}`);
    });
}
```

---

## HTML Card Display

```html
<div class="ipqs-card">
    <div class="header">
        <h3>IPQualityScore Threat Intelligence</h3>
        <span class="request-id">ID: fFppVuqAdQ</span>
    </div>
    
    <div class="threat-level alert-critical">
        ⚠️ CRITICAL THREAT
        <p>Fraud Score: 100/100</p>
    </div>
    
    <div class="location">
        <h4>📍 Location</h4>
        <p>London, England, GB</p>
        <p>Timezone: Europe/London</p>
        <p>51.51, -0.09</p>
    </div>
    
    <div class="network">
        <h4>🔗 Network</h4>
        <p><strong>Hostname:</strong> 185.93.89.48</p>
        <p><strong>ISP:</strong> Limited Network</p>
        <p><strong>Organization:</strong> Limited Network</p>
        <p><strong>ASN:</strong> 213790</p>
    </div>
    
    <div class="threat-flags">
        <h4>🚨 Threat Indicators</h4>
        <ul>
            <li>🚫 <strong>Proxy:</strong> Detected</li>
            <li>🤖 <strong>Bot:</strong> Detected</li>
            <li>⚡ <strong>Recent Abuse:</strong> Yes</li>
            <li>✅ <strong>VPN:</strong> No</li>
            <li>✅ <strong>TOR:</strong> No</li>
        </ul>
    </div>
    
    <div class="risk-reasons">
        <h4>⚠️ Top Risk Reasons</h4>
        <ol>
            <li>Proxy detected</li>
            <li>Bot traffic detected</li>
            <li>Critical fraud score: 100</li>
            <li>Recent abuse detected</li>
        </ol>
    </div>
</div>
```

---

## Example API Response

```json
{
  "name": "IPQualityScore",
  "success": true,
  "score": 95,
  "isMalicious": true,
  "request_id": "fFppVuqAdQ",
  
  "important_results": {
    "fraud_score": 100,
    "fraud_severity": "Critical (90+)",
    "country": "GB",
    "city": "London",
    "region": "England",
    "timezone": "Europe/London",
    "latitude": 51.5085,
    "longitude": -0.1257,
    "hostname": "185.93.89.48",
    "isp": "Limited Network",
    "organization": "Limited Network",
    "asn": 213790,
    "proxy_status": true,
    "vpn_status": false,
    "tor_status": false,
    "bot_activity": true,
    "recent_abuse": true,
    "threat_summary": {
      "overall_threat_level": "Critical",
      "threat_types": [
        "Proxy",
        "Bot",
        "High-Risk-Attacks"
      ],
      "risk_indicators": [
        "Proxy detected",
        "Bot traffic detected",
        "Critical fraud score: 100",
        "Recent abuse detected",
        "Detected high-risk attacks"
      ]
    }
  },
  
  "fraud_score": 100,
  
  "anonymity": {
    "is_vpn": false,
    "is_active_vpn": false,
    "is_proxy": true,
    "is_tor": false,
    "is_active_tor": false
  },
  
  "abuse": {
    "recent_abuse": true,
    "frequent_abuser": null,
    "high_risk_attacks": true,
    "abuse_velocity": null
  },
  
  "automation": {
    "is_bot": true,
    "is_crawler": false,
    "is_security_scanner": false
  },
  
  "connection": {
    "type": "Premium required",
    "shared": null,
    "dynamic": null,
    "trusted": false
  },
  
  "device": {
    "mobile": false,
    "os": null,
    "browser": null,
    "model": null,
    "brand": null
  },
  
  "location": {
    "country": "GB",
    "city": "London",
    "region": "England",
    "latitude": 51.5085,
    "longitude": -0.1257,
    "zip": null,
    "timezone": "Europe/London"
  },
  
  "network": {
    "isp": "Limited Network",
    "organization": "Limited Network",
    "asn": 213790,
    "host": "185.93.89.48"
  },
  
  "threat_types": ["Proxy", "Bot", "High-Risk-Attacks"],
  "risk_indicators": [
    "Proxy detected",
    "Bot traffic detected",
    "Critical fraud score: 100",
    "Recent abuse detected",
    "Detected high-risk attacks"
  ]
}
```

---

## Fraud Severity Levels

Auto-calculated based on fraud_score:

| Fraud Score | Severity Level | Risk Category |
|---|---|---|
| 0-24 | Clean | ✅ Safe |
| 25-49 | Low | ✅ Low Risk |
| 50-74 | Elevated | ⚠️ Medium Risk |
| 75-84 | Suspicious (75+) | ⚠️ High Caution |
| 85-89 | Risky (85+) | ⚠️ Very High Risk |
| 90-100 | Critical (90+) | 🛑 Critical Threat |

---

## Free vs Premium Fields

### ✅ FREE (Available Always)

```json
"important_results": {
  "fraud_score": 100,
  "country": "GB",
  "city": "London",
  "region": "England",
  "timezone": "Europe/London",
  "latitude": 51.51,
  "longitude": -0.09,
  "hostname": "185.93.89.48",
  "isp": "Limited Network",
  "organization": "Limited Network",
  "asn": 213790,
  "proxy_status": true,
  "vpn_status": false,
  "tor_status": false,
  "bot_activity": true,
  "recent_abuse": true
}
```

### 🔒 PREMIUM (Upgrade Required)

```json
"abuse_velocity": null,  // Rate of abuse
"frequent_abuser": null,  // Chronic abuser flag
"high_risk_attacks": null,  // Attack detection
"connection_type": null,  // Residential/Commercial/etc
"shared_connection": null,  // Shared network flag
"dynamic_connection": null,  // Dynamic IP flag
"security_scanner": null,  // Security tool flag
"trusted_network": null   // Enterprise trust flag
```

---

## Frontend Integration Steps

1. **Update script.js** - Parse `important_results` section
2. **Display Location Card** - Show country/city/timezone
3. **Display Network Card** - Show hostname/ISP/ASN
4. **Display Threat Card** - Show fraud score + status
5. **Display Risk Reasons** - Show top 5 indicators
6. **Add Visual Alerts** - Color-code by threat level

---

## Testing with Example IP

Test IP: **185.93.89.48** (Known malicious proxy)

Expected response:
- ✅ fraud_score: 100
- ✅ proxy_status: true
- ✅ bot_activity: true
- ✅ recent_abuse: true
- ✅ threat_types include "Proxy" and "Bot"
- ✅ risk_indicators populated with reasons

---

## Notes

- All free-tier fields grouped in `important_results` for easy access
- Threat severity auto-calculated from fraud_score
- No API calls blocked - all data available on free tier
- Premium fields return `null` (won't crash dashboard)
- Risk indicators show top 5 reasons IP is flagged
- Backward compatible (all old fields still available in nested structure)

