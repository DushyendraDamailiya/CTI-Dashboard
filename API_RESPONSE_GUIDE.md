# API Response Data & Display Guide

## Overview
This guide shows what data each threat intelligence API returns and how to display it in the dashboard.

---

## 1. AbuseIPDB API Response

### Raw API Response Structure
```json
{
  "data": {
    "ipAddress": "192.168.1.105",
    "abuseConfidenceScore": 95,
    "countryCode": "CN",
    "usageType": "Data Center",
    "isp": "China Telecom",
    "domain": "chinatelecom.com.cn",
    "totalReports": 342,
    "numDistinctUsers": 89,
    "lastReportedAt": "2025-12-05T14:22:00+00:00",
    "reports": [
      {
        "reportedAt": "2025-12-05T14:22:00+00:00",
        "comment": "SSH brute force attack",
        "categories": [22],
        "reportedByName": "Security Team A"
      }
    ]
  }
}
```

### Displayable Results
```
┌─────────────────────────────────────────┐
│        AbuseIPDB Reputation Report      │
├─────────────────────────────────────────┤
│ Abuse Confidence Score:    95/100       │
│ Threat Level:              CRITICAL     │
│ ISP:                       China Telecom│
│ Domain:                    chinatelecom │
│ Usage Type:                Data Center  │
│ Total Reports:             342          │
│ Unique Reporters:          89           │
│ Last Reported:             2 hours ago  │
│ Report Categories:         SSH (22),    │
│                            HTTP (80)    │
│ Sample Comments:           "SSH brute   │
│                            force attack"│
└─────────────────────────────────────────┘
```

### Key Metrics to Display
- **Abuse Confidence Score** (0-100): Main threat indicator
- **Total Reports**: Number of abuse reports
- **Unique Users**: How many people reported it
- **Last Reported**: Recency of threat
- **Report Categories**: Types of attacks (SSH, HTTP, FTP, etc.)
- **ISP & Domain**: Network owner info
- **Usage Type**: Data center, residential, mobile, etc.

---

## 2. VirusTotal API Response

### Raw API Response Structure
```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 12,
        "suspicious": 3,
        "undetected": 60,
        "harmless": 2
      },
      "last_analysis_results": {
        "Kaspersky": { "category": "malicious", "engine_name": "Kaspersky" },
        "Norton": { "category": "suspicious", "engine_name": "Norton" },
        "McAfee": { "category": "harmless", "engine_name": "McAfee" }
      },
      "last_analysis_date": 1733418120,
      "country": "CN",
      "asn": 4134,
      "as_owner": "China Unicom",
      "last_dns_records": [
        { "type": "A", "value": "192.168.1.105" }
      ],
      "whois": "China Unicom Beijing"
    }
  }
}
```

### Displayable Results
```
┌────────────────────────────────────────────┐
│      VirusTotal Multi-Vendor Analysis      │
├────────────────────────────────────────────┤
│ Overall Detection:         12/77 vendors   │
│ Status:                    MALICIOUS       │
│                                            │
│ Vendor Verdicts:                           │
│  🔴 Malicious:            12 vendors       │
│  🟡 Suspicious:           3 vendors        │
│  🟢 Harmless:             2 vendors        │
│  ⚪ Undetected:           60 vendors       │
│                                            │
│ Top Detections:                            │
│  • Kaspersky:    Malicious                 │
│  • Norton:       Suspicious                │
│  • McAfee:       Harmless                  │
│                                            │
│ Network Info:                              │
│  ASN:                      AS4134          │
│  ISP:                      China Unicom    │
│  Country:                  China (CN)      │
│  Last Analysis:            2 hours ago     │
│                                            │
│ DNS Records:               A, MX, SOA      │
└────────────────────────────────────────────┘
```

### Key Metrics to Display
- **Detection Ratio**: X/Y vendors flagged as malicious
- **Vendor Breakdown**: Pie chart (Malicious, Suspicious, Harmless, Undetected)
- **Top Detections**: Which antivirus engines detected it
- **ASN & ISP**: Network owner
- **Country**: Geographic location
- **DNS Records**: A, MX, TXT records if available
- **Last Analysis Date**: When last scanned
- **WHOIS Info**: Registrant details

---

## 3. AlienVault OTX API Response

### Raw API Response Structure
```json
{
  "pulse_info": {
    "count": 24,
    "pulses": [
      {
        "id": "507e1f77bcf86cd799439012",
        "name": "Chinese APT28 Infrastructure",
        "description": "Known C2 server used by APT28",
        "created": "2025-11-15T10:22:00Z",
        "modified": "2025-12-05T14:22:00Z"
      }
    ]
  },
  "reputation": -47,
  "indicator": "192.168.1.105",
  "type": "IPv4",
  "whitelisted": false,
  "validation": [
    {
      "source": "PALOALTONETWORKS",
      "name": "PaloAlto Networks",
      "result": true
    }
  ],
  "country_code": "CN",
  "country_name": "China",
  "asn": "AS4134",
  "last_seen": "2025-12-05T10:00:00Z",
  "first_seen": "2024-01-10T08:30:00Z"
}
```

### Displayable Results
```
┌──────────────────────────────────────────┐
│     AlienVault OTX Threat Intelligence   │
├──────────────────────────────────────────┤
│ Reputation Score:         -47 (Malicious)│
│ Threat Pulses:            24 active      │
│ Whitelisted:              No             │
│                                          │
│ Linked Threat Pulses:                    │
│ 1. Chinese APT28 Infrastructure          │
│    • C2 server used by APT28             │
│    • Created: Nov 15, 2025               │
│    • Updated: Dec 5, 2025                │
│                                          │
│ 2. Mirai Botnet Nodes                    │
│    • Part of Mirai C2 network            │
│    • Created: Aug 20, 2025               │
│                                          │
│ Validation:                              │
│ ✓ Verified by PaloAlto Networks          │
│ ✓ Verified by Cisco Talos                │
│ ✓ Verified by Abuse.ch                   │
│                                          │
│ Location Info:                           │
│  Country:                  China (CN)    │
│  ASN:                      AS4134        │
│  First Seen:               Jan 10, 2024  │
│  Last Seen:                Dec 5, 2025   │
│  Active Duration:          1 year 11mo   │
└──────────────────────────────────────────┘
```

### Key Metrics to Display
- **Reputation Score**: Numerical rating (typically -100 to 0)
- **Threat Pulse Count**: Number of threat campaigns linked
- **Linked Threat Pulses**: 
  - Threat name
  - Description
  - Created/Updated dates
  - Severity level
- **Validation**: Which organizations verified this threat
- **Whitelisted Status**: If it's on whitelist
- **Geographic Info**: Country, ASN, location
- **Timeline**: First seen, last seen, active duration
- **Tags**: Attack type, malware family, etc.

---

## 4. GreyNoise API Response

### Raw API Response Structure
```json
{
  "ip": "192.168.1.105",
  "seen": true,
  "classification": "malicious",
  "last_seen": "2025-12-05T14:22:00Z",
  "first_seen": "2025-01-10T08:30:00Z",
  "tags": [
    "SSH Brute Forcer",
    "HTTP Scanner",
    "Port Scanner"
  ],
  "intentions": "Malicious Activity",
  "raw_data": {
    "scan": {
      "http": {
        "paths": ["/admin", "/wp-admin", "/login"],
        "user_agents": ["Mozilla/5.0"]
      },
      "ssh": {
        "username_list": ["admin", "root", "user"],
        "auth_attempts": 1523
      }
    },
    "web": {
      "paths": ["/admin", "/wp-admin"],
      "user_agents": ["curl/7.64.1"]
    }
  },
  "actor": {
    "id": "unknown",
    "name": "Unknown Actor"
  }
}
```

### Displayable Results
```
┌──────────────────────────────────────────┐
│      GreyNoise Threat Classification     │
├──────────────────────────────────────────┤
│ Classification:           MALICIOUS      │
│ Threat Level:             CRITICAL       │
│ Status:                   Active in wild │
│                                          │
│ Observed Intentions:                     │
│ • SSH Brute Forcer                       │
│ • HTTP Scanner                           │
│ • Port Scanner                           │
│                                          │
│ Attack Activity:                         │
│ ┌──────────────────────────────────────┐ │
│ │ SSH Attack                           │ │
│ │ • Auth Attempts: 1,523               │ │
│ │ • Target Accounts:                   │ │
│ │   - admin, root, user                │ │
│ │                                      │ │
│ │ HTTP Scanning                        │ │
│ │ • Paths Scanned:                     │ │
│ │   - /admin, /wp-admin, /login        │ │
│ │ • User Agents:                       │ │
│ │   - Mozilla/5.0, curl/7.64.1         │ │
│ └──────────────────────────────────────┘ │
│                                          │
│ Timeline:                                │
│  First Seen:              Jan 10, 2025   │
│  Last Seen:               Dec 5, 2025    │
│  Active Period:           11 months      │
│                                          │
│ Identified Actor:         Unknown        │
└──────────────────────────────────────────┘
```

### Key Metrics to Display
- **Classification**: Malicious, Suspicious, or Benign
- **Seen Status**: Whether IP is in active use
- **Tags/Intentions**: Attack types (brute force, scanning, etc.)
- **Attack Methods**: 
  - SSH attempts (username list, attempt count)
  - HTTP scanning (paths, user agents)
  - Port scanning
- **First/Last Seen**: Timeline of activity
- **Actor Info**: Known threat group (if identified)
- **Activity Breakdown**: Table of detected scan patterns
- **Raw scan data**: Specific endpoints targeted

---

## 5. Recommended Display Format: Summary Card

```
╔════════════════════════════════════════════════════════╗
║           MULTI-API THREAT ANALYSIS RESULTS            ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║ TARGET: 192.168.1.105                                 ║
║ STATUS: 🔴 MALICIOUS (Confirmed by 4/4 APIs)         ║
║ THREAT LEVEL: CRITICAL (Score: 92/100)                ║
║                                                        ║
╠════════════════════════════════════════════════════════╣
║ THREAT INTELLIGENCE BREAKDOWN                         ║
├────────────────────────────────────────────────────────┤
║                                                        ║
║ AbuseIPDB:                                             ║
║  ✓ Confidence: 95/100                                 ║
║  ✓ Reports: 342 (89 unique reporters)                 ║
║  ✓ Category: SSH Brute Force, HTTP Attack             ║
║                                                        ║
║ VirusTotal:                                            ║
║  ✓ Detection: 12/77 vendors                           ║
║  ✓ Engines: Kaspersky, Norton, Avast                  ║
║  ✓ ASN: AS4134 (China Unicom)                         ║
║                                                        ║
║ AlienVault OTX:                                        ║
║  ✓ Reputation: -47 (Malicious)                        ║
║  ✓ Pulses: 24 (APT28, Mirai, etc.)                    ║
║  ✓ Verified: 8 organizations                          ║
║                                                        ║
║ GreyNoise:                                             ║
║  ✓ Classification: Malicious                          ║
║  ✓ Intentions: SSH Brute Force, Port Scan             ║
║  ✓ Active: 11 months (Since Jan 10, 2025)             ║
║                                                        ║
╠════════════════════════════════════════════════════════╣
║ RECOMMENDED ACTION: BLOCK & MONITOR                   ║
║ CONFIDENCE LEVEL: VERY HIGH (98%)                     ║
╚════════════════════════════════════════════════════════╝
```

---

## 6. Visual Display Elements to Implement

### A. Threat Score Gauge
```
┌─────────────────────────┐
│   Threat Score Gauge    │
│                         │
│     0   25   50  75 100 │
│     |    |    |   |  |  │
│     ├────┼────┼───┼──┤  │
│     🟢  🟡   🟠  🔴 🔴  │
│                    ↑    │
│                   92    │
│                (CRITICAL)│
└─────────────────────────┘
```

### B. Detection Timeline
```
Jan 2024              Now (Dec 5, 2025)
└──────────────────────────────────────┘
        [████████████ Active ████]
        First Seen    Last Seen
```

### C. API Consensus Chart
```
APIs Agreement:
┌─────────────┐
│ Malicious  │  4/4 APIs agree
├─────────────┤
│ ████████████│ 100% consensus
└─────────────┘
```

### D. Attack Pattern Breakdown
```
Attack Methods (Last 30 days):
┌────────────────────────────┐
│ SSH Brute Force    ███ 45% │
│ HTTP Scanning      ██  28% │
│ Port Scanning      ██  18% │
│ DDoS              █   9%   │
└────────────────────────────┘
```

---

## 7. Data Organization Strategy

### Option 1: Tabbed Interface
```
[AbuseIPDB] [VirusTotal] [AlienVault] [GreyNoise] [Summary]
     ↓
Show only the selected API's detailed data
```

### Option 2: Accordion Collapsible
```
▼ AbuseIPDB Report
  • Score: 95/100
  • Reports: 342
▶ VirusTotal Report
▶ AlienVault Report
▶ GreyNoise Report
```

### Option 3: Side-by-Side Comparison
```
┌──────────────┬──────────────┬──────────────┐
│  AbuseIPDB   │ VirusTotal   │  GreyNoise   │
├──────────────┼──────────────┼──────────────┤
│ Score: 95    │ 12/77        │ Malicious    │
│ Reports: 342 │ Kaspersky    │ SSH Attack   │
│ ISP: China   │ China Unicom │ Active       │
└──────────────┴──────────────┴──────────────┘
```

---

## 8. Export Formats

You can export results as:
- **PDF Report**: Full detailed analysis
- **JSON**: Structured data for integration
- **CSV**: Tabular format for analysis
- **HTML**: Shareable report
- **Plain Text**: Email-friendly format

---

## Next Steps

1. **Choose a display format** (tabs, accordion, or comparison)
2. **Implement result parsing** to show real data instead of mocks
3. **Create result cards** for each API
4. **Add export functionality**
5. **Implement caching** to reduce API calls
