# API Integration Guide

## 🔌 Connecting Threat Intelligence APIs

This guide explains how to connect real threat intelligence APIs to the dashboard.

## Overview

The dashboard has placeholder API hooks ready for integration. All functions are located in `script.js` under the `API_HOOKS` object (around line 850).

## API Services Integration

### 1. AbuseIPDB

#### Setup
1. Sign up at https://www.abuseipdb.com/
2. Get your API key from dashboard
3. API Endpoint: `https://api.abuseipdb.com/api/v2/check`

#### Implementation
```javascript
API_HOOKS.queryAbuseIPDB = async (target) => {
    try {
        const response = await fetch('https://api.abuseipdb.com/api/v2/check', {
            method: 'POST',
            headers: {
                'Key': 'YOUR_ABUSEIPDB_API_KEY',
                'Accept': 'application/json'
            },
            body: new URLSearchParams({
                'ipAddress': target,
                'maxAgeInDays': 90
            })
        });
        const data = await response.json();
        return {
            name: 'AbuseIPDB',
            score: data.data?.abuseConfidenceScore || 0,
            reports: data.data?.totalReports || 0,
            isMalicious: (data.data?.abuseConfidenceScore || 0) > 50,
            lastReported: data.data?.lastReportedAt || 'Never'
        };
    } catch (error) {
        console.error('AbuseIPDB Error:', error);
        return { error: 'Failed to query AbuseIPDB' };
    }
};
```

#### Response Mapping
```javascript
// API Response → Dashboard Format
{
    abuseConfidenceScore: 95,  → threat score
    totalReports: 42,           → number of reports
    usageType: "Data Center"    → threat category
    lastReportedAt: "2024-01-15T10:30:00+00:00"
}
```

---

### 2. VirusTotal

#### Setup
1. Sign up at https://www.virustotal.com/
2. Get your API key from settings
3. API Endpoint: `https://www.virustotal.com/api/v3/`

#### Implementation
```javascript
API_HOOKS.queryVirusTotal = async (target) => {
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${target}`, {
            method: 'GET',
            headers: {
                'x-apikey': 'YOUR_VIRUSTOTAL_API_KEY'
            }
        });
        const data = await response.json();
        
        // Calculate threat score from vendor votes
        const stats = data.data?.attributes?.last_analysis_stats || {};
        const detections = stats.malicious || 0;
        const score = (detections / (detections + stats.undetected || 1)) * 100;
        
        return {
            name: 'VirusTotal',
            score: Math.round(score),
            detections: detections,
            vendors: Object.keys(data.data?.attributes?.last_analysis_results || {}),
            isMalicious: detections > 0,
            lastAnalysis: data.data?.attributes?.last_analysis_date
        };
    } catch (error) {
        console.error('VirusTotal Error:', error);
        return { error: 'Failed to query VirusTotal' };
    }
};
```

#### Response Mapping
```javascript
// API Response → Dashboard Format
{
    last_analysis_stats: {
        malicious: 15,          → detection count
        suspicious: 2,
        undetected: 50
    },
    last_dns_records: [],       → domain info
    asn: 16509                  → network info
}
```

---

### 3. AlienVault OTX

#### Setup
1. Sign up at https://otx.alienvault.com/
2. Get your API key from account settings
3. API Endpoint: `https://otx.alienvault.com/api/v1/`

#### Implementation
```javascript
API_HOOKS.queryAlienVault = async (target) => {
    try {
        const response = await fetch(
            `https://otx.alienvault.com/api/v1/indicators/ip/${target}/general`,
            {
                headers: {
                    'X-OTX-API-KEY': 'YOUR_ALIENVAULT_API_KEY'
                }
            }
        );
        const data = await response.json();
        
        // Calculate reputation score
        const pulses = data.pulse_info?.count || 0;
        const score = Math.min(100, pulses * 10);
        
        return {
            name: 'AlienVault OTX',
            score: score,
            pulses: pulses,
            reputation: data.reputation || 0,
            whitelisted: data.whitelisted || false,
            isMalicious: !data.whitelisted && pulses > 0,
            threat_types: data.pulse_info?.pulses?.map(p => p.name) || []
        };
    } catch (error) {
        console.error('AlienVault Error:', error);
        return { error: 'Failed to query AlienVault OTX' };
    }
};
```

#### Response Mapping
```javascript
// API Response → Dashboard Format
{
    pulse_info: {
        count: 8,               → number of pulses
        pulses: [
            {
                name: "Malware Family",
                description: "..."
            }
        ]
    },
    reputation: 2,              → reputation score
    whitelisted: false
}
```

---

### 4. GreyNoise

#### Setup
1. Sign up at https://www.greynoise.io/
2. Get your API key from console
3. API Endpoint: `https://api.greynoise.io/v3/community/ip/`

#### Implementation
```javascript
API_HOOKS.queryGreyNoise = async (target) => {
    try {
        const response = await fetch(
            `https://api.greynoise.io/v3/community/ip/${target}`,
            {
                headers: {
                    'key': 'YOUR_GREYNOISE_API_KEY'
                }
            }
        );
        const data = await response.json();
        
        // Convert GreyNoise classification to score
        const classificationScores = {
            'benign': 10,
            'suspicious': 50,
            'malicious': 90,
            'unknown': 30
        };
        
        return {
            name: 'GreyNoise',
            score: classificationScores[data.classification] || 30,
            classification: data.classification,
            seen: data.seen || false,
            isMalicious: data.classification === 'malicious',
            last_seen: data.last_seen,
            actor: data.actor
        };
    } catch (error) {
        console.error('GreyNoise Error:', error);
        return { error: 'Failed to query GreyNoise' };
    }
};
```

#### Response Mapping
```javascript
// API Response → Dashboard Format
{
    ip: "192.168.1.1",
    classification: "malicious",    → threat level
    seen: true,
    actor: "APT-42",
    last_seen: "2024-01-15T10:30:00Z"
}
```

---

## Complete Integration Example

Here's how to implement a full scan with all APIs:

```javascript
// In script.js, replace performScan function
async function performScan() {
    const scanType = document.getElementById('scanType').value;
    const scanInput = document.getElementById('scanInput').value.trim();

    if (!scanInput) {
        showToast('Please enter a valid input', 'error');
        return;
    }

    showToast('Scanning... Please wait', 'warning');
    document.getElementById('scanResults').classList.remove('hidden');
    document.getElementById('scanTimestamp').textContent = new Date().toLocaleString();

    try {
        // Query all APIs in parallel
        const [abuseIPDB, virusTotal, alienVault, greyNoise] = await Promise.all([
            API_HOOKS.queryAbuseIPDB(scanInput),
            API_HOOKS.queryVirusTotal(scanInput),
            API_HOOKS.queryAlienVault(scanInput),
            API_HOOKS.queryGreyNoise(scanInput)
        ]);

        // Calculate average threat score
        const scores = [
            abuseIPDB.score || 0,
            virusTotal.score || 0,
            alienVault.score || 0,
            greyNoise.score || 0
        ];
        const averageScore = Math.round(scores.reduce((a, b) => a + b) / scores.length);

        // Display results
        displayScanResults(scanType, scanInput);
        
        // Store API results for display
        window.scanResults = {
            abuseIPDB, virusTotal, alienVault, greyNoise,
            averageScore
        };

        showToast('Scan completed successfully', 'success');
    } catch (error) {
        showToast('Scan failed. Please try again.', 'error');
        console.error('Scan error:', error);
    }
}
```

---

## Real-Time Threat Data

### WebSocket Implementation

For true real-time updates, implement WebSocket:

```javascript
// Connect to your threat intelligence server
function initializeWebSocket() {
    const socket = new WebSocket('wss://your-threat-server.com/threats');

    socket.onopen = () => {
        console.log('WebSocket connected');
        showToast('Real-time threat feed connected', 'success');
    };

    socket.onmessage = (event) => {
        const newThreat = JSON.parse(event.data);
        
        // Add to mockThreats
        mockThreats.unshift(newThreat);
        if (mockThreats.length > 100) mockThreats.pop();
        
        // Update UI
        populateThreatTable();
        updateKPICards();
        
        // If new threat is critical, show alert
        if (newThreat.score >= 80) {
            showToast(`⚠️ Critical threat detected: ${newThreat.ip}`, 'error');
        }
    };

    socket.onerror = (error) => {
        console.error('WebSocket error:', error);
        showToast('Connection lost. Retrying...', 'error');
    };

    socket.onclose = () => {
        console.log('WebSocket disconnected');
        // Reconnect after 5 seconds
        setTimeout(initializeWebSocket, 5000);
    };
}
```

---

## Block IP Implementation

Connect your backend for IP blocking:

```javascript
API_HOOKS.blockIPAddress = async (ip) => {
    try {
        const response = await fetch('/api/block-ip', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer YOUR_AUTH_TOKEN'
            },
            body: JSON.stringify({
                ip: ip,
                reason: 'Malicious activity detected',
                duration: 'permanent'  // or '24h', '7d', etc.
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        
        return {
            success: true,
            message: `IP ${ip} has been blocked`,
            blockId: data.blockId,
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        console.error('Block IP error:', error);
        return { success: false, error: error.message };
    }
};
```

---

## Environment Variables

Use environment variables for API keys:

```javascript
// Create a .env file (local only, don't commit)
VITE_ABUSEIPDB_KEY=your_key_here
VITE_VIRUSTOTAL_KEY=your_key_here
VITE_ALIENVAULT_KEY=your_key_here
VITE_GREYNOISE_KEY=your_key_here

// Access in code
const apiKey = import.meta.env.VITE_ABUSEIPDB_KEY;
```

For vanilla JS without build tools, use a config file:

```javascript
// config.js
const API_KEYS = {
    abuseipdb: process.env.ABUSEIPDB_KEY || 'YOUR_KEY',
    virustotal: process.env.VIRUSTOTAL_KEY || 'YOUR_KEY',
    alienvault: process.env.ALIENVAULT_KEY || 'YOUR_KEY',
    greynoise: process.env.GREYNOISE_KEY || 'YOUR_KEY'
};
```

---

## Rate Limiting Considerations

Most APIs have rate limits:

```javascript
// Implement rate limiting
class RateLimiter {
    constructor(limit, window) {
        this.limit = limit;        // requests per window
        this.window = window;      // time window in ms
        this.requests = [];
    }

    async acquire() {
        const now = Date.now();
        this.requests = this.requests.filter(t => t > now - this.window);
        
        if (this.requests.length >= this.limit) {
            const oldestRequest = Math.min(...this.requests);
            const waitTime = oldestRequest + this.window - now;
            await new Promise(resolve => setTimeout(resolve, waitTime));
            return this.acquire(); // Retry
        }
        
        this.requests.push(now);
    }
}

const apiLimiter = new RateLimiter(10, 60000); // 10 requests per minute

// Use in queries
API_HOOKS.queryAbuseIPDB = async (target) => {
    await apiLimiter.acquire();
    // ... make API call
};
```

---

## Error Handling

Implement robust error handling:

```javascript
// Wrapper for API calls with retry logic
async function queryAPIWithRetry(fn, maxRetries = 3, backoff = 1000) {
    for (let i = 0; i < maxRetries; i++) {
        try {
            return await fn();
        } catch (error) {
            if (i === maxRetries - 1) throw error;
            
            // Exponential backoff
            const delay = backoff * Math.pow(2, i);
            console.log(`Retrying in ${delay}ms...`);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
}

// Usage
const result = await queryAPIWithRetry(() => 
    API_HOOKS.queryAbuseIPDB('192.168.1.1')
);
```

---

## Testing

### Unit Testing Example

```javascript
// test.js
async function testAPIs() {
    const testIPs = [
        '8.8.8.8',          // Google DNS (benign)
        '192.168.1.1',      // Local IP
        '127.0.0.1'         // Localhost
    ];

    for (const ip of testIPs) {
        console.log(`Testing: ${ip}`);
        
        const results = await Promise.all([
            API_HOOKS.queryAbuseIPDB(ip),
            API_HOOKS.queryVirusTotal(ip),
            API_HOOKS.queryAlienVault(ip),
            API_HOOKS.queryGreyNoise(ip)
        ]);
        
        console.table(results);
    }
}

// Run in console: testAPIs()
```

---

## Production Checklist

- ✅ API keys stored in environment variables (never commit)
- ✅ Rate limiting implemented
- ✅ Error handling for API failures
- ✅ Caching to reduce API calls
- ✅ Request timeout handling
- ✅ HTTPS for all API calls
- ✅ CORS headers configured
- ✅ Input validation before API calls
- ✅ Monitoring/logging for API usage
- ✅ Fallback data when APIs fail

---

## Resources

- [AbuseIPDB Docs](https://docs.abuseipdb.com/)
- [VirusTotal API Docs](https://developers.virustotal.com/reference)
- [AlienVault OTX API](https://otx.alienvault.com/api)
- [GreyNoise API Docs](https://docs.greynoise.io/)

---

**Happy Integrating! 🚀**
