# IPQualityScore Optional Handling - Update

## Overview
Backend.py has been updated to **gracefully handle IPQualityScore unavailability**. The dashboard will now continue working with 4 APIs (AbuseIPDB, VirusTotal, AlienVault, GreyNoise) even if IPQualityScore experiences DNS errors or API key is missing.

## Changes Made

### 1. **New Utility Function: `get_optional_env()`**
Added a new function to load optional environment variables with defaults.

```python
def get_optional_env(name, default=None):
    """Load optional environment variable with default."""
    return os.getenv(name, default)
```

**Before:** `get_required_env()` only - would crash if env var missing.
**After:** Both `get_required_env()` and `get_optional_env()` - optional keys don't crash.

---

### 2. **Updated API_CONFIG for IPQualityScore**
Changed IPQualityScore key loading from required to optional:

```python
'ipqualityscore': {
    'endpoint': 'https://api.ipqualityscore.com/api/json/ip',
    'key': get_optional_env('IPQUALITYSCORE_KEY'),  # ← Optional now
    'method': 'GET',
    'timeout': 10
}
```

**Impact:** Backend starts even if IPQUALITYSCORE_KEY is missing or empty.

---

### 3. **Enhanced `query_ipqualityscore()` Function**
Added API key availability check at start of function:

```python
def query_ipqualityscore(target):
    """Query IPQualityScore API - Fraud detection (IP only)"""
    config = API_CONFIG['ipqualityscore']
    
    # Check if API key is configured
    if not config['key']:
        logger.warning('IPQualityScore API key not configured')
        return {
            'name': 'IPQualityScore',
            'success': False,
            'error': 'IPQualityScore API key not configured',
            'score': 0,
            'isMalicious': False,
            'offline': True  # ← New flag
        }
    
    # ... rest of function with improved exception handling
```

**Benefits:**
- No HTTP requests if key is missing (saves bandwidth)
- Returns standardized error response
- Includes `'offline': True` flag for frontend to identify service status

**Error Handling Catches:**
- API key not configured
- IPv6 addresses (not supported)
- DNS resolution errors
- Network connectivity issues
- API timeout errors
- API response errors

---

### 4. **Updated `get_scan_tasks()` Function**
Modified to skip IPQualityScore task if API key is not available:

```python
def get_scan_tasks(target, target_type):
    """Return API tasks based on target type."""
    tasks = {
        'AbuseIPDB': lambda: query_abuseipdb(target),
        'VirusTotal': lambda: query_virustotal(target),
        'AlienVault': lambda: query_alienvault(target),
        'GreyNoise': lambda: query_greynoise(target)
    }
    
    # Only add IPQualityScore if: IPv4 target AND API key configured
    if target_type == 'ip' and is_valid_ipv4(target) and API_CONFIG['ipqualityscore']['key']:
        tasks['IPQualityScore'] = lambda: query_ipqualityscore(target)
    
    return tasks
```

**Benefits:**
- Don't attempt to query if not configured
- Dashboard doesn't wait for timeout on missing service
- Cleaner response structure

---

## Usage Scenarios

### Scenario 1: IPQualityScore Key Configured (Normal Operation)
```
User scans IP: 85.217.149.44
↓
Backend queries all 5 APIs:
  ✅ AbuseIPDB
  ✅ VirusTotal
  ✅ AlienVault
  ✅ GreyNoise
  ✅ IPQualityScore (if network works)
  
If DNS error occurs:
  ✅ First 4 APIs return results
  ✅ IPQualityScore returns: 
     {
       "name": "IPQualityScore",
       "success": false,
       "error": "HTTPSConnectionPool...Failed to resolve 'api.ipqualityscore.com'",
       "offline": true
     }
  
Dashboard shows: "IPQualityScore: Unavailable (DNS error)"
```

### Scenario 2: IPQualityScore Key NOT in .env (Optional Missing)
```
Backend starts normally with only 4 APIs configured.

User scans IP: 85.217.149.44
↓
Backend queries only 4 APIs:
  ✅ AbuseIPDB
  ✅ VirusTotal
  ✅ AlienVault
  ✅ GreyNoise
  (IPQualityScore task not added - skipped)

Dashboard shows 4 results normally.
```

### Scenario 3: IPv6 Address (Not Supported by IPQualityScore)
```
User scans: 2606:2800:220:1:248:1893:25c8:1946
↓
Backend queries 4 standard APIs + IPQualityScore:
  ✅ AbuseIPDB
  ✅ VirusTotal
  ✅ AlienVault
  ✅ GreyNoise
  ✅ IPQualityScore returns:
     {
       "name": "IPQualityScore",
       "success": false,
       "error": "IPQualityScore only supports IPv4 addresses"
     }

Dashboard correctly handles IPv6 scans.
```

---

## Frontend Behavior

The frontend script.js should check the `success` and `offline` flags:

```javascript
// In script.js (scan results display)
const ipqsResult = results.find(r => r.name === 'IPQualityScore');

if (ipqsResult) {
    if (ipqsResult.success) {
        // Display IPQualityScore data normally
        displayIPQualityScoreResults(ipqsResult);
    } else if (ipqsResult.offline) {
        // Show "Service unavailable" message
        showWarning('IPQualityScore temporarily unavailable');
    } else {
        // Show error message
        showError('IPQualityScore error: ' + ipqsResult.error);
    }
} else {
    // IPQualityScore task wasn't included (key not configured)
    console.log('IPQualityScore not configured');
}
```

---

## Testing the Changes

### 1. **Test Backend Startup Without key:**
```bash
# Remove or comment out IPQUALITYSCORE_KEY in .env
python3 backend.py

# Expected: Backend starts normally
# No "Missing required environment variable" error
```

### 2. **Test Scan Without Key:**
```bash
# In another terminal:
curl http://localhost:5001/api/scan -X POST \
  -H "Content-Type: application/json" \
  -d '{"target": "85.217.149.44"}'

# Expected: 4 API results, IPQualityScore not included in response
```

### 3. **Test With Key But DNS Error:**
```bash
# Ensure IPQUALITYSCORE_KEY is in .env
# Keep DNS broken (or disconnect network)

# Same curl command as above
# Expected: 4 API results, IPQualityScore with 'offline': true
```

---

## How to Recover IPQualityScore

1. **If DNS Error:** Follow [IPQUALITYSCORE_DNS_ERROR_TROUBLESHOOTING.md](IPQUALITYSCORE_DNS_ERROR_TROUBLESHOOTING.md)
   - Restart network
   - Change DNS server
   - Disconnect VPN if used
   - Check firewall/security software

2. **If Key Missing:** Add to .env:
   ```bash
   IPQUALITYSCORE_KEY=your_api_key_here
   ```

3. **Restart Backend:**
   ```bash
   # Kill current process (Ctrl+C)
   python3 backend.py  # Restart
   ```

4. **Test New IP:**
   ```bash
   curl http://localhost:5001/api/scan -X POST \
     -H "Content-Type: application/json" \
     -d '{"target": "1.2.3.4"}'
   ```

---

## Benefits Summary

| Issue | Before | After |
|-------|--------|-------|
| Missing API key | ❌ Backend crash | ✅ Graceful skip |
| DNS error | ❌ Dashboard hangs | ✅ Returns error response |
| Network timeout | ❌ Request hangs | ✅ Times out, continues |
| IPv6 address | ❌ Unused task | ✅ Skipped from task list |
| Dashboard reliability | ⚠️ 1 API = 20% failure | ✅ 4/5 APIs always work |

---

## Code Changes Summary

**Files Modified:** 1
- `backend.py` (3 functions updated)

**Functions Updated:**
1. `get_required_env()` → Added companion `get_optional_env()`
2. `API_CONFIG['ipqualityscore']['key']` → Changed to `get_optional_env()`
3. `query_ipqualityscore()` → Added API key check + improved error handling
4. `get_scan_tasks()` → Added key availability check

**Lines Changed:** ~20 lines
**Backwards Compatible:** ✅ Yes (if key is in .env, works exactly the same)
**Python Version:** ✅ 3.6+

---

## Next Steps

1. **Monitor Dashboard:** Keep monitoring for DNS/network recovery
2. **Update .env:** Add IPQUALITYSCORE_KEY when network is fixed
3. **Restart Backend:** `python3 backend.py`
4. **Test Scan:** Verify all 5 APIs work
5. **Check Logs:** `python3 backend.py 2>&1 | grep -i ipquality`

---

## Logs to Watch

When running backend with debug logging:

```bash
# DNS error example:
# ERROR:__main__:IPQualityScore Error: HTTPSConnectionPool...Failed to resolve 'api.ipqualityscore.com'

# Missing key example:
# WARNING:__main__:IPQualityScore API key not configured (IPQUALITYSCORE_KEY not in .env)

# Success example:
# [No warning/error - query completes normally]
```

