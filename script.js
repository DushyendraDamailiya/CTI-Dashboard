// ============================================
// THREAT INTELLIGENCE DASHBOARD - JAVASCRIPT
// ============================================

// ========== BACKEND CONFIGURATION ==========
const BACKEND_URL = 'http://localhost:5001'; // Change for production
const API_ENDPOINTS = {
    validate: `${BACKEND_URL}/api/validate`,
    scan: `${BACKEND_URL}/api/scan`,
    health: `${BACKEND_URL}/health`,
    block: `${BACKEND_URL}/api/block-ip`,
    alerts: `${BACKEND_URL}/api/alerts`,
    threatLogs: `${BACKEND_URL}/api/threat-logs`
};

// ========== INPUT VALIDATION FUNCTIONS ==========

function isValidIPv4(ip) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(ip)) return false;
    return ip.split('.').every(num => parseInt(num) <= 255);
}

function isValidDomain(domain) {
    const domainRegex = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
    return domainRegex.test(domain);
}

function isValidHash(hash) {
    // MD5: 32 chars, SHA1: 40 chars, SHA256: 64 chars
    const hashRegex = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
    return hashRegex.test(hash);
}

function validateInput(target, targetType = 'auto') {
    target = target.trim();
    
    if (targetType === 'auto' || targetType === 'ip') {
        if (isValidIPv4(target)) return { valid: true, type: 'ip' };
        if (targetType === 'ip') return { valid: false, error: 'Invalid IPv4 address' };
    }
    
    if (targetType === 'auto' || targetType === 'domain') {
        if (isValidDomain(target)) return { valid: true, type: 'domain' };
        if (targetType === 'domain') return { valid: false, error: 'Invalid domain' };
    }
    
    if (targetType === 'auto' || targetType === 'hash') {
        if (isValidHash(target)) return { valid: true, type: 'hash' };
        if (targetType === 'hash') return { valid: false, error: 'Invalid hash (MD5, SHA1, or SHA256)' };
    }
    
    if (targetType === 'auto') {
        return { valid: false, error: 'Invalid input - not a valid IP, domain, or hash' };
    }
    
    return { valid: false, error: 'Unknown validation error' };
}

// ========== CONFIGURATION & CONSTANTS ==========

const CONFIG = {
    // API Endpoints (placeholder - replace with actual backend URLs)
    apis: {
        abuseipdb: { name: 'AbuseIPDB', color: '#ff4757' },
        virustotal: { name: 'VirusTotal', color: '#00d4ff' },
        alienvault: { name: 'AlienVault OTX', color: '#ffa502' },
        greynoise: { name: 'GreyNoise', color: '#2ed573' }
    },
    
    refreshInterval: 5000, // 5 seconds for live data
    threatScoreThresholds: {
        critical: 80,
        high: 60,
        medium: 40,
        low: 0
    }
};

// ========== MOCK DATA ==========

const mockThreats = [
    { ip: '192.168.1.105', country: 'China', flag: '🇨🇳', score: 95, type: 'Botnet', api: 'AbuseIPDB', timestamp: getRecentTime(2) },
    { ip: '10.0.0.45', country: 'Russia', flag: '🇷🇺', score: 87, type: 'DDoS Attack', api: 'GreyNoise', timestamp: getRecentTime(5) },
    { ip: '172.16.0.1', country: 'North Korea', flag: '🇰🇵', score: 92, type: 'Trojan', api: 'VirusTotal', timestamp: getRecentTime(8) },
    { ip: '203.0.113.42', country: 'Iran', flag: '🇮🇷', score: 78, type: 'Malware', api: 'AlienVault OTX', timestamp: getRecentTime(12) },
    { ip: '198.51.100.89', country: 'Brazil', flag: '🇧🇷', score: 65, type: 'Phishing', api: 'AbuseIPDB', timestamp: getRecentTime(15) },
    { ip: '192.0.2.55', country: 'India', flag: '🇮🇳', score: 73, type: 'Ransomware', api: 'GreyNoise', timestamp: getRecentTime(18) },
    { ip: '203.0.113.100', country: 'Vietnam', flag: '🇻🇳', score: 81, type: 'Brute Force', api: 'VirusTotal', timestamp: getRecentTime(22) },
    { ip: '198.51.100.200', country: 'Ukraine', flag: '🇺🇦', score: 72, type: 'SQL Injection', api: 'AbuseIPDB', timestamp: getRecentTime(25) }
];

const fallbackAlerts = [
    { type: 'Critical DDoS Detected', ip: '192.168.1.105', severity: 'critical', time: getRecentTime(2), description: 'Massive DDoS attack from coordinated botnets' },
    { type: 'Malware Distribution', ip: '10.0.0.45', severity: 'high', time: getRecentTime(8), description: 'Known malware hosting detected' },
    { type: 'Brute Force Attack', ip: '203.0.113.42', severity: 'medium', time: getRecentTime(15), description: 'Multiple failed login attempts detected' },
    { type: 'Ransomware Activity', ip: '172.16.0.1', severity: 'critical', time: getRecentTime(5), description: 'Ransomware encryption behavior detected' },
    { type: 'Suspicious API Access', ip: '198.51.100.89', severity: 'medium', time: getRecentTime(20), description: 'Unusual API access pattern from this IP' },
    { type: 'Data Exfiltration', ip: '203.0.113.100', severity: 'high', time: getRecentTime(12), description: 'Unusual data transfer volume detected' }
];

const mockLogsData = [];
let alertsData = [...fallbackAlerts];
let alertsRefreshTimer = null;
let knownAlertIds = new Set(alertsData.map(alert => String(alert.id || '')));

// Initialize mock logs data
function initializeMockLogs() {
    mockLogsData.length = 0;
    for (let i = 0; i < 150; i++) {
        const threat = mockThreats[i % mockThreats.length];
        const timestamp = Date.now() - i * 6 * 60 * 60 * 1000;
        const scoreDelta = (i % 11) - 5; // deterministic adjustment [-5..5]
        mockLogsData.push({
            id: `mock-${i}`,
            ip: threat.ip,
            country: threat.country,
            flag: threat.flag,
            score: Math.max(0, Math.min(100, threat.score + scoreDelta)),
            api: threat.api,
            date: new Date(timestamp).toLocaleString(),
            timestamp,
            status: ['blocked', 'monitored', 'whitelisted'][i % 3],
            scanResults: []
        });
    }
    // Sort by timestamp descending
    mockLogsData.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
}

// ========== UTILITY FUNCTIONS ==========

function getRecentTime(minutesAgo) {
    const date = new Date(Date.now() - minutesAgo * 60000);
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${hours}:${minutes}`;
}

function getRandomCountry() {
    const countries = ['China', 'Russia', 'North Korea', 'Iran', 'Brazil', 'India', 'Vietnam', 'Ukraine', 'Pakistan', 'Nigeria'];
    return countries[Math.floor(Math.random() * countries.length)];
}

function getCountryFlag(country) {
    const flags = {
        'China': '🇨🇳', 'Russia': '🇷🇺', 'North Korea': '🇰🇵', 'Iran': '🇮🇷', 'Brazil': '🇧🇷',
        'India': '🇮🇳', 'Vietnam': '🇻🇳', 'Ukraine': '🇺🇦', 'Pakistan': '🇵🇰', 'Nigeria': '🇳🇬'
    };
    return flags[country] || '🌍';
}

function generateRandomIP() {
    return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

function getThreatLevel(score) {
    if (score >= CONFIG.threatScoreThresholds.critical) return 'critical';
    if (score >= CONFIG.threatScoreThresholds.high) return 'high';
    if (score >= CONFIG.threatScoreThresholds.medium) return 'medium';
    return 'low';
}

function formatScore(score) {
    return Math.round(score);
}

function showToast(message, type = 'success', duration = 3000) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
        <span>${message}</span>
    `;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), duration);
}

function showRealtimeAlertPopup(alert) {
    const attackerIp = alert?.ip || 'Unknown';
    const attackType = alert?.type || 'Threat Alert';
    showToast(`Real-time threat detected: ${attackType} from ${attackerIp}`, 'error', 4000);
}

// ========== TAB NAVIGATION ==========

function initializeTabNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const tabContents = document.querySelectorAll('.tab-content');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const tabName = link.getAttribute('data-tab');

            // Remove active class from all links and tabs
            navLinks.forEach(l => l.classList.remove('active'));
            tabContents.forEach(tab => tab.classList.remove('active'));

            // Add active class to clicked link and corresponding tab
            link.classList.add('active');
            document.getElementById(tabName).classList.add('active');

            // Initialize specific tab content if needed
            if (tabName === 'global-map') {
                setTimeout(initializeMap, 100);
            }
        });
    });
}

// ========== REAL-TIME MONITORING TAB ==========

function initializeMonitoring() {
    updateKPICards();
    populateThreatTable();
    initializeCharts();
    setupLiveUpdates();
}

function updateKPICards() {
    document.getElementById('totalRequests').textContent = Math.floor(Math.random() * 20000 + 10000).toLocaleString();
    document.getElementById('maliciousCount').textContent = mockThreats.length;
    document.getElementById('criticalAlerts').textContent = alertsData.filter(a => a.severity === 'critical').length;
}

function populateThreatTable(threats = mockThreats) {
    const tbody = document.getElementById('threatTableBody');
    tbody.innerHTML = '';

    threats.forEach((threat, index) => {
        const row = document.createElement('tr');
        const threatLevel = getThreatLevel(threat.score);
        
        row.innerHTML = `
            <td><code>${threat.ip}</code></td>
            <td><span class="country-cell"><span class="flag">${threat.flag}</span>${threat.country}</span></td>
            <td><span class="threat-score-badge ${threatLevel}">${formatScore(threat.score)}</span></td>
            <td>${threat.type}</td>
            <td><span class="api-source">${threat.api}</span></td>
            <td>${threat.timestamp}</td>
            <td>
                <div class="action-buttons">
                    <button class="btn-action btn-block" onclick="blockIP('${threat.ip}')">
                        <i class="fas fa-ban"></i> Block
                    </button>
                    <button class="btn-action btn-details" onclick="showDetails('${threat.ip}', ${index})">
                        <i class="fas fa-expand"></i> Details
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function blockIP(ip) {
    if (!isValidIPv4(ip)) {
        showToast(`Cannot block non-IPv4 target: ${ip}`, 'error');
        return;
    }

    try {
        // Ask user if they want system-level firewall blocking
        const enableFirewall = confirm(
            `Block IP ${ip}?\n\n` +
            `Choose:\n` +
            `  OK = Block in app + ask for firewall\n` +
            `  Cancel = Block in app only\n\n` +
            `⚠️ Firewall blocking requires admin/sudo privileges`
        );

        const response = await fetch(API_ENDPOINTS.block, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                ip,
                firewall: enableFirewall  // Send firewall preference
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP Error: ${response.status}`);
        }

        const result = await response.json();
        
        let message = `✅ IP ${ip} blocked in application`;
        
        // Show firewall status if available
        if (result.firewall_status) {
            if (result.firewall_status.success) {
                message += `\n🔒 ${result.firewall_status.message}`;
                showToast(message, 'success');
            } else {
                message += `\n⚠️ Firewall: ${result.firewall_status.message}`;
                message += `\n(May need admin/sudo privileges)`;
                showToast(message, 'warning');
            }
        } else {
            showToast(message, 'success');
        }
        
        console.log(`Blocking IP: ${ip}`, result);
        
        // Refresh threat table to show updated status
        if (typeof loadRealtimeThreatData === 'function') {
            setTimeout(loadRealtimeThreatData, 500);
        }
    } catch (error) {
        console.error('Block IP error:', error);
        showToast(`Block failed: ${error.message}`, 'error');
    }
}

function showDetails(ip, index) {
    const threat = mockThreats[index];
    const modal = document.getElementById('detailModal');
    const modalBody = document.getElementById('modalBody');
    const modalTitle = modal.querySelector('.modal-header h2');

    if (modalTitle) {
        modalTitle.textContent = 'IP Details';
    }

    modalBody.innerHTML = `
        <div class="modal-detail-row">
            <span class="modal-detail-label">IP Address</span>
            <span class="modal-detail-value"><code>${threat.ip}</code></span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Country</span>
            <span class="modal-detail-value">${threat.flag} ${threat.country}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Threat Score</span>
            <span class="modal-detail-value">${formatScore(threat.score)}/100</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Threat Level</span>
            <span class="modal-detail-value" style="text-transform: uppercase; color: ${getThreatColor(getThreatLevel(threat.score))}">${getThreatLevel(threat.score)}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Attack Type</span>
            <span class="modal-detail-value">${threat.type}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">API Source</span>
            <span class="modal-detail-value">${threat.api}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Last Detected</span>
            <span class="modal-detail-value">${threat.timestamp}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Reputation</span>
            <span class="modal-detail-value">Highly Malicious</span>
        </div>
    `;

    document.getElementById('modalBlockBtn').onclick = () => {
        blockIP(ip);
        modal.classList.add('hidden');
    };

    modal.classList.remove('hidden');
}

function getAlertById(alertId) {
    return alertsData.find(alert => String(alert.id) === String(alertId));
}

function formatAlertDateTime(dateTimeValue) {
    if (!dateTimeValue) {
        return { date: 'Unknown', time: 'Unknown' };
    }

    const parsed = new Date(dateTimeValue);
    if (Number.isNaN(parsed.getTime())) {
        const parts = String(dateTimeValue).split(' ');
        return {
            date: parts[0] || 'Unknown',
            time: parts.slice(1).join(' ') || 'Unknown'
        };
    }

    return {
        date: parsed.toLocaleDateString(),
        time: parsed.toLocaleTimeString()
    };
}

function showAlertDetails(alertId) {
    const alert = getAlertById(alertId);
    if (!alert) {
        showToast('Alert details not found', 'error');
        return;
    }

    const modal = document.getElementById('detailModal');
    const modalBody = document.getElementById('modalBody');
    const modalTitle = modal.querySelector('.modal-header h2');
    const blockBtn = document.getElementById('modalBlockBtn');
    const alertDateTime = formatAlertDateTime(alert.time);
    const attackAttempts = Number(alert.attemptCount) > 0 ? Number(alert.attemptCount) : 1;
    const attackerIp = alert.ip || 'Unknown';

    if (modalTitle) {
        modalTitle.textContent = 'Alert Details';
    }

    modalBody.innerHTML = `
        <div class="modal-detail-row">
            <span class="modal-detail-label">Attacker IP Address</span>
            <span class="modal-detail-value"><code>${attackerIp}</code></span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Date</span>
            <span class="modal-detail-value">${alertDateTime.date}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Time</span>
            <span class="modal-detail-value">${alertDateTime.time}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Type of Attack</span>
            <span class="modal-detail-value">${alert.type || 'Unknown'}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Attack Attempts</span>
            <span class="modal-detail-value">${attackAttempts}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Severity</span>
            <span class="modal-detail-value" style="text-transform: uppercase; color: ${getThreatColor(alert.severity)}">${alert.severity}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Target IP</span>
            <span class="modal-detail-value">${alert.targetIp || 'N/A'}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Description</span>
            <span class="modal-detail-value">${alert.description || 'No description available'}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Log Entry</span>
            <span class="modal-detail-value">${alert.logLine || 'N/A'}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Source</span>
            <span class="modal-detail-value">${alert.source || 'attack_detector'}</span>
        </div>
    `;

    if (isValidIPv4(attackerIp)) {
        blockBtn.disabled = false;
        blockBtn.onclick = () => {
            blockIP(attackerIp);
            modal.classList.add('hidden');
        };
    } else {
        blockBtn.disabled = true;
        blockBtn.onclick = null;
    }

    modal.classList.remove('hidden');
}

function getThreatColor(level) {
    const colors = {
        critical: '#ff4757',
        high: '#ffa502',
        medium: '#ff9f43',
        low: '#2ed573'
    };
    return colors[level] || '#00d4ff';
}

function setupLiveUpdates() {
    const refreshBtn = document.getElementById('refreshBtn');
    const searchInput = document.getElementById('ipSearch');

    refreshBtn.addEventListener('click', () => {
        refreshBtn.style.animation = 'none';
        setTimeout(() => {
            refreshBtn.style.animation = 'spin 1s linear';
            // Simulate new threat data
            const newThreat = {
                ip: generateRandomIP(),
                country: getRandomCountry(),
                flag: getCountryFlag(getRandomCountry()),
                score: Math.floor(Math.random() * 100),
                type: ['Botnet', 'DDoS', 'Malware', 'Phishing'][Math.floor(Math.random() * 4)],
                api: ['AbuseIPDB', 'VirusTotal', 'AlienVault OTX', 'GreyNoise'][Math.floor(Math.random() * 4)],
                timestamp: getRecentTime(0)
            };
            mockThreats.unshift(newThreat);
            if (mockThreats.length > 8) mockThreats.pop();
            populateThreatTable();
            updateKPICards();
        }, 600);
    });

    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const filtered = mockThreats.filter(threat => threat.ip.toLowerCase().includes(query));
        populateThreatTable(filtered);
    });

    // Auto-refresh every 5 seconds
    setInterval(() => {
        if (!document.getElementById('monitoring').classList.contains('active')) return;
        const randomThreat = mockThreats[Math.floor(Math.random() * mockThreats.length)];
        randomThreat.score = Math.floor(Math.random() * 100);
        populateThreatTable();
    }, CONFIG.refreshInterval);
}

// ========== CHARTS INITIALIZATION ==========

let threatTrendChart = null;
let attackTypesChart = null;

function initializeCharts() {
    initializeThreatTrendChart();
    initializeAttackTypesChart();
}

function initializeThreatTrendChart() {
    const ctx = document.getElementById('threatTrendChart').getContext('2d');
    
    if (threatTrendChart) {
        threatTrendChart.destroy();
    }

    threatTrendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '23:59'],
            datasets: [
                {
                    label: 'Critical Threats',
                    data: [12, 19, 8, 15, 22, 18, 25],
                    borderColor: '#ff4757',
                    backgroundColor: 'rgba(255, 71, 87, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'High Severity',
                    data: [25, 32, 28, 35, 30, 28, 32],
                    borderColor: '#ffa502',
                    backgroundColor: 'rgba(255, 165, 2, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Medium Threats',
                    data: [15, 18, 20, 22, 25, 24, 28],
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#e4e8f0',
                        font: { size: 11, weight: 'bold' }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(42, 47, 71, 0.3)', drawBorder: false },
                    ticks: { color: '#a8b3c1' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#a8b3c1' }
                }
            }
        }
    });
}

function initializeAttackTypesChart() {
    const ctx = document.getElementById('attackTypesChart').getContext('2d');
    
    if (attackTypesChart) {
        attackTypesChart.destroy();
    }

    attackTypesChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['DDoS', 'Malware', 'Botnet', 'Phishing', 'Ransomware', 'Brute Force'],
            datasets: [{
                data: [28, 22, 18, 15, 12, 5],
                backgroundColor: [
                    '#ff4757',
                    '#ffa502',
                    '#ff9f43',
                    '#00d4ff',
                    '#2ed573',
                    '#d946ef'
                ],
                borderColor: '#141829',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#e4e8f0',
                        font: { size: 10, weight: 'bold' },
                        padding: 15
                    }
                }
            }
        }
    });
}

// ========== MANUAL SCAN TAB ==========

function initializeManualScan() {
    const scanTypeSelect = document.getElementById('scanType');
    const scanInput = document.getElementById('scanInput');
    const scanNowBtn = document.getElementById('scanNowBtn');
    const clearScanBtn = document.getElementById('clearScanBtn');

    scanTypeSelect.addEventListener('change', () => {
        updateScanPlaceholder();
    });

    scanNowBtn.addEventListener('click', performScan);
    clearScanBtn.addEventListener('click', clearScan);

    updateScanPlaceholder();
}

function updateScanPlaceholder() {
    const scanType = document.getElementById('scanType').value;
    const scanInput = document.getElementById('scanInput');
    
    const placeholders = {
        ip: '192.168.1.1',
        domain: 'example.com',
        hash: 'a1b2c3d4e5f6...'
    };
    
    scanInput.placeholder = placeholders[scanType];
}

async function performScan() {
    const scanInput = document.getElementById('scanInput').value.trim();
    const scanNowBtn = document.getElementById('scanNowBtn');

    if (!scanInput) {
        showToast('Please enter a target IP, domain, or hash', 'error');
        return;
    }

    // Validate input
    const validation = validateInput(scanInput);
    if (!validation.valid) {
        showToast(validation.error, 'error');
        return;
    }

    try {
        // Show loading state
        scanNowBtn.disabled = true;
        const originalText = scanNowBtn.innerHTML;
        scanNowBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        
        showToast('Scanning... This may take up to 30 seconds', 'info');
        document.getElementById('scanResults').classList.remove('hidden');
        document.getElementById('scanTimestamp').textContent = new Date().toLocaleString();

        // Call backend API
        const response = await fetch(API_ENDPOINTS.scan, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: scanInput })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP Error: ${response.status}`);
        }

        const results = await response.json();
        displayScanResults(results);

        // Add scanned IP to global map (keeps previous markers)
        if (validation.type === 'ip') {
            addScanResultToMap(scanInput, results);
        }
        
        // Add to logs table
        await addScanToLogs(scanInput, results);
        
        showToast('Scan completed successfully!', 'success');

    } catch (error) {
        console.error('Scan error:', error);
        showToast(`Scan failed: ${error.message}`, 'error');
        document.getElementById('scanResults').classList.add('hidden');
    } finally {
        // Restore button
        scanNowBtn.disabled = false;
        scanNowBtn.innerHTML = '<i class="fas fa-search"></i> Scan Now';
    }
}

function displayScanResults(results) {
    if (!results.results || results.results.length === 0) {
        showToast('No results received', 'error');
        return;
    }

    // Get overall assessment
    const overall = results.overall || {};
    const threatScore = overall.averageScore || 0;
    const threatLevel = overall.threatLevel || 'UNKNOWN';
    const consensus = overall.consensus || 'UNKNOWN';
    const isMalicious = consensus === 'MALICIOUS' || consensus === 'SUSPICIOUS';

    // Update status badge
    const statusBadge = document.getElementById('resultStatus');
    if (statusBadge) {
        const statusText = consensus === 'MALICIOUS' ? 'MALICIOUS' :
                           consensus === 'SUSPICIOUS' ? 'SUSPICIOUS' :
                           'CLEAN';
        statusBadge.textContent = statusText;
        statusBadge.className = `status-badge ${consensus.toLowerCase()}`;
    }

    // Update threat score
    const scoreElement = document.getElementById('overallThreatScore');
    if (scoreElement) {
        scoreElement.textContent = formatScore(threatScore);
        scoreElement.className = `threat-score-large ${getThreatLevel(threatScore)}`;
    }

    // Update risk level
    const riskElement = document.getElementById('riskLevel');
    if (riskElement) {
        riskElement.textContent = threatLevel;
        riskElement.className = `risk-level ${getThreatLevel(threatScore)}`;
    }

    // Display API details with real data
    displayAPIDetails(results.results);

    // Display reputation analysis
    displayReputationAnalysis(results);
}

function displayAPIDetails(apiResults) {
    const container = document.getElementById('apiDetailsContainer');
    if (!container) return;
    
    container.innerHTML = '';

    if (!apiResults || !Array.isArray(apiResults)) {
        container.innerHTML = '<p style="color: #ff4757;">No API results available</p>';
        return;
    }

    apiResults.forEach(result => {
        const card = document.createElement('div');
        card.className = 'api-card';
        
        if (result.success) {
            const statusClass = result.isMalicious ? 'malicious' : result.isSuspicious ? 'suspicious' : '';
            const statusText = result.isMalicious ? '🔴 MALICIOUS' : result.isSuspicious ? '🟡 SUSPICIOUS' : '🟢 CLEAN';
            
            // Build details list based on API type
            let detailsHTML = '';
            
            if (result.name === 'AbuseIPDB') {
                const reportsValue = Number.isFinite(Number(result.reports)) ? Number(result.reports) : 0;
                detailsHTML = `
                    <li><strong>Score:</strong> ${result.score}/100</li>
                    <li><strong>Reports (90d):</strong> ${reportsValue}</li>
                    <li><strong>ISP:</strong> ${result.isp}</li>
                    <li><strong>Country:</strong> ${result.country || 'Unknown'}</li>
                    <li><strong>Last Reported:</strong> ${result.lastReportedAt}</li>
                `;
            } else if (result.name === 'VirusTotal') {
                detailsHTML = `
                    <li><strong>Score:</strong> ${result.score}/100</li>
                    <li><strong>Malicious:</strong> ${result.maliciousVendors}/${result.totalVendors}</li>
                    <li><strong>Suspicious:</strong> ${result.suspiciousVendors}</li>
                    <li><strong>ASN:</strong> ${result.asn}</li>
                    <li><strong>Country:</strong> ${result.country}</li>
                `;
            } else if (result.name === 'AlienVault OTX') {
                detailsHTML = `
                    <li><strong>Score:</strong> ${result.score}/100</li>
                    <li><strong>Reputation:</strong> ${result.reputation}</li>
                    <li><strong>Pulses:</strong> ${result.pulseCount}</li>
                    <li><strong>Country:</strong> ${result.country}</li>
                    <li><strong>Whitelisted:</strong> ${result.whitelisted ? 'Yes' : 'No'}</li>
                `;
            } else if (result.name === 'GreyNoise') {
                const tags = (result.tags && result.tags.length > 0) ? result.tags.join(', ') : 'N/A';
                detailsHTML = `
                    <li><strong>Score:</strong> ${result.score}/100</li>
                    <li><strong>Classification:</strong> ${result.classification}</li>
                    <li><strong>Tags:</strong> ${tags}</li>
                    <li><strong>Country:</strong> ${result.country || 'Unknown'}</li>
                    <li><strong>First Seen:</strong> ${result.firstSeen}</li>
                    <li><strong>Last Seen:</strong> ${result.lastSeen}</li>
                `;
            } else if (result.name === 'IPQualityScore') {
                // Display important free-tier results
                const imp = result.important_results || {};
                const fraudSeverity = imp.fraud_severity || 'Unknown';
                const proxyStat = imp.proxy_status ? 'Yes' : 'No';
                const vpnStat = imp.vpn_status ? 'Yes' : 'No';
                const torStat = imp.tor_status ? 'Yes' : 'No';
                const botStat = imp.bot_activity ? 'Yes' : 'No';
                const abuseVal = imp.recent_abuse ? 'Yes' : 'No';
                
                detailsHTML = `
                    <li><strong>Fraud Score:</strong> ${imp.fraud_score}/100</li>
                    <li><strong>Severity:</strong> ${fraudSeverity}</li>
                    <li><strong>Proxy:</strong> ${proxyStat}</li>
                    <li><strong>VPN:</strong> ${vpnStat}</li>
                    <li><strong>TOR:</strong> ${torStat}</li>
                    <li><strong>Bot Activity:</strong> ${botStat}</li>
                    <li><strong>Recent Abuse:</strong> ${abuseVal}</li>
                    <li><strong>Location:</strong> ${imp.city}, ${imp.region}, ${imp.country}</li>
                    <li><strong>ISP:</strong> ${imp.isp}</li>
                    <li><strong>ASN:</strong> ${imp.asn}</li>
                `;
            }
            
            card.innerHTML = `
                <div class="api-card-header">
                    <span class="api-name">${result.name}</span>
                    <span class="api-status ${statusClass}">${statusText}</span>
                </div>
                <ul class="api-details-list">
                    ${detailsHTML}
                </ul>
            `;
        } else {
            // API failed
            card.innerHTML = `
                <div class="api-card-header">
                    <span class="api-name">${result.name}</span>
                    <span class="api-status error">❌ ERROR</span>
                </div>
                <p style="color: #ff4757; font-size: 0.9rem; margin: 1rem;">
                    ${result.error || 'API call failed'}
                </p>
            `;
        }
        container.appendChild(card);
    });
}

function displayReputationAnalysis(scanResults) {
    const container = document.getElementById('reputationContainer');
    if (!container) return;
    
    const overall = scanResults.overall || {};
    const consensus = overall.consensus || 'UNKNOWN';
    const maliciousAPIs = overall.maliciousAPIs || 0;
    const totalAPIs = overall.totalAPIs || 0;
    const averageScore = overall.averageScore || 0;
    
    const overallReputation = consensus === 'MALICIOUS' ? '🔴 Highly Suspicious' :
                              consensus === 'SUSPICIOUS' ? '🟡 Potentially Malicious' :
                              '🟢 Good Standing';
    
    const abuseHistory = maliciousAPIs > 0 ? `${maliciousAPIs}/${totalAPIs} APIs detected malicious activity` :
                         'No abuse history detected';
    
    const blacklistStatus = consensus === 'MALICIOUS' ? `Listed by ${maliciousAPIs} threat intelligence APIs` :
                           consensus === 'SUSPICIOUS' ? 'Listed by some threat intelligence services' :
                           'Not listed on major threat databases';
    
    const threatCategory = maliciousAPIs >= totalAPIs / 2 ? 'High-Risk Threat' :
                          maliciousAPIs > 0 ? 'Suspicious/Potentially Malicious' :
                          'Legitimate/Safe';
    container.innerHTML = `
        <div class="reputation-item">
            <div class="reputation-label">Overall Reputation</div>
            <div class="reputation-value">${overallReputation}</div>
        </div>
        <div class="reputation-item">
            <div class="reputation-label">API Consensus</div>
            <div class="reputation-value">${consensus} (${maliciousAPIs}/${totalAPIs} APIs)</div>
        </div>
        <div class="reputation-item">
            <div class="reputation-label">Average Threat Score</div>
            <div class="reputation-value">${averageScore}/100</div>
        </div>
        <div class="reputation-item">
            <div class="reputation-label">Threat Classification</div>
            <div class="reputation-value">${threatCategory}</div>
        </div>
    `;
}

function clearScan() {
    document.getElementById('scanType').value = 'ip';
    document.getElementById('scanInput').value = '';
    document.getElementById('scanResults').classList.add('hidden');
    updateScanPlaceholder();
}

// ========== GLOBAL MAP TAB ==========

let mapInstance = null;
const mapMarkers = [];
const MAP_STORAGE_KEY = 'scannedThreatLocations';
const scannedThreatLocations = [];

const countryCoordinates = {
    'china': { lat: 35.8617, lng: 104.1954 },
    'russia': { lat: 61.5240, lng: 105.3188 },
    'north korea': { lat: 40.3399, lng: 127.5101 },
    'iran': { lat: 32.4279, lng: 53.6880 },
    'brazil': { lat: -14.2350, lng: -51.9253 },
    'india': { lat: 20.5937, lng: 78.9629 },
    'vietnam': { lat: 14.0583, lng: 108.2772 },
    'ukraine': { lat: 48.3794, lng: 31.1656 },
    'united states': { lat: 37.0902, lng: -95.7129 },
    'usa': { lat: 37.0902, lng: -95.7129 },
    'us': { lat: 37.0902, lng: -95.7129 },
    'united kingdom': { lat: 55.3781, lng: -3.4360 },
    'uk': { lat: 55.3781, lng: -3.4360 },
    'germany': { lat: 51.1657, lng: 10.4515 },
    'france': { lat: 46.2276, lng: 2.2137 },
    'canada': { lat: 56.1304, lng: -106.3468 },
    'australia': { lat: -25.2744, lng: 133.7751 },
    'japan': { lat: 36.2048, lng: 138.2529 },
    'south korea': { lat: 35.9078, lng: 127.7669 },
    'pakistan': { lat: 30.3753, lng: 69.3451 },
    'nigeria': { lat: 9.0820, lng: 8.6753 },
    'netherlands': { lat: 52.1326, lng: 5.2913 },
    'singapore': { lat: 1.3521, lng: 103.8198 },
    'turkey': { lat: 38.9637, lng: 35.2433 },
    'spain': { lat: 40.4637, lng: -3.7492 },
    'italy': { lat: 41.8719, lng: 12.5674 },
    'mexico': { lat: 23.6345, lng: -102.5528 },
    'indonesia': { lat: -0.7893, lng: 113.9213 }
};

function getMapThreatColor(level) {
    if (level === 'critical' || level === 'high') return '#ff4757'; // red
    if (level === 'medium') return '#f1c40f'; // yellow
    return '#2ed573'; // green
}

function getCountryCoordinates(country) {
    const key = (country || '').toLowerCase().trim();
    return countryCoordinates[key] || null;
}

function extractCountryFromApiResults(apiResults) {
    if (!Array.isArray(apiResults)) return 'Unknown';
    for (const result of apiResults) {
        if (result && result.country && result.country !== 'Unknown') {
            return result.country;
        }
    }
    return 'Unknown';
}

function renderThreatMarker(location) {
    if (!mapInstance) return;

    const level = getThreatLevel(location.score);
    const marker = L.circleMarker([location.lat, location.lng], {
        radius: 5, // smaller circle
        fillColor: getMapThreatColor(level),
        color: '#ffffff',
        weight: 1.5,
        opacity: 1,
        fillOpacity: 0.85
    }).addTo(mapInstance);

    marker.bindPopup(`
        <div style="color: #e4e8f0; background: #141829; padding: 8px; border-radius: 4px;">
            <strong>${location.country}</strong><br>
            IP: ${location.ip}<br>
            Score: ${formatScore(location.score)}/100<br>
            Threat: ${level.toUpperCase()}<br>
            ${location.timestamp ? `Scanned: ${location.timestamp}<br>` : ''}
            ${location.source ? `Source: ${location.source}` : ''}
        </div>
    `);

    mapMarkers.push(marker);
}

function updateMapStats() {
    const allLocations = [...scannedThreatLocations];
    const uniqueCountries = new Set(allLocations.map(loc => loc.country));
    const avgScore = allLocations.length
        ? Math.round(allLocations.reduce((sum, loc) => sum + (loc.score || 0), 0) / allLocations.length)
        : 0;

    const countriesCount = document.getElementById('countriesCount');
    const sourcesCount = document.getElementById('sourcesCount');
    const avgThreatScore = document.getElementById('avgThreatScore');

    if (countriesCount) countriesCount.textContent = uniqueCountries.size;
    if (sourcesCount) sourcesCount.textContent = allLocations.length;
    if (avgThreatScore) avgThreatScore.textContent = avgScore;
}

function saveScannedMapLocations() {
    try {
        localStorage.setItem(MAP_STORAGE_KEY, JSON.stringify(scannedThreatLocations));
    } catch (error) {
        console.error('Failed to save scanned map locations:', error);
    }
}

function loadScannedMapLocations() {
    try {
        const raw = localStorage.getItem(MAP_STORAGE_KEY);
        if (!raw) return;
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return;

        scannedThreatLocations.length = 0;
        parsed.forEach(location => {
            if (
                location &&
                typeof location.lat === 'number' &&
                typeof location.lng === 'number' &&
                typeof location.ip === 'string'
            ) {
                scannedThreatLocations.push(location);
            }
        });
    } catch (error) {
        console.error('Failed to load scanned map locations:', error);
    }
}

function addScanResultToMap(ip, scanResponse) {
    const apiResults = scanResponse?.results || [];
    const overallScore = scanResponse?.overall?.averageScore ?? 0;
    const geo = scanResponse?.geo || null;
    const rawCountry = geo?.country || extractCountryFromApiResults(apiResults);
    const countryInfo = normalizeCountryInfo(rawCountry);
    const coords = (geo && Number.isFinite(geo.lat) && Number.isFinite(geo.lon))
        ? { lat: geo.lat, lng: geo.lon }
        : getCountryCoordinates(countryInfo.country);

    if (!coords) {
        showToast(`No map coordinates available for ${countryInfo.country}`, 'info');
        return;
    }

    const location = {
        lat: coords.lat,
        lng: coords.lng,
        country: countryInfo.country,
        ip,
        score: overallScore,
        source: 'Manual Scan',
        timestamp: new Date().toLocaleString()
    };

    scannedThreatLocations.push(location);
    saveScannedMapLocations();

    if (mapInstance) {
        renderThreatMarker(location);
        updateMapStats();
    }
}

function initializeMap() {
    if (mapInstance) return;

    loadScannedMapLocations();

    const mapContainer = document.getElementById('worldMap');
    mapContainer.innerHTML = ''; // Clear previous map

    // Initialize Leaflet map
    mapInstance = L.map('worldMap').setView([20, 0], 2);

    // Add map tiles
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 19
    }).addTo(mapInstance);

    // Render only scanned markers (keep previous scanned entries)
    [...scannedThreatLocations].forEach(renderThreatMarker);
    updateMapStats();

    // Setup map controls
    document.getElementById('toggleHeatmap').addEventListener('click', () => {
        showToast('Heatmap view toggled', 'success');
    });

    document.getElementById('resetMapView').addEventListener('click', () => {
        mapInstance.setView([20, 0], 2);
        showToast('Map view reset', 'success');
    });
}

// ========== ALERTS TAB ==========

function initializeAlerts() {
    const filterBtns = document.querySelectorAll('.filter-btn');
    let currentFilter = 'all';

    filterBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            filterBtns.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentFilter = e.target.getAttribute('data-filter');
            displayAlerts(currentFilter);
        });
    });

    displayAlerts('all');
    loadAlertsFromBackend(currentFilter);

    if (!alertsRefreshTimer) {
        alertsRefreshTimer = setInterval(() => {
            loadAlertsFromBackend(currentFilter, false);
        }, 10000);
    }
}

function displayAlerts(filter = 'all') {
    const container = document.getElementById('alertsContainer');
    container.innerHTML = '';
    const criticalCount = alertsData.filter(a => a.severity === 'critical').length;

    const banner = document.getElementById('criticalBanner');
    if (banner) {
        banner.classList.toggle('hidden', criticalCount === 0);
    }

    const bannerMessage = document.getElementById('bannerMessage');
    if (bannerMessage) {
        bannerMessage.textContent = criticalCount > 0
            ? `${criticalCount} critical real-time threat${criticalCount === 1 ? '' : 's'} detected`
            : 'Multiple high-severity attacks in progress';
    }

    const badge = document.getElementById('alert-badge');
    if (badge) {
        badge.textContent = String(alertsData.length);
        badge.style.display = alertsData.length ? 'inline-flex' : 'none';
    }

    const criticalBadge = document.getElementById('critical-badge');
    if (criticalBadge) {
        criticalBadge.textContent = String(criticalCount);
        criticalBadge.style.display = criticalCount ? 'inline-flex' : 'none';
    }

    const filtered = filter === 'all' ? alertsData : alertsData.filter(a => a.severity === filter);

    filtered.forEach(alert => {
        const card = document.createElement('div');
        card.className = `alert-card ${alert.severity}`;
        card.innerHTML = `
            <div class="alert-card-header">
                <span class="alert-type">${alert.type}</span>
                <span class="alert-severity ${alert.severity}">${alert.severity}</span>
            </div>
            <div class="alert-details">
                <div class="alert-detail-row">
                    <label>IP Address</label>
                    <value><code>${alert.ip}</code></value>
                </div>
                <div class="alert-detail-row">
                    <label>Description</label>
                    <value>${alert.description}</value>
                </div>
            </div>
            <div class="alert-time">
                <i class="fas fa-clock"></i> Detected at ${alert.time}
            </div>
            <div class="alert-actions-row">
                <button class="btn-action btn-details" onclick="showAlertDetails('${alert.id}')">
                    <i class="fas fa-expand"></i> Details
                </button>
                <button class="btn-action btn-block" onclick="blockIP('${alert.ip}')">
                    <i class="fas fa-ban"></i> Block
                </button>
            </div>
        `;
        container.appendChild(card);
    });

    if (filtered.length === 0) {
        container.innerHTML = '<p style="grid-column: 1/-1; text-align: center; color: var(--text-secondary); padding: 2rem;">No alerts found</p>';
    }

    updateKPICards();
}

function normalizeAlert(alert) {
    return {
        id: String(alert?.id || `alert-${Date.now()}`),
        type: alert?.type || alert?.alert_type || 'Threat Alert',
        ip: alert?.ip || alert?.ip_address || 'Unknown',
        severity: (alert?.severity || 'medium').toLowerCase(),
        time: alert?.time || alert?.created_at || new Date().toLocaleString(),
        description: alert?.description || alert?.logLine || 'No description available',
        attemptCount: Number(alert?.attemptCount || alert?.attempt_count || 1) || 1,
        targetIp: alert?.targetIp || alert?.target_ip || '',
        logLine: alert?.logLine || alert?.log_line || '',
        source: alert?.source || 'attack_detector'
    };
}

async function loadAlertsFromBackend(filter = 'all', notifyOnError = true) {
    try {
        const response = await fetch(`${API_ENDPOINTS.alerts}?limit=100`);
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const payload = await response.json();
        const nextAlerts = Array.isArray(payload.alerts)
            ? payload.alerts.map(normalizeAlert)
            : [];
        const nextAlertIds = new Set(nextAlerts.map(alert => String(alert.id)));

        nextAlerts.forEach(alert => {
            const alertId = String(alert.id);
            if (knownAlertIds.size > 0 && !knownAlertIds.has(alertId)) {
                showRealtimeAlertPopup(alert);
            }
        });

        alertsData = nextAlerts;
        knownAlertIds = nextAlertIds;
        displayAlerts(filter);
    } catch (error) {
        console.error('Failed to load alerts:', error);
        alertsData = [];
        knownAlertIds = new Set();
        displayAlerts(filter);
        if (notifyOnError) {
            showToast(`Failed to load alerts: ${error.message}`, 'error');
        }
    }
}

async function clearAllAlerts() {
    const hasAlerts = alertsData.length > 0;
    if (!hasAlerts) {
        showToast('No alerts to clear', 'info');
        return;
    }

    const confirmed = confirm('Clear all stored real-time alerts?');
    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch(API_ENDPOINTS.alerts, { method: 'DELETE' });
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        alertsData = [];
        knownAlertIds = new Set();
        displayAlerts('all');
        showToast('All alerts cleared', 'success');
    } catch (error) {
        console.error('Failed to clear alerts:', error);
        showToast(`Failed to clear alerts: ${error.message}`, 'error');
    }
}

// ========== THREAT LOGS TAB ==========

const logsPageSize = 10;
let currentLogsPage = 1;
let expandedLogId = null;
const LOGS_STORAGE_KEY = 'threatLogsDataV1';

function initializeThreatLogs() {
    loadThreatLogsFromBackend();
    displayLogsTable();
    setupLogsControls();
}

function normalizeStoredLog(log, index = 0) {
    const ts = Number(log?.timestamp) || Date.parse(log?.date) || (Date.now() - index * 60000);
    return {
        id: log?.id || `log-${ts}-${index}`,
        ip: log?.ip || 'Unknown',
        country: log?.country || 'Unknown',
        flag: log?.flag || getCountryFlag(log?.country || ''),
        score: Number(log?.score) || 0,
        api: log?.api || 'N/A',
        date: new Date(ts).toLocaleString(),
        timestamp: ts,
        status: (log?.status || 'monitored').toLowerCase(),
        scanResults: Array.isArray(log?.scanResults) ? log.scanResults : []
    };
}

async function loadThreatLogsFromBackend(notifyOnError = true) {
    try {
        const response = await fetch(`${API_ENDPOINTS.threatLogs}?limit=500`);
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const payload = await response.json();
        const parsed = Array.isArray(payload.logs) ? payload.logs : [];

        mockLogsData.length = 0;
        parsed.forEach((log, idx) => mockLogsData.push(normalizeStoredLog(log, idx)));
        mockLogsData.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        displayLogsTable();
    } catch (error) {
        console.error('Failed to load threat logs:', error);
        mockLogsData.length = 0;
        displayLogsTable();
        if (notifyOnError) {
            showToast(`Failed to load threat logs: ${error.message}`, 'error');
        }
    }
}

function setupLogsControls() {
    const searchInput = document.getElementById('logsSearch');
    const filterSelect = document.getElementById('logsFilter');
    const sortSelect = document.getElementById('logsSort');

    searchInput.addEventListener('input', () => {
        currentLogsPage = 1;
        displayLogsTable();
    });
    filterSelect.addEventListener('change', () => {
        currentLogsPage = 1;
        displayLogsTable();
    });
    sortSelect.addEventListener('change', () => {
        currentLogsPage = 1;
        displayLogsTable();
    });

    document.getElementById('prevPage').addEventListener('click', () => {
        if (currentLogsPage > 1) {
            currentLogsPage--;
            displayLogsTable();
        }
    });

    document.getElementById('nextPage').addEventListener('click', () => {
        const maxPage = Math.max(1, Math.ceil(getFilteredLogs().length / logsPageSize));
        if (currentLogsPage < maxPage) {
            currentLogsPage++;
            displayLogsTable();
        }
    });
}

function getFilteredLogs() {
    const search = document.getElementById('logsSearch').value.toLowerCase();
    const filter = document.getElementById('logsFilter').value;
    const sort = document.getElementById('logsSort').value;

    let filtered = mockLogsData.filter(log => {
        const matchesSearch = (log.ip || '').toLowerCase().includes(search) ||
            (log.country || '').toLowerCase().includes(search) ||
            (log.api || '').toLowerCase().includes(search);
        const matchesFilter = !filter || (log.status || '').toLowerCase() === filter;
        return matchesSearch && matchesFilter;
    });

    filtered.sort((a, b) => {
        const aTs = Number(a.timestamp) || Date.parse(a.date) || 0;
        const bTs = Number(b.timestamp) || Date.parse(b.date) || 0;
        switch (sort) {
            case 'date-asc':
                return aTs - bTs;
            case 'score-desc':
                return b.score - a.score;
            case 'score-asc':
                return a.score - b.score;
            case 'date-desc':
            default:
                return bTs - aTs;
        }
    });

    return filtered;
}

function displayLogsTable() {
    const filtered = getFilteredLogs();
    const maxPage = Math.max(1, Math.ceil(filtered.length / logsPageSize));
    if (currentLogsPage > maxPage) currentLogsPage = maxPage;

    const start = (currentLogsPage - 1) * logsPageSize;
    const end = start + logsPageSize;
    const paginatedLogs = filtered.slice(start, end);

    const tbody = document.getElementById('logsTableBody');
    tbody.innerHTML = '';

    if (paginatedLogs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 1rem;">No logs found</td></tr>';
    }

    paginatedLogs.forEach(log => {
        const threatLevel = getThreatLevel(log.score);
        const isExpanded = expandedLogId === log.id;

        const row = document.createElement('tr');
        row.innerHTML = `
            <td><code>${log.ip}</code></td>
            <td>
                <span class="country-cell">
                    <span class="flag">${log.flag}</span>${log.country}
                </span>
            </td>
            <td><span class="threat-score-badge ${threatLevel}">${formatScore(log.score)}</span></td>
            <td>${log.api}</td>
            <td>${log.date}</td>
            <td><span class="status-badge-log ${(log.status || '').toLowerCase()}">${formatLogStatus(log.status)}</span></td>
            <td>
                <button class="btn-action btn-details ${isExpanded ? 'active' : ''}" onclick="expandLogDetail('${log.id}')">
                    <i class="fas ${isExpanded ? 'fa-chevron-up' : 'fa-chevron-down'}"></i>
                </button>
            </td>
        `;
        tbody.appendChild(row);

        if (isExpanded) {
            const detailRow = document.createElement('tr');
            detailRow.className = 'log-detail-row';
            detailRow.innerHTML = `<td colspan="7">${buildLogDetailsContent(log)}</td>`;
            tbody.appendChild(detailRow);
        }
    });

    document.getElementById('pageNumber').textContent = `Page ${currentLogsPage} of ${maxPage}`;
    document.getElementById('prevPage').disabled = currentLogsPage === 1;
    document.getElementById('nextPage').disabled = currentLogsPage === maxPage;
}

function formatLogStatus(status) {
    const normalized = (status || '').toLowerCase();
    if (!normalized) return 'Unknown';
    return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function countryCodeToName(code) {
    if (!code || !/^[A-Z]{2}$/.test(code)) return null;
    try {
        if (typeof Intl !== 'undefined' && typeof Intl.DisplayNames === 'function') {
            const names = new Intl.DisplayNames(['en'], { type: 'region' });
            return names.of(code) || code;
        }
    } catch (e) {
        console.warn('Country code conversion failed:', e);
    }
    return code;
}

function countryCodeToFlag(code) {
    if (!code || !/^[A-Z]{2}$/.test(code)) return '??';
    return String.fromCodePoint(...code.split('').map(c => c.charCodeAt(0) + 127397));
}

function normalizeCountryInfo(rawCountry) {
    if (!rawCountry || rawCountry === 'Unknown') {
        return { country: 'Unknown', flag: '??' };
    }

    const value = String(rawCountry).trim();
    const upper = value.toUpperCase();
    if (/^[A-Z]{2}$/.test(upper)) {
        return {
            country: countryCodeToName(upper) || upper,
            flag: countryCodeToFlag(upper)
        };
    }

    return {
        country: value,
        flag: getCountryFlag(value)
    };
}

function resolveCountryFromResults(results) {
    for (const result of results) {
        if (result && result.country && result.country !== 'Unknown') {
            return normalizeCountryInfo(result.country);
        }
    }
    return { country: 'Unknown', flag: '??' };
}

async function addScanToLogs(target, scanResponse) {
    expandedLogId = null;
    currentLogsPage = 1;
    await loadThreatLogsFromBackend(false);
}

function buildLogDetailsContent(log) {
    const threatLevel = getThreatLevel(log.score);
    const resultCards = (log.scanResults && log.scanResults.length > 0)
        ? log.scanResults.map(result => {
            const status = result.success ? (result.isMalicious ? 'Malicious' : 'Clean') : 'Error';
            return `
                <div style="border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 10px;">
                    <div style="display:flex; justify-content:space-between; gap:8px;">
                        <strong>${result.name || 'API'}</strong>
                        <span>${status}</span>
                    </div>
                    <div style="margin-top:6px; font-size:0.9rem; color:#c7d0e0;">
                        Score: ${result.score ?? 0}/100
                        ${result.country ? `<br>Country: ${normalizeCountryInfo(result.country).country}` : ''}
                        ${result.error ? `<br>Error: ${result.error}` : ''}
                    </div>
                </div>
            `;
        }).join('')
        : '<div style="color:#c7d0e0;">No API detail available for this entry.</div>';

    return `
        <div style="padding: 12px; background: rgba(0,0,0,0.2); border-radius: 8px;">
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-bottom: 10px;">
                <div><strong>IP/Target:</strong> <code>${log.ip}</code></div>
                <div><strong>Country:</strong> ${log.flag} ${log.country}</div>
                <div><strong>Threat:</strong> <span class="threat-score-badge ${threatLevel}">${formatScore(log.score)}</span></div>
                <div><strong>Status:</strong> ${formatLogStatus(log.status)}</div>
            </div>
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px;">
                ${resultCards}
            </div>
        </div>
    `;
}

function expandLogDetail(logId) {
    expandedLogId = (expandedLogId === logId) ? null : logId;
    displayLogsTable();
}

// ========== INITIALIZATION ==========

document.addEventListener('DOMContentLoaded', () => {
    initializeTabNavigation();
    initializeMonitoring();
    initializeManualScan();
    initializeAlerts();
    initializeThreatLogs();

    // Display charts once page loads
    setTimeout(() => {
        const chartsContainer = document.querySelector('.charts-row');
        if (chartsContainer && !threatTrendChart) {
            initializeCharts();
        }
    }, 100);

    console.log('Threat Intelligence Dashboard initialized successfully');
});

// ========== PLACEHOLDER API HOOKS ==========
// Note: All API calls now go through the backend proxy at /api/scan
// This ensures proper CORS handling, rate limiting, and caching

const API_HOOKS = {
    /**
     * All API queries are now handled by the backend
     * The frontend sends requests to /api/scan which proxies to all 4 APIs
     * This provides:
     * - CORS protection (APIs can't access frontend directly)
     * - API key security (keys stored on backend)
     * - Rate limiting (server-side protection)
     * - Caching (reduce repeated API calls)
     * - Error handling (consistent error messages)
     */
    
    // Backend handles all scanning through POST /api/scan
    scanWithBackend: async (target) => {
        try {
            const response = await fetch(API_ENDPOINTS.scan, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ target })
            });
            
            if (!response.ok) {
                throw new Error(`Backend error: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('Backend scan error:', error);
            return { success: false, error: error.message };
        }
    }
};

// Export for use in external scripts if needed
window.THREAT_DASHBOARD = {
    config: CONFIG,
    apiHooks: API_HOOKS,
    utils: {
        getThreatLevel,
        formatScore,
        showToast,
        blockIP,
        validateInput,
        isValidIPv4,
        isValidDomain,
        isValidHash
    },
    backend: {
        url: BACKEND_URL,
        endpoints: API_ENDPOINTS
    }
};
