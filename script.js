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
    alertStats: `${BACKEND_URL}/api/alert-stats`,
    threatLogs: `${BACKEND_URL}/api/threat-logs`,
    edrDashboard: `${BACKEND_URL}/api/edr/dashboard`,
    edrResponse: `${BACKEND_URL}/api/edr/respond`
};

// ========== INPUT VALIDATION FUNCTIONS ==========

function isValidIPv4(ip) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(ip)) return false;
    return ip.split('.').every(num => parseInt(num) <= 255);
}

function isPublicIPv4(ip) {
    if (!isValidIPv4(ip)) return false;
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;

    return !(
        a === 0 ||
        a === 10 ||
        a === 127 ||
        a >= 224 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 192 && b === 0 && parts[2] === 0) ||
        (a === 192 && b === 0 && parts[2] === 2) ||
        (a === 198 && (b === 18 || b === 19)) ||
        (a === 198 && b === 51 && parts[2] === 100) ||
        (a === 203 && b === 0 && parts[2] === 113)
    );
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
    threatScoreThresholds: {
        critical: 80,
        high: 60,
        medium: 40,
        low: 0
    }
};

// ========== MOCK DATA ==========

const mockThreats = [
    { ip: '8.8.8.8', country: 'United States', flag: '[US]', score: 95, type: 'Botnet', api: 'AbuseIPDB', timestamp: getRecentTime(2) },
    { ip: '1.1.1.1', country: 'Australia', flag: '[AU]', score: 87, type: 'DDoS Attack', api: 'GreyNoise', timestamp: getRecentTime(5) },
    { ip: '45.33.32.156', country: 'United States', flag: '[US]', score: 92, type: 'Trojan', api: 'VirusTotal', timestamp: getRecentTime(8) },
    { ip: '91.198.174.192', country: 'Netherlands', flag: '[NL]', score: 78, type: 'Malware', api: 'AlienVault OTX', timestamp: getRecentTime(12) },
    { ip: '151.101.1.69', country: 'United States', flag: '[US]', score: 65, type: 'Phishing', api: 'AbuseIPDB', timestamp: getRecentTime(15) },
    { ip: '9.9.9.9', country: 'United States', flag: '[US]', score: 73, type: 'Ransomware', api: 'GreyNoise', timestamp: getRecentTime(18) },
    { ip: '208.67.222.222', country: 'United States', flag: '[US]', score: 81, type: 'Brute Force', api: 'VirusTotal', timestamp: getRecentTime(22) },
    { ip: '185.199.108.153', country: 'United States', flag: '[US]', score: 72, type: 'SQL Injection', api: 'AbuseIPDB', timestamp: getRecentTime(25) }
];

const fallbackAlerts = [
    { type: 'Critical DDoS Detected', ip: '8.8.8.8', severity: 'critical', time: getRecentTime(2), description: 'Massive DDoS attack from coordinated botnets' },
    { type: 'Malware Distribution', ip: '1.1.1.1', severity: 'high', time: getRecentTime(8), description: 'Known malware hosting detected' },
    { type: 'Brute Force Attack', ip: '45.33.32.156', severity: 'medium', time: getRecentTime(15), description: 'Multiple failed login attempts detected' },
    { type: 'Ransomware Activity', ip: '91.198.174.192', severity: 'critical', time: getRecentTime(5), description: 'Ransomware encryption behavior detected' },
    { type: 'Suspicious API Access', ip: '151.101.1.69', severity: 'medium', time: getRecentTime(20), description: 'Unusual API access pattern from this IP' },
    { type: 'Data Exfiltration', ip: '185.199.108.153', severity: 'high', time: getRecentTime(12), description: 'Unusual data transfer volume detected' }
];

function createEmptyEDRDashboard() {
    return {
        summary: {
            totalEndpoints: 0,
            onlineEndpoints: 0,
            offlineEndpoints: 0,
            openAlerts: 0,
            criticalAlerts: 0,
            eventsToday: 0,
            responses: 0
        },
        endpoints: [],
        events: [],
        alerts: [],
        responses: [],
        heartbeatTimeoutSeconds: EDR_DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
        coverage: []
    };
}

const SHOWN_ALERTS_STORAGE_KEY = 'shownRealtimeAlertIds';
const mockLogsData = [];
const EDR_DASHBOARD_REFRESH_MS = 5000;
const EDR_DASHBOARD_REQUEST_TIMEOUT_MS = 7000;
const EDR_DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 20;
let alertsData = [...fallbackAlerts];
let alertsRefreshTimer = null;
let edrRefreshTimer = null;
let knownAlertIds = new Set();
let shownAlertIds = loadShownAlertIds();
let hasBootstrappedBackendAlerts = false;
let currentAlertFilter = 'all';
let edrDashboardData = createEmptyEDRDashboard();
let isLoadingEDRDashboard = false;

function loadShownAlertIds() {
    try {
        const stored = JSON.parse(localStorage.getItem(SHOWN_ALERTS_STORAGE_KEY) || '[]');
        if (!Array.isArray(stored)) {
            return new Set();
        }
        return new Set(stored.map(id => String(id)));
    } catch (error) {
        console.warn('Failed to load shown alert IDs:', error);
        return new Set();
    }
}

function saveShownAlertIds() {
    try {
        const maxStoredIds = 500;
        const idsToStore = Array.from(shownAlertIds).slice(-maxStoredIds);
        localStorage.setItem(SHOWN_ALERTS_STORAGE_KEY, JSON.stringify(idsToStore));
    } catch (error) {
        console.warn('Failed to persist shown alert IDs:', error);
    }
}

function getSeverityRank(severity) {
    const severityOrder = {
        low: 0,
        medium: 1,
        high: 2,
        critical: 3
    };
    return severityOrder[String(severity || '').toLowerCase()] ?? -1;
}

function shouldShowGroupedAlertPopup(nextAlert, previousAlert) {
    if (!previousAlert) {
        return false;
    }

    const nextAttempts = Number(nextAlert.attemptCount) || 1;
    const previousAttempts = Number(previousAlert.attemptCount) || 1;
    const severityIncreased = getSeverityRank(nextAlert.severity) > getSeverityRank(previousAlert.severity);
    const attemptsIncreased = nextAttempts > previousAttempts;

    return severityIncreased || attemptsIncreased;
}

function escapeCsvValue(value) {
    const text = String(value ?? '');
    return `"${text.replace(/"/g, '""')}"`;
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function downloadTextFile(filename, content, type = 'text/plain;charset=utf-8') {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}

function exportRowsToCsv(filename, headers, rows) {
    if (!rows.length) {
        showToast('No data to export', 'info');
        return;
    }

    const headerLine = headers.map(header => escapeCsvValue(header.label)).join(',');
    const bodyLines = rows.map(row => headers
        .map(header => escapeCsvValue(typeof header.value === 'function' ? header.value(row) : row[header.value]))
        .join(',')
    );
    downloadTextFile(filename, [headerLine, ...bodyLines].join('\n'), 'text/csv;charset=utf-8');
    showToast('CSV export downloaded', 'success');
}

function exportRowsToPdf(title, headers, rows) {
    if (!rows.length) {
        showToast('No data to export', 'info');
        return;
    }

    const printable = window.open('', '_blank');
    if (!printable) {
        showToast('Allow popups to export PDF', 'error');
        return;
    }

    const tableRows = rows.map(row => `
        <tr>${headers.map(header => `<td>${escapeHtml(typeof header.value === 'function' ? header.value(row) : row[header.value])}</td>`).join('')}</tr>
    `).join('');

    printable.document.write(`
        <!doctype html>
        <html>
        <head>
            <title>${escapeHtml(title)}</title>
            <style>
                body { font-family: Arial, sans-serif; color: #111827; padding: 24px; }
                h1 { font-size: 20px; margin-bottom: 4px; }
                p { color: #4b5563; margin-top: 0; }
                table { width: 100%; border-collapse: collapse; font-size: 12px; }
                th, td { border: 1px solid #d1d5db; padding: 8px; text-align: left; vertical-align: top; }
                th { background: #f3f4f6; }
            </style>
        </head>
        <body>
            <h1>${escapeHtml(title)}</h1>
            <p>Exported ${new Date().toLocaleString()}</p>
            <table>
                <thead><tr>${headers.map(header => `<th>${escapeHtml(header.label)}</th>`).join('')}</tr></thead>
                <tbody>${tableRows}</tbody>
            </table>
        </body>
        </html>
    `);
    printable.document.close();
    printable.focus();
    printable.print();
}

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

function getCountryBadge(country) {
    const badges = {
        'China': '[CN]',
        'Russia': '[RU]',
        'North Korea': '[KP]',
        'Iran': '[IR]',
        'Brazil': '[BR]',
        'India': '[IN]',
        'Vietnam': '[VN]',
        'Ukraine': '[UA]',
        'Pakistan': '[PK]',
        'Nigeria': '[NG]',
        'United States': '[US]',
        'Australia': '[AU]',
        'Netherlands': '[NL]'
    };
    return badges[country] || '[--]';
}

function getCountryFlag(country) {
    return getCountryBadge(country);
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

function getAlertSeverityFromAttempts(attemptCount, fallback = 'medium') {
    const normalizedFallback = String(fallback || '').trim().toLowerCase();
    if (['low', 'medium', 'high', 'critical'].includes(normalizedFallback)) {
        return normalizedFallback;
    }

    const attempts = Number(attemptCount) > 0 ? Number(attemptCount) : 1;

    if (attempts <= 10) return 'low';
    if (attempts <= 20) return 'medium';
    if (attempts <= 30) return 'high';
    return 'critical';
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
        <span>${escapeHtml(message)}</span>
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
    initializeCharts();
    initializeEDRDashboard();
    setupLiveUpdates();
}

function updateKPICards() {
    document.getElementById('totalRequests').textContent = Math.floor(Math.random() * 20000 + 10000).toLocaleString();
    document.getElementById('maliciousCount').textContent = mockThreats.length;
    document.getElementById('criticalAlerts').textContent = alertsData.filter(a => a.severity === 'critical').length;
}

async function blockIP(ip) {
    if (!isValidIPv4(ip)) {
        showToast(`Cannot block non-IPv4 target: ${ip}`, 'error');
        return;
    }
    if (!isPublicIPv4(ip)) {
        showToast(`Refusing to block non-public or reserved IP: ${ip}`, 'error');
        return;
    }

    try {
        // Ask user if they want system-level firewall blocking
        const enableFirewall = confirm(
            `Block IP ${ip}?\n\n` +
            `Choose:\n` +
            `  OK = Block in app and system firewall\n` +
            `  Cancel = Block in app only\n\n` +
            `Firewall blocking requires admin/sudo privileges`
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
        
        let message = `IP ${ip} blocked in application`;
        
        // Show firewall status if available
        if (result.firewall_status) {
            if (result.firewall_status.success) {
                message += `\nFirewall: ${result.firewall_status.message}`;
                showToast(message, 'success');
            } else {
                message += `\nFirewall: ${result.firewall_status.message}`;
                message += `\n(May need admin/sudo privileges)`;
                showToast(message, 'warning');
            }
        } else {
            showToast(message, 'success');
        }
        
    } catch (error) {
        console.error('Block IP error:', error);
        showToast(`Block failed: ${error.message}`, 'error');
    }
}

function showDetails(ip) {
    const threat = mockThreats.find(entry => entry.ip === ip);
    if (!threat) {
        showToast('Threat details not found', 'error');
        return;
    }
    const modal = document.getElementById('detailModal');
    const modalBody = document.getElementById('modalBody');
    const modalTitle = modal.querySelector('.modal-header h2');
    const blockBtn = document.getElementById('modalBlockBtn');

    if (modalTitle) {
        modalTitle.textContent = 'IP Details';
    }
    blockBtn.textContent = 'Block IP';
    blockBtn.disabled = false;

    modalBody.innerHTML = `
        <div class="modal-detail-row">
            <span class="modal-detail-label">IP Address</span>
            <span class="modal-detail-value"><code>${escapeHtml(threat.ip)}</code></span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Country</span>
            <span class="modal-detail-value">${escapeHtml(getCountryBadge(threat.country))} ${escapeHtml(threat.country)}</span>
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
            <span class="modal-detail-value">${escapeHtml(threat.type)}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">API Source</span>
            <span class="modal-detail-value">${escapeHtml(threat.api)}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Last Detected</span>
            <span class="modal-detail-value">${escapeHtml(threat.timestamp)}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Reputation</span>
            <span class="modal-detail-value">Highly Malicious</span>
        </div>
    `;

    blockBtn.onclick = () => {
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
    const firstSeenDateTime = formatAlertDateTime(alert.firstSeen || alert.time);
    const lastSeenDateTime = formatAlertDateTime(alert.lastSeen || alert.time);
    const attackAttempts = Number(alert.attemptCount) > 0 ? Number(alert.attemptCount) : 1;
    const attackerIp = alert.ip || 'Unknown';

    if (modalTitle) {
        modalTitle.textContent = 'Alert Details';
    }
    blockBtn.textContent = 'Block IP';

    modalBody.innerHTML = `
        <div class="modal-detail-row">
            <span class="modal-detail-label">Attacker IP Address</span>
            <span class="modal-detail-value"><code>${escapeHtml(attackerIp)}</code></span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Last Seen Date</span>
            <span class="modal-detail-value">${escapeHtml(lastSeenDateTime.date)}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Last Seen Time</span>
            <span class="modal-detail-value">${escapeHtml(lastSeenDateTime.time)}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">First Seen</span>
            <span class="modal-detail-value">${escapeHtml(firstSeenDateTime.date)} ${escapeHtml(firstSeenDateTime.time)}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Type of Attack</span>
            <span class="modal-detail-value">${escapeHtml(alert.type || 'Unknown')}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Attack Attempts</span>
            <span class="modal-detail-value">${attackAttempts}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Severity</span>
            <span class="modal-detail-value" style="text-transform: uppercase; color: ${getThreatColor(alert.severity)}">${escapeHtml(alert.severity)}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Target IP</span>
            <span class="modal-detail-value">${escapeHtml(alert.targetIp || 'N/A')}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Description</span>
            <span class="modal-detail-value">${escapeHtml(alert.description || 'No description available')}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Log Entry</span>
            <span class="modal-detail-value">${escapeHtml(alert.logLine || 'N/A')}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Source</span>
            <span class="modal-detail-value">${escapeHtml(alert.source || 'attack_detector')}</span>
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
    const refreshBtn = document.getElementById('edrRefreshBtn');
    const searchInput = document.getElementById('edrSearch');
    const filterSelect = document.getElementById('edrFilter');

    if (refreshBtn) {
        refreshBtn.addEventListener('click', async (event) => {
            event.preventDefault();
            await loadEDRDashboardFromBackend(true, { force: true });
        });
    }

    if (searchInput) {
        searchInput.addEventListener('input', () => renderEDRDashboard());
    }

    if (filterSelect) {
        filterSelect.addEventListener('change', () => renderEDRDashboard());
    }

    startEDRAutoRefresh();
}

// ========== EDR DASHBOARD ==========

function initializeEDRDashboard() {
    renderEDRDashboard();
    loadEDRDashboardFromBackend(false, { force: true, showLoading: false });
}

function startEDRAutoRefresh() {
    if (edrRefreshTimer) {
        return;
    }

    edrRefreshTimer = setInterval(() => {
        loadEDRDashboardFromBackend(false, { showLoading: false });
    }, EDR_DASHBOARD_REFRESH_MS);
}

function setEDRRefreshState(isLoading) {
    const refreshBtn = document.getElementById('edrRefreshBtn');
    if (!refreshBtn) return;

    refreshBtn.disabled = isLoading;
    refreshBtn.classList.toggle('is-loading', isLoading);
    refreshBtn.innerHTML = isLoading
        ? '<i class="fas fa-sync"></i> Refreshing'
        : '<i class="fas fa-sync"></i> Refresh';
}

function getEDRHeartbeatTimeoutMs(data = edrDashboardData) {
    const seconds = Number(data?.heartbeatTimeoutSeconds || EDR_DEFAULT_HEARTBEAT_TIMEOUT_SECONDS);
    return Math.max(10, seconds) * 1000;
}

function computeEDREndpointStatus(endpoint, data = edrDashboardData) {
    const parsed = new Date(endpoint?.last_seen || endpoint?.timestamp || '');
    if (Number.isNaN(parsed.getTime())) {
        return 'offline';
    }

    return Date.now() - parsed.getTime() <= getEDRHeartbeatTimeoutMs(data)
        ? 'online'
        : 'offline';
}

function refreshLocalEDRLiveness() {
    const endpoints = Array.isArray(edrDashboardData.endpoints) ? edrDashboardData.endpoints : [];
    endpoints.forEach(endpoint => {
        endpoint.status = computeEDREndpointStatus(endpoint);
    });

    const summary = edrDashboardData.summary || {};
    summary.totalEndpoints = endpoints.length;
    summary.onlineEndpoints = endpoints.filter(endpoint => endpoint.status === 'online').length;
    summary.offlineEndpoints = endpoints.length - summary.onlineEndpoints;
    edrDashboardData.summary = summary;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = EDR_DASHBOARD_REQUEST_TIMEOUT_MS) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, {
            ...options,
            signal: controller.signal
        });
    } finally {
        clearTimeout(timeoutId);
    }
}

function normalizeEDRDashboardPayload(payload) {
    const empty = createEmptyEDRDashboard();
    const heartbeatTimeoutSeconds = Number(payload?.heartbeatTimeoutSeconds || EDR_DEFAULT_HEARTBEAT_TIMEOUT_SECONDS);
    const dashboardShell = {
        ...empty,
        heartbeatTimeoutSeconds
    };
    const endpoints = (Array.isArray(payload?.endpoints) ? payload.endpoints : []).map(endpoint => ({
        ...endpoint,
        status: computeEDREndpointStatus(endpoint, dashboardShell)
    }));
    const events = Array.isArray(payload?.events) ? payload.events : [];
    const alerts = Array.isArray(payload?.alerts) ? payload.alerts : [];
    const responses = Array.isArray(payload?.responses) ? payload.responses : [];

    return {
        summary: {
            ...empty.summary,
            ...(payload.summary || {}),
            totalEndpoints: Number(payload?.summary?.totalEndpoints ?? endpoints.length),
            onlineEndpoints: endpoints.filter(endpoint => endpoint.status === 'online').length,
            offlineEndpoints: endpoints.filter(endpoint => endpoint.status !== 'online').length,
            openAlerts: Number(payload?.summary?.openAlerts ?? alerts.filter(alert => (alert.status || 'open') === 'open').length),
            criticalAlerts: Number(payload?.summary?.criticalAlerts ?? alerts.filter(alert => alert.severity === 'critical').length),
            eventsToday: Number(payload?.summary?.eventsToday ?? events.length),
            responses: Number(payload?.summary?.responses ?? responses.length)
        },
        endpoints,
        events,
        alerts,
        responses,
        heartbeatTimeoutSeconds,
        coverage: Array.isArray(payload?.coverage) ? payload.coverage : []
    };
}

async function loadEDRDashboardFromBackend(notifyOnError = true, options = {}) {
    if (isLoadingEDRDashboard) {
        return;
    }

    isLoadingEDRDashboard = true;
    const showLoading = options.showLoading !== false;
    if (showLoading) {
        setEDRRefreshState(true);
    }

    try {
        const cacheBuster = options.force ? `?ts=${Date.now()}` : '';
        const response = await fetchWithTimeout(`${API_ENDPOINTS.edrDashboard}${cacheBuster}`, {
            cache: 'no-store'
        });
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const payload = await response.json();
        edrDashboardData = normalizeEDRDashboardPayload(payload);
        renderEDRDashboard();
        if (notifyOnError) {
            showToast('EDR events refreshed', 'success', 1600);
        }
    } catch (error) {
        console.error('Failed to load EDR dashboard:', error);
        renderEDRDashboard();
        if (notifyOnError) {
            const message = error.name === 'AbortError'
                ? 'EDR dashboard refresh timed out. Check backend server.'
                : `Failed to load EDR data: ${error.message}`;
            showToast(message, 'error');
        }
    } finally {
        isLoadingEDRDashboard = false;
        if (showLoading) {
            setEDRRefreshState(false);
        }
    }
}

function getEDRSearchQuery() {
    const input = document.getElementById('edrSearch');
    return (input?.value || '').trim().toLowerCase();
}

function getEDRFilter() {
    const select = document.getElementById('edrFilter');
    return select?.value || 'all';
}

function matchesEDRSearch(item, query) {
    if (!query) return true;
    return [
        item.hostname,
        item.endpoint_name,
        item.ip_address,
        item.user,
        item.process,
        item.process_name,
        item.parent_process,
        item.child_process,
        item.title,
        item.summary,
        item.command_line,
        item.destination_ip,
        item.file_path,
        item.registry_key,
        item.task_name,
        item.signature_status,
        item.signature_subject,
        item.usb_action,
        item.device_name,
        item.device_id,
        item.rdp_result,
        item.target_user,
        item.source_ip,
        item.failed_count,
        item.mitre_id,
        item.status
    ].some(value => String(value || '').toLowerCase().includes(query));
}

function getFilteredEDRData() {
    const query = getEDRSearchQuery();
    const filter = getEDRFilter();
    const endpoints = (edrDashboardData.endpoints || []).filter(endpoint => matchesEDRSearch(endpoint, query));
    let alerts = (edrDashboardData.alerts || []).filter(alert => matchesEDRSearch(alert, query));
    let events = (edrDashboardData.events || []).filter(event => matchesEDRSearch(event, query));
    const responses = (edrDashboardData.responses || []).filter(response => matchesEDRSearch(response, query));

    if (filter === 'critical') {
        alerts = alerts.filter(alert => String(alert.severity || '').toLowerCase() === 'critical');
    } else if (['process', 'network', 'file', 'usb', 'rdp_login', 'failed_login_burst'].includes(filter)) {
        events = events.filter(event => String(event.event_type || '').toLowerCase() === filter);
    }

    return { endpoints, alerts, events, responses };
}

function renderEDRDashboard() {
    if (!document.getElementById('edrDashboard')) return;

    refreshLocalEDRLiveness();
    const filtered = getFilteredEDRData();
    renderEDRSummary();
    renderEDREndpoints(filtered.endpoints);
    renderEDRAlerts(filtered.alerts);
    renderEDREvents(filtered.events);
    renderEDRProcessContext(filtered.alerts, filtered.events);
    renderEDRResponses(filtered.responses);
}

function renderEDRSummary() {
    const summary = edrDashboardData.summary || {};
    const online = Number(summary.onlineEndpoints || 0);
    const total = Number(summary.totalEndpoints || 0);
    setTextContent('edrEndpointsOnline', `${online}/${total}`);
    setTextContent('edrOpenAlerts', Number(summary.openAlerts || 0).toLocaleString());
    setTextContent('edrCriticalAlerts', Number(summary.criticalAlerts || 0).toLocaleString());
    setTextContent('edrEventsToday', Number(summary.eventsToday || 0).toLocaleString());
}

function setTextContent(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function formatRelativeTime(value) {
    if (!value) return 'Unknown';
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value);
    const diffSeconds = Math.max(0, Math.round((Date.now() - parsed.getTime()) / 1000));
    if (diffSeconds < 10) return 'Just now';
    if (diffSeconds < 60) return `${diffSeconds}s ago`;
    const diffMinutes = Math.round(diffSeconds / 60);
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    const diffHours = Math.round(diffMinutes / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return parsed.toLocaleString();
}

function normalizeClassToken(value, fallback = 'unknown') {
    return String(value || fallback).toLowerCase().replace(/[^a-z0-9_-]/g, '-');
}

function renderEDREndpoints(endpoints) {
    const tbody = document.getElementById('edrEndpointsBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!endpoints.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="edr-empty-state">No endpoint telemetry available</td></tr>';
        return;
    }

    endpoints.forEach(endpoint => {
        const status = normalizeClassToken(endpoint.status || 'offline');
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><strong>${escapeHtml(endpoint.hostname || endpoint.endpoint_id || 'Unknown')}</strong></td>
            <td><code>${escapeHtml(endpoint.ip_address || 'N/A')}</code></td>
            <td>${escapeHtml(endpoint.user || 'N/A')}</td>
            <td>${escapeHtml(endpoint.agent_version || 'N/A')}</td>
            <td><span class="edr-status ${status}">${escapeHtml(endpoint.status || 'offline')}</span></td>
            <td>${escapeHtml(formatRelativeTime(endpoint.last_seen))}</td>
        `;
        tbody.appendChild(row);
    });
}

function renderEDRAlerts(alerts) {
    const container = document.getElementById('edrAlertsQueue');
    if (!container) return;
    container.innerHTML = '';

    if (!alerts.length) {
        container.innerHTML = '<div class="edr-empty-state">No endpoint alerts in queue</div>';
        return;
    }

    alerts.slice(0, 8).forEach(alert => {
        const severity = normalizeClassToken(alert.severity || 'medium');
        const item = document.createElement('div');
        item.className = `edr-alert-item ${severity}`;
        item.innerHTML = `
            <div class="edr-alert-top">
                <div class="edr-alert-title">${escapeHtml(alert.title || 'Endpoint Alert')}</div>
                <span class="edr-severity ${severity}">${escapeHtml(alert.severity || 'medium')}</span>
            </div>
            <div class="edr-alert-meta">
                <div>${escapeHtml(alert.endpoint_name || alert.endpoint_id || 'Unknown Endpoint')} | ${escapeHtml(alert.user || 'Unknown User')}</div>
                <div>Process: <code>${escapeHtml(alert.process || alert.process_name || 'N/A')}</code></div>
                ${alert.destination_ip ? `<div>Destination: <code>${escapeHtml(alert.destination_ip)}${alert.destination_port ? `:${escapeHtml(alert.destination_port)}` : ''}</code></div>` : ''}
                ${alert.mitre_id ? `<div>MITRE: ${escapeHtml(alert.mitre_id)}</div>` : ''}
                <div>${escapeHtml(formatRelativeTime(alert.timestamp))}</div>
            </div>
            <div class="edr-alert-actions">
                <button class="btn-action btn-details" type="button" data-action="details">
                    <i class="fas fa-expand"></i> Details
                </button>
                <button class="btn-action btn-block" type="button" data-action="kill">
                    <i class="fas fa-skull-crossbones"></i> Kill
                </button>
                ${alert.destination_ip ? `
                    <button class="btn-action btn-details" type="button" data-action="block">
                        <i class="fas fa-ban"></i> Block IP
                    </button>
                ` : ''}
            </div>
        `;

        item.querySelector('[data-action="details"]').addEventListener('click', () => showEDRAlertDetails(alert.id || alert.alert_id));
        item.querySelector('[data-action="kill"]').addEventListener('click', () => submitEDRResponse('kill_process', alert.process || alert.process_name || 'unknown-process', alert));
        const blockButton = item.querySelector('[data-action="block"]');
        if (blockButton) {
            blockButton.addEventListener('click', () => submitEDRResponse('block_ip', alert.destination_ip, alert));
        }
        container.appendChild(item);
    });
}

function renderEDREvents(events) {
    const tbody = document.getElementById('edrEventsBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!events.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="edr-empty-state">No endpoint events found</td></tr>';
        return;
    }

    events.slice(0, 50).forEach(event => {
        const eventType = normalizeClassToken(event.event_type || 'event');
        const target = getEDREventTarget(event);
        const row = document.createElement('tr');
        row.className = 'edr-clickable-row';
        row.tabIndex = 0;
        row.title = 'Open event details';
        row.innerHTML = `
            <td>${escapeHtml(formatRelativeTime(event.timestamp))}</td>
            <td>${escapeHtml(event.endpoint_name || event.endpoint_id || 'Unknown')}</td>
            <td><span class="edr-event-type ${eventType}">${escapeHtml(event.event_type || 'event')}</span></td>
            <td><code>${escapeHtml(event.process_name || 'N/A')}</code></td>
            <td>${target}</td>
        `;
        row.addEventListener('click', () => showEDREventDetails(event.id || event.event_id));
        row.addEventListener('keydown', (keyboardEvent) => {
            if (keyboardEvent.key === 'Enter' || keyboardEvent.key === ' ') {
                keyboardEvent.preventDefault();
                showEDREventDetails(event.id || event.event_id);
            }
        });
        tbody.appendChild(row);
    });
}

function getEDREventTarget(event) {
    if (event.destination_ip) {
        return `<code>${escapeHtml(event.destination_ip)}${event.destination_port ? `:${escapeHtml(event.destination_port)}` : ''}</code>`;
    }
    if (event.event_type === 'usb') {
        return `${escapeHtml(event.usb_action || 'USB')} <code>${escapeHtml(event.device_name || event.device_id || 'USB device')}</code>`;
    }
    if (event.event_type === 'rdp_login') {
        return `${escapeHtml(event.rdp_result || 'RDP')} ${escapeHtml(event.target_user || 'unknown user')} from <code>${escapeHtml(event.source_ip || 'unknown source')}</code>`;
    }
    if (event.event_type === 'failed_login_burst') {
        return `${escapeHtml(event.failed_count || 0)} failed logins for ${escapeHtml(event.target_user || 'unknown user')} from <code>${escapeHtml(event.source_ip || 'unknown source')}</code>`;
    }
    if (event.file_path) {
        return `<code>${escapeHtml(event.file_path)}</code>`;
    }
    if (event.registry_key) {
        return `<code>${escapeHtml(event.registry_key)}</code>`;
    }
    if (event.task_name) {
        return escapeHtml(event.task_name);
    }
    if (event.command_line) {
        return `<span class="edr-command-line">${escapeHtml(event.command_line)}</span>`;
    }
    return 'N/A';
}

function getEDREventById(eventId) {
    return (edrDashboardData.events || []).find(event =>
        String(event.id || event.event_id) === String(eventId)
    );
}

function renderEDRDetailRow(label, value, options = {}) {
    const displayValue = value === undefined || value === null || value === '' ? 'N/A' : value;
    const content = options.code
        ? `<code>${escapeHtml(displayValue)}</code>`
        : escapeHtml(displayValue);
    return `
        <div class="modal-detail-row">
            <span class="modal-detail-label">${escapeHtml(label)}</span>
            <span class="modal-detail-value">${content}</span>
        </div>
    `;
}

function showEDREventDetails(eventId) {
    const event = getEDREventById(eventId);
    if (!event) {
        showToast('EDR event details not found', 'error');
        return;
    }

    const modal = document.getElementById('detailModal');
    const modalBody = document.getElementById('modalBody');
    const modalTitle = modal.querySelector('.modal-header h2');
    const responseBtn = document.getElementById('modalBlockBtn');

    if (modalTitle) {
        modalTitle.textContent = 'EDR Event Details';
    }

    const rows = [
        renderEDRDetailRow('Event ID', event.id || event.event_id, { code: true }),
        renderEDRDetailRow('Type', event.event_type),
        renderEDRDetailRow('Endpoint', event.endpoint_name || event.endpoint_id),
        renderEDRDetailRow('User', event.user),
        renderEDRDetailRow('Time', event.timestamp),
        renderEDRDetailRow('Process', event.process_name, { code: true }),
        renderEDRDetailRow('PID', event.pid),
        renderEDRDetailRow('Parent Process', event.parent_process, { code: true }),
        renderEDRDetailRow('Command Line', event.command_line, { code: true }),
        renderEDRDetailRow('Image Path', event.image_path, { code: true }),
        renderEDRDetailRow('Destination', event.destination_ip ? `${event.destination_ip}${event.destination_port ? `:${event.destination_port}` : ''}` : '', { code: true }),
        renderEDRDetailRow('File Path', event.file_path, { code: true }),
        renderEDRDetailRow('Registry Key', event.registry_key, { code: true }),
        renderEDRDetailRow('Signature', event.signature_status),
        renderEDRDetailRow('Target User', event.target_user),
        renderEDRDetailRow('Source IP', event.source_ip, { code: true }),
        renderEDRDetailRow('Failed Count', event.failed_count),
        renderEDRDetailRow('Window', event.window_start || event.window_end ? `${event.window_start || 'N/A'} to ${event.window_end || 'N/A'}` : ''),
    ].join('');

    modalBody.innerHTML = `
        ${rows}
        <div class="log-section">
            <h4>Raw Event</h4>
            <pre class="log-pre">${escapeHtml(JSON.stringify(event.raw || event, null, 2))}</pre>
        </div>
    `;

    responseBtn.textContent = 'Collect Details';
    responseBtn.disabled = false;
    responseBtn.onclick = () => {
        submitEDRResponse('collect_process_details', event.process_name || event.endpoint_name || event.endpoint_id || 'endpoint', event);
        modal.classList.add('hidden');
    };

    modal.classList.remove('hidden');
}

function renderEDRProcessContext(alerts, events) {
    const container = document.getElementById('edrProcessTree');
    if (!container) return;
    const alert = alerts[0] || (edrDashboardData.alerts || [])[0];
    const event = events.find(item => item.event_type === 'process') || (edrDashboardData.events || []).find(item => item.event_type === 'process');

    if (!alert && !event) {
        container.innerHTML = '<div class="edr-empty-state">No process context available</div>';
        return;
    }

    const parentProcess = alert?.parent_process || event?.parent_process || 'parent.exe';
    const childProcess = alert?.child_process || alert?.process || event?.process_name || 'process.exe';
    const commandLine = alert?.command_line || event?.command_line || '';
    const destination = alert?.destination_ip
        ? `${alert.destination_ip}${alert.destination_port ? `:${alert.destination_port}` : ''}`
        : '';

    container.innerHTML = `
        <div class="edr-tree-node">
            <strong>Parent Process</strong>
            <div><code>${escapeHtml(parentProcess || 'N/A')}</code></div>
        </div>
        <div class="edr-tree-node child">
            <strong>Child Process</strong>
            <div><code>${escapeHtml(childProcess || 'N/A')}</code></div>
            ${commandLine ? `<div class="edr-command-line">${escapeHtml(commandLine)}</div>` : ''}
        </div>
        ${destination ? `
            <div class="edr-tree-node child">
                <strong>Network Connection</strong>
                <div><code>${escapeHtml(destination)}</code></div>
            </div>
        ` : ''}
    `;
}

function renderEDRResponses(responses) {
    const tbody = document.getElementById('edrResponsesBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!responses.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="edr-empty-state">No response actions recorded</td></tr>';
        return;
    }

    responses.slice(0, 8).forEach(response => {
        const mode = normalizeClassToken(response.mode || 'dry-run');
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${escapeHtml(formatEDRAction(response.action || response.action_type))}</td>
            <td><code>${escapeHtml(response.target || 'N/A')}</code></td>
            <td><span class="edr-mode ${mode}">${escapeHtml(response.mode || 'dry-run')}</span></td>
            <td>${escapeHtml(response.status || 'unknown')}</td>
            <td>${escapeHtml(formatRelativeTime(response.timestamp))}</td>
        `;
        tbody.appendChild(row);
    });
}

function formatEDRAction(action) {
    return String(action || 'response')
        .replace(/_/g, ' ')
        .replace(/\b\w/g, char => char.toUpperCase());
}

function getEDRAlertById(alertId) {
    return (edrDashboardData.alerts || []).find(alert =>
        String(alert.id || alert.alert_id) === String(alertId)
    );
}

function showEDRAlertDetails(alertId) {
    const alert = getEDRAlertById(alertId);
    if (!alert) {
        showToast('EDR alert details not found', 'error');
        return;
    }

    const modal = document.getElementById('detailModal');
    const modalBody = document.getElementById('modalBody');
    const modalTitle = modal.querySelector('.modal-header h2');
    const responseBtn = document.getElementById('modalBlockBtn');
    const relatedEvents = (edrDashboardData.events || []).filter(event =>
        (alert.related_event_ids || []).map(String).includes(String(event.id || event.event_id))
    );

    if (modalTitle) {
        modalTitle.textContent = 'EDR Alert Details';
    }

    modalBody.innerHTML = `
        <div class="modal-detail-row">
            <span class="modal-detail-label">Alert</span>
            <span class="modal-detail-value">${escapeHtml(alert.title || 'Endpoint Alert')}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Severity</span>
            <span class="modal-detail-value" style="text-transform: uppercase; color: ${getThreatColor(alert.severity)}">${escapeHtml(alert.severity || 'medium')}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Endpoint</span>
            <span class="modal-detail-value">${escapeHtml(alert.endpoint_name || alert.endpoint_id || 'Unknown')}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">User</span>
            <span class="modal-detail-value">${escapeHtml(alert.user || 'Unknown')}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Parent Process</span>
            <span class="modal-detail-value"><code>${escapeHtml(alert.parent_process || 'N/A')}</code></span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Child Process</span>
            <span class="modal-detail-value"><code>${escapeHtml(alert.child_process || alert.process || 'N/A')}</code></span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Command Line</span>
            <span class="modal-detail-value"><code>${escapeHtml(alert.command_line || 'N/A')}</code></span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Destination IP</span>
            <span class="modal-detail-value"><code>${escapeHtml(alert.destination_ip || 'N/A')}</code></span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">MITRE</span>
            <span class="modal-detail-value">${escapeHtml(alert.mitre_id || 'N/A')}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Summary</span>
            <span class="modal-detail-value">${escapeHtml(alert.summary || 'No summary available')}</span>
        </div>
        <div class="modal-detail-row">
            <span class="modal-detail-label">Recommended Action</span>
            <span class="modal-detail-value">${escapeHtml(alert.recommended_action || 'Collect process details')}</span>
        </div>
        <div class="log-section">
            <h4>Related Events</h4>
            <pre class="log-pre">${escapeHtml(JSON.stringify(relatedEvents.slice(0, 5), null, 2))}</pre>
        </div>
    `;

    responseBtn.textContent = 'Collect Details';
    responseBtn.disabled = false;
    responseBtn.onclick = () => {
        submitEDRResponse('collect_process_details', alert.process || alert.process_name || alert.endpoint_name || 'endpoint', alert);
        modal.classList.add('hidden');
    };

    modal.classList.remove('hidden');
}

async function submitEDRResponse(action, target, alert = {}) {
    if (!target) {
        showToast('Response target is missing', 'error');
        return;
    }

    try {
        const response = await fetch(API_ENDPOINTS.edrResponse, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action,
                target,
                dry_run: true,
                endpoint_id: alert.endpoint_id || '',
                alert_id: alert.id || alert.alert_id || '',
                actor: 'dashboard'
            })
        });
        const payload = await response.json();
        if (!response.ok) {
            throw new Error(payload.error || payload.message || `HTTP Error: ${response.status}`);
        }

        showToast(payload.message || 'EDR response recorded', 'success');
        await loadEDRDashboardFromBackend(false);
    } catch (error) {
        console.error('EDR response failed:', error);
        showToast(`EDR response failed: ${error.message}`, 'error');
    }
}

// ========== CHARTS INITIALIZATION ==========

let threatTrendChart = null;
let attackTypesChart = null;

function initializeCharts() {
    initializeThreatTrendChart();
    initializeAttackTypesChart();
    loadAlertStatsFromBackend(false);
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
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: '#ff4757',
                    backgroundColor: 'rgba(255, 71, 87, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'High Severity',
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: '#ffa502',
                    backgroundColor: 'rgba(255, 165, 2, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Medium Threats',
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Low Threats',
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: '#2ed573',
                    backgroundColor: 'rgba(46, 213, 115, 0.08)',
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
            labels: ['No Alerts Yet'],
            datasets: [{
                data: [1],
                backgroundColor: [
                    '#2a2f47',
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

function updateThreatTrendChart(trend = {}) {
    if (!threatTrendChart) return;

    threatTrendChart.data.labels = Array.isArray(trend.labels) && trend.labels.length
        ? trend.labels
        : ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
    threatTrendChart.data.datasets[0].data = Array.isArray(trend.critical) ? trend.critical : [];
    threatTrendChart.data.datasets[1].data = Array.isArray(trend.high) ? trend.high : [];
    threatTrendChart.data.datasets[2].data = Array.isArray(trend.medium) ? trend.medium : [];
    threatTrendChart.data.datasets[3].data = Array.isArray(trend.low) ? trend.low : [];
    threatTrendChart.update();
}

function updateAttackTypesChart(attackTypes = {}) {
    if (!attackTypesChart) return;

    const labels = Array.isArray(attackTypes.labels) ? attackTypes.labels : [];
    const values = Array.isArray(attackTypes.values) ? attackTypes.values : [];
    const hasValues = values.some(value => Number(value) > 0);

    attackTypesChart.data.labels = hasValues ? labels : ['No Alerts Yet'];
    attackTypesChart.data.datasets[0].data = hasValues ? values : [1];
    attackTypesChart.data.datasets[0].backgroundColor = hasValues
        ? ['#ff4757', '#ffa502', '#ff9f43', '#00d4ff', '#2ed573', '#d946ef']
        : ['#2a2f47'];
    attackTypesChart.update();
}

async function loadAlertStatsFromBackend(notifyOnError = true) {
    try {
        const response = await fetch(API_ENDPOINTS.alertStats);
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const stats = await response.json();
        updateThreatTrendChart(stats.trend || {});
        updateAttackTypesChart(stats.attackTypes || {});
    } catch (error) {
        console.error('Failed to load alert stats:', error);
        if (notifyOnError) {
            showToast(`Failed to load chart data: ${error.message}`, 'error');
        }
    }
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
        ip: '8.8.8.8',
        domain: 'example.com',
        hash: 'a1b2c3d4e5f6...'
    };
    
    scanInput.placeholder = placeholders[scanType];
}

async function performScan() {
    const scanInput = document.getElementById('scanInput').value.trim();
    const scanType = document.getElementById('scanType').value;
    const scanNowBtn = document.getElementById('scanNowBtn');

    if (!scanInput) {
        showToast('Please enter a target IP, domain, or hash', 'error');
        return;
    }

    // Validate input
    const validation = validateInput(scanInput, scanType);
    if (!validation.valid) {
        showToast(validation.error, 'error');
        return;
    }
    if (validation.type === 'ip' && !isPublicIPv4(scanInput)) {
        showToast(`Threat intelligence scans require a public IPv4 address: ${scanInput}`, 'error');
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
            body: JSON.stringify({ target: scanInput, type: scanType })
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
    if (!Array.isArray(results.results)) {
        results.results = [];
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

    if (!apiResults || !Array.isArray(apiResults) || apiResults.length === 0) {
        container.innerHTML = '<p style="color: #ff4757;">No API results available</p>';
        return;
    }

    apiResults.forEach(result => {
        const card = document.createElement('div');
        card.className = 'api-card';
        const value = (field, fallback = 'Unknown') => escapeHtml(result[field] ?? fallback);
        
        if (result.success) {
            const statusClass = result.isMalicious ? 'malicious' : result.isSuspicious ? 'suspicious' : '';
            const statusText = result.isMalicious ? 'MALICIOUS' : result.isSuspicious ? 'SUSPICIOUS' : 'CLEAN';
            
            // Build details list based on API type
            let detailsHTML = '';
            
            if (result.name === 'AbuseIPDB') {
                const reportsValue = Number.isFinite(Number(result.reports)) ? Number(result.reports) : 0;
                detailsHTML = `
                    <li><strong>Score:</strong> ${escapeHtml(result.score ?? 0)}/100</li>
                    <li><strong>Reports (90d):</strong> ${reportsValue}</li>
                    <li><strong>ISP:</strong> ${value('isp')}</li>
                    <li><strong>Country:</strong> ${value('country')}</li>
                    <li><strong>Last Reported:</strong> ${value('lastReportedAt')}</li>
                `;
            } else if (result.name === 'VirusTotal') {
                detailsHTML = `
                    <li><strong>Score:</strong> ${escapeHtml(result.score ?? 0)}/100</li>
                    <li><strong>Malicious:</strong> ${escapeHtml(result.maliciousVendors ?? 0)}/${escapeHtml(result.totalVendors ?? 0)}</li>
                    <li><strong>Suspicious:</strong> ${escapeHtml(result.suspiciousVendors ?? 0)}</li>
                    <li><strong>ASN:</strong> ${value('asn')}</li>
                    <li><strong>Country:</strong> ${value('country')}</li>
                `;
            } else if (result.name === 'AlienVault OTX') {
                detailsHTML = `
                    <li><strong>Score:</strong> ${escapeHtml(result.score ?? 0)}/100</li>
                    <li><strong>Reputation:</strong> ${value('reputation')}</li>
                    <li><strong>Pulses:</strong> ${escapeHtml(result.pulseCount ?? 0)}</li>
                    <li><strong>Country:</strong> ${value('country')}</li>
                    <li><strong>Whitelisted:</strong> ${result.whitelisted ? 'Yes' : 'No'}</li>
                `;
            } else if (result.name === 'GreyNoise') {
                const tags = (result.tags && result.tags.length > 0) ? result.tags.join(', ') : 'N/A';
                detailsHTML = `
                    <li><strong>Score:</strong> ${escapeHtml(result.score ?? 0)}/100</li>
                    <li><strong>Classification:</strong> ${value('classification')}</li>
                    <li><strong>Tags:</strong> ${escapeHtml(tags)}</li>
                    <li><strong>Country:</strong> ${value('country')}</li>
                    <li><strong>First Seen:</strong> ${value('firstSeen')}</li>
                    <li><strong>Last Seen:</strong> ${value('lastSeen')}</li>
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
                    <li><strong>Fraud Score:</strong> ${escapeHtml(imp.fraud_score ?? 0)}/100</li>
                    <li><strong>Severity:</strong> ${escapeHtml(fraudSeverity)}</li>
                    <li><strong>Proxy:</strong> ${proxyStat}</li>
                    <li><strong>VPN:</strong> ${vpnStat}</li>
                    <li><strong>TOR:</strong> ${torStat}</li>
                    <li><strong>Bot Activity:</strong> ${botStat}</li>
                    <li><strong>Recent Abuse:</strong> ${abuseVal}</li>
                    <li><strong>Location:</strong> ${escapeHtml(imp.city || 'Unknown')}, ${escapeHtml(imp.region || 'Unknown')}, ${escapeHtml(imp.country || 'Unknown')}</li>
                    <li><strong>ISP:</strong> ${escapeHtml(imp.isp || 'Unknown')}</li>
                    <li><strong>ASN:</strong> ${escapeHtml(imp.asn || 'Unknown')}</li>
                `;
            }
            
            card.innerHTML = `
                <div class="api-card-header">
                    <span class="api-name">${escapeHtml(result.name)}</span>
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
                    <span class="api-name">${escapeHtml(result.name || 'API')}</span>
                    <span class="api-status error">ERROR</span>
                </div>
                <p style="color: #ff4757; font-size: 0.9rem; margin: 1rem;">
                    ${escapeHtml(result.error || 'API call failed')}
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
    
    const overallReputation = consensus === 'MALICIOUS' ? 'Highly Suspicious' :
                              consensus === 'SUSPICIOUS' ? 'Potentially Malicious' :
                              'Good Standing';
    
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
            <div class="reputation-value">${escapeHtml(overallReputation)}</div>
        </div>
        <div class="reputation-item">
            <div class="reputation-label">API Consensus</div>
            <div class="reputation-value">${escapeHtml(consensus)} (${maliciousAPIs}/${totalAPIs} APIs)</div>
        </div>
        <div class="reputation-item">
            <div class="reputation-label">Average Threat Score</div>
            <div class="reputation-value">${averageScore}/100</div>
        </div>
        <div class="reputation-item">
            <div class="reputation-label">Threat Classification</div>
            <div class="reputation-value">${escapeHtml(threatCategory)}</div>
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
            <strong>${escapeHtml(location.country)}</strong><br>
            IP: ${escapeHtml(location.ip)}<br>
            Score: ${formatScore(location.score)}/100<br>
            Threat: ${level.toUpperCase()}<br>
            ${location.timestamp ? `Scanned: ${escapeHtml(location.timestamp)}<br>` : ''}
            ${location.source ? `Source: ${escapeHtml(location.source)}` : ''}
        </div>
    `);

    mapMarkers.push(marker);
}

function clearRenderedMapMarkers() {
    while (mapMarkers.length) {
        const marker = mapMarkers.pop();
        if (mapInstance && marker) {
            mapInstance.removeLayer(marker);
        }
    }
}

function renderStoredMapLocations() {
    if (!mapInstance) return;
    clearRenderedMapMarkers();
    scannedThreatLocations.forEach(renderThreatMarker);
    updateMapStats();
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

    const existingIndex = scannedThreatLocations.findIndex(item => item.ip === ip);
    if (existingIndex >= 0) {
        scannedThreatLocations[existingIndex] = location;
    } else {
        scannedThreatLocations.push(location);
    }
    saveScannedMapLocations();

    if (mapInstance) {
        renderStoredMapLocations();
    }
}

function clearAllMapLocations() {
    if (!scannedThreatLocations.length) {
        showToast('No saved map locations to clear', 'info');
        return;
    }

    scannedThreatLocations.length = 0;
    saveScannedMapLocations();
    renderStoredMapLocations();
    showToast('Saved map locations cleared', 'success');
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
        attribution: '(c) OpenStreetMap contributors',
        maxZoom: 19
    }).addTo(mapInstance);

    // Render only saved manual scan markers.
    renderStoredMapLocations();

    // Setup map controls
    document.getElementById('toggleHeatmap').addEventListener('click', () => {
        showToast('Heatmap view toggled', 'success');
    });

    document.getElementById('resetMapView').addEventListener('click', () => {
        mapInstance.setView([20, 0], 2);
        showToast('Map view reset', 'success');
    });

    const clearMapLocationsBtn = document.getElementById('clearMapLocations');
    if (clearMapLocationsBtn) {
        clearMapLocationsBtn.addEventListener('click', clearAllMapLocations);
    }
}

// ========== ALERTS TAB ==========

function initializeAlerts() {
    const filterBtns = document.querySelectorAll('.filter-btn');
    const searchInput = document.getElementById('alertsSearch');
    const sortSelect = document.getElementById('alertsSort');

    filterBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            filterBtns.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentAlertFilter = e.target.getAttribute('data-filter');
            displayAlerts(currentAlertFilter);
        });
    });

    if (searchInput) {
        searchInput.addEventListener('input', () => displayAlerts(currentAlertFilter));
    }

    if (sortSelect) {
        sortSelect.addEventListener('change', () => displayAlerts(currentAlertFilter));
    }

    displayAlerts('all');
    loadAlertsFromBackend(currentAlertFilter);

    if (!alertsRefreshTimer) {
        alertsRefreshTimer = setInterval(() => {
            loadAlertsFromBackend(currentAlertFilter, false);
        }, 10000);
    }
}

function getFilteredAlerts(filter = currentAlertFilter) {
    const searchInput = document.getElementById('alertsSearch');
    const sortSelect = document.getElementById('alertsSort');
    const search = (searchInput?.value || '').trim().toLowerCase();
    const sort = sortSelect?.value || 'last-desc';

    let filtered = alertsData.filter(alert => {
        const matchesFilter = filter === 'all' || alert.severity === filter;
        const matchesSearch = !search ||
            String(alert.ip || '').toLowerCase().includes(search) ||
            String(alert.type || '').toLowerCase().includes(search) ||
            String(alert.description || '').toLowerCase().includes(search) ||
            String(alert.source || '').toLowerCase().includes(search);
        return matchesFilter && matchesSearch;
    });

    filtered.sort((a, b) => {
        const aTs = Date.parse(a.lastSeen || a.time) || 0;
        const bTs = Date.parse(b.lastSeen || b.time) || 0;
        const aAttempts = Number(a.attemptCount) || 0;
        const bAttempts = Number(b.attemptCount) || 0;
        const aSeverity = getSeverityRank(a.severity);
        const bSeverity = getSeverityRank(b.severity);

        switch (sort) {
            case 'last-asc':
                return aTs - bTs;
            case 'attempts-desc':
                return bAttempts - aAttempts;
            case 'attempts-asc':
                return aAttempts - bAttempts;
            case 'severity-desc':
                return bSeverity - aSeverity || bTs - aTs;
            case 'severity-asc':
                return aSeverity - bSeverity || bTs - aTs;
            case 'last-desc':
            default:
                return bTs - aTs;
        }
    });

    return filtered;
}

function displayAlerts(filter = currentAlertFilter) {
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

    const filtered = getFilteredAlerts(filter);

    filtered.forEach(alert => {
        const card = document.createElement('div');
        card.className = `alert-card ${alert.severity}`;
        card.innerHTML = `
            <div class="alert-card-header">
                <span class="alert-type">${escapeHtml(alert.type)}</span>
                <span class="alert-severity ${escapeHtml(alert.severity)}">${escapeHtml(alert.severity)}</span>
            </div>
            <div class="alert-details">
                <div class="alert-detail-row">
                    <label>IP Address</label>
                    <value><code>${escapeHtml(alert.ip)}</code></value>
                </div>
                <div class="alert-detail-row">
                    <label>Description</label>
                    <value>${escapeHtml(alert.description)}</value>
                </div>
            </div>
            <div class="alert-time">
                <i class="fas fa-clock"></i> Last seen at ${escapeHtml(alert.time)}
            </div>
            <div class="alert-actions-row">
                <button class="btn-action btn-details" type="button">
                    <i class="fas fa-expand"></i> Details
                </button>
                <button class="btn-action btn-block" type="button">
                    <i class="fas fa-ban"></i> Block
                </button>
            </div>
        `;
        card.querySelector('.btn-details').addEventListener('click', () => showAlertDetails(alert.id));
        card.querySelector('.btn-block').addEventListener('click', () => blockIP(alert.ip));
        container.appendChild(card);
    });

    if (filtered.length === 0) {
        container.innerHTML = '<p style="grid-column: 1/-1; text-align: center; color: var(--text-secondary); padding: 2rem;">No alerts found</p>';
    }

    updateKPICards();
}

function normalizeAlert(alert) {
    const attemptCount = Number(alert?.attemptCount || alert?.attempt_count || 1) || 1;
    return {
        id: String(alert?.id || `alert-${Date.now()}`),
        type: alert?.type || alert?.alert_type || 'Threat Alert',
        ip: alert?.ip || alert?.ip_address || 'Unknown',
        severity: getAlertSeverityFromAttempts(attemptCount, alert?.severity),
        firstSeen: alert?.firstSeen || alert?.first_seen || alert?.created_at || '',
        lastSeen: alert?.lastSeen || alert?.last_seen || alert?.updated_at || alert?.time || '',
        time: alert?.time || alert?.lastSeen || alert?.last_seen || alert?.updated_at || new Date().toLocaleString(),
        description: alert?.description || alert?.logLine || 'No description available',
        attemptCount,
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
        const previousAlertsById = new Map(alertsData.map(alert => [String(alert.id), alert]));
        const isInitialAlertLoad = !hasBootstrappedBackendAlerts;

        if (isInitialAlertLoad) {
            nextAlertIds.forEach(alertId => shownAlertIds.add(String(alertId)));
            saveShownAlertIds();
            hasBootstrappedBackendAlerts = true;
        } else {
            nextAlerts.forEach(alert => {
                const alertId = String(alert.id);
                const previousAlert = previousAlertsById.get(alertId);
                if (!shownAlertIds.has(alertId)) {
                    showRealtimeAlertPopup(alert);
                    shownAlertIds.add(alertId);
                } else if (shouldShowGroupedAlertPopup(alert, previousAlert)) {
                    showRealtimeAlertPopup(alert);
                }
            });
            saveShownAlertIds();
        }

        alertsData = nextAlerts;
        knownAlertIds = nextAlertIds;
        displayAlerts(filter);
        loadAlertStatsFromBackend(false);
    } catch (error) {
        console.error('Failed to load alerts:', error);
        alertsData = [...fallbackAlerts];
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
        shownAlertIds = new Set();
        localStorage.removeItem(SHOWN_ALERTS_STORAGE_KEY);
        displayAlerts('all');
        loadAlertStatsFromBackend(false);
        showToast('All alerts cleared', 'success');
    } catch (error) {
        console.error('Failed to clear alerts:', error);
        showToast(`Failed to clear alerts: ${error.message}`, 'error');
    }
}

function getAlertExportHeaders() {
    return [
        { label: 'IP Address', value: 'ip' },
        { label: 'Attack Type', value: 'type' },
        { label: 'Severity', value: 'severity' },
        { label: 'Attempts', value: 'attemptCount' },
        { label: 'First Seen', value: 'firstSeen' },
        { label: 'Last Seen', value: 'lastSeen' },
        { label: 'Target IP', value: 'targetIp' },
        { label: 'Description', value: 'description' },
        { label: 'Log Entry', value: 'logLine' },
        { label: 'Source', value: 'source' }
    ];
}

function exportAlertsCsv() {
    exportRowsToCsv('alerts-export.csv', getAlertExportHeaders(), getFilteredAlerts(currentAlertFilter));
}

function exportAlertsPdf() {
    exportRowsToPdf('Alerts Export', getAlertExportHeaders(), getFilteredAlerts(currentAlertFilter));
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
        flag: log?.flag || getCountryBadge(log?.country || ''),
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
        initializeMockLogs();
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

function getLogExportHeaders() {
    return [
        { label: 'IP Address', value: 'ip' },
        { label: 'Country', value: 'country' },
        { label: 'Threat Score', value: row => formatScore(row.score) },
        { label: 'API Source', value: 'api' },
        { label: 'Date & Time', value: 'date' },
        { label: 'Status', value: row => formatLogStatus(row.status) }
    ];
}

function exportLogsCsv() {
    exportRowsToCsv('scan-logs-export.csv', getLogExportHeaders(), getFilteredLogs());
}

function exportLogsPdf() {
    exportRowsToPdf('Scan Logs Export', getLogExportHeaders(), getFilteredLogs());
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
            <td><code>${escapeHtml(log.ip)}</code></td>
            <td>
                <span class="country-cell">
                    <span class="flag">${escapeHtml(log.flag)}</span>${escapeHtml(log.country)}
                </span>
            </td>
            <td><span class="threat-score-badge ${threatLevel}">${formatScore(log.score)}</span></td>
            <td>${escapeHtml(log.api)}</td>
            <td>${escapeHtml(log.date)}</td>
            <td><span class="status-badge-log ${(log.status || '').toLowerCase()}">${formatLogStatus(log.status)}</span></td>
            <td>
                <button class="btn-action btn-details ${isExpanded ? 'active' : ''}" type="button">
                    <i class="fas ${isExpanded ? 'fa-chevron-up' : 'fa-chevron-down'}"></i>
                </button>
            </td>
        `;
        row.querySelector('.btn-details').addEventListener('click', () => expandLogDetail(log.id));
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
            const resultCountry = result.country ? normalizeCountryInfo(result.country).country : '';
            return `
                <div style="border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 10px;">
                    <div style="display:flex; justify-content:space-between; gap:8px;">
                        <strong>${escapeHtml(result.name || 'API')}</strong>
                        <span>${escapeHtml(status)}</span>
                    </div>
                    <div style="margin-top:6px; font-size:0.9rem; color:#c7d0e0;">
                        Score: ${result.score ?? 0}/100
                        ${resultCountry ? `<br>Country: ${escapeHtml(resultCountry)}` : ''}
                        ${result.error ? `<br>Error: ${escapeHtml(result.error)}` : ''}
                    </div>
                </div>
            `;
        }).join('')
        : '<div style="color:#c7d0e0;">No API detail available for this entry.</div>';

    return `
        <div style="padding: 12px; background: rgba(0,0,0,0.2); border-radius: 8px;">
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-bottom: 10px;">
                <div><strong>IP/Target:</strong> <code>${escapeHtml(log.ip)}</code></div>
                <div><strong>Country:</strong> ${escapeHtml(log.flag)} ${escapeHtml(log.country)}</div>
                <div><strong>Threat:</strong> <span class="threat-score-badge ${threatLevel}">${formatScore(log.score)}</span></div>
                <div><strong>Status:</strong> ${escapeHtml(formatLogStatus(log.status))}</div>
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
    initializeMockLogs();
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
    },
    edr: {
        refresh: loadEDRDashboardFromBackend,
        respond: submitEDRResponse
    }
};
