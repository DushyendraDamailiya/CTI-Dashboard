#!/usr/bin/env python3
"""
Threat Intelligence Dashboard - Backend Proxy Server
Handles CORS, rate limiting, caching, and API proxying
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_caching import Cache
from dotenv import load_dotenv
import requests
import os
import logging
from datetime import datetime, timedelta
import re
from functools import wraps
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import subprocess
import platform
import json
try:
    import mysql.connector
    from mysql.connector import pooling
except ImportError:  # pragma: no cover - handled at runtime
    mysql = None
    pooling = None

# Suppress SSL warnings for production
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Load environment variables from .env if present
load_dotenv()

# ============================================
# CONFIGURATION
# ============================================

app = Flask(__name__)

def get_cors_origins():
    """Load allowed CORS origins from environment."""
    origins_raw = os.getenv(
        'CORS_ORIGINS',
        'http://localhost:3000,http://localhost:5173,http://localhost:5500,http://127.0.0.1:5500,null'
    )
    return [origin.strip() for origin in origins_raw.split(',') if origin.strip()]

def get_required_env(name):
    """Load required environment variable or fail fast."""
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f'Missing required environment variable: {name}')
    return value

def get_optional_env(name, default=None):
    """Load optional environment variable with default."""
    return os.getenv(name, default)

CORS(app, resources={r"/api/*": {"origins": get_cors_origins()}})

# Configure caching (in-memory, 1 hour expiration)
cache_config = {
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 3600
}
cache = Cache(app, config=cache_config)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MYSQL_ENABLED = get_optional_env('MYSQL_ENABLED', 'false').lower() == 'true'
MYSQL_CONFIG = {
    'host': get_optional_env('MYSQL_HOST', '127.0.0.1'),
    'port': int(get_optional_env('MYSQL_PORT', '3306')),
    'user': get_optional_env('MYSQL_USER', 'root'),
    'password': get_optional_env('MYSQL_PASSWORD', ''),
    'database': get_optional_env('MYSQL_DATABASE', 'threat_dashboard'),
}
MYSQL_POOL_SIZE = int(get_optional_env('MYSQL_POOL_SIZE', '5'))
mysql_pool = None

# API Configuration
API_CONFIG = {
    'abuseipdb': {
        'endpoint': 'https://api.abuseipdb.com/api/v2/check',
        'key': get_required_env('ABUSEIPDB_KEY'),
        'header_name': 'Key',
        'method': 'GET',
        'timeout': 10
    },
    'virustotal': {
        'endpoint': 'https://www.virustotal.com/api/v3/ip_addresses',
        'key': get_required_env('VIRUSTOTAL_KEY'),
        'header_name': 'x-apikey',
        'method': 'GET',
        'timeout': 10
    },
    'alienvault': {
        'endpoint': 'https://otx.alienvault.com/api/v1/indicators/ip',
        'key': get_required_env('ALIENVAULT_KEY'),
        'header_name': 'X-OTX-API-KEY',
        'method': 'GET',
        'timeout': 10
    },
    'greynoise': {
        'endpoint': 'https://api.greynoise.io/v3/community',
        'key': get_required_env('GREYNOISE_KEY'),
        'header_name': 'key',
        'method': 'GET',
        'timeout': 10
    },
    'ipqualityscore': {
        'endpoint': 'https://www.ipqualityscore.com/api/json/ip',
        'key': get_optional_env('IPQUALITYSCORE_KEY'),
        'method': 'GET',
        'timeout': 10
    }
}

# Rate limiting
REQUEST_LIMIT = 100  # requests per hour per IP
rate_limit_store = {}
blocked_ips = {}


def mysql_available():
    """Return True when MySQL persistence is configured and the driver exists."""
    return MYSQL_ENABLED and mysql is not None and pooling is not None


def get_mysql_connection():
    """Borrow a MySQL connection from the configured pool."""
    if not mysql_pool:
        raise RuntimeError('MySQL connection pool is not initialized')
    return mysql_pool.get_connection()


def init_mysql():
    """Create the database, initialize the pool, and ensure required tables exist."""
    global mysql_pool

    if not MYSQL_ENABLED:
        logger.info('MySQL persistence disabled')
        return

    if not mysql_available():
        raise RuntimeError('MYSQL_ENABLED=true but mysql-connector-python is not installed')

    bootstrap_conn = mysql.connector.connect(
        host=MYSQL_CONFIG['host'],
        port=MYSQL_CONFIG['port'],
        user=MYSQL_CONFIG['user'],
        password=MYSQL_CONFIG['password'],
    )
    try:
        bootstrap_cursor = bootstrap_conn.cursor()
        bootstrap_cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{MYSQL_CONFIG['database']}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        bootstrap_cursor.close()
        bootstrap_conn.commit()
    finally:
        bootstrap_conn.close()

    mysql_pool = pooling.MySQLConnectionPool(
        pool_name='threat_dashboard_pool',
        pool_size=max(1, MYSQL_POOL_SIZE),
        host=MYSQL_CONFIG['host'],
        port=MYSQL_CONFIG['port'],
        user=MYSQL_CONFIG['user'],
        password=MYSQL_CONFIG['password'],
        database=MYSQL_CONFIG['database'],
    )

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                alert_type VARCHAR(255) NOT NULL,
                source VARCHAR(100) NOT NULL DEFAULT 'attack_detector',
                ip_address VARCHAR(45) NOT NULL,
                severity VARCHAR(20) NOT NULL DEFAULT 'medium',
                description TEXT,
                target_ip VARCHAR(45),
                log_line TEXT,
                attempt_count INT NOT NULL DEFAULT 1,
                raw_payload JSON,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_alerts_created_at (created_at),
                INDEX idx_alerts_severity (severity),
                INDEX idx_alerts_ip_address (ip_address)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                country VARCHAR(100) NOT NULL DEFAULT 'Unknown',
                country_code VARCHAR(8),
                threat_score INT NOT NULL DEFAULT 0,
                api_sources TEXT,
                status VARCHAR(32) NOT NULL DEFAULT 'monitored',
                scan_results JSON,
                overall_data JSON,
                last_scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_threat_logs_ip_address (ip_address),
                INDEX idx_threat_logs_score (threat_score),
                INDEX idx_threat_logs_last_scanned_at (last_scanned_at)
            )
            """
        )
        conn.commit()
        cursor.close()
        logger.info('MySQL tables ensured successfully')
    finally:
        conn.close()


def normalize_country_value(raw_country):
    """Split a raw country value into display value and ISO-style code when available."""
    if not raw_country:
        return 'Unknown', None

    country = str(raw_country).strip()
    if re.match(r'^[A-Z]{2}$', country):
        return country, country
    return country, None


def compute_log_status(score):
    """Map a threat score to the log status used by the frontend."""
    if score >= 80:
        return 'blocked'
    if score >= 40:
        return 'monitored'
    return 'whitelisted'


def save_threat_log(ip_address, scan_payload):
    """Persist a manual IP scan to MySQL without allowing duplicate rows for the same IP."""
    if not mysql_available() or not is_valid_ipv4(ip_address):
        return

    results = scan_payload.get('results', [])
    successful = [result for result in results if result.get('success')]
    score = int(scan_payload.get('overall', {}).get('averageScore', 0) or 0)
    best_country = extract_best_country(successful) or 'Unknown'
    country, country_code = normalize_country_value(best_country)
    api_sources = ', '.join(result.get('name', 'Unknown API') for result in successful) or 'N/A'
    status = compute_log_status(score)

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO threat_logs (
                ip_address, country, country_code, threat_score, api_sources,
                status, scan_results, overall_data, last_scanned_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                country = VALUES(country),
                country_code = VALUES(country_code),
                threat_score = VALUES(threat_score),
                api_sources = VALUES(api_sources),
                status = VALUES(status),
                scan_results = VALUES(scan_results),
                overall_data = VALUES(overall_data),
                last_scanned_at = VALUES(last_scanned_at),
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                ip_address,
                country,
                country_code,
                score,
                api_sources,
                status,
                json.dumps(results),
                json.dumps(scan_payload.get('overall', {})),
                datetime.now(),
            )
        )
        conn.commit()
        cursor.close()
    finally:
        conn.close()


def save_alert(alert_payload):
    """Persist a real-time alert to MySQL."""
    if not mysql_available():
        return None

    severity = str(alert_payload.get('severity', 'medium')).lower()
    attacker_ip = (
        alert_payload.get('attacker_ip')
        or alert_payload.get('ip')
        or alert_payload.get('ip_address')
        or 'Unknown'
    )
    alert_type = alert_payload.get('name') or alert_payload.get('type') or 'Threat Alert'
    description = alert_payload.get('description') or alert_payload.get('log_line') or alert_type

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO alerts (
                alert_type, source, ip_address, severity, description,
                target_ip, log_line, attempt_count, raw_payload
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                alert_type,
                str(alert_payload.get('source', 'attack_detector')),
                attacker_ip,
                severity,
                description,
                alert_payload.get('target_ip'),
                alert_payload.get('log_line'),
                int(alert_payload.get('attempt_count', 1) or 1),
                json.dumps(alert_payload),
            )
        )
        conn.commit()
        alert_id = cursor.lastrowid
        cursor.close()
        return alert_id
    finally:
        conn.close()


def serialize_alert_row(row):
    """Convert an alerts row into the frontend response shape."""
    return {
        'id': row[0],
        'type': row[1],
        'source': row[2],
        'ip': row[3],
        'severity': row[4],
        'description': row[5] or '',
        'targetIp': row[6],
        'logLine': row[7],
        'attemptCount': row[8],
        'time': row[9].strftime('%Y-%m-%d %H:%M:%S') if row[9] else '',
    }


def fetch_alerts(limit=100):
    """Load recent alerts from MySQL."""
    if not mysql_available():
        return []

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, alert_type, source, ip_address, severity, description,
                   target_ip, log_line, attempt_count, created_at
            FROM alerts
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (max(1, int(limit)),)
        )
        rows = cursor.fetchall()
        cursor.close()
        return [serialize_alert_row(row) for row in rows]
    finally:
        conn.close()


def clear_alerts():
    """Delete all stored real-time alerts from MySQL."""
    if not mysql_available():
        return 0

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts")
        deleted_rows = cursor.rowcount
        conn.commit()
        cursor.close()
        return deleted_rows
    finally:
        conn.close()


def serialize_threat_log_row(row):
    """Convert a threat_logs row into the frontend response shape."""
    country = row[2] or 'Unknown'
    country_code = row[3]
    if country_code and re.match(r'^[A-Z]{2}$', country_code):
        flag = ''.join(chr(ord(char) + 127397) for char in country_code)
    else:
        flag = '??'

    try:
        scan_results = json.loads(row[6]) if row[6] else []
    except (TypeError, json.JSONDecodeError):
        scan_results = []

    return {
        'id': str(row[0]),
        'ip': row[1],
        'country': country,
        'flag': flag,
        'score': int(row[4] or 0),
        'api': row[5] or 'N/A',
        'status': row[7] or 'monitored',
        'scanResults': scan_results,
        'date': row[8].strftime('%Y-%m-%d %H:%M:%S') if row[8] else '',
        'timestamp': int(row[8].timestamp() * 1000) if row[8] else 0,
    }


def fetch_threat_logs(limit=500):
    """Load manual IP scan history from MySQL."""
    if not mysql_available():
        return []

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, ip_address, country, country_code, threat_score, api_sources,
                   scan_results, status, last_scanned_at
            FROM threat_logs
            ORDER BY last_scanned_at DESC
            LIMIT %s
            """,
            (max(1, int(limit)),)
        )
        rows = cursor.fetchall()
        cursor.close()
        return [serialize_threat_log_row(row) for row in rows]
    finally:
        conn.close()

# ============================================
# VALIDATION FUNCTIONS
# ============================================

def is_valid_ipv4(ip):
    """Validate IPv4 address"""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ipv4_pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

def is_valid_domain(domain):
    """Validate domain name"""
    domain_pattern = r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return re.match(domain_pattern, domain, re.IGNORECASE) is not None

def is_valid_hash(hash_value):
    """Validate MD5, SHA1, or SHA256 hash"""
    if len(hash_value) == 32 or len(hash_value) == 40 or len(hash_value) == 64:
        return re.match(r'^[a-f0-9]+$', hash_value, re.IGNORECASE) is not None
    return False

# ============================================
# FIREWALL/SYSTEM-LEVEL IP BLOCKING
# ============================================

def block_ip_firewall(ip):
    """Block IP at the firewall/system level (cross-platform)"""
    system = platform.system()
    
    try:
        if system == 'Darwin':  # macOS
            return block_ip_macos(ip)
        elif system == 'Linux':
            return block_ip_linux(ip)
        elif system == 'Windows':
            return block_ip_windows(ip)
        else:
            return False, f"Unsupported OS: {system}"
    except Exception as e:
        logger.error(f"Firewall blocking error on {system}: {str(e)}")
        return False, str(e)

def block_ip_macos(ip):
    """Block IP on macOS using route command (requires sudo)"""
    try:
        # Method 1: Using route (no sudo needed)
        result = subprocess.run(
            ['sudo', 'route', 'add', '-net', ip, '127.0.0.1'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            logger.info(f"Successfully blocked IP {ip} on macOS")
            return True, f"IP {ip} blocked via route"
        else:
            error_msg = result.stderr or result.stdout
            # IP might already be blocked
            if 'EEXIST' in error_msg or 'already exists' in error_msg:
                return True, f"IP {ip} already in blocklist"
            raise Exception(error_msg)
    except subprocess.TimeoutExpired:
        return False, "Timeout: macOS firewall blocking"
    except Exception as e:
        logger.error(f"macOS blocking error: {str(e)}")
        return False, str(e)

def block_ip_linux(ip):
    """Block IP on Linux using iptables (requires sudo)"""
    try:
        # Drop incoming packets from the IP
        result = subprocess.run(
            ['sudo', 'iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            logger.info(f"Successfully blocked IP {ip} on Linux")
            return True, f"IP {ip} blocked via iptables"
        else:
            error_msg = result.stderr or result.stdout
            if 'No such file' in error_msg:
                return False, "iptables not found - try 'sudo apt-get install iptables'"
            raise Exception(error_msg)
    except subprocess.TimeoutExpired:
        return False, "Timeout: Linux firewall blocking"
    except Exception as e:
        logger.error(f"Linux blocking error: {str(e)}")
        return False, str(e)

def block_ip_windows(ip):
    """Block IP on Windows using netsh (requires admin)"""
    try:
        # Use netsh advfirewall
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
             'name=BlockIP_' + ip.replace('.', '_'),
             'dir=in', 'action=block',
             'remoteip=' + ip,
             'protocol=any'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            logger.info(f"Successfully blocked IP {ip} on Windows")
            return True, f"IP {ip} blocked via Windows Firewall"
        else:
            error_msg = result.stderr or result.stdout
            if 'already exists' in error_msg.lower():
                return True, f"IP {ip} already in Windows Firewall blocklist"
            raise Exception(error_msg)
    except subprocess.TimeoutExpired:
        return False, "Timeout: Windows firewall blocking"
    except Exception as e:
        logger.error(f"Windows blocking error: {str(e)}")
        return False, str(e)

def unblock_ip_firewall(ip):
    """Unblock IP at the firewall/system level"""
    system = platform.system()
    
    try:
        if system == 'Darwin':  # macOS
            return unblock_ip_macos(ip)
        elif system == 'Linux':
            return unblock_ip_linux(ip)
        elif system == 'Windows':
            return unblock_ip_windows(ip)
        else:
            return False, f"Unsupported OS: {system}"
    except Exception as e:
        logger.error(f"Firewall unblocking error on {system}: {str(e)}")
        return False, str(e)

def unblock_ip_macos(ip):
    """Unblock IP on macOS"""
    try:
        result = subprocess.run(
            ['sudo', 'route', 'delete', '-net', ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            logger.info(f"Successfully unblocked IP {ip} on macOS")
            return True, f"IP {ip} unblocked"
        else:
            raise Exception(result.stderr or result.stdout)
    except Exception as e:
        return False, str(e)

def unblock_ip_linux(ip):
    """Unblock IP on Linux"""
    try:
        result = subprocess.run(
            ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            logger.info(f"Successfully unblocked IP {ip} on Linux")
            return True, f"IP {ip} unblocked"
        else:
            raise Exception(result.stderr or result.stdout)
    except Exception as e:
        return False, str(e)

def unblock_ip_windows(ip):
    """Unblock IP on Windows"""
    try:
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
             'name=BlockIP_' + ip.replace('.', '_')],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            logger.info(f"Successfully unblocked IP {ip} on Windows")
            return True, f"IP {ip} unblocked"
        else:
            raise Exception(result.stderr or result.stdout)
    except Exception as e:
        return False, str(e)

def validate_input(target, target_type='auto'):
    """Validate input based on type"""
    target = target.strip()
    
    if target_type == 'auto':
        if is_valid_ipv4(target):
            return True, 'ip'
        elif is_valid_domain(target):
            return True, 'domain'
        elif is_valid_hash(target):
            return True, 'hash'
        else:
            return False, 'Invalid target: Must be a valid IPv4, domain, or hash'
    else:
        if target_type == 'ip' and is_valid_ipv4(target):
            return True, 'ip'
        elif target_type == 'domain' and is_valid_domain(target):
            return True, 'domain'
        elif target_type == 'hash' and is_valid_hash(target):
            return True, 'hash'
        else:
            return False, f'Invalid {target_type}: {target}'

# ============================================
# RATE LIMITING
# ============================================

def rate_limit(func):
    """Rate limit decorator"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr
        current_time = datetime.now()
        
        # Initialize rate limit store for IP
        if client_ip not in rate_limit_store:
            rate_limit_store[client_ip] = []
        
        # Remove old requests (older than 1 hour)
        rate_limit_store[client_ip] = [
            req_time for req_time in rate_limit_store[client_ip]
            if (current_time - req_time).total_seconds() < 3600
        ]
        
        # Check limit
        if len(rate_limit_store[client_ip]) >= REQUEST_LIMIT:
            return jsonify({
                'success': False,
                'error': f'Rate limit exceeded: {REQUEST_LIMIT} requests per hour'
            }), 429
        
        # Add current request
        rate_limit_store[client_ip].append(current_time)
        return func(*args, **kwargs)
    
    return wrapper

# ============================================
# API PROXY FUNCTIONS
# ============================================

def query_abuseipdb(target):
    """Query AbuseIPDB API"""
    config = API_CONFIG['abuseipdb']
    
    try:
        headers = {
            config['header_name']: config['key'],
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': target,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        response = requests.get(
            config['endpoint'],
            headers=headers,
            params=params,
            timeout=config['timeout']
        )
        response.raise_for_status()
        
        api_data = response.json()
        
        return {
            'name': 'AbuseIPDB',
            'score': api_data.get('data', {}).get('abuseConfidenceScore', 0),
            'reports': api_data.get('data', {}).get('totalReports', 0),
            'isMalicious': api_data.get('data', {}).get('abuseConfidenceScore', 0) > 50,
            'usageType': api_data.get('data', {}).get('usageType', 'Unknown'),
            'isp': api_data.get('data', {}).get('isp', 'Unknown'),
            'domain': api_data.get('data', {}).get('domain', 'Unknown'),
            'lastReportedAt': api_data.get('data', {}).get('lastReportedAt', 'Never'),
            'numDistinctUsers': api_data.get('data', {}).get('numDistinctUsers', 0),
            'success': True
        }
    except requests.exceptions.RequestException as e:
        logger.error(f'AbuseIPDB Error: {str(e)}')
        return {
            'name': 'AbuseIPDB',
            'error': str(e),
            'success': False,
            'score': 0,
            'isMalicious': False
        }

def query_virustotal(target):
    """Query VirusTotal API"""
    config = API_CONFIG['virustotal']
    
    try:
        headers = {
            config['header_name']: config['key'],
            'Accept': 'application/json'
        }
        
        url = f"{config['endpoint']}/{target}"
        response = requests.get(
            url,
            headers=headers,
            timeout=config['timeout']
        )
        response.raise_for_status()
        
        api_data = response.json()
        attributes = api_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        malicious = stats.get('malicious', 0)
        total = sum(stats.values())
        score = (malicious / total * 100) if total > 0 else 0
        
        return {
            'name': 'VirusTotal',
            'score': round(score),
            'maliciousVendors': malicious,
            'suspiciousVendors': stats.get('suspicious', 0),
            'harmlessVendors': stats.get('harmless', 0),
            'totalVendors': total,
            'isMalicious': malicious > 0 or stats.get('suspicious', 0) > 3,
            'country': attributes.get('country', 'Unknown'),
            'asn': attributes.get('asn', 'Unknown'),
            'lastAnalysisDate': datetime.fromtimestamp(
                attributes.get('last_analysis_date', 0)
            ).strftime('%Y-%m-%d %H:%M:%S') if attributes.get('last_analysis_date') else 'Never',
            'success': True
        }
    except requests.exceptions.RequestException as e:
        logger.error(f'VirusTotal Error: {str(e)}')
        return {
            'name': 'VirusTotal',
            'error': str(e),
            'success': False,
            'score': 0,
            'isMalicious': False
        }

def query_alienvault(target):
    """Query AlienVault OTX API"""
    config = API_CONFIG['alienvault']
    
    try:
        headers = {
            config['header_name']: config['key'],
            'Accept': 'application/json'
        }
        
        # Use /general endpoint for basic IP reputation
        url = f"{config['endpoint']}/{target}/general"
        response = requests.get(
            url,
            headers=headers,
            timeout=20  # Increased timeout - AlienVault is slow
        )
        
        # AlienVault returns 404 for unknown IPs (which is fine - not a threat)
        if response.status_code == 404:
            return {
                'name': 'AlienVault OTX',
                'score': 0,
                'pulseCount': 0,
                'reputation': 0,
                'isMalicious': False,
                'whitelisted': False,
                'asn': 'Unknown',
                'country': 'Unknown',
                'lastSeen': 'Never',
                'firstSeen': 'Unknown',
                'success': True
            }
        
        response.raise_for_status()
        
        api_data = response.json()
        
        pulse_count = api_data.get('pulse_info', {}).get('count', 0)
        reputation = api_data.get('reputation', 0)
        
        score = min(100, (pulse_count * 10) + (abs(reputation) * 5)) if (pulse_count > 0 or reputation < 0) else 0
        
        return {
            'name': 'AlienVault OTX',
            'score': score,
            'pulseCount': pulse_count,
            'reputation': reputation,
            'isMalicious': pulse_count > 0 or reputation < 0,
            'whitelisted': api_data.get('whitelisted', False),
            'asn': api_data.get('asn', 'Unknown'),
            'country': api_data.get('country_code', 'Unknown'),
            'lastSeen': api_data.get('last_seen', 'Never'),
            'firstSeen': api_data.get('first_seen', 'Unknown'),
            'success': True
        }
    except requests.exceptions.RequestException as e:
        logger.error(f'AlienVault Error: {str(e)}')
        # If it's just a timeout or connection error, return success with zero score
        return {
            'name': 'AlienVault OTX',
            'score': 0,
            'pulseCount': 0,
            'reputation': 0,
            'isMalicious': False,
            'whitelisted': False,
            'asn': 'Unknown',
            'country': 'Unknown',
            'lastSeen': 'Never',
            'firstSeen': 'Unknown',
            'success': True
        }

def get_scan_tasks(target, target_type):
    """Return API tasks based on target type."""
    tasks = {
        'AbuseIPDB': lambda: query_abuseipdb(target),
        'VirusTotal': lambda: query_virustotal(target),
        'AlienVault': lambda: query_alienvault(target),
        'GreyNoise': lambda: query_greynoise(target)
    }
    
    # IPQualityScore only supports IPv4 addresses and requires API key
    if target_type == 'ip' and is_valid_ipv4(target) and API_CONFIG['ipqualityscore']['key']:
        tasks['IPQualityScore'] = lambda: query_ipqualityscore(target)
    
    return tasks

def query_greynoise(target):
    """Query GreyNoise API (Community Version)"""
    config = API_CONFIG['greynoise']
    
    try:
        headers = {
            'Accept': 'application/json'
        }
        
        # Add key as query parameter for community API
        params = {'key': config['key']}
        
        url = f"{config['endpoint']}/{target}"
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=config['timeout']
        )
        
        # GreyNoise returns 404 for IPs not in their database
        # GreyNoise returns 400 for private/reserved IPs (which is fine)
        if response.status_code in [404, 400]:
            return {
                'name': 'GreyNoise',
                'score': 0,
                'classification': 'unknown',
                'isMalicious': False,
                'isSuspicious': False,
                'seen': False,
                'lastSeen': 'Never',
                'firstSeen': 'Unknown',
                'intentions': 'Unknown',
                'tags': [],
                'success': True
            }
        
        # Handle rate limiting (429) - return gracefully
        if response.status_code == 429:
            logger.warning('GreyNoise API rate limited (429)')
            return {
                'name': 'GreyNoise',
                'score': 0,
                'classification': 'unknown',
                'isMalicious': False,
                'isSuspicious': False,
                'seen': False,
                'lastSeen': 'Never',
                'firstSeen': 'Unknown',
                'intentions': 'Rate limit exceeded',
                'tags': [],
                'success': True
            }
        
        response.raise_for_status()
        
        api_data = response.json()
        
        classification = api_data.get('classification', 'unknown')
        
        if classification == 'malicious':
            score = 95
        elif classification == 'suspicious':
            score = 65
        elif classification == 'benign':
            score = 10
        else:
            score = 0
        
        return {
            'name': 'GreyNoise',
            'score': score,
            'classification': classification,
            'isMalicious': classification == 'malicious',
            'isSuspicious': classification == 'suspicious',
            'seen': api_data.get('seen', False),
            'lastSeen': api_data.get('last_seen', 'Never'),
            'firstSeen': api_data.get('first_seen', 'Unknown'),
            'intentions': api_data.get('intentions', 'Unknown'),
            'tags': api_data.get('tags', []),
            'success': True
        }
    except requests.exceptions.RequestException as e:
        logger.error(f'GreyNoise Error: {str(e)}')
        # Return success with unknown classification on error
        return {
            'name': 'GreyNoise',
            'score': 0,
            'classification': 'unknown',
            'isMalicious': False,
            'isSuspicious': False,
            'seen': False,
            'lastSeen': 'Never',
            'firstSeen': 'Unknown',
            'intentions': 'Unknown',
            'tags': [],
            'success': True
        }

def query_ipqualityscore(target):
    """Query IPQualityScore API - Comprehensive fraud detection (IPv4 only)"""
    config = API_CONFIG['ipqualityscore']
    
    # Check if API key is configured
    if not config['key']:
        logger.warning('IPQualityScore API key not configured (IPQUALITYSCORE_KEY not in .env)')
        return {
            'name': 'IPQualityScore',
            'success': False,
            'error': 'IPQualityScore API key not configured',
            'score': 0,
            'isMalicious': False,
            'offline': True
        }
    
    # IPQualityScore works for IPv4 only
    if not is_valid_ipv4(target):
        return {
            'name': 'IPQualityScore',
            'success': False,
            'error': 'IPQualityScore only supports IPv4 addresses',
            'score': 0,
            'isMalicious': False
        }
    
    try:
        # Official API format: https://www.ipqualityscore.com/api/json/ip/{KEY}/{IP}
        url = f"{config['endpoint']}/{config['key']}/{target}"
        
        params = {
            'strictness': 1,  # 0=fastest, 1=recommended, 2=strict, 3=strictest
            'allow_public_access_points': 'true'  # Better accommodate research/academic IPs
        }
        
        response = requests.get(url, params=params, timeout=config['timeout'])
        response.raise_for_status()
        
        api_data = response.json()
        
        # Check API success flag
        if not api_data.get('success', False):
            logger.warning(f'IPQualityScore query failed for {target}: {api_data.get("message", "Unknown error")}')
            return {
                'name': 'IPQualityScore',
                'success': False,
                'error': api_data.get('message', 'API error'),
                'score': 0,
                'isMalicious': False
            }
        
        # Extract comprehensive fields from API response
        fraud_score = api_data.get('fraud_score', 0)  # 0-100
        
        # VPN/Proxy/Anonymity detection (active vs stored state)
        is_vpn = api_data.get('vpn', False)  # Ever detected as VPN
        is_active_vpn = api_data.get('active_vpn', False)  # Currently using VPN
        is_proxy = api_data.get('proxy', False)  # Ever detected as proxy
        is_tor = api_data.get('tor', False)  # TOR exit node
        is_active_tor = api_data.get('active_tor', False)  # Current TOR usage
        
        # Behavior indicators
        is_crawler = api_data.get('is_crawler', False)  # Search engine crawler
        is_bot = api_data.get('bot_status', False)  # General bot detection
        is_security_scanner = api_data.get('security_scanner', False)  # Security tools
        
        # Abuse indicators
        recent_abuse = api_data.get('recent_abuse', False)  # Recently abusive
        frequent_abuser = api_data.get('frequent_abuser', False)  # Chronic abuser
        high_risk_attacks = api_data.get('high_risk_attacks', False)  # Detected attacks
        abuse_velocity = api_data.get('abuse_velocity', 'low')  # Rate of abuse (low/medium/high)
        
        # Connection characteristics
        shared_connection = api_data.get('shared_connection', False)  # Shared network
        dynamic_connection = api_data.get('dynamic_connection', False)  # Dynamic IP (frequently changes)
        connection_type = api_data.get('connection_type', 'Unknown')  # Residential/Commercial/etc
        
        # Device & Fingerprinting
        is_mobile = api_data.get('mobile', False)  # Mobile device
        operating_system = api_data.get('operating_system', None)
        browser = api_data.get('browser', None)
        device_model = api_data.get('device_model', None)
        device_brand = api_data.get('device_brand', None)
        
        # Geo & ISP information
        country_code = api_data.get('country_code', 'Unknown')
        city = api_data.get('city', None)
        region = api_data.get('region', None)
        latitude = api_data.get('latitude', None)
        longitude = api_data.get('longitude', None)
        zip_code = api_data.get('zip_code', None)
        timezone = api_data.get('timezone', None)
        
        isp = api_data.get('ISP', 'Unknown')
        organization = api_data.get('organization', isp)
        asn = api_data.get('ASN', None)
        host = api_data.get('host', None)
        
        # Network trust indicators
        is_trusted_network = api_data.get('trusted_network', False)
        
        request_id = api_data.get('request_id', None)
        
        # ============================================
        # SOPHISTICATED FRAUD DETECTION LOGIC
        # ============================================
        
        # Determine base malicious score using multiple factors
        malicious_score = 0
        threat_types = []
        risk_indicators = []
        
        # High-risk anonymity indicators
        if is_active_vpn or is_active_tor:
            malicious_score += 35
            threat_types.append('Active-VPN' if is_active_vpn else 'Active-TOR')
            risk_indicators.append('Currently using VPN/TOR')
        elif is_vpn:
            malicious_score += 20
            threat_types.append('VPN')
            risk_indicators.append('VPN detected')
        elif is_proxy:
            malicious_score += 15
            threat_types.append('Proxy')
            risk_indicators.append('Proxy detected')
        elif is_tor:
            malicious_score += 25
            threat_types.append('TOR')
            risk_indicators.append('TOR exit node')
        
        # Abuse history scores
        if high_risk_attacks:
            malicious_score += 30
            threat_types.append('High-Risk-Attacks')
            risk_indicators.append('Detected high-risk attacks')
        
        if frequent_abuser:
            malicious_score += 25
            threat_types.append('Frequent-Abuser')
            risk_indicators.append('Known frequent abuser')
        
        if recent_abuse and abuse_velocity == 'high':
            malicious_score += 20
            threat_types.append('High-Velocity-Abuse')
            risk_indicators.append('Recent abuse at high velocity')
        elif recent_abuse:
            malicious_score += 10
            threat_types.append('Recent-Abuse')
            risk_indicators.append('Recent abuse detected')
        
        # Connection characteristics
        if shared_connection and not is_trusted_network:
            malicious_score += 5
            risk_indicators.append('Shared connection without trust status')
        
        if dynamic_connection and abuse_velocity in ['high', 'medium']:
            malicious_score += 8
            risk_indicators.append('Dynamic IP with abuse activity')
        
        # Bot/Crawler handling
        if is_security_scanner:
            malicious_score += 5
            threat_types.append('Security-Scanner')
            risk_indicators.append('Security scanner detected')
        
        if is_bot and not is_crawler:
            malicious_score += 20
            threat_types.append('Bot')
            risk_indicators.append('Bot traffic detected')
        elif is_crawler:
            malicious_score += 0  # Crawlers OK
            threat_types.append('Crawler')
            risk_indicators.append('Legitimate crawler')
        
        # Mobile device handling (less strict for mobile)
        if is_mobile and abuse_velocity == 'high':
            malicious_score += 10
            risk_indicators.append('Mobile device with high abuse velocity')
        elif is_mobile:
            malicious_score += 0  # Mobile devices generally OK
        
        # Fraud score from API (already calculated)
        if fraud_score >= 85:
            malicious_score += 25
            risk_indicators.append(f'Critical fraud score: {fraud_score}')
        elif fraud_score >= 75:
            malicious_score += 15
            risk_indicators.append(f'High fraud score: {fraud_score}')
        elif fraud_score >= 50:
            malicious_score += 8
            risk_indicators.append(f'Elevated fraud score: {fraud_score}')
        elif fraud_score >= 25:
            malicious_score += 3
            risk_indicators.append(f'Low fraud score: {fraud_score}')
        
        # Cap the malicious score at 100
        malicious_score = min(malicious_score + fraud_score // 2, 100)
        
        # Determine if malicious based on combined indicators
        is_malicious = (
            malicious_score >= 75 or
            is_active_vpn or
            is_active_tor or
            (fraud_score >= 80) or
            (high_risk_attacks and frequent_abuser)
        )
        
        # Build comprehensive response
        return {
            'name': 'IPQualityScore',
            'success': True,
            'score': malicious_score,
            'isMalicious': is_malicious,
            'request_id': request_id,
            
            # ============================================
            # IMPORTANT FREE-TIER RESULTS (TOP PRIORITY)
            # ============================================
            'important_results': {
                'fraud_score': fraud_score,
                'fraud_severity': (
                    'Critical (90+)' if fraud_score >= 90 else
                    'High Risk (85+)' if fraud_score >= 85 else
                    'Suspicious (75+)' if fraud_score >= 75 else
                    'Elevated' if fraud_score >= 50 else
                    'Low' if fraud_score >= 25 else
                    'Clean'
                ),
                'country': country_code,
                'city': city,
                'region': region,
                'timezone': timezone,
                'latitude': latitude,
                'longitude': longitude,
                'hostname': host,
                'isp': isp,
                'organization': organization,
                'asn': asn,
                'proxy_status': is_proxy,
                'vpn_status': is_vpn,
                'tor_status': is_tor,
                'bot_activity': is_bot,
                'recent_abuse': recent_abuse,
                'threat_summary': {
                    'overall_threat_level': 'Critical' if malicious_score >= 85 else 'High' if malicious_score >= 75 else 'Medium' if malicious_score >= 50 else 'Low',
                    'threat_types': threat_types,
                    'risk_indicators': risk_indicators[:5]
                }
            },
            
            # Full fraud score
            'fraud_score': fraud_score,
            
            # Anonymity
            'anonymity': {
                'is_vpn': is_vpn,
                'is_active_vpn': is_active_vpn,
                'is_proxy': is_proxy,
                'is_tor': is_tor,
                'is_active_tor': is_active_tor
            },
            
            # Abuse indicators
            'abuse': {
                'recent_abuse': recent_abuse,
                'frequent_abuser': frequent_abuser,
                'high_risk_attacks': high_risk_attacks,
                'abuse_velocity': abuse_velocity
            },
            
            # Bot/Automation
            'automation': {
                'is_bot': is_bot,
                'is_crawler': is_crawler,
                'is_security_scanner': is_security_scanner
            },
            
            # Connection info
            'connection': {
                'type': connection_type,
                'shared': shared_connection,
                'dynamic': dynamic_connection,
                'trusted': is_trusted_network
            },
            
            # Device fingerprinting
            'device': {
                'mobile': is_mobile,
                'os': operating_system,
                'browser': browser,
                'model': device_model,
                'brand': device_brand
            },
            
            # Location & ISP
            'location': {
                'country': country_code,
                'city': city,
                'region': region,
                'latitude': latitude,
                'longitude': longitude,
                'zip': zip_code,
                'timezone': timezone
            },
            
            'network': {
                'isp': isp,
                'organization': organization,
                'asn': asn,
                'host': host
            },
            
            # Threat summary
            'threat_types': threat_types,
            'risk_indicators': risk_indicators[:5],  # Top 5 risk indicators
            'request_id': request_id
        }
        
    except requests.exceptions.RequestException as e:
        logger.error(f'IPQualityScore Error: {str(e)}')
        return {
            'name': 'IPQualityScore',
            'success': False,
            'error': str(e),
            'score': 0,
            'isMalicious': False
        }

def get_country_geolocation(country_value):
    """Resolve country to lat/lon using a country API."""
    if not country_value or country_value == 'Unknown':
        return None

    value = str(country_value).strip()
    try:
        if len(value) == 2 and value.isalpha():
            response = requests.get(
                f"https://restcountries.com/v3.1/alpha/{value}",
                timeout=6
            )
        else:
            response = requests.get(
                f"https://restcountries.com/v3.1/name/{value}",
                params={'fullText': 'false'},
                timeout=6
            )
        response.raise_for_status()
        payload = response.json()
        country = payload[0] if isinstance(payload, list) and payload else payload
        latlng = country.get('latlng', []) if isinstance(country, dict) else []
        if not isinstance(latlng, list) or len(latlng) < 2:
            return None
        name_obj = country.get('name', {}) if isinstance(country, dict) else {}
        return {
            'country': name_obj.get('common', value) if isinstance(name_obj, dict) else value,
            'lat': latlng[0],
            'lon': latlng[1]
        }
    except requests.exceptions.RequestException:
        return None

def extract_best_country(results_list):
    """Pick first valid country field from API results."""
    for item in results_list:
        country = item.get('country')
        if country and country != 'Unknown':
            return country
    return None

# ============================================
# FLASK ROUTES
# ============================================

@app.route('/', methods=['GET'])
def index():
    """Root endpoint - API info"""
    return jsonify({
        'service': 'Threat Intelligence Dashboard Backend',
        'version': '1.0.0',
        'status': 'operational',
        'endpoints': {
            'health': 'GET /health',
            'validate': 'POST /api/validate',
            'scan': 'POST /api/scan',
            'scan_service': 'POST /api/scan/<service>',
            'alerts': 'GET /api/alerts',
            'receive_alert': 'POST /api/receive-alert',
            'threat_logs': 'GET /api/threat-logs',
            'block_ip': 'POST /api/block-ip',
            'cache_stats': 'GET /api/cache-stats',
            'status': 'GET /api/status'
        }
    }), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'mysql': 'enabled' if mysql_available() else 'disabled',
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/validate', methods=['POST'])
@rate_limit
def validate_target():
    """Validate input target"""
    data = request.get_json()
    target = data.get('target', '').strip()
    target_type = data.get('type', 'auto')
    
    if not target:
        return jsonify({
            'success': False,
            'error': 'Target is required'
        }), 400
    
    is_valid, result = validate_input(target, target_type)
    
    return jsonify({
        'success': is_valid,
        'target': target,
        'type': result,
        'message': result if not is_valid else 'Valid input'
    }), 200 if is_valid else 400

@app.route('/api/scan', methods=['POST'])
@rate_limit
def scan_target():
    """Scan target with relevant APIs in parallel"""
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({
            'success': False,
            'error': 'Target is required'
        }), 400
    
    # Validate input
    is_valid, target_type = validate_input(target)
    if not is_valid:
        return jsonify({
            'success': False,
            'error': target_type
        }), 400
    
    logger.info(f'Scanning target: {target}')
    
    scan_tasks = get_scan_tasks(target, target_type)

    # Query selected APIs in parallel with timeout
    results_list = []
    with ThreadPoolExecutor(max_workers=max(1, len(scan_tasks))) as executor:
        futures = {
            executor.submit(task): name
            for name, task in scan_tasks.items()
        }
        
        for future in as_completed(futures, timeout=30):
            try:
                result = future.result(timeout=25)
                results_list.append(result)
            except Exception as e:
                logger.error(f"Error querying {futures[future]}: {str(e)}")
                results_list.append({
                    'name': futures[future],
                    'error': str(e),
                    'success': False,
                    'score': 0,
                    'isMalicious': False
                })
    
    results = {
        'target': target,
        'type': target_type,
        'timestamp': datetime.now().isoformat(),
        'results': results_list
    }

    # Add geolocation for IP scans using country from threat APIs.
    if target_type == 'ip':
        best_country = extract_best_country(results_list)
        geo = get_country_geolocation(best_country) if best_country else None
        if geo:
            results['geo'] = geo

    # Calculate overall threat level
    successful_results = [r for r in results['results'] if r.get('success')]
    if successful_results:
        avg_score = sum(r.get('score', 0) for r in successful_results) / len(successful_results)
        malicious_count = sum(1 for r in successful_results if r.get('isMalicious'))
        
        results['overall'] = {
            'averageScore': round(avg_score),
            'threatLevel': 'CRITICAL' if avg_score >= 80 else 'HIGH' if avg_score >= 60 else 'MEDIUM' if avg_score >= 40 else 'LOW',
            'maliciousAPIs': malicious_count,
            'totalAPIs': len(successful_results),
            'consensus': 'MALICIOUS' if malicious_count >= len(successful_results) / 2 else 'SUSPICIOUS' if malicious_count > 0 else 'CLEAN'
        }
    else:
        results['overall'] = {
            'averageScore': 0,
            'threatLevel': 'UNKNOWN',
            'maliciousAPIs': 0,
            'totalAPIs': 0,
            'consensus': 'UNKNOWN',
            'message': 'No API results available'
        }

    if target_type == 'ip':
        try:
            save_threat_log(target, results)
        except Exception as exc:
            logger.error(f'Failed to persist threat log for {target}: {str(exc)}')
    
    return jsonify(results), 200


@app.route('/api/alerts', methods=['GET', 'DELETE'])
def get_alerts():
    """Get or clear real-time alerts from MySQL."""
    if request.method == 'DELETE':
        try:
            deleted_rows = clear_alerts()
        except Exception as exc:
            logger.error(f'Failed to clear alerts: {str(exc)}')
            return jsonify({'success': False, 'error': 'Failed to clear alerts'}), 500

        return jsonify({
            'success': True,
            'deleted': deleted_rows,
            'message': 'Alerts cleared successfully'
        }), 200

    limit = request.args.get('limit', default=100, type=int)
    alerts = fetch_alerts(limit=limit)
    return jsonify({
        'success': True,
        'alerts': alerts,
        'total': len(alerts),
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/receive-alert', methods=['POST'])
def receive_alert():
    """Receive an alert payload from the attack detector and store it."""
    data = request.get_json() or {}
    attacker_ip = (
        data.get('attacker_ip')
        or data.get('ip')
        or data.get('ip_address')
    )
    if not attacker_ip:
        return jsonify({'success': False, 'error': 'attacker_ip is required'}), 400

    try:
        alert_id = save_alert(data)
    except Exception as exc:
        logger.error(f'Failed to store alert: {str(exc)}')
        return jsonify({'success': False, 'error': 'Failed to store alert'}), 500

    return jsonify({
        'success': True,
        'alertId': alert_id,
        'message': 'Alert stored successfully'
    }), 200


@app.route('/api/threat-logs', methods=['GET'])
def get_threat_logs():
    """Get manual IP scan logs from MySQL."""
    limit = request.args.get('limit', default=500, type=int)
    logs = fetch_threat_logs(limit=limit)
    return jsonify({
        'success': True,
        'logs': logs,
        'total': len(logs),
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/scan/<service>', methods=['POST'])
@rate_limit
def scan_with_service(service):
    """Scan target with specific API service"""
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'success': False, 'error': 'Target is required'}), 400
    
    # Validate type for service-specific scan
    is_valid, target_type = validate_input(target)
    if not is_valid:
        return jsonify({'success': False, 'error': target_type}), 400

    service = service.lower()
    
    if service == 'abuseipdb':
        result = query_abuseipdb(target)
    elif service == 'virustotal':
        result = query_virustotal(target)
    elif service == 'alienvault':
        result = query_alienvault(target)
    elif service == 'greynoise':
        result = query_greynoise(target)
    else:
        return jsonify({'success': False, 'error': f'Unknown service: {service}'}), 400

    return jsonify(result), 200

@app.route('/api/block-ip', methods=['POST'])
@rate_limit
def block_ip():
    """Block IPv4 address at firewall + in-memory blocklist"""
    data = request.get_json() or {}
    ip = data.get('ip', '').strip()
    reason = data.get('reason', 'manual_block')
    enable_firewall = data.get('firewall', False)  # Optional: enable system firewall blocking

    if not ip:
        return jsonify({'success': False, 'error': 'IP is required'}), 400

    if not is_valid_ipv4(ip):
        return jsonify({'success': False, 'error': f'Invalid IPv4: {ip}'}), 400

    # Store in memory blocklist
    blocked_ips[ip] = {
        'ip': ip,
        'reason': reason,
        'blockedAt': datetime.now().isoformat(),
        'firewall_blocked': False
    }

    firewall_status = None
    
    # Optional: Block at system firewall level (requires sudo/admin)
    if enable_firewall:
        success, msg = block_ip_firewall(ip)
        firewall_status = {
            'success': success,
            'message': msg
        }
        if success:
            blocked_ips[ip]['firewall_blocked'] = True
            logger.info(f"Successfully added {ip} to firewall blocklist")

    return jsonify({
        'success': True,
        'message': f'IP {ip} blocked',
        'blocked': blocked_ips[ip],
        'totalBlocked': len(blocked_ips),
        'firewall_status': firewall_status
    }), 200

@app.route('/api/unblock-ip', methods=['POST'])
@rate_limit
def unblock_ip():
    """Unblock IPv4 address from firewall + in-memory blocklist"""
    data = request.get_json() or {}
    ip = data.get('ip', '').strip()

    if not ip:
        return jsonify({'success': False, 'error': 'IP is required'}), 400

    if not is_valid_ipv4(ip):
        return jsonify({'success': False, 'error': f'Invalid IPv4: {ip}'}), 400

    if ip not in blocked_ips:
        return jsonify({'success': False, 'error': f'IP {ip} not in blocklist'}), 404

    # Remove from memory blocklist
    blocked_entry = blocked_ips.pop(ip)
    firewall_status = None

    # Unblock from firewall if it was blocked there
    if blocked_entry.get('firewall_blocked'):
        success, msg = unblock_ip_firewall(ip)
        firewall_status = {
            'success': success,
            'message': msg
        }
        if success:
            logger.info(f"Successfully removed {ip} from firewall blocklist")

    return jsonify({
        'success': True,
        'message': f'IP {ip} unblocked',
        'totalBlocked': len(blocked_ips),
        'firewall_status': firewall_status
    }), 200

@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """Get list of all blocked IPs"""
    return jsonify({
        'success': True,
        'blocked_ips': list(blocked_ips.values()),
        'total_blocked': len(blocked_ips),
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/cache-stats', methods=['GET'])
def cache_stats():
    """Get cache statistics"""
    return jsonify({
        'cache_type': 'simple',
        'cache_timeout': 3600,
        'rate_limit': REQUEST_LIMIT,
        'rate_limit_window': '1 hour',
        'blocked_ips_count': len(blocked_ips)
    }), 200

@app.route('/api/status', methods=['GET'])
def api_status():
    """Get API status"""
    return jsonify({
        'status': 'operational',
        'mysql': {
            'enabled': mysql_available(),
            'database': MYSQL_CONFIG['database'] if mysql_available() else None
        },
        'apis': {
            'abuseipdb': 'operational',
            'virustotal': 'operational',
            'alienvault': 'operational',
            'greynoise': 'operational'
        },
        'blockedIps': len(blocked_ips),
        'timestamp': datetime.now().isoformat()
    }), 200

# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found', 'status': 404}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f'Internal error: {str(error)}')
    return jsonify({'error': 'Internal server error'}), 500

# ============================================
# STARTUP
# ============================================

init_mysql()

# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    logging.info('Starting Threat Intelligence Backend')
    app.run(debug=False, host='0.0.0.0', port=5001)
