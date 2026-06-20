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
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
import warnings
import subprocess
import platform
import json
import ipaddress
import uuid
import hashlib
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
        'http://localhost:3000,http://localhost:5173,http://localhost:5500,http://127.0.0.1:5500,http://localhost:8000,http://127.0.0.1:8000'
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
    value = os.getenv(name, default)
    if isinstance(value, str) and value.strip().lower().startswith('your_'):
        return None
    return value


def parse_bool(value, default=False):
    """Parse booleans from env vars and JSON payloads predictably."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    normalized = str(value).strip().lower()
    if normalized in {'1', 'true', 'yes', 'y', 'on'}:
        return True
    if normalized in {'0', 'false', 'no', 'n', 'off'}:
        return False
    return default


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

MYSQL_ENABLED = parse_bool(get_optional_env('MYSQL_ENABLED', 'false'), default=False)
MYSQL_CONFIG = {
    'host': get_optional_env('MYSQL_HOST', '127.0.0.1'),
    'port': int(get_optional_env('MYSQL_PORT', '3306')),
    'user': get_optional_env('MYSQL_USER', 'root'),
    'password': get_optional_env('MYSQL_PASSWORD', ''),
    'database': get_optional_env('MYSQL_DATABASE', 'threat_dashboard'),
}
MYSQL_POOL_SIZE = int(get_optional_env('MYSQL_POOL_SIZE', '5'))
ALERT_DEDUP_WINDOW_MINUTES = max(1, int(get_optional_env('ALERT_DEDUP_WINDOW_MINUTES', '10')))
ALERT_INGEST_TOKEN = get_optional_env('ALERT_INGEST_TOKEN')
EDR_AGENT_TOKEN = get_optional_env('EDR_AGENT_TOKEN') or ALERT_INGEST_TOKEN
EDR_HEARTBEAT_TIMEOUT_SECONDS = max(10, int(get_optional_env('EDR_HEARTBEAT_TIMEOUT_SECONDS', '20')))
EDR_RESPONSE_DRY_RUN = parse_bool(get_optional_env('EDR_RESPONSE_DRY_RUN', 'true'), default=True)
mysql_pool = None

# API Configuration
API_CONFIG = {
    'abuseipdb': {
        'endpoint': 'https://api.abuseipdb.com/api/v2/check',
        'key': get_optional_env('ABUSEIPDB_KEY'),
        'header_name': 'Key',
        'method': 'GET',
        'timeout': 10
    },
    'virustotal': {
        'endpoint': 'https://www.virustotal.com/api/v3/ip_addresses',
        'key': get_optional_env('VIRUSTOTAL_KEY'),
        'header_name': 'x-apikey',
        'method': 'GET',
        'timeout': 10
    },
    'alienvault': {
        'endpoint': 'https://otx.alienvault.com/api/v1/indicators',
        'key': get_optional_env('ALIENVAULT_KEY'),
        'header_name': 'X-OTX-API-KEY',
        'method': 'GET',
        'timeout': 10
    },
    'greynoise': {
        'endpoint': 'https://api.greynoise.io/v3/community',
        'key': get_optional_env('GREYNOISE_KEY'),
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
edr_memory = {
    'endpoints': {},
    'events': [],
    'alerts': [],
    'responses': []
}


def api_key_response(name):
    """Return a consistent offline response when an API key is not configured."""
    logger.warning(f'{name} API key not configured')
    return {
        'name': name,
        'success': False,
        'error': f'{name} API key not configured',
        'score': 0,
        'isMalicious': False,
        'offline': True
    }


def unsupported_target_response(name, target_type):
    """Return a consistent response for services that do not support a target type."""
    return {
        'name': name,
        'success': False,
        'error': f'{name} does not support {target_type} scans in this dashboard',
        'score': 0,
        'isMalicious': False,
        'unsupported': True,
    }


def get_json_body():
    """Safely parse a JSON request body."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def get_bounded_limit(default=100, maximum=1000):
    """Read a positive integer limit from query parameters."""
    limit = request.args.get('limit', default=default, type=int)
    if limit is None:
        limit = default
    return min(max(1, int(limit)), maximum)


def get_target_type(target):
    """Return the validated target type or None."""
    is_valid, target_type = validate_input(str(target or ''))
    return target_type if is_valid else None


def is_blockable_public_ipv4(ip):
    """Allow firewall blocking only for public, globally routable IPv4 addresses."""
    try:
        parsed = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return parsed.version == 4 and parsed.is_global


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
                INDEX idx_alerts_ip_address (ip_address),
                INDEX idx_alerts_dedup (source, ip_address, alert_type, updated_at)
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
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS endpoints (
                endpoint_id VARCHAR(128) PRIMARY KEY,
                hostname VARCHAR(255) NOT NULL,
                ip_address VARCHAR(45),
                os_name VARCHAR(255),
                logged_in_user VARCHAR(255),
                agent_version VARCHAR(50),
                status VARCHAR(32) NOT NULL DEFAULT 'offline',
                total_alerts INT NOT NULL DEFAULT 0,
                raw_payload JSON,
                last_seen DATETIME,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_endpoints_status (status),
                INDEX idx_endpoints_last_seen (last_seen)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_heartbeats (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                endpoint_id VARCHAR(128) NOT NULL,
                status VARCHAR(32) NOT NULL DEFAULT 'online',
                raw_payload JSON,
                received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_agent_heartbeats_endpoint (endpoint_id),
                INDEX idx_agent_heartbeats_received_at (received_at)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS `events` (
                event_id VARCHAR(64) PRIMARY KEY,
                endpoint_id VARCHAR(128) NOT NULL,
                event_type VARCHAR(64) NOT NULL,
                source VARCHAR(100) NOT NULL DEFAULT 'windows_agent',
                severity VARCHAR(20) NOT NULL DEFAULT 'info',
                process_name VARCHAR(255),
                command_line TEXT,
                destination_ip VARCHAR(45),
                file_path TEXT,
                registry_key TEXT,
                raw_payload JSON,
                occurred_at DATETIME NOT NULL,
                received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_events_endpoint (endpoint_id),
                INDEX idx_events_type (event_type),
                INDEX idx_events_occurred_at (occurred_at)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS process_events (
                event_id VARCHAR(64) PRIMARY KEY,
                endpoint_id VARCHAR(128) NOT NULL,
                process_name VARCHAR(255),
                pid INT,
                parent_pid INT,
                parent_process VARCHAR(255),
                image_path TEXT,
                command_line TEXT,
                occurred_at DATETIME NOT NULL,
                INDEX idx_process_events_endpoint (endpoint_id),
                INDEX idx_process_events_process (process_name)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS network_events (
                event_id VARCHAR(64) PRIMARY KEY,
                endpoint_id VARCHAR(128) NOT NULL,
                process_name VARCHAR(255),
                pid INT,
                destination_ip VARCHAR(45),
                destination_port INT,
                protocol VARCHAR(16),
                threat_intel JSON,
                occurred_at DATETIME NOT NULL,
                INDEX idx_network_events_endpoint (endpoint_id),
                INDEX idx_network_events_destination (destination_ip)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS file_events (
                event_id VARCHAR(64) PRIMARY KEY,
                endpoint_id VARCHAR(128) NOT NULL,
                process_name VARCHAR(255),
                file_path TEXT,
                file_action VARCHAR(64),
                file_hash VARCHAR(128),
                occurred_at DATETIME NOT NULL,
                INDEX idx_file_events_endpoint (endpoint_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS registry_events (
                event_id VARCHAR(64) PRIMARY KEY,
                endpoint_id VARCHAR(128) NOT NULL,
                process_name VARCHAR(255),
                registry_key TEXT,
                registry_value TEXT,
                registry_action VARCHAR(64),
                occurred_at DATETIME NOT NULL,
                INDEX idx_registry_events_endpoint (endpoint_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS edr_alerts (
                alert_id VARCHAR(64) PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                severity VARCHAR(20) NOT NULL DEFAULT 'medium',
                endpoint_id VARCHAR(128) NOT NULL,
                endpoint_name VARCHAR(255),
                logged_in_user VARCHAR(255),
                process_name VARCHAR(255),
                parent_process VARCHAR(255),
                child_process VARCHAR(255),
                command_line TEXT,
                destination_ip VARCHAR(45),
                destination_port INT,
                mitre_id VARCHAR(32),
                status VARCHAR(32) NOT NULL DEFAULT 'open',
                summary TEXT,
                recommended_action VARCHAR(255),
                related_event_ids JSON,
                raw_payload JSON,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_edr_alerts_endpoint (endpoint_id),
                INDEX idx_edr_alerts_severity (severity),
                INDEX idx_edr_alerts_status (status),
                INDEX idx_edr_alerts_created_at (created_at)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_events (
                alert_id VARCHAR(64) NOT NULL,
                event_id VARCHAR(64) NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (alert_id, event_id),
                INDEX idx_alert_events_event (event_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS response_actions (
                action_id VARCHAR(64) PRIMARY KEY,
                action_type VARCHAR(64) NOT NULL,
                target TEXT NOT NULL,
                mode VARCHAR(32) NOT NULL DEFAULT 'dry-run',
                status VARCHAR(32) NOT NULL DEFAULT 'queued',
                endpoint_id VARCHAR(128),
                alert_id VARCHAR(64),
                result TEXT,
                raw_payload JSON,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_response_actions_endpoint (endpoint_id),
                INDEX idx_response_actions_alert (alert_id),
                INDEX idx_response_actions_created_at (created_at)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_cache (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                ioc VARCHAR(255) NOT NULL,
                ioc_type VARCHAR(32) NOT NULL,
                reputation VARCHAR(64),
                source VARCHAR(100),
                raw_payload JSON,
                expires_at DATETIME,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_ioc_cache_ioc_source (ioc, source),
                INDEX idx_ioc_cache_ioc (ioc),
                INDEX idx_ioc_cache_expires_at (expires_at)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id VARCHAR(64) PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                severity VARCHAR(20) NOT NULL DEFAULT 'medium',
                status VARCHAR(32) NOT NULL DEFAULT 'open',
                owner VARCHAR(255),
                raw_payload JSON,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_cases_status (status),
                INDEX idx_cases_severity (severity)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                actor VARCHAR(255) NOT NULL DEFAULT 'system',
                action VARCHAR(255) NOT NULL,
                target TEXT,
                raw_payload JSON,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_audit_logs_created_at (created_at)
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


def parse_attempt_count(raw_value, default=1):
    """Normalize attempt counts from detector and simulator payloads."""
    try:
        attempts = int(raw_value or default)
    except (TypeError, ValueError):
        attempts = default
    lower_bound = 0 if int(default or 0) <= 0 else 1
    return max(lower_bound, attempts)


def extract_payload_attempt_count(raw_payload):
    """Read attempt_count from the previous raw alert payload when available."""
    if not raw_payload:
        return 0

    try:
        payload = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
    except (TypeError, json.JSONDecodeError):
        return 0

    if not isinstance(payload, dict):
        return 0
    return parse_attempt_count(payload.get('attempt_count'), default=0)


def severity_rank(severity):
    """Return an integer rank for severity comparisons."""
    return {
        'low': 0,
        'medium': 1,
        'high': 2,
        'critical': 3,
    }.get(str(severity or '').strip().lower(), -1)


def highest_severity(*severities):
    """Return the highest severity from supplied severity labels."""
    valid = [severity for severity in severities if severity_rank(severity) >= 0]
    if not valid:
        return 'low'
    return max(valid, key=severity_rank)


def truncate_db_value(value, max_length):
    """Trim string values before inserting into bounded VARCHAR columns."""
    if value is None:
        return None
    return str(value)[:max_length]


def save_alert(alert_payload):
    """Persist a real-time alert, grouping repeated active alerts by source, IP, and type."""
    if not mysql_available():
        return None

    attacker_ip = (
        alert_payload.get('attacker_ip')
        or alert_payload.get('ip')
        or alert_payload.get('ip_address')
        or 'Unknown'
    )
    alert_type = truncate_db_value(alert_payload.get('name') or alert_payload.get('type') or 'Threat Alert', 255)
    source = truncate_db_value(alert_payload.get('source', 'attack_detector'), 100)
    description = alert_payload.get('description') or alert_payload.get('log_line') or alert_type
    incoming_attempt_count = parse_attempt_count(alert_payload.get('attempt_count'), default=1)
    target_ip = alert_payload.get('target_ip')
    if target_ip and not is_valid_ipv4(str(target_ip)):
        target_ip = None
    now = datetime.now()

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, attempt_count, created_at, updated_at, raw_payload
            FROM alerts
            WHERE source = %s AND ip_address = %s AND alert_type = %s
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (source, attacker_ip, alert_type)
        )
        existing_alert = cursor.fetchone()

        if existing_alert:
            alert_id, current_attempts, first_seen, last_seen, previous_raw_payload = existing_alert
            is_active_group = (
                last_seen is not None
                and now - last_seen <= timedelta(minutes=ALERT_DEDUP_WINDOW_MINUTES)
            )
            if is_active_group:
                previous_payload_attempts = extract_payload_attempt_count(previous_raw_payload)
                if incoming_attempt_count > previous_payload_attempts:
                    attempt_delta = incoming_attempt_count - previous_payload_attempts
                else:
                    attempt_delta = incoming_attempt_count

                next_attempt_count = int(current_attempts or 0) + max(1, attempt_delta)
                severity = get_alert_severity(
                    next_attempt_count,
                    first_seen=first_seen,
                    last_seen=now,
                    alert_type=alert_payload.get('type') or alert_type,
                )
                cursor.execute(
                    """
                    UPDATE alerts
                    SET severity = %s,
                        description = %s,
                        target_ip = %s,
                        log_line = %s,
                        attempt_count = %s,
                        raw_payload = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    """,
                    (
                        severity,
                        description,
                        target_ip,
                        alert_payload.get('log_line'),
                        next_attempt_count,
                        json.dumps(alert_payload),
                        alert_id,
                    )
                )
                conn.commit()
                cursor.close()
                return alert_id

        attempt_count = incoming_attempt_count
        severity = get_alert_severity(
            attempt_count,
            first_seen=now,
            last_seen=now,
            alert_type=alert_payload.get('type') or alert_type,
        )
        cursor.execute(
            """
            INSERT INTO alerts (
                alert_type, source, ip_address, severity, description,
                target_ip, log_line, attempt_count, raw_payload
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                alert_type,
                source,
                attacker_ip,
                severity,
                description,
                target_ip,
                alert_payload.get('log_line'),
                attempt_count,
                json.dumps(alert_payload),
            )
        )
        conn.commit()
        alert_id = cursor.lastrowid
        cursor.close()
        return alert_id
    finally:
        conn.close()


def get_alert_severity(
    attempt_count,
    fallback='low',
    first_seen=None,
    last_seen=None,
    alert_type=None,
    hour_attempts=None,
    day_attempts=None,
):
    """Map attempts and time-window velocity to dashboard severity bands."""
    try:
        attempts = int(attempt_count or 1)
    except (TypeError, ValueError):
        attempts = 1

    if first_seen is None and last_seen is None and hour_attempts is None and day_attempts is None:
        if attempts <= 10:
            return highest_severity('low', fallback)
        if attempts <= 20:
            return highest_severity('medium', fallback)
        if attempts <= 30:
            return highest_severity('high', fallback)
        return highest_severity('critical', fallback)

    duration_minutes = None
    if first_seen and last_seen:
        duration_seconds = max(0, (last_seen - first_seen).total_seconds())
        duration_minutes = duration_seconds / 60

    severity = 'low'

    if duration_minutes is not None:
        if attempts >= 20 and duration_minutes <= 5:
            severity = highest_severity(severity, 'critical')
        elif attempts >= 10 and duration_minutes <= 1:
            severity = highest_severity(severity, 'high')

        if duration_minutes <= 10:
            if attempts >= 31:
                severity = highest_severity(severity, 'critical')
            elif attempts >= 21:
                severity = highest_severity(severity, 'high')
            elif attempts >= 11:
                severity = highest_severity(severity, 'medium')

    hourly_total = int(hour_attempts if hour_attempts is not None else attempts)
    daily_total = int(day_attempts if day_attempts is not None else attempts)

    if hourly_total >= 101:
        severity = highest_severity(severity, 'critical')
    elif hourly_total >= 51:
        severity = highest_severity(severity, 'high')
    elif hourly_total >= 21:
        severity = highest_severity(severity, 'medium')

    if daily_total >= 201:
        severity = highest_severity(severity, 'critical')
    elif daily_total >= 101:
        severity = highest_severity(severity, 'high')
    elif daily_total >= 51:
        severity = highest_severity(severity, 'medium')

    normalized_type = str(alert_type or '').strip().lower()
    if 'beacon' in normalized_type and attempts >= 10:
        severity = highest_severity(severity, 'critical')

    return highest_severity(severity, fallback)


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
        'firstSeen': row[9].strftime('%Y-%m-%d %H:%M:%S') if row[9] else '',
        'lastSeen': row[10].strftime('%Y-%m-%d %H:%M:%S') if row[10] else '',
        'time': row[10].strftime('%Y-%m-%d %H:%M:%S') if row[10] else '',
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
                   target_ip, log_line, attempt_count, created_at, updated_at
            FROM alerts
            ORDER BY updated_at DESC
            LIMIT %s
            """,
            (max(1, int(limit)),)
        )
        rows = cursor.fetchall()
        cursor.close()
        return [serialize_alert_row(row) for row in rows]
    finally:
        conn.close()


def fetch_alert_stats():
    """Build chart-ready alert stats from stored real-time alerts."""
    trend_labels = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00']
    severities = ['critical', 'high', 'medium', 'low']
    trend = {severity: [0] * len(trend_labels) for severity in severities}
    attack_labels = []
    attack_values = []

    if not mysql_available():
        return {
            'trend': {'labels': trend_labels, **trend},
            'attackTypes': {'labels': attack_labels, 'values': attack_values},
        }

    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    tomorrow_start = today_start + timedelta(days=1)

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT severity, HOUR(updated_at) AS alert_hour, COUNT(*)
            FROM alerts
            WHERE updated_at >= %s AND updated_at < %s
            GROUP BY severity, alert_hour
            """,
            (today_start, tomorrow_start)
        )
        for severity, alert_hour, count in cursor.fetchall():
            severity_key = str(severity or '').lower()
            if severity_key not in trend:
                continue
            bucket_index = min(5, max(0, int(alert_hour or 0) // 4))
            trend[severity_key][bucket_index] += int(count or 0)

        cursor.execute(
            """
            SELECT alert_type, COALESCE(SUM(attempt_count), 0) AS total_attempts
            FROM alerts
            WHERE updated_at >= %s AND updated_at < %s
            GROUP BY alert_type
            ORDER BY total_attempts DESC
            LIMIT 6
            """,
            (today_start, tomorrow_start)
        )
        for alert_type, total_attempts in cursor.fetchall():
            attack_labels.append(alert_type or 'Unknown')
            attack_values.append(int(total_attempts or 0))

        cursor.close()
    finally:
        conn.close()

    return {
        'trend': {'labels': trend_labels, **trend},
        'attackTypes': {'labels': attack_labels, 'values': attack_values},
    }


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
# ENDPOINT DETECTION AND RESPONSE HELPERS
# ============================================

def json_dumps(value):
    """Serialize nested telemetry safely for MySQL JSON columns."""
    return json.dumps(value, default=str)


def parse_edr_datetime(value=None):
    """Parse agent timestamps and return a naive local datetime for storage."""
    if value in (None, ''):
        return datetime.now()

    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 9999999999:
            timestamp = timestamp / 1000
        return datetime.fromtimestamp(timestamp)

    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text.endswith('Z'):
            text = f'{text[:-1]}+00:00'
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            try:
                parsed = datetime.strptime(text, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return datetime.now()

    if parsed.tzinfo:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed


def datetime_to_iso(value):
    if isinstance(value, datetime):
        return value.isoformat(timespec='seconds')
    return str(value or '')


def safe_int(value, default=None):
    try:
        if value in (None, ''):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def make_edr_stable_id(prefix, values):
    """Build compact deterministic IDs for telemetry that may be resent."""
    normalized = json.dumps([str(value or '') for value in values], sort_keys=True, default=str)
    digest = hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:40]
    return f'{prefix}-{digest}'


def check_edr_agent_token():
    """Validate optional agent token for heartbeat and telemetry ingestion."""
    if not EDR_AGENT_TOKEN:
        return None

    provided_token = request.headers.get('X-Agent-Token') or ''
    auth_header = request.headers.get('Authorization') or ''
    bearer_token = auth_header.removeprefix('Bearer ').strip()

    if provided_token == EDR_AGENT_TOKEN or bearer_token == EDR_AGENT_TOKEN:
        return None
    return jsonify({'success': False, 'error': 'Unauthorized EDR agent'}), 401


def compute_endpoint_status(last_seen):
    """Classify endpoint liveness from last heartbeat time."""
    last_seen_dt = parse_edr_datetime(last_seen) if last_seen else None
    if not last_seen_dt:
        return 'offline'
    age_seconds = (datetime.now() - last_seen_dt).total_seconds()
    return 'online' if age_seconds <= EDR_HEARTBEAT_TIMEOUT_SECONDS else 'offline'


def normalize_endpoint(payload):
    """Normalize endpoint identity from heartbeat or event payloads."""
    endpoint_payload = payload.get('endpoint') if isinstance(payload.get('endpoint'), dict) else {}
    merged = {**endpoint_payload, **payload}
    hostname = str(
        merged.get('hostname')
        or merged.get('host')
        or merged.get('computer_name')
        or 'Unknown Endpoint'
    ).strip()
    endpoint_id = str(
        merged.get('endpoint_id')
        or merged.get('agent_id')
        or merged.get('device_id')
        or hostname
    ).strip()

    if not endpoint_id:
        endpoint_id = hostname or f'endpoint-{uuid.uuid4().hex[:8]}'

    last_seen = datetime_to_iso(parse_edr_datetime(merged.get('last_seen') or merged.get('timestamp')))
    return {
        'id': endpoint_id[:128],
        'endpoint_id': endpoint_id[:128],
        'hostname': hostname[:255],
        'ip_address': str(merged.get('ip_address') or merged.get('ip') or '')[:45],
        'os': str(merged.get('os') or merged.get('os_name') or platform.platform())[:255],
        'user': str(merged.get('user') or merged.get('logged_in_user') or '')[:255],
        'agent_version': str(merged.get('agent_version') or merged.get('version') or '0.1.0')[:50],
        'status': 'online',
        'last_seen': last_seen,
        'total_alerts': safe_int(merged.get('total_alerts'), 0) or 0,
        'raw': merged
    }


def upsert_memory_endpoint(endpoint):
    """Update in-memory endpoint state for local demo mode and live process cache."""
    stored = edr_memory['endpoints'].get(endpoint['id'], {})
    merged = {**stored, **endpoint}
    merged['status'] = compute_endpoint_status(merged.get('last_seen'))
    edr_memory['endpoints'][endpoint['id']] = merged
    return merged


def push_limited_memory(bucket, item, limit):
    items = edr_memory[bucket]
    item_id = item.get('id') or item.get('event_id') or item.get('alert_id') or item.get('action_id')
    existing_index = None
    if item_id:
        for index, existing in enumerate(items):
            existing_id = existing.get('id') or existing.get('event_id') or existing.get('alert_id') or existing.get('action_id')
            if str(existing_id) == str(item_id):
                existing_index = index
                break

    is_new = existing_index is None
    if existing_index is not None:
        existing_item = items.pop(existing_index)
        item = {**existing_item, **item}

    items.insert(0, item)
    del items[limit:]
    return is_new


def save_edr_endpoint(endpoint, heartbeat=False):
    """Store endpoint heartbeat in memory and MySQL when configured."""
    upsert_memory_endpoint(endpoint)

    if not mysql_available():
        return

    last_seen_dt = parse_edr_datetime(endpoint.get('last_seen'))
    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO endpoints (
                endpoint_id, hostname, ip_address, os_name, logged_in_user,
                agent_version, status, total_alerts, raw_payload, last_seen
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                hostname = VALUES(hostname),
                ip_address = VALUES(ip_address),
                os_name = VALUES(os_name),
                logged_in_user = VALUES(logged_in_user),
                agent_version = VALUES(agent_version),
                status = VALUES(status),
                raw_payload = VALUES(raw_payload),
                last_seen = VALUES(last_seen),
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                endpoint['id'],
                endpoint['hostname'],
                endpoint.get('ip_address') or None,
                endpoint.get('os') or None,
                endpoint.get('user') or None,
                endpoint.get('agent_version') or None,
                endpoint.get('status') or 'online',
                int(endpoint.get('total_alerts') or 0),
                json_dumps(endpoint.get('raw') or endpoint),
                last_seen_dt,
            )
        )
        if heartbeat:
            cursor.execute(
                """
                INSERT INTO agent_heartbeats (endpoint_id, status, raw_payload, received_at)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    endpoint['id'],
                    endpoint.get('status') or 'online',
                    json_dumps(endpoint.get('raw') or endpoint),
                    datetime.now(),
                )
            )
        conn.commit()
        cursor.close()
    finally:
        conn.close()


def infer_edr_event_type(raw_event):
    explicit_type = raw_event.get('event_type') or raw_event.get('type') or raw_event.get('category')
    if explicit_type:
        return str(explicit_type).strip().lower()
    if raw_event.get('destination_ip') or raw_event.get('remote_address'):
        return 'network'
    if raw_event.get('file_path') or raw_event.get('path'):
        return 'file'
    if raw_event.get('registry_key') or raw_event.get('key_path'):
        return 'registry'
    if raw_event.get('task_name') or raw_event.get('scheduled_task_name'):
        return 'scheduled_task'
    if raw_event.get('usb_action') or raw_event.get('device_id'):
        return 'usb'
    if raw_event.get('rdp_result'):
        return 'rdp_login'
    if raw_event.get('failed_count'):
        return 'failed_login_burst'
    return 'process'


def normalize_edr_event(raw_event, endpoint):
    """Normalize process, network, file, registry, login, and Sysmon events."""
    if not isinstance(raw_event, dict):
        raw_event = {'message': str(raw_event)}

    provided_event_id = raw_event.get('event_id') or raw_event.get('id')
    event_type = infer_edr_event_type(raw_event)
    occurred_at = parse_edr_datetime(raw_event.get('timestamp') or raw_event.get('time') or raw_event.get('occurred_at'))
    process_name = str(
        raw_event.get('process_name')
        or raw_event.get('process')
        or raw_event.get('image')
        or ''
    ).split('\\')[-1]
    parent_process = str(raw_event.get('parent_process') or raw_event.get('parent_image') or '').split('\\')[-1]
    destination_port = safe_int(raw_event.get('destination_port') or raw_event.get('remote_port'))

    if provided_event_id:
        event_id = str(provided_event_id)
    elif event_type == 'failed_login_burst':
        event_id = make_edr_stable_id('event', [
            endpoint['id'],
            event_type,
            raw_event.get('target_user'),
            raw_event.get('source_ip') or 'local',
            raw_event.get('failed_count'),
            raw_event.get('window_start'),
            raw_event.get('window_end'),
            raw_event.get('threshold'),
        ])
    elif event_type in {'rdp_login', 'login'}:
        event_id = make_edr_stable_id('event', [
            endpoint['id'],
            event_type,
            raw_event.get('windows_event_id'),
            datetime_to_iso(occurred_at),
            raw_event.get('target_user'),
            raw_event.get('source_ip') or raw_event.get('workstation'),
            raw_event.get('logon_type'),
            raw_event.get('status_code') or raw_event.get('login_result') or raw_event.get('rdp_result'),
        ])
    else:
        event_id = uuid.uuid4().hex

    return {
        'id': event_id,
        'event_id': event_id,
        'endpoint_id': endpoint['id'],
        'endpoint_name': endpoint.get('hostname') or endpoint['id'],
        'user': raw_event.get('user') or endpoint.get('user') or '',
        'event_type': event_type,
        'source': raw_event.get('source') or 'windows_agent',
        'severity': raw_event.get('severity') or 'info',
        'timestamp': datetime_to_iso(occurred_at),
        'process_name': process_name,
        'pid': safe_int(raw_event.get('pid') or raw_event.get('process_id')),
        'parent_pid': safe_int(raw_event.get('ppid') or raw_event.get('parent_pid')),
        'parent_process': parent_process,
        'child_process': raw_event.get('child_process') or process_name,
        'image_path': raw_event.get('image_path') or raw_event.get('path') or raw_event.get('image') or '',
        'command_line': raw_event.get('command_line') or raw_event.get('cmdline') or raw_event.get('command') or '',
        'destination_ip': raw_event.get('destination_ip') or raw_event.get('remote_address') or raw_event.get('remote_ip') or '',
        'destination_port': destination_port,
        'protocol': raw_event.get('protocol') or '',
        'threat_intel': raw_event.get('threat_intel') or raw_event.get('intel') or {},
        'file_path': raw_event.get('file_path') or raw_event.get('path') or '',
        'file_action': raw_event.get('file_action') or raw_event.get('action') or '',
        'file_hash': raw_event.get('file_hash') or raw_event.get('hash') or '',
        'registry_key': raw_event.get('registry_key') or raw_event.get('key_path') or '',
        'registry_value': raw_event.get('registry_value') or raw_event.get('value_name') or '',
        'registry_action': raw_event.get('registry_action') or raw_event.get('action') or '',
        'task_name': raw_event.get('task_name') or raw_event.get('scheduled_task_name') or '',
        'signature_status': raw_event.get('signature_status') or '',
        'signature_subject': raw_event.get('signature_subject') or '',
        'signature_issuer': raw_event.get('signature_issuer') or '',
        'signature_thumbprint': raw_event.get('signature_thumbprint') or '',
        'is_signed': raw_event.get('is_signed'),
        'usb_action': raw_event.get('usb_action') or '',
        'device_name': raw_event.get('device_name') or '',
        'device_id': raw_event.get('device_id') or '',
        'manufacturer': raw_event.get('manufacturer') or '',
        'rdp_result': raw_event.get('rdp_result') or '',
        'login_result': raw_event.get('login_result') or '',
        'logon_type': raw_event.get('logon_type') or '',
        'target_user': raw_event.get('target_user') or '',
        'source_ip': raw_event.get('source_ip') or '',
        'workstation': raw_event.get('workstation') or '',
        'failed_count': safe_int(raw_event.get('failed_count'), 0) or 0,
        'window_start': raw_event.get('window_start') or '',
        'window_end': raw_event.get('window_end') or '',
        'threshold': safe_int(raw_event.get('threshold'), 0) or 0,
        'windows_event_id': raw_event.get('windows_event_id') or '',
        'status_code': raw_event.get('status_code') or '',
        'sub_status_code': raw_event.get('sub_status_code') or '',
        'raw': raw_event,
    }


def is_external_ipv4(value):
    try:
        parsed = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return parsed.version == 4 and parsed.is_global


def text_contains_any(text, values):
    normalized = str(text or '').lower()
    return any(value.lower() in normalized for value in values)


def path_in_folder(path, folder_name):
    normalized = str(path or '').replace('/', '\\').lower()
    return f'\\{folder_name.lower()}\\' in normalized


def has_extension(path, extensions):
    normalized = str(path or '').lower()
    return any(normalized.endswith(ext) for ext in extensions)


def is_user_writable_path(path):
    normalized = str(path or '').replace('/', '\\').lower()
    return any(marker in normalized for marker in [
        '\\users\\',
        '\\downloads\\',
        '\\desktop\\',
        '\\documents\\',
        '\\appdata\\',
        '\\temp\\',
        '\\programdata\\',
        '\\public\\',
    ])


def get_recent_endpoint_events(endpoint_id, minutes=10):
    cutoff = datetime.now() - timedelta(minutes=minutes)
    recent = []
    for event in edr_memory['events']:
        if event.get('endpoint_id') != endpoint_id:
            continue
        if parse_edr_datetime(event.get('timestamp')) >= cutoff:
            recent.append(event)
    return recent


def build_edr_alert(event, title, severity, mitre_id, summary, recommended_action, related_event_ids=None):
    """Build a normalized endpoint alert."""
    related_ids = related_event_ids or [event.get('id') or event.get('event_id')]
    alert_id = make_edr_stable_id('alert', [
        event.get('endpoint_id'),
        title,
        severity,
        mitre_id,
        event.get('process_name'),
        event.get('destination_ip'),
        event.get('destination_port'),
        event.get('file_path'),
        event.get('registry_key'),
        event.get('target_user'),
        event.get('source_ip'),
        event.get('failed_count'),
        ','.join(str(event_id or '') for event_id in related_ids),
    ])
    return {
        'id': alert_id,
        'alert_id': alert_id,
        'title': title,
        'severity': severity,
        'endpoint_id': event.get('endpoint_id'),
        'endpoint_name': event.get('endpoint_name'),
        'user': event.get('user') or '',
        'process': event.get('process_name') or '',
        'process_name': event.get('process_name') or '',
        'parent_process': event.get('parent_process') or '',
        'child_process': event.get('child_process') or event.get('process_name') or '',
        'command_line': event.get('command_line') or '',
        'destination_ip': event.get('destination_ip') or '',
        'destination_port': event.get('destination_port'),
        'mitre_id': mitre_id,
        'status': 'open',
        'summary': summary,
        'recommended_action': recommended_action,
        'related_event_ids': related_ids,
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'raw': event,
    }


def is_threat_intel_malicious(event):
    intel = event.get('threat_intel') or {}
    if not isinstance(intel, dict):
        return False
    verdict = str(intel.get('verdict') or intel.get('reputation') or intel.get('status') or '').lower()
    score = safe_int(intel.get('score') or intel.get('threat_score'), 0) or 0
    return bool(intel.get('malicious') or intel.get('isMalicious') or 'malicious' in verdict or score >= 80)


def detect_edr_alerts(event):
    """Apply endpoint, network, file, registry, scheduled-task, and correlation rules."""
    alerts = []
    event_type = str(event.get('event_type') or '').lower()
    process = str(event.get('process_name') or '').lower()
    parent = str(event.get('parent_process') or '').lower()
    command = str(event.get('command_line') or '')
    image_path = str(event.get('image_path') or event.get('file_path') or '')
    destination_ip = str(event.get('destination_ip') or '')
    destination_port = safe_int(event.get('destination_port'))
    office_processes = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'onenote.exe'}
    shell_processes = {'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'}
    signature_status = str(event.get('signature_status') or '').lower()

    if event_type == 'process':
        if signature_status and signature_status not in {'valid', 'notsigned', 'missingfile'}:
            alerts.append(build_edr_alert(
                event,
                'Invalid Digital Signature Detected',
                'high',
                'T1036',
                f'Process digital signature status is {event.get("signature_status")}.',
                'Verify the executable path, publisher, and hash before allowing the process to continue.'
            ))

        if signature_status == 'notsigned' and has_extension(image_path, ['.exe', '.dll']) and is_user_writable_path(image_path):
            alerts.append(build_edr_alert(
                event,
                'Unsigned Executable In User-Writable Path',
                'medium',
                'T1204.002',
                'An unsigned executable started from a user-writable location.',
                'Check the file hash, source folder, and parent process.'
            ))

        if process in {'powershell.exe', 'pwsh.exe'} and text_contains_any(command, ['-encodedcommand', ' -enc ', '/enc ']):
            alerts.append(build_edr_alert(
                event,
                'Suspicious Encoded PowerShell Execution',
                'high',
                'T1059.001',
                'PowerShell started with an encoded command line.',
                'Collect process details, inspect command content, and kill the process if unauthorized.'
            ))

        if process in {'powershell.exe', 'pwsh.exe'} and text_contains_any(command, ['-windowstyle hidden', '-w hidden', 'hidden']):
            alerts.append(build_edr_alert(
                event,
                'Hidden PowerShell Window Execution',
                'high',
                'T1059.001',
                'PowerShell started with hidden-window arguments.',
                'Collect process details and isolate the endpoint if the command is not approved.'
            ))

        if process == 'cmd.exe' and text_contains_any(
            command,
            ['certutil', 'bitsadmin', 'vssadmin', 'bcdedit', 'schtasks', 'reg add', 'net user', 'whoami /all']
        ):
            alerts.append(build_edr_alert(
                event,
                'Suspicious CMD Command Line',
                'medium',
                'T1059.003',
                'CMD executed a command commonly seen in discovery, download, or persistence activity.',
                'Review the parent process and collect command-line details.'
            ))

        if parent in office_processes and process in shell_processes:
            alerts.append(build_edr_alert(
                event,
                'Office Application Spawned Script Interpreter',
                'critical',
                'T1204.002',
                'An Office process launched a shell or scripting interpreter.',
                'Kill the child process, quarantine the originating document, and review related events.'
            ))

        if has_extension(image_path, ['.exe']) and path_in_folder(image_path, 'downloads'):
            alerts.append(build_edr_alert(
                event,
                'Executable Started From Downloads',
                'medium',
                'T1204.002',
                'An executable was launched from the Downloads folder.',
                'Collect file details and quarantine the file if it is untrusted.'
            ))

        if has_extension(image_path, ['.exe']) and path_in_folder(image_path, 'temp'):
            alerts.append(build_edr_alert(
                event,
                'Executable Started From Temp Folder',
                'high',
                'T1204.002',
                'An executable was launched from a temporary directory.',
                'Collect file details and quarantine the executable if unauthorized.'
            ))

    if event_type == 'network':
        if process in {'powershell.exe', 'pwsh.exe'} and is_external_ipv4(destination_ip):
            alerts.append(build_edr_alert(
                event,
                'PowerShell Connected To External IP',
                'high',
                'T1105',
                'PowerShell opened an outbound network connection to an external IP.',
                'Block the IP and collect process details if the connection is not approved.'
            ))

        if destination_port in {4444, 1337, 3389, 5985, 5986, 8080, 8443} and is_external_ipv4(destination_ip):
            alerts.append(build_edr_alert(
                event,
                'Process Connected To High-Risk Port',
                'medium',
                'T1105',
                f'A process connected to external port {destination_port}.',
                'Inspect the process and block the destination if suspicious.'
            ))

        if is_threat_intel_malicious(event):
            alerts.append(build_edr_alert(
                event,
                'Process Connected To Malicious IP',
                'critical',
                'T1071',
                'Endpoint process network activity matched malicious threat intelligence.',
                'Block the IP, collect process details, and isolate or kill the process if needed.'
            ))

        recent_events = get_recent_endpoint_events(event.get('endpoint_id'), minutes=10)
        encoded_powershell_events = [
            recent_event for recent_event in recent_events
            if str(recent_event.get('process_name') or '').lower() in {'powershell.exe', 'pwsh.exe'}
            and text_contains_any(recent_event.get('command_line'), ['-encodedcommand', ' -enc ', '/enc '])
        ]
        if encoded_powershell_events and is_external_ipv4(destination_ip) and is_threat_intel_malicious(event):
            related_ids = [event.get('id') or event.get('event_id')]
            related_ids.extend(recent_event.get('id') or recent_event.get('event_id') for recent_event in encoded_powershell_events[:3])
            alerts.append(build_edr_alert(
                event,
                'Critical PowerShell And Malicious Network Correlation',
                'critical',
                'T1059.001',
                'Encoded PowerShell activity correlated with a malicious external network connection.',
                'Kill the process, block the IP, quarantine related files, and open an investigation case.',
                related_event_ids=related_ids
            ))

    if event_type == 'file':
        file_path = event.get('file_path') or ''
        file_signature_status = str(event.get('signature_status') or '').lower()
        if file_signature_status and file_signature_status not in {'valid', 'notsigned', 'missingfile'}:
            alerts.append(build_edr_alert(
                event,
                'File Has Invalid Digital Signature',
                'high',
                'T1036',
                f'File signature status is {event.get("signature_status")}.',
                'Quarantine the file if it is not from a trusted source.'
            ))

        if file_signature_status == 'notsigned' and has_extension(file_path, ['.exe', '.dll']) and is_user_writable_path(file_path):
            alerts.append(build_edr_alert(
                event,
                'Unsigned File Created In User-Writable Path',
                'medium',
                'T1204.002',
                'An unsigned executable or DLL appeared in a user-writable folder.',
                'Check the hash reputation and quarantine if untrusted.'
            ))

        if path_in_folder(file_path, 'downloads') and has_extension(file_path, ['.exe']):
            alerts.append(build_edr_alert(
                event,
                'Executable Created In Downloads Folder',
                'medium',
                'T1204.002',
                'A new executable file was created in Downloads.',
                'Quarantine the file if it is untrusted.'
            ))

        if path_in_folder(file_path, 'temp') and has_extension(file_path, ['.ps1', '.vbs', '.js', '.jse', '.bat', '.cmd']):
            alerts.append(build_edr_alert(
                event,
                'Script Created In Temp Folder',
                'high',
                'T1059',
                'A script file was created in a temporary directory.',
                'Collect file details and quarantine the script if unauthorized.'
            ))

        if str(event.get('process_name') or '').lower() in {'powershell.exe', 'pwsh.exe'} and file_path:
            alerts.append(build_edr_alert(
                event,
                'File Created By PowerShell',
                'medium',
                'T1105',
                'PowerShell created or modified a file.',
                'Review the file path, hash, and parent process.'
            ))

        recent_file_events = [
            recent_event for recent_event in get_recent_endpoint_events(event.get('endpoint_id'), minutes=1)
            if recent_event.get('event_type') == 'file'
        ]
        if len(recent_file_events) >= 20:
            alerts.append(build_edr_alert(
                event,
                'Multiple Files Modified Quickly',
                'high',
                'T1486',
                'Many file changes occurred in a short window.',
                'Collect process details and consider isolating the endpoint.'
            ))

    if event_type == 'registry':
        registry_key = str(event.get('registry_key') or '').lower()
        if text_contains_any(registry_key, [
            r'hkcu\software\microsoft\windows\currentversion\run',
            r'hklm\software\microsoft\windows\currentversion\run',
            r'currentversion\run'
        ]):
            alerts.append(build_edr_alert(
                event,
                'Suspicious Registry Run Key Modification',
                'high',
                'T1547.001',
                'A Windows Run key was created or modified.',
                'Review the value, collect process details, and remove unauthorized persistence.'
            ))

    if event_type == 'usb':
        if str(event.get('usb_action') or '').lower() == 'inserted':
            alerts.append(build_edr_alert(
                event,
                'USB Device Inserted',
                'medium',
                'T1091',
                f'USB device connected: {event.get("device_name") or "Unknown USB device"}.',
                'Confirm the USB device is authorized before opening files from it.'
            ))

    if event_type == 'rdp_login':
        rdp_result = str(event.get('rdp_result') or '').lower()
        if rdp_result == 'failed':
            alerts.append(build_edr_alert(
                event,
                'Failed RDP Login Attempt',
                'medium',
                'T1110',
                f'Failed RDP login for {event.get("target_user") or "unknown user"} from {event.get("source_ip") or "unknown source"}.',
                'Review the source IP and look for repeated failed logins.'
            ))
        elif rdp_result == 'successful':
            alerts.append(build_edr_alert(
                event,
                'Successful RDP Login Observed',
                'low',
                'T1021.001',
                f'RDP login succeeded for {event.get("target_user") or "unknown user"} from {event.get("source_ip") or "unknown source"}.',
                'Confirm the remote login was expected.'
            ))

    if event_type == 'failed_login_burst':
        failed_count = safe_int(event.get('failed_count'), 0) or 0
        alerts.append(build_edr_alert(
            event,
            'Failed Login Burst Detected',
            'high' if failed_count < 20 else 'critical',
            'T1110',
            f'{failed_count} failed logins were observed for {event.get("target_user") or "unknown user"} from {event.get("source_ip") or "unknown source"}.',
            'Block suspicious source IPs and review authentication logs.'
        ))

    if event_type == 'scheduled_task':
        task_command = f"{event.get('task_name') or ''} {event.get('command_line') or ''}"
        if text_contains_any(task_command, ['powershell', 'cmd.exe', 'wscript', 'cscript', 'temp', 'downloads']):
            alerts.append(build_edr_alert(
                event,
                'Suspicious Scheduled Task Created',
                'high',
                'T1053.005',
                'A scheduled task references a shell, script interpreter, or risky path.',
                'Disable the task and collect its action details.'
            ))

    return alerts


def save_edr_event(event):
    """Store normalized endpoint event in memory and MySQL."""
    event['id'] = event.get('id') or event.get('event_id') or uuid.uuid4().hex
    event['event_id'] = event.get('event_id') or event['id']
    push_limited_memory('events', event, 1000)

    if not mysql_available():
        return

    occurred_at = parse_edr_datetime(event.get('timestamp'))
    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO `events` (
                event_id, endpoint_id, event_type, source, severity, process_name,
                command_line, destination_ip, file_path, registry_key, raw_payload, occurred_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                severity = VALUES(severity),
                raw_payload = VALUES(raw_payload),
                received_at = CURRENT_TIMESTAMP
            """,
            (
                event['event_id'],
                event.get('endpoint_id'),
                event.get('event_type'),
                event.get('source') or 'windows_agent',
                event.get('severity') or 'info',
                truncate_db_value(event.get('process_name'), 255),
                event.get('command_line'),
                event.get('destination_ip') or None,
                event.get('file_path') or None,
                event.get('registry_key') or None,
                json_dumps(event.get('raw') or event),
                occurred_at,
            )
        )

        if event.get('event_type') == 'process':
            cursor.execute(
                """
                INSERT INTO process_events (
                    event_id, endpoint_id, process_name, pid, parent_pid, parent_process,
                    image_path, command_line, occurred_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    command_line = VALUES(command_line),
                    occurred_at = VALUES(occurred_at)
                """,
                (
                    event['event_id'],
                    event.get('endpoint_id'),
                    truncate_db_value(event.get('process_name'), 255),
                    event.get('pid'),
                    event.get('parent_pid'),
                    truncate_db_value(event.get('parent_process'), 255),
                    event.get('image_path'),
                    event.get('command_line'),
                    occurred_at,
                )
            )
        elif event.get('event_type') == 'network':
            cursor.execute(
                """
                INSERT INTO network_events (
                    event_id, endpoint_id, process_name, pid, destination_ip,
                    destination_port, protocol, threat_intel, occurred_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    destination_ip = VALUES(destination_ip),
                    destination_port = VALUES(destination_port),
                    threat_intel = VALUES(threat_intel),
                    occurred_at = VALUES(occurred_at)
                """,
                (
                    event['event_id'],
                    event.get('endpoint_id'),
                    truncate_db_value(event.get('process_name'), 255),
                    event.get('pid'),
                    event.get('destination_ip') or None,
                    event.get('destination_port'),
                    truncate_db_value(event.get('protocol'), 16),
                    json_dumps(event.get('threat_intel') or {}),
                    occurred_at,
                )
            )
        elif event.get('event_type') == 'file':
            cursor.execute(
                """
                INSERT INTO file_events (
                    event_id, endpoint_id, process_name, file_path, file_action, file_hash, occurred_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    file_action = VALUES(file_action),
                    file_hash = VALUES(file_hash),
                    occurred_at = VALUES(occurred_at)
                """,
                (
                    event['event_id'],
                    event.get('endpoint_id'),
                    truncate_db_value(event.get('process_name'), 255),
                    event.get('file_path'),
                    truncate_db_value(event.get('file_action'), 64),
                    truncate_db_value(event.get('file_hash'), 128),
                    occurred_at,
                )
            )
        elif event.get('event_type') == 'registry':
            cursor.execute(
                """
                INSERT INTO registry_events (
                    event_id, endpoint_id, process_name, registry_key,
                    registry_value, registry_action, occurred_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    registry_value = VALUES(registry_value),
                    registry_action = VALUES(registry_action),
                    occurred_at = VALUES(occurred_at)
                """,
                (
                    event['event_id'],
                    event.get('endpoint_id'),
                    truncate_db_value(event.get('process_name'), 255),
                    event.get('registry_key'),
                    event.get('registry_value'),
                    truncate_db_value(event.get('registry_action'), 64),
                    occurred_at,
                )
            )

        conn.commit()
        cursor.close()
    finally:
        conn.close()


def save_edr_alert(alert):
    """Store EDR alert and its event links."""
    alert['id'] = alert.get('id') or alert.get('alert_id') or uuid.uuid4().hex
    alert['alert_id'] = alert.get('alert_id') or alert['id']
    is_new_memory_alert = push_limited_memory('alerts', alert, 500)

    endpoint = edr_memory['endpoints'].get(alert.get('endpoint_id'))
    if endpoint and is_new_memory_alert:
        endpoint['total_alerts'] = int(endpoint.get('total_alerts') or 0) + 1

    if not mysql_available():
        return

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO edr_alerts (
                alert_id, title, severity, endpoint_id, endpoint_name, logged_in_user,
                process_name, parent_process, child_process, command_line, destination_ip,
                destination_port, mitre_id, status, summary, recommended_action,
                related_event_ids, raw_payload, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                title = VALUES(title),
                severity = VALUES(severity),
                endpoint_name = VALUES(endpoint_name),
                logged_in_user = VALUES(logged_in_user),
                process_name = VALUES(process_name),
                parent_process = VALUES(parent_process),
                child_process = VALUES(child_process),
                command_line = VALUES(command_line),
                destination_ip = VALUES(destination_ip),
                destination_port = VALUES(destination_port),
                mitre_id = VALUES(mitre_id),
                status = VALUES(status),
                summary = VALUES(summary),
                recommended_action = VALUES(recommended_action),
                related_event_ids = VALUES(related_event_ids),
                raw_payload = VALUES(raw_payload),
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                alert['alert_id'],
                truncate_db_value(alert.get('title'), 255),
                alert.get('severity') or 'medium',
                alert.get('endpoint_id'),
                truncate_db_value(alert.get('endpoint_name'), 255),
                truncate_db_value(alert.get('user'), 255),
                truncate_db_value(alert.get('process_name') or alert.get('process'), 255),
                truncate_db_value(alert.get('parent_process'), 255),
                truncate_db_value(alert.get('child_process'), 255),
                alert.get('command_line'),
                alert.get('destination_ip') or None,
                alert.get('destination_port'),
                truncate_db_value(alert.get('mitre_id'), 32),
                alert.get('status') or 'open',
                alert.get('summary'),
                truncate_db_value(alert.get('recommended_action'), 255),
                json_dumps(alert.get('related_event_ids') or []),
                json_dumps(alert.get('raw') or alert),
                parse_edr_datetime(alert.get('timestamp')),
            )
        )
        is_new_db_alert = cursor.rowcount == 1
        for event_id in alert.get('related_event_ids') or []:
            cursor.execute(
                """
                INSERT IGNORE INTO alert_events (alert_id, event_id)
                VALUES (%s, %s)
                """,
                (alert['alert_id'], event_id)
            )
        if is_new_db_alert:
            cursor.execute(
                """
                UPDATE endpoints
                SET total_alerts = total_alerts + 1, updated_at = CURRENT_TIMESTAMP
                WHERE endpoint_id = %s
                """,
                (alert.get('endpoint_id'),)
            )
        conn.commit()
        cursor.close()
    finally:
        conn.close()


def serialize_edr_endpoint_row(row):
    last_seen = row[7]
    return {
        'id': row[0],
        'endpoint_id': row[0],
        'hostname': row[1],
        'ip_address': row[2] or '',
        'os': row[3] or '',
        'user': row[4] or '',
        'agent_version': row[5] or '',
        'status': compute_endpoint_status(last_seen),
        'total_alerts': int(row[6] or 0),
        'last_seen': datetime_to_iso(last_seen),
    }


def fetch_edr_endpoints(limit=50):
    if not mysql_available():
        endpoints = list(edr_memory['endpoints'].values())
        for endpoint in endpoints:
            endpoint['status'] = compute_endpoint_status(endpoint.get('last_seen'))
        return sorted(endpoints, key=lambda item: item.get('last_seen') or '', reverse=True)[:limit]

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT endpoint_id, hostname, ip_address, os_name, logged_in_user,
                   agent_version, total_alerts, last_seen
            FROM endpoints
            ORDER BY last_seen DESC
            LIMIT %s
            """,
            (max(1, int(limit)),)
        )
        rows = cursor.fetchall()
        cursor.close()
        return [serialize_edr_endpoint_row(row) for row in rows]
    finally:
        conn.close()


def fetch_edr_events(limit=100):
    if not mysql_available():
        return dedupe_edr_events(edr_memory['events'])[:limit]

    conn = get_mysql_connection()
    fetch_limit = max(1, int(limit)) * 4
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT ev.event_id, ev.endpoint_id, ep.hostname, ep.logged_in_user,
                   ev.event_type, ev.source, ev.severity, ev.process_name,
                   ev.command_line, ev.destination_ip, ev.file_path, ev.registry_key,
                   ev.raw_payload, ev.occurred_at
            FROM `events` ev
            LEFT JOIN endpoints ep ON ep.endpoint_id = ev.endpoint_id
            ORDER BY ev.occurred_at DESC
            LIMIT %s
            """,
            (fetch_limit,)
        )
        rows = cursor.fetchall()
        cursor.close()
    finally:
        conn.close()

    events = []
    for row in rows:
        try:
            raw_payload = json.loads(row[12]) if row[12] else {}
        except (TypeError, json.JSONDecodeError):
            raw_payload = {}
        events.append({
            **raw_payload,
            'id': row[0],
            'event_id': row[0],
            'endpoint_id': row[1],
            'endpoint_name': row[2] or row[1],
            'user': row[3] or '',
            'event_type': row[4],
            'source': row[5],
            'severity': row[6],
            'process_name': row[7] or raw_payload.get('process_name') or '',
            'command_line': row[8] or raw_payload.get('command_line') or '',
            'destination_ip': row[9] or raw_payload.get('destination_ip') or '',
            'file_path': row[10] or raw_payload.get('file_path') or '',
            'registry_key': row[11] or raw_payload.get('registry_key') or '',
            'timestamp': datetime_to_iso(row[13]),
        })
    return dedupe_edr_events(events)[:limit]


def get_edr_event_display_key(event):
    event_type = str(event.get('event_type') or '').lower()
    if event_type == 'failed_login_burst':
        return (
            event_type,
            event.get('endpoint_id'),
            event.get('target_user'),
            event.get('source_ip') or 'local',
            event.get('failed_count'),
            event.get('window_start'),
            event.get('window_end'),
        )
    return ('id', event.get('id') or event.get('event_id'))


def dedupe_edr_events(events):
    deduped = []
    seen = set()
    for event in events:
        key = get_edr_event_display_key(event)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def fetch_edr_alerts(limit=100):
    if not mysql_available():
        return dedupe_edr_alerts(edr_memory['alerts'])[:limit]

    conn = get_mysql_connection()
    fetch_limit = max(1, int(limit)) * 4
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT alert_id, title, severity, endpoint_id, endpoint_name, logged_in_user,
                   process_name, parent_process, child_process, command_line, destination_ip,
                   destination_port, mitre_id, status, summary, recommended_action,
                   related_event_ids, created_at
            FROM edr_alerts
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (fetch_limit,)
        )
        rows = cursor.fetchall()
        cursor.close()
    finally:
        conn.close()

    alerts = []
    for row in rows:
        try:
            related_event_ids = json.loads(row[16]) if row[16] else []
        except (TypeError, json.JSONDecodeError):
            related_event_ids = []
        alerts.append({
            'id': row[0],
            'alert_id': row[0],
            'title': row[1],
            'severity': row[2],
            'endpoint_id': row[3],
            'endpoint_name': row[4],
            'user': row[5] or '',
            'process': row[6] or '',
            'process_name': row[6] or '',
            'parent_process': row[7] or '',
            'child_process': row[8] or '',
            'command_line': row[9] or '',
            'destination_ip': row[10] or '',
            'destination_port': row[11],
            'mitre_id': row[12] or '',
            'status': row[13] or 'open',
            'summary': row[14] or '',
            'recommended_action': row[15] or '',
            'related_event_ids': related_event_ids,
            'timestamp': datetime_to_iso(row[17]),
        })
    return dedupe_edr_alerts(alerts)[:limit]


def get_edr_alert_display_key(alert):
    return (
        alert.get('title'),
        alert.get('severity'),
        alert.get('endpoint_id'),
        alert.get('user'),
        alert.get('process_name') or alert.get('process'),
        alert.get('destination_ip'),
        alert.get('destination_port'),
        alert.get('mitre_id'),
        alert.get('summary'),
    )


def dedupe_edr_alerts(alerts):
    deduped = []
    seen = set()
    for alert in alerts:
        key = get_edr_alert_display_key(alert)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(alert)
    return deduped


def fetch_edr_responses(limit=50):
    if not mysql_available():
        return edr_memory['responses'][:limit]

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT action_id, action_type, target, mode, status, endpoint_id,
                   alert_id, result, created_at
            FROM response_actions
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (max(1, int(limit)),)
        )
        rows = cursor.fetchall()
        cursor.close()
    finally:
        conn.close()

    return [
        {
            'id': row[0],
            'action_id': row[0],
            'action': row[1],
            'target': row[2],
            'mode': row[3],
            'status': row[4],
            'endpoint_id': row[5] or '',
            'alert_id': row[6] or '',
            'result': row[7] or '',
            'timestamp': datetime_to_iso(row[8]),
        }
        for row in rows
    ]


def count_edr_events_today():
    today = datetime.now().date()
    if not mysql_available():
        return sum(
            1 for event in dedupe_edr_events(edr_memory['events'])
            if parse_edr_datetime(event.get('timestamp')).date() == today
        )

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM `events`
            WHERE occurred_at >= CURDATE()
            """
        )
        row = cursor.fetchone()
        cursor.close()
        return int(row[0] or 0) if row else 0
    finally:
        conn.close()


def build_edr_dashboard_payload(limit=50):
    endpoints = fetch_edr_endpoints(limit=50)
    events = fetch_edr_events(limit=max(100, int(limit)))
    alerts = fetch_edr_alerts(limit=max(200, int(limit) * 4))
    responses = fetch_edr_responses(limit=30)

    alerts_by_endpoint = {}
    for alert in alerts:
        alerts_by_endpoint[alert.get('endpoint_id')] = alerts_by_endpoint.get(alert.get('endpoint_id'), 0) + 1
    for endpoint in endpoints:
        endpoint['total_alerts'] = max(int(endpoint.get('total_alerts') or 0), alerts_by_endpoint.get(endpoint.get('id'), 0))

    open_alerts = [alert for alert in alerts if str(alert.get('status') or '').lower() == 'open']
    critical_alerts = [alert for alert in open_alerts if str(alert.get('severity') or '').lower() == 'critical']
    return {
        'summary': {
            'totalEndpoints': len(endpoints),
            'onlineEndpoints': sum(1 for endpoint in endpoints if endpoint.get('status') == 'online'),
            'offlineEndpoints': sum(1 for endpoint in endpoints if endpoint.get('status') != 'online'),
            'openAlerts': len(open_alerts),
            'criticalAlerts': len(critical_alerts),
            'eventsToday': count_edr_events_today(),
            'responses': len(responses),
        },
        'endpoints': endpoints,
        'events': events[:limit],
        'alerts': alerts[:limit],
        'responses': responses[:limit],
        'heartbeatTimeoutSeconds': EDR_HEARTBEAT_TIMEOUT_SECONDS,
        'coverage': [
            'Heartbeat',
            'Process',
            'Command Line',
            'Parent/Child',
            'Network',
            'File',
            'Registry',
            'Scheduled Task',
            'Sysmon Ready',
            'MITRE',
            'Dry-Run Response'
        ],
    }


def save_edr_response_action(action):
    push_limited_memory('responses', action, 300)

    if not mysql_available():
        return

    conn = get_mysql_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO response_actions (
                action_id, action_type, target, mode, status, endpoint_id,
                alert_id, result, raw_payload, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                action['id'],
                action.get('action'),
                action.get('target'),
                action.get('mode'),
                action.get('status'),
                action.get('endpoint_id') or None,
                action.get('alert_id') or None,
                action.get('result'),
                json_dumps(action),
                parse_edr_datetime(action.get('timestamp')),
            )
        )
        cursor.execute(
            """
            INSERT INTO audit_logs (actor, action, target, raw_payload, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                action.get('actor') or 'dashboard',
                action.get('action'),
                action.get('target'),
                json_dumps(action),
                parse_edr_datetime(action.get('timestamp')),
            )
        )
        conn.commit()
        cursor.close()
    finally:
        conn.close()


def execute_edr_response_action(action, target, dry_run=True):
    """Execute only safe dry-run response actions by default."""
    supported_actions = {
        'kill_process': 'Kill Process',
        'block_ip': 'Block IP',
        'unblock_ip': 'Unblock IP',
        'quarantine_file': 'Quarantine File',
        'restore_file': 'Restore File',
        'collect_process_details': 'Collect Process Details',
    }
    if action not in supported_actions:
        return 'rejected', f'Unsupported action: {action}'

    if dry_run:
        return 'dry_run', f'{supported_actions[action]} would run against {target}'

    if action == 'block_ip':
        if not is_valid_ipv4(target) or not is_blockable_public_ipv4(target):
            return 'failed', f'Invalid or non-public IP: {target}'
        blocked_ips[target] = {
            'ip': target,
            'reason': 'edr_response',
            'blockedAt': datetime.now().isoformat(),
            'firewall_blocked': False
        }
        return 'successful', f'IP {target} blocked in application memory'

    if action == 'unblock_ip':
        if target in blocked_ips:
            blocked_ips.pop(target)
            return 'successful', f'IP {target} unblocked from application memory'
        return 'failed', f'IP {target} was not blocked'

    return 'dry_run', f'{supported_actions[action]} remains dry-run only for endpoint safety'

# ============================================
# VALIDATION FUNCTIONS
# ============================================

def is_valid_ipv4(ip):
    """Validate IPv4 address"""
    try:
        parsed = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return parsed.version == 4

def is_valid_domain(domain):
    """Validate domain name"""
    if not isinstance(domain, str) or len(domain) > 253:
        return False
    domain_pattern = r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return re.match(domain_pattern, domain, re.IGNORECASE) is not None

def is_valid_hash(hash_value):
    """Validate MD5, SHA1, or SHA256 hash"""
    if not isinstance(hash_value, str):
        return False
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
    target = str(target or '').strip()
    target_type = str(target_type or 'auto').strip().lower()

    if target_type not in {'auto', 'ip', 'domain', 'hash'}:
        return False, f'Unsupported target type: {target_type}'
    
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
    if not is_valid_ipv4(target):
        return unsupported_target_response('AbuseIPDB', get_target_type(target) or 'target')

    if not config['key']:
        return api_key_response('AbuseIPDB')
    
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
    target_type = get_target_type(target)

    if not config['key']:
        return api_key_response('VirusTotal')
    if target_type not in {'ip', 'domain', 'hash'}:
        return unsupported_target_response('VirusTotal', target_type or 'target')
    
    try:
        headers = {
            config['header_name']: config['key'],
            'Accept': 'application/json'
        }
        
        endpoint_by_type = {
            'ip': config['endpoint'],
            'domain': 'https://www.virustotal.com/api/v3/domains',
            'hash': 'https://www.virustotal.com/api/v3/files',
        }
        url = f"{endpoint_by_type[target_type]}/{target}"
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
    target_type = get_target_type(target)

    if not config['key']:
        return api_key_response('AlienVault OTX')
    if target_type not in {'ip', 'domain', 'hash'}:
        return unsupported_target_response('AlienVault OTX', target_type or 'target')
    
    try:
        headers = {
            config['header_name']: config['key'],
            'Accept': 'application/json'
        }
        
        indicator_by_type = {
            'ip': 'IPv4',
            'domain': 'domain',
            'hash': 'file',
        }
        url = f"{config['endpoint']}/{indicator_by_type[target_type]}/{target}/general"
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
            'success': False,
            'error': str(e)
        }

def get_scan_tasks(target, target_type):
    """Return API tasks based on target type."""
    tasks = {}

    if target_type == 'ip':
        tasks['AbuseIPDB'] = lambda: query_abuseipdb(target)

    if target_type in {'ip', 'domain', 'hash'}:
        tasks['VirusTotal'] = lambda: query_virustotal(target)
        tasks['AlienVault'] = lambda: query_alienvault(target)

    if target_type == 'ip':
        tasks['GreyNoise'] = lambda: query_greynoise(target)
        tasks['IPQualityScore'] = lambda: query_ipqualityscore(target)
    
    return tasks

def query_greynoise(target):
    """Query GreyNoise API (Community Version)"""
    config = API_CONFIG['greynoise']
    if not is_valid_ipv4(target):
        return unsupported_target_response('GreyNoise', get_target_type(target) or 'target')

    if not config['key']:
        return api_key_response('GreyNoise')
    
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
            'success': False,
            'error': str(e)
        }

def query_ipqualityscore(target):
    """Query IPQualityScore API - Comprehensive fraud detection (IPv4 only)"""
    config = API_CONFIG['ipqualityscore']
    
    # Check if API key is configured
    if not config['key']:
        return api_key_response('IPQualityScore')
    
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
            'alert_stats': 'GET /api/alert-stats',
            'receive_alert': 'POST /api/receive-alert',
            'threat_logs': 'GET /api/threat-logs',
            'edr_dashboard': 'GET /api/edr/dashboard',
            'edr_heartbeat': 'POST /api/edr/heartbeat',
            'edr_ingest': 'POST /api/edr/ingest',
            'edr_events': 'GET /api/edr/events',
            'edr_alerts': 'GET /api/edr/alerts',
            'edr_response': 'POST /api/edr/respond',
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
    data = get_json_body()
    target = str(data.get('target', '')).strip()
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
    data = get_json_body()
    target = str(data.get('target', '')).strip()
    requested_type = data.get('type', 'auto')
    
    if not target:
        return jsonify({
            'success': False,
            'error': 'Target is required'
        }), 400
    
    # Validate input
    is_valid, target_type = validate_input(target, requested_type)
    if not is_valid:
        return jsonify({
            'success': False,
            'error': target_type
        }), 400

    if target_type == 'ip' and not is_blockable_public_ipv4(target):
        return jsonify({
            'success': False,
            'error': f'Only public, globally routable IPv4 addresses can be scanned: {target}'
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

        try:
            completed_futures = as_completed(futures, timeout=30)
            for future in completed_futures:
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
        except TimeoutError:
            logger.error('Timed out waiting for threat intelligence services')
            for future, name in futures.items():
                if not future.done():
                    future.cancel()
                    results_list.append({
                        'name': name,
                        'error': 'Service timed out',
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

    limit = get_bounded_limit(default=100, maximum=1000)
    alerts = fetch_alerts(limit=limit)
    return jsonify({
        'success': True,
        'alerts': alerts,
        'total': len(alerts),
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/alert-stats', methods=['GET'])
def get_alert_stats():
    """Get real-time chart stats from stored alerts."""
    stats = fetch_alert_stats()
    return jsonify({
        'success': True,
        **stats,
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/receive-alert', methods=['POST'])
def receive_alert():
    """Receive an alert payload from the attack detector and store it."""
    if ALERT_INGEST_TOKEN:
        provided_token = request.headers.get('X-Alert-Token') or ''
        auth_header = request.headers.get('Authorization') or ''
        bearer_token = auth_header.removeprefix('Bearer ').strip()
        if provided_token != ALERT_INGEST_TOKEN and bearer_token != ALERT_INGEST_TOKEN:
            return jsonify({'success': False, 'error': 'Unauthorized alert source'}), 401

    data = get_json_body()
    attacker_ip = (
        data.get('attacker_ip')
        or data.get('ip')
        or data.get('ip_address')
    )
    if not attacker_ip:
        return jsonify({'success': False, 'error': 'attacker_ip is required'}), 400
    if not is_valid_ipv4(str(attacker_ip)):
        return jsonify({'success': False, 'error': 'attacker_ip must be a valid IPv4 address'}), 400

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
    limit = get_bounded_limit(default=500, maximum=1000)
    logs = fetch_threat_logs(limit=limit)
    return jsonify({
        'success': True,
        'logs': logs,
        'total': len(logs),
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/edr/dashboard', methods=['GET'])
def get_edr_dashboard():
    """Return endpoint heartbeat, events, alerts, and response history for the dashboard."""
    limit = get_bounded_limit(default=50, maximum=200)
    return jsonify({
        'success': True,
        **build_edr_dashboard_payload(limit=limit),
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/edr/heartbeat', methods=['POST'])
def receive_edr_heartbeat():
    """Receive endpoint heartbeat from the Windows agent."""
    token_error = check_edr_agent_token()
    if token_error:
        return token_error

    data = get_json_body()
    endpoint = normalize_endpoint(data)
    endpoint['status'] = 'online'
    endpoint['last_seen'] = datetime.now().isoformat(timespec='seconds')

    try:
        save_edr_endpoint(endpoint, heartbeat=True)
    except Exception as exc:
        logger.error(f'Failed to store EDR heartbeat: {str(exc)}')
        return jsonify({'success': False, 'error': 'Failed to store endpoint heartbeat'}), 500

    return jsonify({
        'success': True,
        'endpoint': endpoint,
        'heartbeatTimeoutSeconds': EDR_HEARTBEAT_TIMEOUT_SECONDS,
        'message': 'Endpoint heartbeat accepted'
    }), 200


@app.route('/api/edr/ingest', methods=['POST'])
def ingest_edr_events():
    """Receive endpoint events, run EDR detection rules, and generate alerts."""
    token_error = check_edr_agent_token()
    if token_error:
        return token_error

    data = get_json_body()
    endpoint = normalize_endpoint(data)
    endpoint['status'] = 'online'
    endpoint['last_seen'] = datetime.now().isoformat(timespec='seconds')

    raw_events = data.get('events')
    if raw_events is None:
        raw_events = [data.get('event') or data]
    if not isinstance(raw_events, list):
        raw_events = [raw_events]

    stored_events = []
    generated_alerts = []

    try:
        save_edr_endpoint(endpoint, heartbeat=False)
        for raw_event in raw_events:
            event = normalize_edr_event(raw_event if isinstance(raw_event, dict) else {'message': raw_event}, endpoint)
            save_edr_event(event)
            stored_events.append(event)

            for alert in detect_edr_alerts(event):
                save_edr_alert(alert)
                generated_alerts.append(alert)
    except Exception as exc:
        logger.error(f'Failed to ingest EDR events: {str(exc)}')
        return jsonify({'success': False, 'error': 'Failed to ingest endpoint events'}), 500

    return jsonify({
        'success': True,
        'endpoint': endpoint,
        'eventsStored': len(stored_events),
        'alertsGenerated': len(generated_alerts),
        'alerts': generated_alerts,
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/edr/events', methods=['GET'])
def get_edr_events():
    """Return raw endpoint events."""
    limit = get_bounded_limit(default=100, maximum=1000)
    events = fetch_edr_events(limit=limit)
    return jsonify({
        'success': True,
        'events': events,
        'total': len(events),
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/edr/alerts', methods=['GET'])
def get_edr_alerts():
    """Return endpoint alert queue."""
    limit = get_bounded_limit(default=100, maximum=1000)
    alerts = fetch_edr_alerts(limit=limit)
    return jsonify({
        'success': True,
        'alerts': alerts,
        'total': len(alerts),
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/edr/responses', methods=['GET'])
def get_edr_responses():
    """Return endpoint response action history."""
    limit = get_bounded_limit(default=50, maximum=500)
    responses = fetch_edr_responses(limit=limit)
    return jsonify({
        'success': True,
        'responses': responses,
        'total': len(responses),
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/edr/respond', methods=['POST'])
def submit_edr_response_action():
    """Record a safe endpoint response action; dry-run is the default mode."""
    data = get_json_body()
    action_type = str(data.get('action') or data.get('action_type') or '').strip().lower()
    target = str(data.get('target') or '').strip()
    requested_dry_run = parse_bool(data.get('dry_run'), default=True)
    dry_run = EDR_RESPONSE_DRY_RUN or requested_dry_run

    if not action_type:
        return jsonify({'success': False, 'error': 'action is required'}), 400
    if not target:
        return jsonify({'success': False, 'error': 'target is required'}), 400

    status, result = execute_edr_response_action(action_type, target, dry_run=dry_run)
    response_action = {
        'id': uuid.uuid4().hex,
        'action_id': None,
        'action': action_type,
        'target': target,
        'mode': 'dry-run' if dry_run or status == 'dry_run' else 'live',
        'status': status,
        'endpoint_id': data.get('endpoint_id') or '',
        'alert_id': data.get('alert_id') or '',
        'result': result,
        'actor': data.get('actor') or 'dashboard',
        'timestamp': datetime.now().isoformat(timespec='seconds'),
    }
    response_action['action_id'] = response_action['id']

    try:
        save_edr_response_action(response_action)
    except Exception as exc:
        logger.error(f'Failed to store EDR response action: {str(exc)}')
        return jsonify({'success': False, 'error': 'Failed to store response action'}), 500

    return jsonify({
        'success': status not in {'failed', 'rejected'},
        'response': response_action,
        'message': result
    }), 200 if status not in {'failed', 'rejected'} else 400

@app.route('/api/scan/<service>', methods=['POST'])
@rate_limit
def scan_with_service(service):
    """Scan target with specific API service"""
    data = get_json_body()
    target = str(data.get('target', '')).strip()
    
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
    data = get_json_body()
    ip = str(data.get('ip', '')).strip()
    reason = data.get('reason', 'manual_block')
    enable_firewall = data.get('firewall', False)  # Optional: enable system firewall blocking

    if not ip:
        return jsonify({'success': False, 'error': 'IP is required'}), 400

    if not is_valid_ipv4(ip):
        return jsonify({'success': False, 'error': f'Invalid IPv4: {ip}'}), 400

    if not is_blockable_public_ipv4(ip):
        return jsonify({
            'success': False,
            'error': f'Only public, globally routable IPv4 addresses can be blocked: {ip}'
        }), 400

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
    data = get_json_body()
    ip = str(data.get('ip', '')).strip()

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
