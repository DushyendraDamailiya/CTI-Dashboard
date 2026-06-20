CREATE DATABASE IF NOT EXISTS `threat_dashboard`
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE `threat_dashboard`;

CREATE TABLE IF NOT EXISTS `alerts` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `alert_type` VARCHAR(255) NOT NULL,
    `source` VARCHAR(100) NOT NULL DEFAULT 'attack_detector',
    `ip_address` VARCHAR(45) NOT NULL,
    `severity` VARCHAR(20) NOT NULL DEFAULT 'medium',
    `description` TEXT,
    `target_ip` VARCHAR(45),
    `log_line` TEXT,
    `attempt_count` INT NOT NULL DEFAULT 1,
    `raw_payload` JSON,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_alerts_created_at` (`created_at`),
    INDEX `idx_alerts_severity` (`severity`),
    INDEX `idx_alerts_ip_address` (`ip_address`),
    INDEX `idx_alerts_dedup` (`source`, `ip_address`, `alert_type`, `updated_at`)
);

CREATE TABLE IF NOT EXISTS `threat_logs` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `ip_address` VARCHAR(45) NOT NULL,
    `country` VARCHAR(100) NOT NULL DEFAULT 'Unknown',
    `country_code` VARCHAR(8),
    `threat_score` INT NOT NULL DEFAULT 0,
    `api_sources` TEXT,
    `status` VARCHAR(32) NOT NULL DEFAULT 'monitored',
    `scan_results` JSON,
    `overall_data` JSON,
    `last_scanned_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `uq_threat_logs_ip_address` (`ip_address`),
    INDEX `idx_threat_logs_score` (`threat_score`),
    INDEX `idx_threat_logs_last_scanned_at` (`last_scanned_at`)
);

CREATE TABLE IF NOT EXISTS `endpoints` (
    `endpoint_id` VARCHAR(128) PRIMARY KEY,
    `hostname` VARCHAR(255) NOT NULL,
    `ip_address` VARCHAR(45),
    `os_name` VARCHAR(255),
    `logged_in_user` VARCHAR(255),
    `agent_version` VARCHAR(50),
    `status` VARCHAR(32) NOT NULL DEFAULT 'offline',
    `total_alerts` INT NOT NULL DEFAULT 0,
    `raw_payload` JSON,
    `last_seen` DATETIME,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_endpoints_status` (`status`),
    INDEX `idx_endpoints_last_seen` (`last_seen`)
);

CREATE TABLE IF NOT EXISTS `agent_heartbeats` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `endpoint_id` VARCHAR(128) NOT NULL,
    `status` VARCHAR(32) NOT NULL DEFAULT 'online',
    `raw_payload` JSON,
    `received_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_agent_heartbeats_endpoint` (`endpoint_id`),
    INDEX `idx_agent_heartbeats_received_at` (`received_at`)
);

CREATE TABLE IF NOT EXISTS `events` (
    `event_id` VARCHAR(64) PRIMARY KEY,
    `endpoint_id` VARCHAR(128) NOT NULL,
    `event_type` VARCHAR(64) NOT NULL,
    `source` VARCHAR(100) NOT NULL DEFAULT 'windows_agent',
    `severity` VARCHAR(20) NOT NULL DEFAULT 'info',
    `process_name` VARCHAR(255),
    `command_line` TEXT,
    `destination_ip` VARCHAR(45),
    `file_path` TEXT,
    `registry_key` TEXT,
    `raw_payload` JSON,
    `occurred_at` DATETIME NOT NULL,
    `received_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_events_endpoint` (`endpoint_id`),
    INDEX `idx_events_type` (`event_type`),
    INDEX `idx_events_occurred_at` (`occurred_at`)
);

CREATE TABLE IF NOT EXISTS `process_events` (
    `event_id` VARCHAR(64) PRIMARY KEY,
    `endpoint_id` VARCHAR(128) NOT NULL,
    `process_name` VARCHAR(255),
    `pid` INT,
    `parent_pid` INT,
    `parent_process` VARCHAR(255),
    `image_path` TEXT,
    `command_line` TEXT,
    `occurred_at` DATETIME NOT NULL,
    INDEX `idx_process_events_endpoint` (`endpoint_id`),
    INDEX `idx_process_events_process` (`process_name`)
);

CREATE TABLE IF NOT EXISTS `network_events` (
    `event_id` VARCHAR(64) PRIMARY KEY,
    `endpoint_id` VARCHAR(128) NOT NULL,
    `process_name` VARCHAR(255),
    `pid` INT,
    `destination_ip` VARCHAR(45),
    `destination_port` INT,
    `protocol` VARCHAR(16),
    `threat_intel` JSON,
    `occurred_at` DATETIME NOT NULL,
    INDEX `idx_network_events_endpoint` (`endpoint_id`),
    INDEX `idx_network_events_destination` (`destination_ip`)
);

CREATE TABLE IF NOT EXISTS `file_events` (
    `event_id` VARCHAR(64) PRIMARY KEY,
    `endpoint_id` VARCHAR(128) NOT NULL,
    `process_name` VARCHAR(255),
    `file_path` TEXT,
    `file_action` VARCHAR(64),
    `file_hash` VARCHAR(128),
    `occurred_at` DATETIME NOT NULL,
    INDEX `idx_file_events_endpoint` (`endpoint_id`)
);

CREATE TABLE IF NOT EXISTS `registry_events` (
    `event_id` VARCHAR(64) PRIMARY KEY,
    `endpoint_id` VARCHAR(128) NOT NULL,
    `process_name` VARCHAR(255),
    `registry_key` TEXT,
    `registry_value` TEXT,
    `registry_action` VARCHAR(64),
    `occurred_at` DATETIME NOT NULL,
    INDEX `idx_registry_events_endpoint` (`endpoint_id`)
);

CREATE TABLE IF NOT EXISTS `edr_alerts` (
    `alert_id` VARCHAR(64) PRIMARY KEY,
    `title` VARCHAR(255) NOT NULL,
    `severity` VARCHAR(20) NOT NULL DEFAULT 'medium',
    `endpoint_id` VARCHAR(128) NOT NULL,
    `endpoint_name` VARCHAR(255),
    `logged_in_user` VARCHAR(255),
    `process_name` VARCHAR(255),
    `parent_process` VARCHAR(255),
    `child_process` VARCHAR(255),
    `command_line` TEXT,
    `destination_ip` VARCHAR(45),
    `destination_port` INT,
    `mitre_id` VARCHAR(32),
    `status` VARCHAR(32) NOT NULL DEFAULT 'open',
    `summary` TEXT,
    `recommended_action` VARCHAR(255),
    `related_event_ids` JSON,
    `raw_payload` JSON,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_edr_alerts_endpoint` (`endpoint_id`),
    INDEX `idx_edr_alerts_severity` (`severity`),
    INDEX `idx_edr_alerts_status` (`status`),
    INDEX `idx_edr_alerts_created_at` (`created_at`)
);

CREATE TABLE IF NOT EXISTS `alert_events` (
    `alert_id` VARCHAR(64) NOT NULL,
    `event_id` VARCHAR(64) NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`alert_id`, `event_id`),
    INDEX `idx_alert_events_event` (`event_id`)
);

CREATE TABLE IF NOT EXISTS `response_actions` (
    `action_id` VARCHAR(64) PRIMARY KEY,
    `action_type` VARCHAR(64) NOT NULL,
    `target` TEXT NOT NULL,
    `mode` VARCHAR(32) NOT NULL DEFAULT 'dry-run',
    `status` VARCHAR(32) NOT NULL DEFAULT 'queued',
    `endpoint_id` VARCHAR(128),
    `alert_id` VARCHAR(64),
    `result` TEXT,
    `raw_payload` JSON,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_response_actions_endpoint` (`endpoint_id`),
    INDEX `idx_response_actions_alert` (`alert_id`),
    INDEX `idx_response_actions_created_at` (`created_at`)
);

CREATE TABLE IF NOT EXISTS `ioc_cache` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `ioc` VARCHAR(255) NOT NULL,
    `ioc_type` VARCHAR(32) NOT NULL,
    `reputation` VARCHAR(64),
    `source` VARCHAR(100),
    `raw_payload` JSON,
    `expires_at` DATETIME,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `uq_ioc_cache_ioc_source` (`ioc`, `source`),
    INDEX `idx_ioc_cache_ioc` (`ioc`),
    INDEX `idx_ioc_cache_expires_at` (`expires_at`)
);

CREATE TABLE IF NOT EXISTS `cases` (
    `case_id` VARCHAR(64) PRIMARY KEY,
    `title` VARCHAR(255) NOT NULL,
    `severity` VARCHAR(20) NOT NULL DEFAULT 'medium',
    `status` VARCHAR(32) NOT NULL DEFAULT 'open',
    `owner` VARCHAR(255),
    `raw_payload` JSON,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_cases_status` (`status`),
    INDEX `idx_cases_severity` (`severity`)
);

CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
    `actor` VARCHAR(255) NOT NULL DEFAULT 'system',
    `action` VARCHAR(255) NOT NULL,
    `target` TEXT,
    `raw_payload` JSON,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_audit_logs_created_at` (`created_at`)
);
