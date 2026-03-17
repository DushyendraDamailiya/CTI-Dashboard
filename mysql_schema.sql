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
    INDEX `idx_alerts_ip_address` (`ip_address`)
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
