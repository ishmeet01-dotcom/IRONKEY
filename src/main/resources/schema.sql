-- ============================================================================
-- IRONKEY — Encrypted Password Management System
-- Database Schema Definition (MySQL 8.0+)
-- Database: ironkey_db
-- ============================================================================

-- Create the database if it doesn't already exist
CREATE DATABASE IF NOT EXISTS ironkey_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE ironkey_db;

-- ----------------------------------------------------------------------------
-- Table: users
-- Stores authentication data and unique salts.
-- Note: master_password_hash is derived via PBKDF2WithHmacSHA256 for login.
-- key_derivation_salt is a separate salt used strictly to derive the AES vault key.
-- Plaintext master passwords and vault encryption keys are NEVER stored.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    username                VARCHAR(50)  NOT NULL UNIQUE,
    email                   VARCHAR(100) NOT NULL UNIQUE,
    master_password_hash    VARCHAR(255) NOT NULL,
    master_password_salt    VARCHAR(255) NOT NULL,
    key_derivation_salt     VARCHAR(255) NOT NULL,
    created_at              TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_users_username (username),
    INDEX idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table: categories
-- Organizes vault credentials into logical groups (e.g., Logins, Financial, Secure Notes).
-- user_id is nullable: NULL represents global default categories; non-null represents custom user categories.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS categories (
    category_id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id                 BIGINT NULL,
    name                    VARCHAR(50) NOT NULL,
    icon                    VARCHAR(50) DEFAULT 'folder',
    created_at              TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_categories_user
        FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE,
    INDEX idx_categories_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table: vault_entries
-- Stores encrypted credentials.
-- encrypted_username and encrypted_password contain AES-256-GCM ciphertexts.
-- nonce stores the unique 12-byte initialization vector (Base64 encoded).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vault_entries (
    entry_id                BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id                 BIGINT NOT NULL,
    website_name            VARCHAR(100) NOT NULL,
    website_url             VARCHAR(255),
    encrypted_username      TEXT NOT NULL,
    encrypted_password      TEXT NOT NULL,
    nonce                   VARCHAR(64) NOT NULL,
    category                VARCHAR(50) NOT NULL DEFAULT 'Logins',
    notes                   TEXT,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_vault_entries_user
        FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE,
    INDEX idx_vault_user_id (user_id),
    INDEX idx_vault_website_name (website_name),
    INDEX idx_vault_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table: security_logs
-- Audit logging for security events (login success/failure, vault locks, export attempts).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_logs (
    log_id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id                 BIGINT NOT NULL,
    event_type              VARCHAR(50)  NOT NULL,
    description             VARCHAR(255) NOT NULL,
    timestamp               TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_security_logs_user
        FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE,
    INDEX idx_security_logs_user (user_id),
    INDEX idx_security_logs_event_type (event_type),
    INDEX idx_security_logs_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Seed Standard Default Categories
-- ----------------------------------------------------------------------------
INSERT IGNORE INTO categories (category_id, user_id, name, icon) VALUES
    (1, NULL, 'Logins', 'key'),
    (2, NULL, 'Financial', 'credit-card'),
    (3, NULL, 'Secure Notes', 'file-text'),
    (4, NULL, 'Identities', 'user'),
    (5, NULL, 'Servers & SSH', 'server');
