-- Create and use the database
CREATE DATABASE IF NOT EXISTS datafort_db;
USE datafort_db;

-- Users table (stores approved users with certificates)
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    role ENUM('employee','manager','admin','auditor') NOT NULL,
    public_key TEXT NOT NULL,
    certificate BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Certificate requests (pending user registrations)
CREATE TABLE IF NOT EXISTS certificate_requests (
    request_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    csr BLOB NOT NULL,
    requested_role ENUM('employee','manager','auditor') DEFAULT 'employee',
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_by INT NULL,
    processed_at TIMESTAMP NULL,
    FOREIGN KEY (processed_by) REFERENCES users(user_id)
);

-- Backups table (stores encrypted backups with IV and tag)
CREATE TABLE IF NOT EXISTS backups (
    backup_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    encrypted_data LONGBLOB NOT NULL,
    encrypted_symmetric_key BLOB NOT NULL,
    iv BLOB NOT NULL,
    tag BLOB NOT NULL,
    signature BLOB NOT NULL,
    reason TEXT,
    status ENUM('pending','approved','restored') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Restore requests (employee requests for restoring backups)
CREATE TABLE IF NOT EXISTS restore_requests (
    request_id INT AUTO_INCREMENT PRIMARY KEY,
    backup_id INT NOT NULL,
    requester_id INT NOT NULL,
    approver_id INT NULL,
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approval_time TIMESTAMP NULL,
    approver_signature BLOB NULL,
    FOREIGN KEY (backup_id) REFERENCES backups(backup_id),
    FOREIGN KEY (requester_id) REFERENCES users(user_id),
    FOREIGN KEY (approver_id) REFERENCES users(user_id)
);

-- Audit log (tracks all significant actions with signatures)
CREATE TABLE IF NOT EXISTS audit_log (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT,
    signature BLOB NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Revoked certificates (list of revoked certificate serial numbers)
CREATE TABLE IF NOT EXISTS revoked_certificates (
    serial_number VARCHAR(100) PRIMARY KEY,
    revocation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- Messages table for user-to-admin communication
CREATE TABLE IF NOT EXISTS messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    recipient_id INT NOT NULL,
    subject VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (recipient_id) REFERENCES users(user_id)
);