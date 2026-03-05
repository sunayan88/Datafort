from .db_connection import get_db_connection
import mysql.connector
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from crypto.key_management import sign_with_system_key

# ---------- User functions ----------
def get_user_by_username(username):
    conn = get_db_connection()
    if not conn:
        return None
    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT user_id, username, role, public_key, certificate,
               failed_login_attempts, locked_until
        FROM users
        WHERE username = %s AND is_active = TRUE
    """
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def insert_user(username, role, public_key, certificate_der):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    query = "INSERT INTO users (username, role, public_key, certificate) VALUES (%s, %s, %s, %s)"
    try:
        cursor.execute(query, (username, role, public_key, certificate_der))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error inserting user: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_all_users():
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor(dictionary=True)
    query = "SELECT user_id, username, role, created_at, is_active FROM users ORDER BY user_id"
    cursor.execute(query)
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return users

def deactivate_user(user_id):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET is_active = FALSE WHERE user_id = %s", (user_id,))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error deactivating user: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def reactivate_user(user_id):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET is_active = TRUE WHERE user_id = %s", (user_id,))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error reactivating user: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

# ---------- Certificate request functions ----------
def insert_certificate_request(username, public_key, csr, requested_role='employee'):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    query = """
        INSERT INTO certificate_requests (username, public_key, csr, requested_role)
        VALUES (%s, %s, %s, %s)
    """
    try:
        cursor.execute(query, (username, public_key, csr, requested_role))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error inserting certificate request: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def check_username_exists(username):
    conn = get_db_connection()
    if not conn:
        return True
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return True
    cursor.execute("SELECT username FROM certificate_requests WHERE username = %s AND status = 'pending'", (username,))
    exists = cursor.fetchone() is not None
    cursor.close()
    conn.close()
    return exists

def get_pending_requests():
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor(dictionary=True)
    query = "SELECT request_id, username, public_key, csr, requested_role, requested_at FROM certificate_requests WHERE status = 'pending'"
    cursor.execute(query)
    requests = cursor.fetchall()
    cursor.close()
    conn.close()
    return requests

def approve_request(request_id, certificate_der, admin_user_id):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, public_key, requested_role FROM certificate_requests WHERE request_id = %s", (request_id,))
        req = cursor.fetchone()
        if not req:
            return False
        username, public_key, role = req
        
        insert_user_query = "INSERT INTO users (username, role, public_key, certificate) VALUES (%s, %s, %s, %s)"
        cursor.execute(insert_user_query, (username, role, public_key, certificate_der))
        
        update_query = "UPDATE certificate_requests SET status = 'approved', processed_by = %s, processed_at = NOW() WHERE request_id = %s"
        cursor.execute(update_query, (admin_user_id, request_id))
        
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error approving request: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def reject_request(request_id, admin_user_id):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    try:
        query = "UPDATE certificate_requests SET status = 'rejected', processed_by = %s, processed_at = NOW() WHERE request_id = %s"
        cursor.execute(query, (admin_user_id, request_id))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error rejecting request: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

# ---------- Backup functions ----------
def insert_backup(user_id, file_name, encrypted_data, encrypted_symmetric_key, iv, tag, signature, reason):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    query = """
        INSERT INTO backups (user_id, file_name, encrypted_data, encrypted_symmetric_key, iv, tag, signature, reason)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    try:
        cursor.execute(query, (user_id, file_name, encrypted_data, encrypted_symmetric_key, iv, tag, signature, reason))
        conn.commit()
        return cursor.lastrowid
    except mysql.connector.Error as err:
        print(f"Error inserting backup: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_user_backups(user_id):
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor(dictionary=True)
    query = "SELECT backup_id, file_name, reason, status, created_at FROM backups WHERE user_id = %s ORDER BY created_at DESC"
    cursor.execute(query, (user_id,))
    backups = cursor.fetchall()
    cursor.close()
    conn.close()
    return backups

def get_backup_by_id(backup_id):
    conn = get_db_connection()
    if not conn:
        return None
    cursor = conn.cursor(dictionary=True)
    query = "SELECT * FROM backups WHERE backup_id = %s"
    cursor.execute(query, (backup_id,))
    backup = cursor.fetchone()
    cursor.close()
    conn.close()
    return backup

# ---------- Restore request functions ----------
def create_restore_request(backup_id, requester_id):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    query = "INSERT INTO restore_requests (backup_id, requester_id) VALUES (%s, %s)"
    try:
        cursor.execute(query, (backup_id, requester_id))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error creating restore request: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_pending_restore_requests():
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT rr.request_id, rr.backup_id, rr.requester_id, rr.request_time,
               u.username as requester_name, b.file_name, b.reason
        FROM restore_requests rr
        JOIN users u ON rr.requester_id = u.user_id
        JOIN backups b ON rr.backup_id = b.backup_id
        WHERE rr.status = 'pending'
    """
    cursor.execute(query)
    requests = cursor.fetchall()
    cursor.close()
    conn.close()
    return requests

def approve_restore_request(request_id, approver_id, approver_signature):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    try:
        query = """
            UPDATE restore_requests
            SET status = 'approved', approver_id = %s, approver_signature = %s, approval_time = NOW()
            WHERE request_id = %s
        """
        cursor.execute(query, (approver_id, approver_signature, request_id))
        cursor.execute("UPDATE backups SET status = 'approved' WHERE backup_id = (SELECT backup_id FROM restore_requests WHERE request_id = %s)", (request_id,))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error approving request: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_restore_requests_by_requester(requester_id):
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT rr.*, b.file_name
        FROM restore_requests rr
        JOIN backups b ON rr.backup_id = b.backup_id
        WHERE rr.requester_id = %s
        ORDER BY rr.request_time DESC
    """
    cursor.execute(query, (requester_id,))
    requests = cursor.fetchall()
    cursor.close()
    conn.close()
    return requests

def reject_restore_request(request_id, approver_id):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    try:
        query = "UPDATE restore_requests SET status = 'rejected', approver_id = %s, approval_time = NOW() WHERE request_id = %s"
        cursor.execute(query, (approver_id, request_id))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error rejecting restore request: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

# ---------- Audit Log functions ----------
def insert_audit_log(user_id, action, details):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    now = datetime.now()
    timestamp_str = now.strftime('%Y-%m-%d %H:%M:%S')
    data_str = f"{user_id}|{action}|{details}|{timestamp_str}"
    signature = sign_with_system_key(data_str.encode())
    try:
        cursor.execute(
            "INSERT INTO audit_log (user_id, action, details, signature, timestamp) VALUES (%s, %s, %s, %s, %s)",
            (user_id, action, details, signature, now)
        )
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error inserting audit log: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_audit_logs():
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT al.*, u.username 
        FROM audit_log al 
        JOIN users u ON al.user_id = u.user_id 
        ORDER BY al.timestamp DESC
    """
    cursor.execute(query)
    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    return logs

def get_audit_log_by_id(log_id):
    conn = get_db_connection()
    if not conn:
        return None
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM audit_log WHERE log_id = %s", (log_id,))
    log = cursor.fetchone()
    cursor.close()
    conn.close()
    return log

# ---------- Certificate Revocation functions ----------
def get_certificate_serial_from_user(user_id):
    conn = get_db_connection()
    if not conn:
        return None
    cursor = conn.cursor()
    cursor.execute("SELECT certificate FROM users WHERE user_id = %s", (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    if result and result[0]:
        cert = x509.load_der_x509_certificate(result[0], default_backend())
        return cert.serial_number
    return None

def revoke_certificate(serial_number):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO revoked_certificates (serial_number) VALUES (%s)", (str(serial_number),))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error revoking certificate: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def is_certificate_revoked(serial_number):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    cursor.execute("SELECT serial_number FROM revoked_certificates WHERE serial_number = %s", (str(serial_number),))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result is not None

# ---------- Message functions (NEW) ----------
def send_message(sender_id, recipient_id, subject, content):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    query = "INSERT INTO messages (sender_id, recipient_id, subject, content) VALUES (%s, %s, %s, %s)"
    try:
        cursor.execute(query, (sender_id, recipient_id, subject, content))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error sending message: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_messages_for_user(user_id):
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT m.*, 
               sender.username as sender_name,
               recipient.username as recipient_name
        FROM messages m
        JOIN users sender ON m.sender_id = sender.user_id
        JOIN users recipient ON m.recipient_id = recipient.user_id
        WHERE m.recipient_id = %s OR m.sender_id = %s
        ORDER BY m.timestamp DESC
    """
    cursor.execute(query, (user_id, user_id))
    messages = cursor.fetchall()
    cursor.close()
    conn.close()
    return messages

def get_unread_count(user_id):
    conn = get_db_connection()
    if not conn:
        return 0
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient_id = %s AND is_read = FALSE", (user_id,))
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return count

def mark_message_read(message_id):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE messages SET is_read = TRUE WHERE message_id = %s", (message_id,))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error marking message read: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_all_messages():  # for admin
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT m.*, 
               sender.username as sender_name,
               recipient.username as recipient_name
        FROM messages m
        JOIN users sender ON m.sender_id = sender.user_id
        JOIN users recipient ON m.recipient_id = recipient.user_id
        ORDER BY m.timestamp DESC
    """
    cursor.execute(query)
    messages = cursor.fetchall()
    cursor.close()
    conn.close()
    return messages

def get_admin_user_id():
    conn = get_db_connection()
    if not conn:
        return None
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1")
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result[0] if result else None

def get_user_by_id(user_id):
    conn = get_db_connection()
    if not conn:
        return None
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id, username, role, public_key, certificate, failed_login_attempts, locked_until FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def increment_failed_attempts(user_id):
    conn = get_db_connection()
    if not conn:
        return
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE user_id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

def reset_failed_attempts(user_id):
    conn = get_db_connection()
    if not conn:
        return
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE user_id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

def lock_user_account(user_id, lock_until):
    conn = get_db_connection()
    if not conn:
        return
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET failed_login_attempts = 0, locked_until = %s WHERE user_id = %s", (lock_until, user_id))
    conn.commit()
    cursor.close()
    conn.close()