import time
from datetime import datetime, timedelta
from database import db_queries

MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def check_account_locked(user_id):
    """Return True if account is locked, else False."""
    user = db_queries.get_user_by_id(user_id)  # you'll need this function
    if user and user['locked_until']:
        if user['locked_until'] > datetime.now():
            return True
        else:
            # Lock expired – reset
            db_queries.reset_failed_attempts(user_id)
    return False

def handle_failed_login(username):
    """Increment failed attempts and lock if threshold reached."""
    user = db_queries.get_user_by_username(username)
    if not user:
        return  # user doesn't exist – we could also log this
    
    attempts = user['failed_login_attempts'] + 1
    if attempts >= MAX_ATTEMPTS:
        lock_until = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
        db_queries.lock_user_account(user['user_id'], lock_until)
        # Optionally send notification to admin/user
    else:
        db_queries.increment_failed_attempts(user['user_id'])

def handle_successful_login(username):
    """Reset failed attempts on successful login."""
    user = db_queries.get_user_by_username(username)
    if user:
        db_queries.reset_failed_attempts(user['user_id'])