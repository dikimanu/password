from database.database import get_connection


def log_login_attempt(user_id, identifier, success, ip_address=None, user_agent=None,
                       risk_score=None, risk_level=None, attack_category=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO login_attempts
            (user_id, identifier, success, ip_address, user_agent, risk_score, risk_level, attack_category)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (user_id, identifier, int(success), ip_address, user_agent, risk_score, risk_level, attack_category))
    conn.commit()
    conn.close()


def log_security_event(user_id, event_type, description=None, risk_level=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO security_events (user_id, event_type, description, risk_level)
        VALUES (%s, %s, %s, %s)
    """, (user_id, event_type, description, risk_level))
    conn.commit()
    conn.close()


def get_recent_attempts(user_id, limit=20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM login_attempts WHERE user_id = %s
        ORDER BY timestamp DESC LIMIT %s
    """, (user_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_attempts_by_identifier(identifier, limit=50):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM login_attempts WHERE identifier = %s
        ORDER BY timestamp DESC LIMIT %s
    """, (identifier, limit))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_security_events(user_id, limit=20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM security_events WHERE user_id = %s
        ORDER BY timestamp DESC LIMIT %s
    """, (user_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_all_login_attempts(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM login_attempts ORDER BY timestamp DESC LIMIT %s", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_all_security_events(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT %s", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows