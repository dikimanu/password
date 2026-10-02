from database.database import get_connection


def is_known_device(user_id, ip_address, user_agent):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM known_devices WHERE user_id = %s AND ip_address = %s AND user_agent = %s
    """, (user_id, ip_address, user_agent))
    row = cursor.fetchone()
    conn.close()
    return row is not None


def register_device(user_id, ip_address, user_agent):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO known_devices (user_id, ip_address, user_agent)
        VALUES (%s, %s, %s)
    """, (user_id, ip_address, user_agent))
    conn.commit()
    conn.close()


def has_any_known_device(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM known_devices WHERE user_id = %s", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row["cnt"] > 0