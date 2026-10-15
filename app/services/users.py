from app.database import utc_now
from app.security import hash_password


def list_investigators(conn, page, per_page=20):
    total = conn.execute("SELECT COUNT(*) AS total FROM users WHERE role = 'Investigator'").fetchone()["total"]
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), pages)
    offset = (page - 1) * per_page
    rows = conn.execute(
        """SELECT user_id, full_name, username, email, created_at FROM users
           WHERE role = 'Investigator' ORDER BY created_at DESC, user_id DESC LIMIT ? OFFSET ?""",
        (per_page, offset),
    ).fetchall()
    return rows, total, page, pages


def all_investigators(conn):
    return conn.execute(
        "SELECT user_id, full_name, username FROM users WHERE role = 'Investigator' ORDER BY full_name, user_id"
    ).fetchall()


def get_user(conn, user_id):
    return conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()


def username_taken(conn, username, exclude_id=None):
    row = conn.execute(
        "SELECT user_id FROM users WHERE username = ? AND (? IS NULL OR user_id != ?)",
        (username, exclude_id, exclude_id),
    ).fetchone()
    return row is not None


def email_taken(conn, email, exclude_id=None):
    row = conn.execute(
        "SELECT user_id FROM users WHERE email = ? AND (? IS NULL OR user_id != ?)",
        (email, exclude_id, exclude_id),
    ).fetchone()
    return row is not None


def create_investigator(conn, full_name, username, email, password):
    now = utc_now()
    cursor = conn.execute(
        """INSERT INTO users (full_name, username, email, password_hash, role, created_at)
           VALUES (?, ?, ?, ?, 'Investigator', ?)""",
        (full_name, username, email, hash_password(password), now),
    )
    conn.commit()
    return cursor.lastrowid


def update_investigator(conn, user_id, full_name, username, email, password):
    if password:
        conn.execute(
            "UPDATE users SET full_name = ?, username = ?, email = ?, password_hash = ? WHERE user_id = ? AND role = 'Investigator'",
            (full_name, username, email, hash_password(password), user_id),
        )
    else:
        conn.execute(
            "UPDATE users SET full_name = ?, username = ?, email = ? WHERE user_id = ? AND role = 'Investigator'",
            (full_name, username, email, user_id),
        )
    conn.commit()


def update_account(conn, user_id, full_name, username, email, password=None):
    if password:
        conn.execute(
            "UPDATE users SET full_name = ?, username = ?, email = ?, password_hash = ? WHERE user_id = ?",
            (full_name, username, email, hash_password(password), user_id),
        )
    else:
        conn.execute(
            "UPDATE users SET full_name = ?, username = ?, email = ? WHERE user_id = ?",
            (full_name, username, email, user_id),
        )
    conn.commit()


def delete_investigator(conn, user_id):
    conn.execute("DELETE FROM users WHERE user_id = ? AND role = 'Investigator'", (user_id,))
    conn.commit()
