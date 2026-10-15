import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from flask import g, request

from app import config
from app.database import utc_now


def _hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def create_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    now = utc_now()
    conn.execute(
        """INSERT INTO sessions (session_hash, user_id, csrf_token, created_at, last_activity)
           VALUES (?, ?, ?, ?, ?)""",
        (_hash(token), user_id, secrets.token_urlsafe(32), now, now),
    )
    return token


def destroy_session(conn, token):
    if not token:
        return
    conn.execute("DELETE FROM sessions WHERE session_hash = ?", (_hash(token),))


def destroy_other_sessions(conn, user_id, token):
    conn.execute(
        "DELETE FROM sessions WHERE user_id = ? AND session_hash != ?",
        (user_id, _hash(token or "")),
    )


def load_session():
    g.user = None
    g.csrf_token = ""
    g.session_token = request.cookies.get("dt_session", "")
    token = g.session_token
    if not token:
        return
    row = g.db.execute(
        """SELECT s.session_hash, s.csrf_token, s.last_activity, u.user_id, u.full_name, u.username, u.email, u.role
           FROM sessions s JOIN users u ON u.user_id = s.user_id WHERE s.session_hash = ?""",
        (_hash(token),),
    ).fetchone()
    if row is None:
        g.session_token = ""
        return
    seen = _parse(row["last_activity"])
    limit = timedelta(minutes=config.SESSION_IDLE_MINUTES)
    if seen is None or datetime.now(timezone.utc) - seen > limit:
        g.db.execute("DELETE FROM sessions WHERE session_hash = ?", (row["session_hash"],))
        g.db.commit()
        g.session_token = ""
        return
    now = utc_now()
    expired = (datetime.now(timezone.utc) - limit).strftime("%Y-%m-%dT%H:%M:%SZ")
    g.db.execute("UPDATE sessions SET last_activity = ? WHERE session_hash = ?", (now, row["session_hash"]))
    g.db.execute("DELETE FROM sessions WHERE last_activity < ?", (expired,))
    g.db.commit()
    g.user = row
    g.csrf_token = row["csrf_token"]


def csrf_valid():
    if not g.csrf_token:
        return False
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    if len(sent) != len(g.csrf_token):
        return False
    return secrets.compare_digest(sent, g.csrf_token)
