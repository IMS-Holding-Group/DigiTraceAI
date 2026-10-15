import re
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from flask import request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app import config

_USERNAME = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DUMMY = None


def hash_password(password):
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS))
    return hashed.decode("utf-8")


def check_password(password, stored):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
    except Exception:
        return False


def dummy_check(password):
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password(secrets.token_urlsafe(24))
    check_password(password or "", _DUMMY)


def valid_name(value):
    text = (value or "").strip()
    return 2 <= len(text) <= 100


def valid_username(value):
    text = (value or "").strip()
    if not _USERNAME.fullmatch(text):
        return False
    if text.isdigit():
        return False
    return True


def valid_email(value):
    text = (value or "").strip()
    return bool(_EMAIL.fullmatch(text)) and len(text) <= 120


def valid_password(value):
    if not value or not isinstance(value, str):
        return False
    if len(value) < 10 or len(value) > 128:
        return False
    if not re.search(r"[A-Z]", value) or not re.search(r"[a-z]", value) or not re.search(r"\d", value):
        return False
    return True


def client_ip():
    address = request.remote_addr or "0.0.0.0"
    if len(address) > 64:
        return "0.0.0.0"
    return address


def _cutoff():
    moment = datetime.now(timezone.utc) - timedelta(minutes=config.LOGIN_LOCK_MINUTES)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def too_many_attempts(conn, identifier, ip_address):
    cutoff = _cutoff()
    by_name = conn.execute(
        "SELECT COUNT(*) AS total FROM login_attempts WHERE identifier = ? AND success = 0 AND attempted_at >= ?",
        (identifier, cutoff),
    ).fetchone()["total"]
    by_ip = conn.execute(
        "SELECT COUNT(*) AS total FROM login_attempts WHERE ip_address = ? AND success = 0 AND attempted_at >= ?",
        (ip_address, cutoff),
    ).fetchone()["total"]
    limit = config.LOGIN_MAX_FAILURES
    return by_name >= limit or by_ip >= limit


def record_attempt(conn, identifier, ip_address, success):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    old = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO login_attempts (identifier, ip_address, success, attempted_at) VALUES (?, ?, ?, ?)",
        (identifier[:120], ip_address, 1 if success else 0, now),
    )
    conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (old,))


def login_serializer():
    return URLSafeTimedSerializer(config.SECRET_KEY or "missing-secret", salt="dt-login-csrf")


def issue_login_csrf():
    return login_serializer().dumps(secrets.token_urlsafe(32))


def valid_login_csrf(form_value, cookie_value):
    if not form_value or not cookie_value:
        return False
    if len(form_value) != len(cookie_value):
        return False
    if not secrets.compare_digest(form_value, cookie_value):
        return False
    try:
        login_serializer().loads(cookie_value, max_age=3600)
    except (BadSignature, SignatureExpired):
        return False
    return True


def safe_display_name(name):
    text = str(name or "").replace("\\", "/").split("/")[-1].strip()
    text = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", text).strip(" .")
    if not text:
        return "file"
    return text[:180]


def like_pattern(value):
    text = str(value or "")[:200]
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"
