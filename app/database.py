import os
import sqlite3
from datetime import datetime, timezone

from app import config
from app.security import hash_password


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect():
    config.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    config.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(config.DATABASE_PATH.parent, 0o700)
    except OSError:
        pass
    conn = connect()
    try:
        schema = (config.ROOT / "app" / "schema.sql").read_text(encoding="utf-8")
        conn.executescript(schema)
        conn.commit()
        _seed(conn)
    finally:
        conn.close()


def _need(name):
    return os.getenv(name, "").strip()


def _seed(conn):
    existing = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
    if existing:
        return
    fields = (
        "SEED_ADMIN_NAME", "SEED_ADMIN_USERNAME", "SEED_ADMIN_EMAIL", "SEED_ADMIN_PASSWORD",
        "SEED_INV1_NAME", "SEED_INV1_USERNAME", "SEED_INV1_EMAIL", "SEED_INV1_PASSWORD",
        "SEED_INV2_NAME", "SEED_INV2_USERNAME", "SEED_INV2_EMAIL", "SEED_INV2_PASSWORD",
    )
    values = {name: _need(name) for name in fields}
    if any(not values[name] for name in fields):
        return
    now = utc_now()
    accounts = (
        (values["SEED_ADMIN_NAME"], values["SEED_ADMIN_USERNAME"], values["SEED_ADMIN_EMAIL"], values["SEED_ADMIN_PASSWORD"], "Admin"),
        (values["SEED_INV1_NAME"], values["SEED_INV1_USERNAME"], values["SEED_INV1_EMAIL"], values["SEED_INV1_PASSWORD"], "Investigator"),
        (values["SEED_INV2_NAME"], values["SEED_INV2_USERNAME"], values["SEED_INV2_EMAIL"], values["SEED_INV2_PASSWORD"], "Investigator"),
    )
    ids = []
    conn.execute("BEGIN")
    try:
        for full_name, username, email, password, role in accounts:
            cursor = conn.execute(
                """INSERT INTO users (full_name, username, email, password_hash, role, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (full_name, username.strip().lower(), email.strip().lower(), hash_password(password), role, now),
            )
            ids.append(cursor.lastrowid)
        cursor = conn.execute(
            """INSERT INTO cases (case_title, description, status, created_by, created_at)
               VALUES (?, ?, 'Open', ?, ?)""",
            (
                "قضية تجريبية: تسريب بيانات مالية خارج ساعات العمل",
                "قضية مخصصة لتجربة رفع ملفات الأدلة وتشغيل التحليل الزمني.",
                ids[0],
                now,
            ),
        )
        case_id = cursor.lastrowid
        for user_id in ids[1:]:
            conn.execute(
                "INSERT INTO case_assignments (case_id, user_id, assigned_at) VALUES (?, ?, ?)",
                (case_id, user_id, now),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
