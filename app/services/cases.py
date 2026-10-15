import logging
import os
import re

from app import config
from app.database import utc_now

_STORED = re.compile(r"^[a-f0-9]{32}\.(csv|json|log|txt)$")
_LOG = logging.getLogger("digitrace")


def _page(conn, sql_count, sql_rows, params, page, per_page):
    total = conn.execute(sql_count, params).fetchone()["total"]
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), pages)
    rows = conn.execute(sql_rows, (*params, per_page, (page - 1) * per_page)).fetchall()
    return rows, total, page, pages


def list_admin_cases(conn, page, per_page=20):
    count_sql = "SELECT COUNT(*) AS total FROM cases"
    rows_sql = """SELECT c.case_id, c.case_title, c.status, c.created_at,
                         (SELECT COUNT(*) FROM evidence_files f WHERE f.case_id = c.case_id) AS file_count
                  FROM cases c ORDER BY c.created_at DESC, c.case_id DESC LIMIT ? OFFSET ?"""
    return _page(conn, count_sql, rows_sql, (), page, per_page)


def recent_cases(conn, limit=8):
    return conn.execute(
        """SELECT case_id, case_title, status, created_at FROM cases
           ORDER BY created_at DESC, case_id DESC LIMIT ?""",
        (limit,),
    ).fetchall()


def assignment_map(conn, case_ids):
    if not case_ids:
        return {}
    marks = ",".join("?" for _ in case_ids)
    rows = conn.execute(
        f"""SELECT a.case_id, u.full_name FROM case_assignments a
            JOIN users u ON u.user_id = a.user_id WHERE a.case_id IN ({marks}) ORDER BY u.full_name""",
        tuple(case_ids),
    ).fetchall()
    grouped = {}
    for row in rows:
        grouped.setdefault(row["case_id"], []).append(row["full_name"])
    return grouped


def assigned_ids(conn, case_id):
    rows = conn.execute("SELECT user_id FROM case_assignments WHERE case_id = ?", (case_id,)).fetchall()
    return {row["user_id"] for row in rows}


def get_case(conn, case_id):
    return conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()


def assigned_case(conn, case_id, user_id):
    return conn.execute(
        """SELECT c.* FROM cases c
           JOIN case_assignments a ON a.case_id = c.case_id
           WHERE c.case_id = ? AND a.user_id = ?""",
        (case_id, user_id),
    ).fetchone()


def list_assigned(conn, user_id):
    return conn.execute(
        """SELECT c.case_id, c.case_title, c.status, c.created_at,
                  (SELECT COUNT(*) FROM events e WHERE e.case_id = c.case_id) AS event_count,
                  (SELECT COUNT(*) FROM evidence_files f WHERE f.case_id = c.case_id) AS file_count
           FROM cases c JOIN case_assignments a ON a.case_id = c.case_id
           WHERE a.user_id = ? ORDER BY c.created_at DESC, c.case_id DESC""",
        (user_id,),
    ).fetchall()


def dashboard_counts(conn):
    investigators = conn.execute("SELECT COUNT(*) AS total FROM users WHERE role = 'Investigator'").fetchone()["total"]
    files = conn.execute("SELECT COUNT(*) AS total FROM evidence_files").fetchone()["total"]
    statuses = {"Open": 0, "Analyzed": 0, "Closed": 0}
    for row in conn.execute("SELECT status, COUNT(*) AS total FROM cases GROUP BY status"):
        statuses[row["status"]] = row["total"]
    return investigators, statuses, files


def _set_assignments(conn, case_id, user_ids, now):
    conn.execute("DELETE FROM case_assignments WHERE case_id = ?", (case_id,))
    for user_id in user_ids:
        conn.execute(
            "INSERT INTO case_assignments (case_id, user_id, assigned_at) VALUES (?, ?, ?)",
            (case_id, user_id, now),
        )


def create_case(conn, title, description, user_ids, created_by):
    now = utc_now()
    conn.execute("BEGIN")
    try:
        cursor = conn.execute(
            """INSERT INTO cases (case_title, description, status, created_by, created_at)
               VALUES (?, ?, 'Open', ?, ?)""",
            (title, description, created_by, now),
        )
        _set_assignments(conn, cursor.lastrowid, user_ids, now)
        conn.commit()
        return cursor.lastrowid
    except Exception:
        conn.rollback()
        raise


def update_case(conn, case_id, title, description, status, user_ids):
    now = utc_now()
    conn.execute("BEGIN")
    try:
        conn.execute(
            "UPDATE cases SET case_title = ?, description = ?, status = ? WHERE case_id = ?",
            (title, description, status, case_id),
        )
        _set_assignments(conn, case_id, user_ids, now)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def delete_case(conn, case_id):
    rows = conn.execute("SELECT stored_name FROM evidence_files WHERE case_id = ?", (case_id,)).fetchall()
    names = [row["stored_name"] for row in rows]
    conn.execute("BEGIN")
    try:
        conn.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    root = config.UPLOAD_DIR.resolve()
    for name in names:
        if not _STORED.fullmatch(name or ""):
            continue
        path = (root / name).resolve()
        if path.parent != root:
            continue
        try:
            os.chmod(path, 0o666)
            path.unlink(missing_ok=True)
        except OSError:
            _LOG.exception("evidence file delete failed")
