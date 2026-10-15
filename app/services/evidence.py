import logging
import os
import secrets
from pathlib import Path

from app import config
from app.database import utc_now
from app.security import safe_display_name
from ai_engine.pipeline import parse_evidence_file

_LOG = logging.getLogger("digitrace")
_ALLOWED = {".csv", ".json", ".log", ".txt"}
_SOURCES = ("Log", "Browser History", "Login Events", "File Events")


def _unlink(path):
    try:
        os.chmod(path, 0o666)
    except OSError:
        pass
    try:
        path.unlink(missing_ok=True)
    except OSError:
        _LOG.exception("removing stored evidence failed")


def save_upload(conn, case_row, user, upload, source_type, tz_offset):
    if case_row["status"] == "Closed":
        return False, "لا يمكن رفع ملفات إلى قضية مغلقة", False
    if source_type not in _SOURCES:
        return False, "نوع المصدر غير صالح", False
    if upload is None or not upload.filename:
        return False, "اختر ملفاً لرفعه", False
    display = safe_display_name(upload.filename)
    extension = Path(display).suffix.lower()
    if extension not in _ALLOWED:
        return False, "امتداد الملف غير مسموح. الامتدادات المقبولة هي csv وjson وlog وtxt", False
    data = upload.read()
    limit = config.MAX_UPLOAD_MB * 1024 * 1024
    if len(data) > limit:
        return False, "حجم الملف يتجاوز الحد المسموح", False
    if not data:
        return False, "الملف فارغ", False
    import hashlib
    digest = hashlib.sha256(data).hexdigest()
    duplicate = conn.execute(
        "SELECT 1 FROM evidence_files WHERE case_id = ? AND file_hash = ?",
        (case_row["case_id"], digest),
    ).fetchone()
    if duplicate:
        return False, "تم رفع هذا الملف مسبقاً إلى هذه القضية", False
    stored = secrets.token_hex(16) + extension
    root = config.UPLOAD_DIR.resolve()
    dest = (root / stored).resolve()
    if dest.parent != root:
        return False, "تعذر حفظ الملف", False
    try:
        dest.write_bytes(data)
    except OSError:
        _LOG.exception("writing evidence failed")
        return False, "تعذر حفظ الملف", False
    parsed = parse_evidence_file(dest, source_type, tz_offset)
    if not parsed["ok"]:
        _unlink(dest)
        return False, parsed["error"] or "لم يُستخرج أي حدث صالح من الملف", False
    reopened = case_row["status"] == "Analyzed"
    try:
        conn.execute("BEGIN")
        cursor = conn.execute(
            """INSERT INTO evidence_files
               (case_id, uploaded_by, uploader_name, file_name, stored_name, source_type, file_size, file_hash, event_count, skipped_count, upload_date)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                case_row["case_id"],
                user["user_id"],
                user["full_name"],
                display,
                stored,
                source_type,
                len(data),
                digest,
                len(parsed["events"]),
                int(parsed["skipped_count"]),
                utc_now(),
            ),
        )
        file_id = cursor.lastrowid
        conn.executemany(
            """INSERT INTO events
               (case_id, file_id, event_time, event_ts, source_type, event_type, action, result, username, ip_address, dest_ip, device, file_path, url, details, raw_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    case_row["case_id"],
                    file_id,
                    event["event_time"],
                    int(event["event_ts"]),
                    event["source_type"],
                    event["event_type"],
                    event.get("action") or "",
                    event.get("result") or "",
                    event.get("username") or "",
                    event.get("ip_address") or "",
                    event.get("dest_ip") or "",
                    event.get("device") or "",
                    event.get("file_path") or "",
                    event.get("url") or "",
                    event.get("details") or "",
                    event.get("raw_data") or "",
                )
                for event in parsed["events"]
            ],
        )
        if reopened:
            conn.execute("UPDATE cases SET status = 'Open' WHERE case_id = ?", (case_row["case_id"],))
        conn.commit()
    except Exception:
        conn.rollback()
        _unlink(dest)
        _LOG.exception("saving evidence rows failed")
        return False, "تعذر حفظ بيانات الملف", False
    try:
        os.chmod(dest, 0o444)
    except OSError:
        pass
    message = f"تم استيراد {len(parsed['events'])} حدثاً وتخطي {parsed['skipped_count']} سطراً غير صالح"
    return True, message, reopened


def list_files(conn, case_id):
    return conn.execute(
        """SELECT file_id, file_name, source_type, uploader_name, upload_date, file_hash, event_count, skipped_count
           FROM evidence_files WHERE case_id = ? ORDER BY upload_date DESC, file_id DESC""",
        (case_id,),
    ).fetchall()
