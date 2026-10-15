import json
import logging

from app.database import utc_now
from ai_engine.pipeline import analyze_case

_LOG = logging.getLogger("digitrace")


def run_analysis(conn, case_row, user):
    if case_row["status"] == "Closed":
        return False, "لا يمكن تحليل قضية مغلقة"
    rows = conn.execute(
        "SELECT * FROM events WHERE case_id = ? ORDER BY event_ts, event_id",
        (case_row["case_id"],),
    ).fetchall()
    if not rows:
        return False, "لا توجد أحداث لتحليلها في هذه القضية"
    payload = []
    for row in rows:
        payload.append({
            "event_id": row["event_id"],
            "event_time": row["event_time"],
            "event_ts": row["event_ts"],
            "source_type": row["source_type"],
            "event_type": row["event_type"],
            "action": row["action"] or "",
            "result": row["result"] or "",
            "username": row["username"] or "",
            "ip_address": row["ip_address"] or "",
            "dest_ip": row["dest_ip"] or "",
            "device": row["device"] or "",
            "file_path": row["file_path"] or "",
            "url": row["url"] or "",
            "details": row["details"] or "",
            "raw_data": row["raw_data"] or "",
            "size_bytes": None,
        })
    file_count = conn.execute(
        "SELECT COUNT(*) AS total FROM evidence_files WHERE case_id = ?",
        (case_row["case_id"],),
    ).fetchone()["total"]
    try:
        result = analyze_case(payload, {"file_count": file_count})
    except Exception:
        _LOG.exception("analysis failed")
        return False, "تعذر إكمال التحليل، يمكن إعادة المحاولة"
    try:
        conn.execute("BEGIN")
        conn.execute("DELETE FROM correlation_groups WHERE case_id = ?", (case_row["case_id"],))
        keys = {}
        for group in result["groups"]:
            cursor = conn.execute(
                """INSERT INTO correlation_groups
                   (case_id, group_label, risk_score, risk_level, start_time, end_time, event_count, key_event_count, main_user, main_ip, main_device, stages)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    case_row["case_id"],
                    group["label"],
                    group["risk_score"],
                    group["risk_level"],
                    group["start_time"],
                    group["end_time"],
                    group["event_count"],
                    group["key_event_count"],
                    group["main_user"] or "",
                    group["main_ip"] or "",
                    group["main_device"] or "",
                    json.dumps(group["stages"], ensure_ascii=False),
                ),
            )
            keys[group["group_key"]] = cursor.lastrowid
        conn.executemany(
            """UPDATE events SET group_id = ?, importance_score = ?, importance_level = ?, anomaly_score = ?, stage = ?, is_noise = ?, repeat_count = ?, reasons = ?
               WHERE event_id = ? AND case_id = ?""",
            [
                (
                    keys.get(item["group_key"]),
                    item["importance_score"],
                    item["importance_level"],
                    item["anomaly_score"],
                    item["stage"],
                    item["is_noise"],
                    item["repeat_count"],
                    json.dumps(item["reasons"], ensure_ascii=False),
                    item["event_id"],
                    case_row["case_id"],
                )
                for item in result["events"]
            ],
        )
        stats = result["stats"]
        conn.execute(
            """INSERT INTO analysis_results
               (case_id, summary_text, total_events, key_events, removed_events, group_count, critical_count, generated_by, generated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                case_row["case_id"],
                result["summary_text"],
                stats["total_events"],
                stats["key_events"],
                stats["removed_events"],
                stats["group_count"],
                stats["critical_count"],
                user["user_id"],
                utc_now(),
            ),
        )
        conn.execute("UPDATE cases SET status = 'Analyzed' WHERE case_id = ?", (case_row["case_id"],))
        conn.commit()
    except Exception:
        conn.rollback()
        _LOG.exception("saving analysis failed")
        return False, "تعذر حفظ نتائج التحليل"
    return True, "اكتمل التحليل"


def latest_result(conn, case_id):
    return conn.execute(
        "SELECT * FROM analysis_results WHERE case_id = ? ORDER BY generated_at DESC, result_id DESC LIMIT 1",
        (case_id,),
    ).fetchone()


def previous_results(conn, case_id):
    return conn.execute(
        """SELECT generated_at, summary_text FROM analysis_results WHERE case_id = ?
           ORDER BY generated_at DESC, result_id DESC LIMIT -1 OFFSET 1""",
        (case_id,),
    ).fetchall()

