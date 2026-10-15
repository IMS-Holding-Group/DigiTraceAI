import json

from flask import Blueprint, abort, g, jsonify, request

from app.formatting import event_label, source_label, stage_label
from app.security import like_pattern
from app.services.cases import assigned_case

bp = Blueprint("api", __name__)
_LEVELS = {"حرج", "عالٍ", "متوسط", "منخفض"}


def _guard_case(case_id):
    if not g.user or g.user["role"] != "Investigator":
        abort(403)
    row = assigned_case(g.db, case_id, g.user["user_id"])
    if row is None:
        abort(404)
    return row


def _int_arg(name, default, low, high):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


def _loads(value):
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


@bp.get("/api/cases/<int:case_id>/events")
def events(case_id):
    _guard_case(case_id)
    page = _int_arg("page", 1, 1, 100000)
    per_page = _int_arg("per_page", 100, 1, 200)
    where = ["e.case_id = ?"]
    params = [case_id]
    if request.args.get("include_noise", "0") != "1":
        where.append("e.is_noise = 0")
    source = request.args.get("source", "").strip()
    if source:
        where.append("e.source_type = ?")
        params.append(source[:40])
    event_type = request.args.get("event_type", "").strip()
    if event_type:
        where.append("e.event_type = ?")
        params.append(event_type[:40])
    for key, column in (("user", "e.username"), ("device", "e.device")):
        text = request.args.get(key, "").strip()
        if text:
            where.append(f"{column} LIKE ? ESCAPE '\\'")
            params.append(like_pattern(text))
    address = request.args.get("ip", "").strip()
    if address:
        pattern = like_pattern(address)
        where.append("(e.ip_address LIKE ? ESCAPE '\\' OR e.dest_ip LIKE ? ESCAPE '\\')")
        params.extend((pattern, pattern))
    file_text = request.args.get("file", "").strip()
    if file_text:
        pattern = like_pattern(file_text)
        where.append("(e.file_path LIKE ? ESCAPE '\\' OR e.url LIKE ? ESCAPE '\\')")
        params.extend((pattern, pattern))
    query = request.args.get("q", "").strip()
    if query:
        pattern = like_pattern(query)
        where.append(
            """(e.username LIKE ? ESCAPE '\\' OR e.device LIKE ? ESCAPE '\\' OR e.ip_address LIKE ? ESCAPE '\\'
               OR e.dest_ip LIKE ? ESCAPE '\\' OR e.file_path LIKE ? ESCAPE '\\' OR e.url LIKE ? ESCAPE '\\'
               OR e.details LIKE ? ESCAPE '\\' OR e.action LIKE ? ESCAPE '\\' OR e.event_type LIKE ? ESCAPE '\\'
               OR e.source_type LIKE ? ESCAPE '\\' OR e.result LIKE ? ESCAPE '\\')"""
        )
        params.extend([pattern] * 11)
    levels = []
    raw_levels = request.args.getlist("importance") or [request.args.get("importance", "")]
    for chunk in raw_levels:
        for piece in str(chunk).split(","):
            piece = piece.strip()
            if piece in _LEVELS and piece not in levels:
                levels.append(piece)
    if levels:
        where.append("e.importance_level IN (" + ",".join("?" for _ in levels) + ")")
        params.extend(levels)
    group_id = request.args.get("group", "").strip()
    if group_id:
        try:
            where.append("e.group_id = ?")
            params.append(int(group_id))
        except ValueError:
            pass
    start = request.args.get("from", "").strip()
    end = request.args.get("to", "").strip()
    if start:
        where.append("e.event_time >= ?")
        params.append(start[:40])
    if end:
        where.append("e.event_time <= ?")
        params.append(end[:40])
    direction = "DESC" if request.args.get("order", "asc") == "desc" else "ASC"
    clause = " AND ".join(where)
    total = g.db.execute(f"SELECT COUNT(*) AS total FROM events e WHERE {clause}", params).fetchone()["total"]
    pages = max(1, (total + per_page - 1) // per_page)
    if page > pages:
        page = pages
    rows = g.db.execute(
        f"""SELECT e.event_id, e.event_time, e.source_type, e.event_type, e.username, e.device, e.ip_address, e.dest_ip,
                  e.file_path, e.url, e.importance_level, e.group_id, e.is_noise, g.group_label
           FROM events e LEFT JOIN correlation_groups g ON g.group_id = e.group_id
           WHERE {clause} ORDER BY e.event_ts {direction}, e.event_id {direction} LIMIT ? OFFSET ?""",
        (*params, per_page, (page - 1) * per_page),
    ).fetchall()
    items = []
    for row in rows:
        items.append({
            "event_id": row["event_id"],
            "event_time": row["event_time"],
            "source_type": row["source_type"],
            "source_label": source_label(row["source_type"]),
            "event_type": row["event_type"],
            "event_label": event_label(row["event_type"]),
            "username": row["username"] or "",
            "device": row["device"] or "",
            "ip_address": row["ip_address"] or "",
            "dest_ip": row["dest_ip"] or "",
            "file_path": row["file_path"] or "",
            "url": row["url"] or "",
            "importance_level": row["importance_level"] or "",
            "group_id": row["group_id"],
            "group_label": row["group_label"] or "",
            "is_noise": row["is_noise"],
        })
    return jsonify({"ok": True, "page": page, "per_page": per_page, "total": total, "pages": pages, "events": items})


@bp.get("/api/cases/<int:case_id>/events/<int:event_id>")
def event_detail(case_id, event_id):
    _guard_case(case_id)
    row = g.db.execute(
        """SELECT e.*, g.group_label, g.risk_level, g.risk_score FROM events e
           LEFT JOIN correlation_groups g ON g.group_id = e.group_id
           WHERE e.case_id = ? AND e.event_id = ?""",
        (case_id, event_id),
    ).fetchone()
    if row is None:
        abort(404)
    return jsonify({
        "ok": True,
        "event": {
            "event_id": row["event_id"],
            "event_time": row["event_time"],
            "source_type": row["source_type"],
            "source_label": source_label(row["source_type"]),
            "event_type": row["event_type"],
            "event_label": event_label(row["event_type"]),
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
            "importance_score": row["importance_score"],
            "importance_level": row["importance_level"] or "",
            "anomaly_score": row["anomaly_score"],
            "stage": row["stage"] or "none",
            "stage_label": stage_label(row["stage"] or "none"),
            "is_noise": row["is_noise"],
            "repeat_count": row["repeat_count"],
            "reasons": _loads(row["reasons"]),
            "group_id": row["group_id"],
            "group_label": row["group_label"] or "",
            "risk_level": row["risk_level"] or "",
            "risk_score": row["risk_score"],
        },
    })


@bp.get("/api/cases/<int:case_id>/groups")
def groups(case_id):
    _guard_case(case_id)
    rows = g.db.execute(
        """SELECT * FROM correlation_groups WHERE case_id = ? ORDER BY risk_score DESC, group_id ASC""",
        (case_id,),
    ).fetchall()
    items = []
    for row in rows:
        items.append({
            "group_id": row["group_id"],
            "group_label": row["group_label"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "start_time": row["start_time"],
            "end_time": row["end_time"],
            "event_count": row["event_count"],
            "key_event_count": row["key_event_count"],
            "main_user": row["main_user"] or "",
            "main_ip": row["main_ip"] or "",
            "main_device": row["main_device"] or "",
            "stages": [stage_label(item) for item in _loads(row["stages"])],
        })
    return jsonify({"ok": True, "groups": items})


@bp.get("/api/cases/<int:case_id>/stats")
def stats(case_id):
    _guard_case(case_id)
    latest = g.db.execute(
        "SELECT * FROM analysis_results WHERE case_id = ? ORDER BY generated_at DESC, result_id DESC LIMIT 1",
        (case_id,),
    ).fetchone()
    if latest is None:
        return jsonify({"ok": True, "ready": False})
    levels = {"حرج": 0, "عالٍ": 0, "متوسط": 0, "منخفض": 0}
    for row in g.db.execute(
        """SELECT importance_level, COUNT(*) AS total FROM events
           WHERE case_id = ? AND is_noise = 0 GROUP BY importance_level""",
        (case_id,),
    ):
        if row["importance_level"] in levels:
            levels[row["importance_level"]] = row["total"]
    total = latest["total_events"] or 0
    ratio = 0 if not total else round((latest["removed_events"] / total) * 100)
    return jsonify({
        "ok": True,
        "ready": True,
        "total_events": total,
        "key_events": latest["key_events"],
        "removed_events": latest["removed_events"],
        "removed_ratio": ratio,
        "group_count": latest["group_count"],
        "critical_count": latest["critical_count"],
        "count_by_level": levels,
        "generated_at": latest["generated_at"],
    })

