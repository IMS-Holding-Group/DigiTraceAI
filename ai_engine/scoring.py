"""حساب الأهمية والشذوذ والاستبعاد وأسباب الدرجة."""

import re
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ai_engine import knowledge
from ai_engine.features import build_matrix, is_external

_ARCHIVE_CMD = re.compile(r"(7z(\.exe)?|winrar|rar\.exe|zip\.exe)", re.I)


def _blob(event):
    return " ".join(
        str(event.get(key) or "")
        for key in ("action", "details", "url", "file_path", "result", "device")
    ).lower()


def is_sensitive(path):
    if not path:
        return False
    text = str(path).lower().replace("\\", "/")
    if any(marker.lower() in text for marker in knowledge.SENSITIVE_MARKERS):
        return True
    tokens = set(re.split(r"[^a-z0-9\u0600-\u06ff]+", text))
    return any(token in tokens for token in knowledge.SENSITIVE_TOKENS)


def _removable(path):
    text = str(path or "").lower().replace("\\", "/")
    if re.match(r"^[e-h]:/", text):
        return True
    return any(token in text for token in ("/media/", "/mnt/", "usb", "removable"))


def _loose(text):
    return text.lower().replace("+", " ").replace("%20", " ")


def _fileshare(event):
    text = _loose(f"{event.get('url') or ''} {event.get('details') or ''}")
    return any(site in text for site in knowledge.SHARE_SITES)


def _evasion(event):
    text = _loose(f"{event.get('url') or ''} {event.get('details') or ''} {event.get('action') or ''}")
    return any(term in text for term in knowledge.EVASION_TERMS)


def _security_service(event):
    text = _blob(event)
    return any(token in text for token in knowledge.SECURITY_SERVICES)


def _suspicious_process(event):
    text = _blob(event)
    if "mimikatz" in text or "psexec" in text:
        return True
    if "powershell" in text and any(token in text for token in ("encoded", "-enc", "-e ")):
        return True
    if re.search(r"(^|[\s\\])nc(\.exe)?(\s|$)", text):
        return True
    if "certutil" in text and "urlcache" in text:
        return True
    if _ARCHIVE_CMD.search(text) and (
        (event.get("size_bytes") or 0) >= 100 * 1024 * 1024
        or is_sensitive(event.get("file_path"))
        or "finance" in text
        or "*" in text
    ):
        return True
    return False


def recover_size(event):
    current = event.get("size_bytes")
    try:
        if current not in (None, ""):
            event["size_bytes"] = max(0, int(float(current)))
            return
    except (TypeError, ValueError):
        pass
    raw = event.get("raw_data") or ""
    event["size_bytes"] = 0
    if not raw:
        return
    try:
        import json
        payload = json.loads(raw)
    except (ValueError, TypeError):
        payload = None
    if isinstance(payload, dict):
        for key, value in payload.items():
            token = re.sub(r"[\s_\-]+", "", str(key).lower())
            if token in {"size", "sizebytes", "bytes", "length", "filesize"} and value not in (None, ""):
                try:
                    event["size_bytes"] = max(0, int(float(value)))
                    return
                except (TypeError, ValueError):
                    continue
    matched = re.search(r"(?:size_bytes|bytes|size)\s*[=:]\s*(\d+)", raw, re.I)
    if matched:
        event["size_bytes"] = int(matched.group(1))


def annotate(events, cfg):
    for event in events:
        recover_size(event)
        moment = datetime.fromtimestamp(event["event_ts"], timezone.utc)
        event["_outside"] = moment.hour < cfg["WORK_START_HOUR_UTC"] or moment.hour >= cfg["WORK_END_HOUR_UTC"]
        event["_weekend"] = moment.weekday() in (4, 5)
        event["_sensitive"] = is_sensitive(event.get("file_path")) or is_sensitive(event.get("details"))
        event["_external"] = is_external(event.get("ip_address")) or is_external(event.get("dest_ip"))
        event["_remote"] = "remote" in (event.get("details") or "").lower() or any(
            token in _blob(event) for token in ("rdp", "vpn", "ssh", "remote desktop")
        )
        event["_fileshare"] = _fileshare(event)
        event["_evasion"] = _evasion(event)
        event["_security_service"] = _security_service(event)
        event["_suspicious"] = event.get("event_type") == "process_exec" and _suspicious_process(event)
        path = (event.get("file_path") or "").lower()
        event["_archive_file"] = path.endswith(knowledge.ARCHIVE_EXTENSIONS) and (
            event["_sensitive"] or (event.get("size_bytes") or 0) >= cfg["ARCHIVE_FILE_BYTES"]
        )
        event["_removable"] = _removable(event.get("file_path"))
        event["_internal_web"] = any(token in (event.get("url") or "").lower() for token in ("intranet", ".local", "sharepoint", "10.", "192.168."))
    _mark_failures(events, cfg)


def _same_actor(left, right):
    user = left.get("username") and left.get("username") == right.get("username")
    address = left.get("ip_address") and left.get("ip_address") == right.get("ip_address")
    return bool(user or address)


def _mark_failures(events, cfg):
    fails = [event for event in events if event.get("event_type") == "login_failed"]
    window = cfg["FAILURE_WINDOW_SECONDS"]
    minimum = cfg["FAILURE_CHAIN_MIN"]
    for event in fails:
        count = sum(
            1
            for other in fails
            if abs(other["event_ts"] - event["event_ts"]) <= window and _same_actor(event, other)
        )
        event["_fail_chain"] = count >= minimum
    prior_window = cfg["PRIOR_FAIL_SECONDS"]
    for event in events:
        if event.get("event_type") != "login_success":
            continue
        event["_prior_fail"] = any(
            0 < event["event_ts"] - other["event_ts"] <= prior_window and _same_actor(event, other)
            for other in fails
        )


def anomaly_scores(events, cfg):
    count = len(events)
    if count < cfg["IF_MIN_EVENTS"]:
        return [0.5] * count
    try:
        matrix = StandardScaler().fit_transform(build_matrix(events))
        model = IsolationForest(
            n_estimators=cfg["IF_ESTIMATORS"],
            contamination="auto",
            random_state=cfg["RANDOM_STATE"],
            n_jobs=1,
        )
        model.fit(matrix)
        raw = -model.decision_function(matrix)
        low = float(np.min(raw))
        high = float(np.max(raw))
        if high - low < 1e-9:
            return [0.5] * count
        return [float((value - low) / (high - low)) for value in raw]
    except Exception:
        return [0.5] * count


def _add(reasons, text):
    if text not in reasons:
        reasons.append(text)


def base_score(event):
    kind = event.get("event_type") or "other"
    score = knowledge.WEIGHTS.get(kind, knowledge.WEIGHTS["other"])
    reasons = []
    if kind == "privilege_change":
        _add(reasons, "تغيير صلاحيات")
    elif kind == "log_cleared":
        _add(reasons, "مسح سجلات")
    elif kind == "config_change":
        _add(reasons, "تغيير إعدادات")
    elif kind == "account_created":
        _add(reasons, "إنشاء حساب")
    elif kind == "account_lockout":
        _add(reasons, "قفل حساب")
    elif kind == "remote_session":
        _add(reasons, "جلسة وصول عن بعد")
    elif kind == "file_transfer":
        _add(reasons, "نقل ملف إلى جهة خارجية")
    elif kind == "logout":
        _add(reasons, "تسجيل خروج")
    elif kind == "system_error":
        _add(reasons, "خطأ نظام")
    elif kind == "other":
        _add(reasons, "حدث غير مصنف")
    if kind == "file_delete":
        _add(reasons, "حذف ملف")
        if event.get("_sensitive"):
            score += 0.20
            _add(reasons, "الوصول إلى مسار حساس")
    if kind == "file_copy":
        _add(reasons, "نسخ ملف")
        if event.get("_external") or event.get("_removable"):
            score += 0.30
            _add(reasons, "نسخ إلى وجهة خارجية أو وسيط قابل للإزالة")
    if kind == "web_download":
        _add(reasons, "تنزيل ملف من الويب")
    if kind == "process_exec":
        _add(reasons, "تنفيذ عملية")
        if event.get("_suspicious"):
            score += 0.50
            _add(reasons, "تنفيذ أداة مشبوهة أو أرشفة واسعة")
    if kind in ("service_start", "service_stop") and event.get("_security_service"):
        score += 0.30
        _add(reasons, "إيقاف خدمة أمنية" if kind == "service_stop" else "تشغيل خدمة أمنية")
    if kind == "network_connection":
        _add(reasons, "اتصال شبكي")
        if event.get("_external"):
            score += 0.30
            _add(reasons, "اتصال بعنوان خارجي")
        if (event.get("size_bytes") or 0) >= 100 * 1024 * 1024:
            score += 0.50
            _add(reasons, "اتصال خارجي بحجم كبير")
    if kind == "login_failed":
        if event.get("_fail_chain"):
            score = max(score, 0.60)
            _add(reasons, "سلسلة إخفاقات دخول متكررة")
        else:
            _add(reasons, "تسجيل دخول فاشل")
    if kind == "login_success":
        if event.get("_external"):
            score += 0.35
            _add(reasons, "تسجيل دخول من عنوان خارجي")
        if event.get("_outside"):
            score += 0.25
            _add(reasons, "خارج ساعات العمل")
        if event.get("_prior_fail"):
            score += 0.30
            _add(reasons, "سبقه إخفاق دخول من نفس المستخدم أو العنوان")
        if len(reasons) == 0:
            _add(reasons, "تسجيل دخول ناجح")
    if kind in ("web_visit", "web_search"):
        if event.get("_fileshare"):
            score += 0.50
            _add(reasons, "زيارة موقع مشاركة ملفات")
        if event.get("_evasion"):
            score += 0.30
            _add(reasons, "بحث عن إخفاء الأثر أو حذف السجلات")
        if len(reasons) == 0:
            _add(reasons, "نشاط تصفح")
    if kind == "file_open":
        if event.get("_sensitive"):
            score += 0.45
            _add(reasons, "الوصول إلى مسار حساس")
        else:
            _add(reasons, "فتح ملف")
    if kind == "file_create":
        _add(reasons, "إنشاء ملف")
    if kind == "file_modify":
        _add(reasons, "تعديل ملف")
    return min(1.0, max(0.0, score)), reasons


def assign_stage(event):
    kind = event.get("event_type")
    if kind == "log_cleared" or event.get("_evasion") or (kind == "file_delete" and event.get("_sensitive")) or (
        kind == "service_stop" and event.get("_security_service")
    ):
        return "defense_evasion"
    if kind == "file_transfer" or event.get("_fileshare") or (
        kind == "network_connection" and event.get("_external") and (event.get("size_bytes") or 0) >= 100 * 1024 * 1024
    ) or (kind == "file_copy" and (event.get("_external") or event.get("_removable"))):
        return "exfiltration"
    if event.get("_suspicious") or kind == "file_copy" or (
        kind in ("file_create", "file_modify") and event.get("_archive_file")
    ):
        return "collection"
    if (kind == "file_open" and event.get("_sensitive")) or event.get("_internal_web"):
        return "discovery"
    if kind in ("privilege_change", "account_created", "config_change"):
        return "privilege_escalation"
    if kind == "remote_session":
        return "initial_access"
    if kind == "login_success" and (
        event.get("_external") or event.get("_outside") or event.get("_prior_fail") or event.get("_remote")
    ):
        return "initial_access"
    if kind == "login_failed" and event.get("_fail_chain"):
        return "initial_access"
    return "none"


def context_score(event, members):
    if event.get("_temporal_isolated") or not event.get("_component"):
        return 0.0
    stages = {item.get("stage") for item in members if item.get("stage") and item.get("stage") != "none"}
    score = (min(len(stages), 5) / 5) * 0.6
    if "exfiltration" in stages or "privilege_escalation" in stages:
        score += 0.4
    if event.get("stage") in ("collection", "discovery") and "exfiltration" in stages:
        score += 0.15
    return min(1.0, score)


def final_score(base, anomaly, context, cfg):
    score = 100 * (
        cfg["WEIGHT_R"] * base + cfg["WEIGHT_A"] * anomaly + cfg["WEIGHT_C"] * context
    )
    return max(0.0, min(100.0, score))


def level_for(score, cfg):
    if score >= cfg["LEVEL_CRITICAL"]:
        return "حرج"
    if score >= cfg["LEVEL_HIGH"]:
        return "عالٍ"
    if score >= cfg["LEVEL_MEDIUM"]:
        return "متوسط"
    return "منخفض"


def apply_noise(event, group_risk, cfg):
    if event.get("_fail_chain"):
        event["is_noise"] = 0
        return
    quiet_group = group_risk is None or group_risk < cfg["GROUP_NOISE_MAX"]
    event["is_noise"] = 1 if event["importance_score"] < cfg["NOISE_THRESHOLD"] and quiet_group else 0
