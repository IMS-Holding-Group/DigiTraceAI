"""توحيد حقول الحدث وتصنيف نوعه."""

import json
import re

from ai_engine import knowledge
from ai_engine.timeutils import parse_timestamp, to_iso, to_unix

_EMPTY = {"", "-", "null", "n/a", "na", "none", "nil", "undefined"}
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
_FROM_TO = re.compile(
    r"from\s+((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\s+to\s+((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))",
    re.I,
)


def norm_key(name):
    return re.sub(r"[\s_\-]+", "", str(name).strip().lower())


def clean_text(value):
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in _EMPTY:
        return ""
    return text


def _has_any(text, words):
    return any(word in text for word in words)


def _map_row(row):
    mapped = {"message_parts": []}
    for key, value in row.items():
        if key == "_raw":
            continue
        token = norm_key(key)
        target = knowledge.ALIASES.get(token)
        cleaned = clean_text(value)
        if not target:
            if cleaned:
                mapped["message_parts"].append(cleaned)
            continue
        if target == "message":
            if cleaned:
                mapped["message_parts"].append(cleaned)
            continue
        if not mapped.get(target):
            mapped[target] = cleaned
    return mapped


def _parse_size(value):
    text = clean_text(value).replace(",", "")
    if not text:
        return 0
    try:
        return max(0, int(float(text)))
    except ValueError:
        return 0


def _classify_login(blob, result, logon):
    if _has_any(result, knowledge.LOGOUT_WORDS) or _has_any(blob, knowledge.LOGOUT_WORDS):
        return "logout"
    if _has_any(result, knowledge.LOCK_WORDS) or _has_any(blob, knowledge.LOCK_WORDS):
        return "account_lockout"
    if _has_any(result, knowledge.FAIL_WORDS) or _has_any(blob, knowledge.FAIL_WORDS):
        return "login_failed"
    if _has_any(result, knowledge.SUCCESS_WORDS) or _has_any(blob, knowledge.SUCCESS_WORDS):
        return "login_success"
    if _has_any(logon, knowledge.REMOTE_WORDS):
        return "remote_session"
    return "other"


def _classify_log(blob):
    if ("log cleared" in blob) or ("audit log" in blob and "clear" in blob) or "1102" in blob or "wevtutil cl" in blob:
        return "log_cleared"
    if any(token in blob for token in ("added to group", "administrators", "sudo", "privilege", "elevat", "4672", "4728", "4732")):
        return "privilege_change"
    if "account was created" in blob or "useradd" in blob or "4720" in blob or "user account was created" in blob:
        return "account_created"
    if any(token in blob for token in ("remote desktop", "rdp", "remote session", "terminal services")):
        return "remote_session"
    if "service" in blob and any(token in blob for token in ("stopped", "stop ", "stopping")):
        return "service_stop"
    if "service" in blob and any(token in blob for token in ("started", "start ", "starting")):
        return "service_start"
    if any(token in blob for token in ("process", "command line", "executed", "process_exec")):
        return "process_exec"
    if any(token in blob for token in ("policy", "registry", "configuration", "firewall rule")):
        return "config_change"
    if any(token in blob for token in ("connection", "outbound", "inbound", "bytes")):
        return "network_connection"
    if any(token in blob for token in ("error", "fail", "critical")):
        return "system_error"
    return "other"


def _classify_browser(url, title, visit_type):
    lower_url = url.lower()
    visit = visit_type.lower()
    path = lower_url.split("?", 1)[0]
    if visit in {"download", "file_download"} or path.endswith(knowledge.DOWNLOAD_EXTENSIONS):
        return "web_download"
    if any(token in lower_url for token in ("q=", "query=", "search=")) or title.lower().startswith(("بحث", "search")):
        return "web_search"
    return "web_visit"


def _classify_file(action):
    text = action.lower()
    if any(token in text for token in ("upload", "send", "transfer", "exfil")):
        return "file_transfer"
    if "copy" in text:
        return "file_copy"
    if any(token in text for token in ("delete", "remove")):
        return "file_delete"
    if any(token in text for token in ("modify", "write", "rename", "move")):
        return "file_modify"
    if any(token in text for token in ("create", "new")):
        return "file_create"
    if any(token in text for token in ("open", "read")):
        return "file_open"
    return "other"


def _classify(source_type, mapped, blob):
    if source_type == "Login Events":
        return _classify_login(blob, (mapped.get("result") or "").lower(), (mapped.get("logon_type") or "").lower())
    if source_type == "Log":
        return _classify_log(blob)
    if source_type == "Browser History":
        return _classify_browser(mapped.get("url") or "", mapped.get("title") or "", mapped.get("visit_type") or "")
    if source_type == "File Events":
        return _classify_file(mapped.get("action") or blob)
    return "other"


def _enrich_network(mapped, blob, event_type):
    found = _IP.findall(blob)
    pair = _FROM_TO.search(blob)
    if pair:
        if not mapped.get("ip_address"):
            mapped["ip_address"] = pair.group(1)
        if not mapped.get("dest_ip"):
            mapped["dest_ip"] = pair.group(2)
    urls = _URL.findall(blob)
    if urls and not mapped.get("url"):
        mapped["url"] = urls[0].rstrip(".,);")
    if event_type == "file_transfer" and not mapped.get("dest_ip") and found:
        mapped["dest_ip"] = found[-1]
    if not mapped.get("ip_address") and found and event_type != "file_transfer":
        mapped["ip_address"] = found[0]


def normalize_record(row, source_type, tz_offset_minutes, default_year):
    mapped = _map_row(row)
    moment = parse_timestamp(mapped.get("event_time_raw"), tz_offset_minutes, default_year)
    if moment is None:
        return None
    parts = [mapped.get("title") or "", mapped.get("service") or "", mapped.get("process_name") or ""]
    parts.extend(mapped.get("message_parts") or [])
    blob = " ".join(part for part in parts if part).lower()
    event_type = _classify(source_type, mapped, blob)
    _enrich_network(mapped, " ".join(parts), event_type)
    username = (mapped.get("username") or "").strip().lower()
    details = " | ".join(part for part in [mapped.get("title") or "", *mapped.get("message_parts", []), mapped.get("service") or ""] if part)
    logon = (mapped.get("logon_type") or "").lower()
    if any(token in logon for token in knowledge.REMOTE_WORDS) or any(token in blob for token in ("rdp", "vpn", "ssh", "remote desktop", "remote session")):
        details = (details + " | remote").strip(" |")
    raw = row.get("_raw")
    if not raw:
        visible = {key: value for key, value in row.items() if key != "_raw"}
        raw = json.dumps(visible, ensure_ascii=False)
    raw = str(raw)[:4000]
    return {
        "event_time": to_iso(moment),
        "event_ts": to_unix(moment),
        "source_type": source_type,
        "event_type": event_type,
        "action": mapped.get("action") or "",
        "result": mapped.get("result") or "",
        "username": username,
        "ip_address": mapped.get("ip_address") or "",
        "dest_ip": mapped.get("dest_ip") or "",
        "device": mapped.get("device") or "",
        "file_path": mapped.get("file_path") or "",
        "url": mapped.get("url") or "",
        "details": details[:2000],
        "raw_data": raw,
        "size_bytes": _parse_size(mapped.get("size_bytes")),
    }

