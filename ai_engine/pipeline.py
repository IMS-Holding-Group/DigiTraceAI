"""الدالتان العامتان لمحرك التحليل: قراءة الدليل وتحليل القضية."""

from collections import Counter

import numpy as np
from sklearn.cluster import DBSCAN

from ai_engine import config as engine_config
from ai_engine import knowledge
from ai_engine.correlation import correlate
from ai_engine.normalizer import normalize_record
from ai_engine.parsers import ParseError, read_records
from ai_engine.scoring import (
    annotate,
    anomaly_scores,
    apply_noise,
    assign_stage,
    base_score,
    context_score,
    final_score,
    level_for,
)
from ai_engine.summarizer import build_groups, render_summary
from ai_engine.timeutils import parse_timestamp

_OPTION_KEYS = (
    "CORRELATION_WINDOW_MINUTES",
    "WORK_START_HOUR_UTC",
    "WORK_END_HOUR_UTC",
    "NOISE_THRESHOLD",
    "GROUP_NOISE_MAX",
    "DEDUP_SECONDS",
    "HUB_RATIO",
    "HUB_MIN_COUNT",
    "WEIGHT_R",
    "WEIGHT_A",
    "WEIGHT_C",
    "LEVEL_CRITICAL",
    "LEVEL_HIGH",
    "LEVEL_MEDIUM",
    "FAILURE_WINDOW_SECONDS",
    "FAILURE_CHAIN_MIN",
    "PRIOR_FAIL_SECONDS",
    "LARGE_TRANSFER_BYTES",
    "ARCHIVE_FILE_BYTES",
    "RANDOM_STATE",
    "IF_ESTIMATORS",
    "IF_MIN_EVENTS",
    "ANOMALY_REASON_MIN",
)


def _settings(overrides):
    values = {key: getattr(engine_config, key) for key in _OPTION_KEYS}
    for key, value in (overrides or {}).items():
        if key in values and value is not None:
            values[key] = value
    return values


def _empty(file_count):
    stats = {
        "total_events": 0,
        "key_events": 0,
        "removed_events": 0,
        "group_count": 0,
        "critical_count": 0,
        "count_by_level": {"حرج": 0, "عالٍ": 0, "متوسط": 0, "منخفض": 0},
    }
    summary = render_summary([], [], stats, file_count)
    return {"events": [], "groups": [], "stats": stats, "summary_text": summary}


def parse_evidence_file(path, source_type, tz_offset_minutes=0):
    if source_type not in knowledge.SOURCE_LABELS:
        return {
            "ok": False,
            "events": [],
            "skipped_count": 0,
            "skip_reasons": ["نوع المصدر غير معروف"],
            "error": "نوع المصدر غير معروف",
        }
    try:
        offset = int(tz_offset_minutes or 0)
    except (TypeError, ValueError):
        offset = 0
    offset = max(-12 * 60, min(14 * 60, offset))
    try:
        records, skipped = read_records(path)
    except ParseError as exc:
        return {
            "ok": False,
            "events": [],
            "skipped_count": 0,
            "skip_reasons": [str(exc)],
            "error": str(exc),
        }
    except OSError:
        return {
            "ok": False,
            "events": [],
            "skipped_count": 0,
            "skip_reasons": ["تعذر قراءة ملف الدليل"],
            "error": "تعذر قراءة ملف الدليل",
        }
    year = None
    events = []
    reasons = []
    for record in records:
        event = normalize_record(record, source_type, offset, year)
        if event is None:
            skipped += 1
            if "سطر بوقت غير صالح" not in reasons and len(reasons) < 20:
                reasons.append("سطر بوقت غير صالح")
            continue
        events.append(event)
    if not events:
        return {
            "ok": False,
            "events": [],
            "skipped_count": skipped,
            "skip_reasons": reasons or ["لم يُستخرج أي حدث صالح من الملف"],
            "error": "لم يُستخرج أي حدث صالح من الملف",
        }
    return {
        "ok": True,
        "events": events,
        "skipped_count": skipped,
        "skip_reasons": reasons,
        "error": None,
    }


def _signature(event):
    return (
        event.get("event_type") or "",
        event.get("username") or "",
        event.get("device") or "",
        event.get("ip_address") or "",
        (event.get("file_path") or "").replace("\\", "/").lower(),
        (event.get("url") or "").lower(),
        (event.get("result") or "").lower(),
    )


def _dedupe(events, window):
    order = sorted(range(len(events)), key=lambda index: (events[index]["event_ts"], index))
    latest = {}
    absorbed = set()
    for index in order:
        event = events[index]
        signature = _signature(event)
        previous = latest.get(signature)
        if previous is not None and 0 <= event["event_ts"] - previous[1] <= window:
            keeper = events[previous[0]]
            keeper["repeat_count"] = keeper.get("repeat_count", 1) + int(event.get("repeat_count") or 1)
            latest[signature] = (previous[0], event["event_ts"])
            absorbed.add(index)
        else:
            event["repeat_count"] = int(event.get("repeat_count") or 1)
            latest[signature] = (index, event["event_ts"])
    return absorbed


def _temporal_labels(events, window_seconds):
    if len(events) < 2:
        return [-1] * len(events)
    points = np.array([[event["event_ts"]] for event in events], dtype=float)
    labels = DBSCAN(eps=window_seconds, min_samples=2).fit(points).labels_
    return [int(label) for label in labels]


def _public_event(event, group_key):
    return {
        "event_id": event.get("event_id"),
        "importance_score": round(float(event.get("importance_score") or 0), 2),
        "importance_level": event.get("importance_level") or "منخفض",
        "anomaly_score": round(float(event.get("anomaly_score") or 0), 4),
        "stage": event.get("stage") or "none",
        "is_noise": int(event.get("is_noise") or 0),
        "repeat_count": int(event.get("repeat_count") or 1),
        "reasons": list(event.get("reasons") or []),
        "group_key": group_key or "",
    }


def analyze_case(events, config=None):
    options = dict(config or {})
    file_count = int(options.pop("file_count", 0) or 0)
    cfg = _settings(options)
    if not events:
        return _empty(file_count)
    working = [dict(item) for item in events]
    for index, event in enumerate(working):
        if event.get("event_id") is None:
            event["event_id"] = index
        if isinstance(event.get("event_time"), str) and event["event_time"]:
            pass
        moment = event.get("event_ts")
        try:
            event["event_ts"] = int(moment)
        except (TypeError, ValueError):
            parsed = parse_timestamp(event.get("event_time"), 0)
            event["event_ts"] = int(parsed.timestamp()) if parsed else 0
    absorbed = _dedupe(working, int(cfg["DEDUP_SECONDS"]))
    keepers = [event for index, event in enumerate(working) if index not in absorbed]
    if not file_count:
        file_count = len({event.get("source_type") for event in keepers if event.get("source_type")})
    annotate(keepers, cfg)
    labels = _temporal_labels(keepers, int(cfg["CORRELATION_WINDOW_MINUTES"]) * 60)
    for event, label in zip(keepers, labels):
        event["_temporal_isolated"] = label == -1
    components = correlate(
        keepers,
        int(cfg["CORRELATION_WINDOW_MINUTES"]) * 60,
        float(cfg["HUB_RATIO"]),
        int(cfg["HUB_MIN_COUNT"]),
    )
    component_of = {}
    for number, members in enumerate(components, start=1):
        for index in members:
            component_of[index] = number
            keepers[index]["_component"] = number
    for event in keepers:
        score, reasons = base_score(event)
        event["_base"] = score
        event["reasons"] = reasons
        if event.get("_outside") and "خارج ساعات العمل" not in event["reasons"]:
            event["reasons"].append("خارج ساعات العمل")
        if event.get("_external") and not any("خارجي" in reason for reason in event["reasons"]):
            event["reasons"].append("عنوان خارجي")
        event["stage"] = assign_stage(event)

    anomalies = anomaly_scores(keepers, cfg)
    for event, anomaly in zip(keepers, anomalies):
        event["anomaly_score"] = anomaly
        if anomaly >= cfg["ANOMALY_REASON_MIN"]:
            if "شاذ إحصائياً بالنسبة لبقية أحداث القضية" not in event["reasons"]:
                event["reasons"].append("شاذ إحصائياً بالنسبة لبقية أحداث القضية")
    for members in components:
        grouped = [keepers[index] for index in members]
        stages = {item.get("stage") for item in grouped}
        for index in members:
            event = keepers[index]
            event["_context"] = 0.0 if event.get("_temporal_isolated") else context_score(event, grouped)
            if "exfiltration" in stages and not event.get("_temporal_isolated"):
                if "ضمن مجموعة تتضمن مرحلة تسريب" not in event["reasons"]:
                    event["reasons"].append("ضمن مجموعة تتضمن مرحلة تسريب")
            if "privilege_escalation" in stages and not event.get("_temporal_isolated"):
                if "ضمن مجموعة تتضمن تصعيد صلاحيات" not in event["reasons"]:
                    event["reasons"].append("ضمن مجموعة تتضمن تصعيد صلاحيات")
    for event in keepers:
        if "_context" not in event:
            event["_context"] = 0.0
        score = final_score(event["_base"], event["anomaly_score"], event["_context"], cfg)
        event["importance_score"] = score
        event["importance_level"] = level_for(score, cfg)
        if not event.get("reasons"):
            event["reasons"] = ["حدث منخفض الصلة بسلسلة واضحة"]
    built = build_groups(components, keepers, cfg, level_for)
    risk_by_component = {}
    for number, group in enumerate(built, start=1):
        group["group_key"] = f"g{number}"
        for event in group["members"]:
            event["_group_key"] = group["group_key"]
            event["_group_risk"] = group["risk_score"]
        risk_by_component[group["group_key"]] = group["risk_score"]
    for event in keepers:
        apply_noise(event, event.get("_group_risk"), cfg)
        event.setdefault("_group_key", "")
    for group in built:
        group["key_event_count"] = sum(
            1
            for event in group["members"]
            if not event["is_noise"] and event["importance_level"] in ("حرج", "عالٍ")
        )
    removed = 0
    key_events = 0
    critical = 0
    levels = Counter()
    total = 0
    for event in keepers:
        repeat = int(event.get("repeat_count") or 1)
        total += repeat
        levels[event["importance_level"]] += 1
        if event["is_noise"]:
            removed += repeat
        else:
            removed += repeat - 1
            if event["importance_level"] in ("حرج", "عالٍ"):
                key_events += 1
            if event["importance_level"] == "حرج":
                critical += 1
    stats = {
        "total_events": total,
        "key_events": key_events,
        "removed_events": removed,
        "group_count": len(built),
        "critical_count": critical,
        "count_by_level": {
            "حرج": levels["حرج"],
            "عالٍ": levels["عالٍ"],
            "متوسط": levels["متوسط"],
            "منخفض": levels["منخفض"],
        },
    }
    summary = render_summary(keepers, built, stats, file_count)
    output = []
    for index, event in enumerate(working):
        if index in absorbed:
            output.append({
                "event_id": event.get("event_id"),
                "importance_score": 0,
                "importance_level": "منخفض",
                "anomaly_score": 0,
                "stage": "none",
                "is_noise": 1,
                "repeat_count": 1,
                "reasons": ["حدث مكرر دُمج في حدث سابق"],
                "group_key": "",
            })
        else:
            output.append(_public_event(event, event.get("_group_key") or ""))
    public_groups = []
    for group in built:
        public_groups.append({
            "group_key": group["group_key"],
            "label": group["label"],
            "risk_score": group["risk_score"],
            "risk_level": group["risk_level"],
            "start_time": group["start_time"],
            "end_time": group["end_time"],
            "event_count": group["event_count"],
            "key_event_count": group["key_event_count"],
            "main_user": group["main_user"],
            "main_ip": group["main_ip"],
            "main_device": group["main_device"],
            "stages": group["stages"],
            "event_ids": [event.get("event_id") for event in group["members"]],
        })
    return {
        "events": output,
        "groups": public_groups,
        "stats": stats,
        "summary_text": summary,
    }


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "sample_data"
    mapping = (
        ("sample_login_events.csv", "Login Events"),
        ("sample_system_log.json", "Log"),
        ("sample_browser_history.csv", "Browser History"),
        ("sample_file_events.csv", "File Events"),
    )
    loaded = []
    for name, source in mapping:
        parsed = parse_evidence_file(root / name, source, 0)
        print(name, parsed["ok"], len(parsed["events"]), parsed["skipped_count"], parsed["error"])
        for event in parsed["events"]:
            event["event_id"] = f"{source}:{event['event_time']}:{event['event_type']}:{event.get('file_path') or event.get('url') or ''}"
            loaded.append(event)
    result = analyze_case(loaded, {"file_count": 4})
    stats = result["stats"]
    ratio = 0 if not stats["total_events"] else stats["removed_events"] / stats["total_events"]
    print("stats", stats["total_events"], stats["key_events"], stats["removed_events"], round(ratio, 3), stats["critical_count"], stats["group_count"])
    if result["groups"]:
        top = result["groups"][0]
        print("top", top["risk_score"], top["risk_level"], top["label"], top["event_count"], top["main_user"])
    incident = [
        event
        for event in loaded
        if event["event_time"].startswith("2026-10-12T0") and event["event_time"][11:16] <= "02:50" and event["event_time"][11:16] >= "01:50"
    ]
    scored = {item["event_id"]: item for item in result["events"]}
    bad = []
    groups = set()
    for event in incident:
        item = scored[event["event_id"]]
        groups.add(item["group_key"])
        if item["importance_level"] not in ("حرج", "عالٍ") or item["is_noise"]:
            bad.append((event["event_time"], event["event_type"], item["importance_score"], item["importance_level"], item["group_key"], item["stage"]))
    print("incident", len(incident), "groups", groups, "bad", len(bad))
    for row in bad:
        print(" ", row)

