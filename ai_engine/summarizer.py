"""توليد ملخص الحادثة بالعربية من قوالب ثابتة."""

from ai_engine import knowledge
from ai_engine.features import is_external
from ai_engine.scoring import is_sensitive
from ai_engine.timeutils import format_dt_text


def _most(values):
    cleaned = [value for value in values if value]
    if not cleaned:
        return ""
    return max(set(cleaned), key=cleaned.count)


def describe_event(event):
    label = knowledge.EVENT_LABELS.get(event.get("event_type"), "حدث")
    parts = [label]
    if event.get("username"):
        parts.append(f"للمستخدم {event['username']}")
    if event.get("file_path"):
        parts.append(f"على الملف {event['file_path']}")
    elif event.get("url"):
        parts.append(f"عبر {event['url']}")
    address = event.get("ip_address") or event.get("dest_ip") or ""
    if address:
        parts.append(f"والعنوان {address}")
    if event.get("device"):
        parts.append(f"على الجهاز {event['device']}")
    return " ".join(parts)


def _group_label(members):
    ordered = []
    for event in sorted(members, key=lambda item: item["event_ts"]):
        stage = event.get("stage")
        if stage and stage != "none" and stage not in ordered:
            ordered.append(stage)
    phrases = [knowledge.STAGE_PHRASES[stage] for stage in ordered if stage in knowledge.STAGE_PHRASES]
    user = _most([event.get("username") or "" for event in members])
    if not phrases:
        text = "أحداث مترابطة زمنياً"
    else:
        text = " ثم ".join(phrases)
    if user:
        text += f" للمستخدم {user}"
    return text


def build_groups(components, events, cfg, level_for):
    groups = []
    for members_index in components:
        members = [events[index] for index in members_index]
        scores = sorted((event["importance_score"] for event in members), reverse=True)
        top = scores[:3]
        risk = 0.6 * scores[0] + 0.4 * (sum(top) / len(top))
        start = min(members, key=lambda item: item["event_ts"])
        end = max(members, key=lambda item: item["event_ts"])
        addresses = []
        for event in members:
            if event.get("ip_address"):
                addresses.append(event["ip_address"])
            elif event.get("dest_ip"):
                addresses.append(event["dest_ip"])
        groups.append({
            "members": members,
            "risk_score": round(risk, 2),
            "risk_level": level_for(risk, cfg),
            "start_time": start["event_time"],
            "end_time": end["event_time"],
            "event_count": int(sum(event.get("repeat_count") or 1 for event in members)),
            "main_user": _most([event.get("username") or "" for event in members]),
            "main_ip": _most(addresses),
            "main_device": _most([event.get("device") or "" for event in members]),
            "stages": [
                stage
                for stage in (
                    event.get("stage")
                    for event in sorted(members, key=lambda item: item["event_ts"])
                )
                if stage and stage != "none"
            ],
            "label": _group_label(members),
        })
    groups.sort(key=lambda item: (-item["risk_score"], item["start_time"]))
    seen = []
    for group in groups:
        stages = []
        for stage in group["stages"]:
            if stage not in stages:
                stages.append(stage)
        group["stages"] = stages
        seen.append(group)
    return seen


def render_summary(events, groups, stats, file_count):
    sources = []
    for event in events:
        label = knowledge.SOURCE_LABELS.get(event.get("source_type"), event.get("source_type") or "")
        if label and label not in sources:
            sources.append(label)
    source_text = "، ".join(sources) if sources else "غير محددة"
    percent = 0 if not stats["total_events"] else round((stats["removed_events"] / stats["total_events"]) * 100)
    lines = [
        (
            f"بلغ عدد الأحداث المحللة {stats['total_events']} حدثاً ضمن {file_count} من ملفات الأدلة، "
            f"ومصادرها: {source_text}. واستُبعد {stats['removed_events']} حدثاً بنسبة {percent}%، "
            f"وبقي {stats['key_events']} حدثاً رئيسياً موزعة على {stats['group_count']} مجموعة."
        )
    ]
    important = [group for group in groups if group["risk_score"] >= 40]
    if not important:
        lines.append("لم تظهر في هذه القضية مجموعة أحداث مهمة تشكل سلسلة حادثة واضحة.")
    else:
        group = important[0]
        lines.append(
            f"أخطر مجموعة هي: {group['label']}. "
            f"نطاقها الزمني من {format_dt_text(group['start_time'])} إلى {format_dt_text(group['end_time'])} بتوقيت UTC. "
            f"المستخدم الرئيسي {group['main_user'] or 'غير محدد'}، والجهاز {group['main_device'] or 'غير محدد'}، "
            f"والعنوان {group['main_ip'] or 'غير محدد'}."
        )
        ranked = sorted(group["members"], key=lambda item: item["importance_score"], reverse=True)[:10]
        ranked.sort(key=lambda item: item["event_ts"])
        lines.append("تسلسل الحادثة:")
        for index, event in enumerate(ranked, start=1):
            lines.append(f"{index}. {format_dt_text(event['event_time'])}: {describe_event(event)}")
        files = []
        addresses = []
        for event in group["members"]:
            path = event.get("file_path") or ""
            if path and is_sensitive(path) and path not in files:
                files.append(path)
            for address in (event.get("ip_address") or "", event.get("dest_ip") or ""):
                if address and is_external(address) and address not in addresses:
                    addresses.append(address)
        if files:
            lines.append("الملفات الحساسة المتأثرة: " + "، ".join(files) + ".")
        if addresses:
            lines.append("العناوين الخارجية ذات الصلة: " + "، ".join(addresses) + ".")
    lines.append("هذا الملخص مولّد آلياً لمساعدة المحقق، ويجب التحقق من الأحداث الداعمة قبل الاعتماد عليه في أي تقرير.")
    return "\n".join(lines)
