from datetime import datetime, timezone

from markupsafe import Markup

from ai_engine.knowledge import EVENT_LABELS, SOURCE_LABELS, STAGE_LABELS
from ai_engine.timeutils import format_dt_text, parse_timestamp


def fmt_dt(value):
    if not value:
        return ""
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    else:
        moment = parse_timestamp(str(value), 0)
    text = format_dt_text(moment) if moment is not None else ""
    if not text:
        return ""
    return Markup(f'<span class="dt" dir="rtl">{text}</span>')


def source_label(value):
    return SOURCE_LABELS.get(value or "", value or "")


def event_label(value):
    return EVENT_LABELS.get(value or "", value or "")


def stage_label(value):
    return STAGE_LABELS.get(value or "", value or "غير مصنف")
