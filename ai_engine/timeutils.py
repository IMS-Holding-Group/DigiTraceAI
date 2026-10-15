"""تحليل أزمنة الأدلة وتحويلها إلى UTC، وتنسيق العرض النصي."""

import re
from datetime import datetime, timedelta, timezone

_OFFSET_TAIL = re.compile(r"([+-]\d{2}:\d{2}|[+-]\d{4}|[+-]\d{2})$")
_SLASH_DT = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?$")
_SYSLOG = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%d-%m-%Y %H:%M:%S",
    "%d-%m-%Y %H:%M",
    "%Y-%m-%d",
)


def from_numeric(number):
    try:
        n = float(number)
    except (TypeError, ValueError):
        return None
    if n >= 1e16:
        return n / 1e6 - 11644473600
    if n >= 1e14:
        return n / 1e6
    if n >= 1e11:
        return n / 1e3
    if n >= 1e8:
        return n
    return None


def _parse_offset(text):
    if text in ("Z", "z"):
        return 0
    sign = 1 if text[0] == "+" else -1
    body = text[1:]
    if ":" in body:
        hour, minute = body.split(":", 1)
        return sign * (int(hour) * 60 + int(minute))
    if len(body) == 4:
        return sign * (int(body[:2]) * 60 + int(body[2:]))
    return sign * int(body) * 60


def _build(year, month, day, hour, minute, second):
    try:
        return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
    except ValueError:
        return None


def _parse_body(body, default_year):
    body = body.strip()
    if not body:
        return None
    matched = _SLASH_DT.match(body)
    if matched:
        first = int(matched.group(1))
        second = int(matched.group(2))
        year = int(matched.group(3))
        if first > 12:
            day, month = first, second
        elif second > 12:
            month, day = first, second
        else:
            day, month = first, second
        return _build(year, month, day, matched.group(4), matched.group(5), matched.group(6) or 0)
    syslog = _SYSLOG.match(body)
    if syslog:
        try:
            return datetime.strptime(
                f"{syslog.group(1)} {int(syslog.group(2))} {default_year} {syslog.group(3)}:{syslog.group(4)}:{syslog.group(5)}",
                "%b %d %Y %H:%M:%S",
            )
        except ValueError:
            return None
    for fmt in _FORMATS:
        try:
            return datetime.strptime(body, fmt)
        except ValueError:
            continue
    return None


def parse_timestamp(value, tz_offset_minutes=0, default_year=None):
    if default_year is None:
        default_year = datetime.now(timezone.utc).year
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        unix = from_numeric(value)
        if unix is None:
            return None
        return datetime.fromtimestamp(unix, timezone.utc)
    text = str(value).strip().strip("\"'")
    if not text:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        unix = from_numeric(text)
        if unix is None:
            return None
        return datetime.fromtimestamp(unix, timezone.utc)
    offset = None
    body = text
    if text.endswith("Z") or text.endswith("z"):
        body = text[:-1]
        offset = 0
    else:
        tail = _OFFSET_TAIL.search(text)
        if tail and re.search(r"\d:\d", text):
            body = text[: tail.start()]
            offset = _parse_offset(tail.group(1))
    body = body.strip().replace("T", " ")
    body = re.sub(r"\.\d+", "", body)
    parsed = _parse_body(body, default_year)
    if parsed is None:
        return None
    if offset is None:
        offset = int(tz_offset_minutes or 0)
    return (parsed - timedelta(minutes=offset)).replace(tzinfo=timezone.utc)


def to_iso(moment):
    if moment is None:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    else:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def to_unix(moment):
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


def format_dt_text(value):
    """نص التاريخ بالصيغة YYYY/M/Dم H:MMص."""
    if isinstance(value, str):
        moment = parse_timestamp(value, 0)
    else:
        moment = value
    if moment is None:
        return ""
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    hour24 = moment.hour
    suffix = "ص" if hour24 < 12 else "م"
    hour12 = hour24 % 12 or 12
    return f"{moment.year}/{moment.month}/{moment.day}م {hour12}:{moment.minute:02d}{suffix}"
