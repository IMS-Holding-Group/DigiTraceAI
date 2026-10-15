"""بناء سمات الأحداث وكشف العناوين الداخلية."""

import math
from collections import Counter
from datetime import datetime, timezone

import numpy as np
from ipaddress import ip_address, ip_network

_INTERNAL = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("::1/128"),
    ip_network("fe80::/10"),
)


def is_internal(value):
    if not value:
        return False
    try:
        parsed = ip_address(str(value).strip())
    except ValueError:
        return False
    return any(parsed in network for network in _INTERNAL)


def is_external(value):
    text = (value or "").strip()
    if not text:
        return False
    return not is_internal(text)


def build_matrix(events):
    type_counts = Counter(event.get("event_type") or "" for event in events)
    user_counts = Counter((event.get("username") or "") for event in events)
    device_counts = Counter((event.get("device") or "") for event in events)
    ip_counts = Counter((event.get("ip_address") or "") for event in events)
    order = sorted(range(len(events)), key=lambda index: events[index]["event_ts"])
    previous = {}
    gaps = [86400] * len(events)
    for index in order:
        user = events[index].get("username") or ""
        moment = events[index]["event_ts"]
        if user and user in previous:
            gaps[index] = max(0, moment - previous[user])
        if user:
            previous[user] = moment
    by_user = {}
    for event in events:
        by_user.setdefault(event.get("username") or "", []).append(event["event_ts"])
    for values in by_user.values():
        values.sort()
    rows = []
    for index, event in enumerate(events):
        moment = datetime.fromtimestamp(event["event_ts"], timezone.utc)
        hour = moment.hour + (moment.minute / 60)
        angle = 2 * math.pi * (hour / 24)
        user = event.get("username") or ""
        device = event.get("device") or ""
        address = event.get("ip_address") or ""
        user_times = by_user.get(user) or []
        burst = sum(1 for item in user_times if abs(item - event["event_ts"]) <= 300)
        rows.append([
            math.sin(angle),
            math.cos(angle),
            1.0 if event.get("_outside") else 0.0,
            1.0 if event.get("_weekend") else 0.0,
            1.0 / type_counts[event.get("event_type") or ""],
            (1.0 / user_counts[user]) if user else 1.0,
            (1.0 / device_counts[device]) if device else 1.0,
            (1.0 / ip_counts[address]) if address else 1.0,
            1.0 if event.get("_external") else 0.0,
            1.0 if event.get("_sensitive") else 0.0,
            math.log1p(event.get("size_bytes") or 0),
            math.log1p(gaps[index]),
            float(burst),
        ])
    return np.array(rows, dtype=float)
