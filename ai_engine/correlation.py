"""ربط الأحداث بالمفاتيح المشتركة عبر Union-Find."""

import re
from collections import Counter

from ai_engine import knowledge


class UnionFind:
    def __init__(self, size):
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, item):
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left, right):
        root_left = self.find(left)
        root_right = self.find(right)
        if root_left == root_right:
            return
        if self.rank[root_left] < self.rank[root_right]:
            self.parent[root_left] = root_right
        elif self.rank[root_left] > self.rank[root_right]:
            self.parent[root_right] = root_left
        else:
            self.parent[root_right] = root_left
            self.rank[root_left] += 1


def norm_path(value):
    if not value:
        return ""
    text = str(value).replace("\\", "/").lower().strip()
    return re.sub(r"/+", "/", text)


def hub_sets(events, ratio, minimum):
    counters = {
        "user": Counter(),
        "ip": Counter(),
        "device": Counter(),
        "path": Counter(),
    }
    for event in events:
        user = event.get("username") or ""
        if user:
            counters["user"][user] += 1
        seen = set()
        for address in (event.get("ip_address") or "", event.get("dest_ip") or ""):
            if address and address not in seen:
                counters["ip"][address] += 1
                seen.add(address)
        device = event.get("device") or ""
        if device:
            counters["device"][device] += 1
        path = norm_path(event.get("file_path"))
        if path:
            counters["path"][path] += 1
    total = len(events)
    hubs = {}
    for name, counter in counters.items():
        hubs[name] = {
            value
            for value, count in counter.items()
            if count > total * ratio and count > minimum
        }
    return hubs


def correlate(events, window_seconds, ratio, minimum):
    if len(events) < 2:
        return []
    hubs = hub_sets(events, ratio, minimum)
    finder = UnionFind(len(events))
    order = sorted(range(len(events)), key=lambda index: (events[index]["event_ts"], index))
    last = {"user": {}, "ip": {}, "device": {}, "path": {}}
    for index in order:
        event = events[index]
        keys = {"user": [], "ip": [], "device": [], "path": []}
        user = event.get("username") or ""
        if user and user not in knowledge.GENERIC_ACCOUNTS and user not in hubs["user"]:
            keys["user"].append(user)
        for address in (event.get("ip_address") or "", event.get("dest_ip") or ""):
            if address and address not in hubs["ip"] and address not in keys["ip"]:
                keys["ip"].append(address)
        device = event.get("device") or ""
        if device and device not in hubs["device"]:
            keys["device"].append(device)
        path = norm_path(event.get("file_path"))
        if path and path not in hubs["path"]:
            keys["path"].append(path)
        moment = event["event_ts"]
        for space, values in keys.items():
            for value in values:
                previous = last[space].get(value)
                if previous is not None and 0 <= moment - events[previous]["event_ts"] <= window_seconds:
                    finder.union(previous, index)
        for space, values in keys.items():
            for value in values:
                last[space][value] = index
    grouped = {}
    for index in range(len(events)):
        grouped.setdefault(finder.find(index), []).append(index)
    return [members for members in grouped.values() if len(members) >= 2]

