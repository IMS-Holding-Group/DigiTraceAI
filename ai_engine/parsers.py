"""قراءة ملفات الأدلة بصيغ CSV وJSON والنص."""

import csv
import json
import re
from pathlib import Path

_LINE_ISO = re.compile(
    r"^(?:<\d+>)?(?:\d\s+)?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+(.+)$"
)
_LINE_SYSLOG = re.compile(
    r"^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+?)(?:\[(\d+)\])?:\s*(.*)$"
)


class ParseError(Exception):
    pass


def load_text(path):
    data = Path(path).read_bytes()
    if not data or not data.strip():
        raise ParseError("الملف فارغ")
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    if b"\x00" in data:
        try:
            text = data.decode("utf-16")
        except UnicodeError:
            text = ""
        if text.strip():
            return text
        raise ParseError("الملف ثنائي وغير مدعوم")
    for encoding in ("utf-8-sig", "utf-8", "cp1256"):
        try:
            return data.decode(encoding)
        except UnicodeError:
            continue
    raise ParseError("تعذر قراءة ترميز الملف")


def _csv_rows(text):
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(text.splitlines(), dialect=dialect)
    if not reader.fieldnames:
        raise ParseError("ملف CSV بلا عناوين أعمدة")
    rows = []
    skipped = 0
    for row in reader:
        if row is None:
            skipped += 1
            continue
        if None in row:
            row.pop(None, None)
        if all(not (value or "").strip() for value in row.values()):
            continue
        visible = {key: value for key, value in row.items() if key}
        row["_raw"] = json.dumps(visible, ensure_ascii=False)[:4000]
        rows.append(row)
    return rows, skipped


def _json_rows(text):
    stripped = text.strip()
    rows = []
    skipped = 0
    if stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    item = dict(item)
                    item["_raw"] = json.dumps(item, ensure_ascii=False)[:4000]
                    rows.append(item)
                else:
                    skipped += 1
            return rows, skipped
    if stripped.startswith("{") and "\n" not in stripped:
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ParseError("تعذر قراءة ملف JSON") from exc
        if not isinstance(item, dict):
            raise ParseError("تعذر قراءة ملف JSON")
        item["_raw"] = stripped[:4000]
        return [item], 0
    found = False
    for line in text.splitlines():
        piece = line.strip()
        if not piece:
            continue
        try:
            item = json.loads(piece)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if isinstance(item, dict):
            item = dict(item)
            item["_raw"] = piece[:4000]
            rows.append(item)
            found = True
        else:
            skipped += 1
    if not found and not rows:
        raise ParseError("تعذر قراءة ملف JSON")
    return rows, skipped


def _split_service(rest):
    if ":" not in rest:
        return "", rest.strip()
    service, message = rest.split(":", 1)
    service = re.sub(r"\[\d+\]$", "", service).strip()
    return service, message.strip()


def _text_rows(text):
    rows = []
    skipped = 0
    for line in text.splitlines():
        piece = line.strip()
        if not piece or piece.startswith("#"):
            skipped += 1 if piece.startswith("#") else 0
            continue
        iso = _LINE_ISO.match(piece)
        if iso:
            service, message = _split_service(iso.group(3))
            rows.append({
                "timestamp": iso.group(1),
                "host": iso.group(2),
                "service": service,
                "message": message,
                "_raw": piece[:4000],
            })
            continue
        syslog = _LINE_SYSLOG.match(piece)
        if syslog:
            rows.append({
                "timestamp": syslog.group(1),
                "host": syslog.group(2),
                "service": syslog.group(3).strip(),
                "message": syslog.group(5).strip(),
                "_raw": piece[:4000],
            })
            continue
        skipped += 1
    return rows, skipped


def read_records(path):
    text = load_text(path)
    suffix = Path(path).suffix.lower()
    stripped = text.lstrip()
    if suffix == ".json" or stripped.startswith("{") or stripped.startswith("["):
        return _json_rows(text)
    if suffix == ".csv" or _looks_delimited(stripped):
        return _csv_rows(text)
    return _text_rows(text)


def _looks_delimited(text):
    first = text.splitlines()[0] if text.splitlines() else ""
    return first.count(",") >= 2 or first.count(";") >= 2 or first.count("\t") >= 2
