import hashlib
import json
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import connect
from ai_engine.pipeline import analyze_case

LEADS = (
    "تسريب",
    "سلسلة إخفاقات دخول إلى",
    "نسخ غير مصرح لـ",
    "إيقاف الحماية قبل نقل",
    "نشاط اعتيادي على",
    "أخطاء نظام حول",
    "تصعيد صلاحيات للوصول إلى",
    "إخفاء أثر بعد التعامل مع",
)
TARGETS = (
    "كشوف الرواتب",
    "عقود الموردين",
    "قاعدة بيانات العملاء",
    "مفاتيح النسخ الاحتياطي",
    "ملفات الموارد البشرية",
    "مراسلات الإدارة",
    "أرشيف المشاريع",
    "حسابات المدراء",
)
BLURB = {
    "empty": "بلاغ أولي بانتظار استلام ملفات الأدلة.",
    "pending": "ملفات الدخول والملفات وصلت، والقضية بانتظار المراجعة.",
    "pending_office": "نشاط يومي مرفوع بانتظار المراجعة.",
    "breach": "دخول غير معتاد خارج الدوام تلاه نقل ملفات حساسة.",
    "insider": "وصول إلى ملفات حساسة من جهاز داخلي بعد نهاية الدوام.",
    "office": "استخدام يومي خلال ساعات العمل بلا مؤشر خارجي.",
    "browser": "زيارات لمواقع مشاركة وبحث مرتبط بإخفاء الأثر.",
    "logins": "إخفاقات دخول متتالية ثم نجاح من عنوان خارجي.",
    "files": "إنشاء ونسخ وحذف ضمن مسارات حساسة.",
    "high": "جلسة بعيدة ثم وصول إلى ملفات حساسة ومسح سجل.",
    "logs": "إيقاف خدمة حماية وتنفيذ أمر غير معتاد على الجهاز.",
    "exfil": "نسخ إلى وسيط خارجي ثم رفع الملفات إلى وجهة خارج الشبكة.",
}
CYCLE = (
    ("Open", "none", "empty"),
    ("Open", "a", "pending"),
    ("Open", "b", "pending_office"),
    ("Open", "both", "pending"),
    ("Analyzed", "both", "breach"),
    ("Analyzed", "a", "insider"),
    ("Analyzed", "b", "office"),
    ("Analyzed", "both", "browser"),
    ("Analyzed", "a", "logins"),
    ("Analyzed", "both", "files"),
    ("Analyzed", "b", "high"),
    ("Analyzed", "both", "logs"),
    ("Closed", "both", "breach"),
    ("Closed", "a", "insider"),
    ("Closed", "b", "office"),
    ("Closed", "both", "exfil"),
)
ACTORS = (
    ("nora.saleh", "FIN-WS-04"),
    ("fahad.otaibi", "HR-LPT-12"),
    ("lina.harbi", "ACC-PC-07"),
    ("majed.qahtani", "DC-01"),
    ("sara.dosari", "SRV-FILE-02"),
    ("khalid.mutairi", "VPN-GW"),
    ("reem.shehri", "LEGAL-PC-03"),
    ("omar.zahrani", "IT-WS-19"),
)
SOURCE = {
    "login_success": "Login Events",
    "login_failed": "Login Events",
    "logout": "Login Events",
    "account_lockout": "Login Events",
    "remote_session": "Login Events",
    "web_visit": "Browser History",
    "web_search": "Browser History",
    "web_download": "Browser History",
    "file_create": "File Events",
    "file_open": "File Events",
    "file_modify": "File Events",
    "file_delete": "File Events",
    "file_copy": "File Events",
    "file_transfer": "File Events",
}
EXT_IPS = ("185.76.12.44", "91.214.8.19", "45.133.20.7", "103.88.41.15")
IN_IPS = ("10.4.12.18", "10.4.8.3", "10.8.20.14", "192.168.10.22")
NIGHT = {"breach", "insider", "logins", "files", "high", "exfil", "pending"}
BIG = '{"size_bytes": 180000000}'


def title_for(index):
    return f"{LEADS[index % 8]} {TARGETS[index // 8]}"


def iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make(ts, kind, user, ip, device, extra):
    moment = datetime.fromtimestamp(ts, timezone.utc)
    return {
        "event_time": iso(moment),
        "event_ts": int(ts),
        "source_type": SOURCE.get(kind, "Log"),
        "event_type": kind,
        "action": extra.get("action", ""),
        "result": extra.get("result", ""),
        "username": user,
        "ip_address": ip,
        "dest_ip": extra.get("dest_ip", ""),
        "device": device,
        "file_path": extra.get("file_path", ""),
        "url": extra.get("url", ""),
        "details": extra.get("details", ""),
        "raw_data": extra.get("raw_data", ""),
    }


def lay(start, gap, specs, user, ip, device):
    ts = int(start)
    rows = []
    for kind, extra in specs:
        rows.append(make(ts, kind, user, ip, device, extra))
        ts += gap
    return rows


def browse(start, user, ip, device, count):
    specs = [
        ("web_visit", {"url": f"https://intranet.local/page/{n}"})
        for n in range(count)
    ]
    specs.append(("logout", {"result": "success"}))
    specs.append(("system_error", {"details": "timeout waiting for spooler"}))
    return lay(start, 90, specs, user, ip, device)


def breach(start, user, ip, device, ext):
    fails = [("login_failed", {"result": "failed"})] * 5
    chain = fails + [
        ("login_success", {"result": "success", "details": "rdp remote desktop"}),
        ("remote_session", {"details": "rdp"}),
        ("privilege_change", {"action": "AddMember", "details": "administrators"}),
        ("account_created", {"details": "svc_backup created"}),
        ("config_change", {"details": "firewall rule added"}),
        ("process_exec", {"action": "powershell.exe", "details": "powershell -enc SQBFAFgA"}),
        ("file_open", {"file_path": "C:/Finance/payroll/salaries_secret.xlsx"}),
        ("file_copy", {"file_path": "E:/usb/payroll_secret.zip"}),
        ("file_transfer", {"file_path": "C:/Finance/payroll/dump.zip", "dest_ip": ext, "url": "https://mega.nz/file/payroll", "raw_data": BIG}),
        ("web_visit", {"url": "https://mega.nz/file/payroll"}),
        ("web_search", {"url": "https://www.google.com/search?q=how+to+delete+event+logs", "details": "clear the log"}),
        ("web_download", {"url": "https://files.example/tool.exe", "file_path": "C:/Users/Public/tool.exe"}),
        ("log_cleared", {"action": "wevtutil cl Security", "details": "event log cleared"}),
        ("service_stop", {"action": "Stop", "details": "WinDefend stopped"}),
        ("file_delete", {"file_path": "C:/Finance/payroll/confidential.xlsx"}),
        ("network_connection", {"dest_ip": ext, "raw_data": BIG}),
        ("account_lockout", {"result": "locked"}),
    ]
    return lay(start, 70, chain, user, ip, device)


def office(start, user, ip, device):
    specs = [
        ("login_success", {"result": "success"}),
        ("file_open", {"file_path": "C:/Projects/readme.txt"}),
        ("file_modify", {"file_path": "C:/Projects/readme.txt"}),
        ("file_create", {"file_path": "C:/Temp/draft.txt"}),
        ("web_visit", {"url": "https://intranet.local/home"}),
        ("web_search", {"url": "https://intranet.local/search?q=policy"}),
        ("service_start", {"details": "spooler started"}),
        ("logout", {"result": "success"}),
        ("other", {"details": "heartbeat"}),
        ("system_error", {"details": "printer timeout"}),
    ]
    return lay(start, 80, specs * 2, user, ip, device)


def insider(start, user, ip, device):
    specs = [
        ("login_success", {"result": "success"}),
        ("file_open", {"file_path": "C:/HR/payroll/salaries.xlsx"}),
        ("file_open", {"file_path": "C:/Finance/contract/vendor_contract.pdf"}),
        ("file_modify", {"file_path": "C:/Finance/contract/vendor_contract.pdf"}),
        ("file_copy", {"file_path": "C:/Shares/hr/contract_copy.docx"}),
        ("file_create", {"file_path": "C:/Shares/hr/notes.txt"}),
        ("web_visit", {"url": "https://intranet.local/hr"}),
        ("logout", {"result": "success"}),
    ]
    return lay(start, 80, specs, user, ip, device)


def browser(start, user, ip, device):
    specs = [
        ("login_success", {"result": "success"}),
        ("web_visit", {"url": "https://mega.nz/folder/contracts"}),
        ("web_visit", {"url": "https://wetransfer.com/downloads/archive"}),
        ("web_search", {"url": "https://www.google.com/search?q=how+to+delete+event+logs", "details": "clear log"}),
        ("web_download", {"url": "https://files.example/archive.exe", "file_path": "C:/Users/Public/archive.exe"}),
        ("web_visit", {"url": "https://dropbox.com/s/payroll"}),
        ("logout", {"result": "success"}),
    ]
    return lay(start, 80, specs, user, ip, device)


def logins(start, user, ip, device):
    specs = [("login_failed", {"result": "failed"})] * 5 + [
        ("login_success", {"result": "success", "details": "vpn remote"}),
        ("remote_session", {"details": "vpn"}),
        ("account_lockout", {"result": "locked"}),
        ("logout", {"result": "success"}),
    ]
    return lay(start, 70, specs, user, ip, device)


def files(start, user, ip, device):
    specs = [
        ("file_open", {"file_path": "C:/Backup/database/customers_secret.bak"}),
        ("file_create", {"file_path": "C:/Backup/database/customers_secret.zip"}),
        ("file_modify", {"file_path": "C:/Backup/database/customers_secret.zip"}),
        ("file_copy", {"file_path": "E:/usb/customers_secret.zip"}),
        ("file_delete", {"file_path": "C:/Backup/keys/id_rsa.pem"}),
        ("file_transfer", {"file_path": "C:/Backup/database/dump.zip", "dest_ip": "185.76.12.44", "raw_data": BIG}),
    ]
    return lay(start, 80, specs, user, ip, device)


def high(start, user, ip, device):
    specs = [
        ("login_success", {"result": "success", "details": "rdp remote desktop"}),
        ("remote_session", {"details": "rdp"}),
        ("file_open", {"file_path": "C:/Finance/payroll/salaries_secret.xlsx"}),
        ("file_open", {"file_path": "C:/Finance/password/vault.txt"}),
        ("file_copy", {"file_path": "C:/Archive/payroll_secret_copy.xlsx"}),
        ("file_modify", {"file_path": "C:/Archive/payroll_secret_copy.xlsx"}),
        ("log_cleared", {"action": "wevtutil cl Security", "details": "event log cleared"}),
        ("account_lockout", {"result": "locked"}),
        ("web_visit", {"url": "https://intranet.local/finance"}),
        ("logout", {"result": "success"}),
    ]
    return lay(start, 80, specs, user, ip, device)


def logs(start, user, ip, device):
    specs = [
        ("service_stop", {"action": "Stop", "details": "WinDefend stopped"}),
        ("process_exec", {"action": "powershell.exe", "details": "powershell -enc SQBFAFgA"}),
        ("system_error", {"details": "audit service stopped"}),
        ("service_start", {"details": "WinDefend started"}),
        ("network_connection", {"dest_ip": "10.4.1.5"}),
        ("config_change", {"details": "audit policy changed"}),
        ("other", {"details": "service control"}),
    ]
    return lay(start, 80, specs, user, ip, device)


def exfil(start, user, ip, device, ext):
    specs = [
        ("login_success", {"result": "success", "details": "rdp remote desktop"}),
        ("file_open", {"file_path": "C:/Finance/payroll/salaries_secret.xlsx"}),
        ("file_copy", {"file_path": "E:/usb/payroll_secret.zip"}),
        ("file_transfer", {"file_path": "C:/Finance/payroll/dump.zip", "dest_ip": ext, "url": "https://mega.nz/file/dump", "raw_data": BIG}),
        ("network_connection", {"dest_ip": ext, "raw_data": BIG}),
        ("web_visit", {"url": "https://gofile.io/d/backup"}),
        ("log_cleared", {"details": "event logs cleared"}),
    ]
    return lay(start, 80, specs, user, ip, device)


def build(kind, start, actor, ext, internal):
    user, device = actor
    ip = ext if kind in ("breach", "logins", "exfil", "pending") else internal
    if kind in ("breach", "pending"):
        rows = breach(start, user, ip, device, ext)
    elif kind in ("office", "pending_office"):
        rows = office(start, user, internal, device)
    elif kind == "insider":
        rows = insider(start, user, internal, device)
    elif kind == "browser":
        rows = browser(start, user, internal, device)
    elif kind == "logins":
        rows = logins(start, user, ext, device)
    elif kind == "files":
        rows = files(start, user, internal, device)
    elif kind == "high":
        rows = high(start, user, internal, device)
    elif kind == "logs":
        rows = logs(start, user, internal, device)
    elif kind == "exfil":
        rows = exfil(start, user, ext, device, ext)
    else:
        rows = []
    if rows:
        rows.extend(browse(start + 2 * 86400, user, internal, device, 12))
    return rows


def save_analysis(conn, case_id, result, user_id, when, prior):
    keys = {}
    for group in result["groups"]:
        cursor = conn.execute(
            """INSERT INTO correlation_groups
               (case_id, group_label, risk_score, risk_level, start_time, end_time, event_count, key_event_count, main_user, main_ip, main_device, stages)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                case_id,
                group["label"],
                group["risk_score"],
                group["risk_level"],
                group["start_time"],
                group["end_time"],
                group["event_count"],
                group["key_event_count"],
                group["main_user"] or "",
                group["main_ip"] or "",
                group["main_device"] or "",
                json.dumps(group["stages"], ensure_ascii=False),
            ),
        )
        keys[group["group_key"]] = cursor.lastrowid
    conn.executemany(
        """UPDATE events SET group_id = ?, importance_score = ?, importance_level = ?, anomaly_score = ?, stage = ?, is_noise = ?, repeat_count = ?, reasons = ?
           WHERE event_id = ? AND case_id = ?""",
        [
            (
                keys.get(item["group_key"]),
                item["importance_score"],
                item["importance_level"],
                item["anomaly_score"],
                item["stage"],
                item["is_noise"],
                item["repeat_count"],
                json.dumps(item["reasons"], ensure_ascii=False),
                item["event_id"],
                case_id,
            )
            for item in result["events"]
        ],
    )
    stats = result["stats"]
    if prior:
        conn.execute(
            """INSERT INTO analysis_results
               (case_id, summary_text, total_events, key_events, removed_events, group_count, critical_count, generated_by, generated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                case_id,
                result["summary_text"],
                max(0, stats["total_events"] - 4),
                max(0, stats["key_events"] - 1),
                stats["removed_events"],
                stats["group_count"],
                max(0, stats["critical_count"] - 1),
                user_id,
                iso(when - timedelta(days=2)),
            ),
        )
    conn.execute(
        """INSERT INTO analysis_results
           (case_id, summary_text, total_events, key_events, removed_events, group_count, critical_count, generated_by, generated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            case_id,
            result["summary_text"],
            stats["total_events"],
            stats["key_events"],
            stats["removed_events"],
            stats["group_count"],
            stats["critical_count"],
            user_id,
            iso(when),
        ),
    )


def store_files(conn, case_id, rows, uploader, when, skipped):
    grouped = {}
    for row in rows:
        grouped.setdefault(row["source_type"], []).append(row)
    file_ids = {}
    for source, items in grouped.items():
        blob = json.dumps(items, ensure_ascii=False).encode("utf-8")
        ext = ".json" if source == "Log" else ".csv"
        cursor = conn.execute(
            """INSERT INTO evidence_files
               (case_id, uploaded_by, uploader_name, file_name, stored_name, source_type, file_size, file_hash, event_count, skipped_count, upload_date)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                case_id,
                uploader["user_id"],
                uploader["full_name"],
                f"{source.replace(' ', '_').lower()}{ext}",
                secrets.token_hex(16) + ext,
                source,
                len(blob),
                hashlib.sha256(blob).hexdigest(),
                len(items),
                skipped,
                iso(when),
            ),
        )
        file_ids[source] = cursor.lastrowid
    return file_ids


def check(conn):
    statuses = {row["status"]: row["n"] for row in conn.execute("SELECT status, COUNT(*) AS n FROM cases GROUP BY status")}
    for status in ("Open", "Analyzed", "Closed"):
        assert statuses.get(status, 0) >= 8, statuses
    sources = {row["source_type"] for row in conn.execute("SELECT DISTINCT source_type FROM evidence_files")}
    assert sources == {"Log", "Browser History", "Login Events", "File Events"}, sources
    levels = {row["importance_level"] for row in conn.execute("SELECT DISTINCT importance_level FROM events WHERE importance_level IS NOT NULL")}
    for level in ("حرج", "عالٍ", "متوسط", "منخفض"):
        assert level in levels, levels
    risks = {row["risk_level"] for row in conn.execute("SELECT DISTINCT risk_level FROM correlation_groups")}
    for level in ("حرج", "عالٍ", "متوسط", "منخفض"):
        assert level in risks, risks
    kinds = {row["event_type"] for row in conn.execute("SELECT DISTINCT event_type FROM events")}
    assert len(kinds) >= 20, kinds
    assert conn.execute("SELECT COUNT(*) AS n FROM events WHERE is_noise = 1").fetchone()["n"] > 0
    assert conn.execute("SELECT COUNT(*) AS n FROM cases c WHERE NOT EXISTS (SELECT 1 FROM evidence_files f WHERE f.case_id = c.case_id)").fetchone()["n"] >= 1
    assert conn.execute("SELECT COUNT(*) AS n FROM cases c WHERE NOT EXISTS (SELECT 1 FROM case_assignments a WHERE a.case_id = c.case_id)").fetchone()["n"] >= 1
    assert conn.execute("SELECT COUNT(*) AS n FROM (SELECT case_id FROM analysis_results GROUP BY case_id HAVING COUNT(*) > 1)").fetchone()["n"] >= 1
    return statuses, len(kinds)


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    conn = connect()
    try:
        admin = conn.execute("SELECT user_id, full_name FROM users WHERE role = 'Admin' ORDER BY user_id LIMIT 1").fetchone()
        investigators = conn.execute("SELECT user_id, full_name FROM users WHERE role = 'Investigator' ORDER BY user_id").fetchall()
        if admin is None:
            raise SystemExit("no admin user")
        titles = [title_for(index) for index in range(len(CYCLE) * 4)]
        marks = ",".join("?" for _ in titles)
        conn.execute(f"DELETE FROM cases WHERE case_title IN ({marks})", titles)
        conn.commit()
        conn.execute("BEGIN")
        for index, case_title in enumerate(titles):
            status, assign, kind = CYCLE[index % len(CYCLE)]
            actor = ACTORS[index % len(ACTORS)]
            hour = 22 if kind in NIGHT else 9
            start = datetime(2026, 1, 8, hour, 5, tzinfo=timezone.utc) + timedelta(days=index)
            created = start - timedelta(hours=6)
            cursor = conn.execute(
                """INSERT INTO cases (case_title, description, status, created_by, created_at)
                   VALUES (?, ?, 'Open', ?, ?)""",
                (case_title, BLURB[kind], admin["user_id"], iso(created)),
            )
            case_id = cursor.lastrowid
            chosen = []
            if assign in ("a", "both") and investigators:
                chosen.append(investigators[0]["user_id"])
            if assign in ("b", "both") and len(investigators) > 1:
                chosen.append(investigators[1]["user_id"])
            elif assign == "b" and investigators:
                chosen.append(investigators[0]["user_id"])
            for user_id in chosen:
                conn.execute(
                    "INSERT INTO case_assignments (case_id, user_id, assigned_at) VALUES (?, ?, ?)",
                    (case_id, user_id, iso(created)),
                )
            rows = build(kind, int(start.timestamp()), actor, EXT_IPS[index % 4], IN_IPS[index % 4])
            if not rows:
                if status != "Open":
                    conn.execute("UPDATE cases SET status = ? WHERE case_id = ?", (status, case_id))
                continue
            uploader = investigators[index % len(investigators)] if investigators else admin
            file_ids = store_files(conn, case_id, rows, uploader, start, 2 if index % 3 == 0 else 0)
            conn.executemany(
                """INSERT INTO events
                   (case_id, file_id, event_time, event_ts, source_type, event_type, action, result, username, ip_address, dest_ip, device, file_path, url, details, raw_data)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        case_id,
                        file_ids[row["source_type"]],
                        row["event_time"],
                        row["event_ts"],
                        row["source_type"],
                        row["event_type"],
                        row["action"],
                        row["result"],
                        row["username"],
                        row["ip_address"],
                        row["dest_ip"],
                        row["device"],
                        row["file_path"],
                        row["url"],
                        row["details"],
                        row["raw_data"],
                    )
                    for row in rows
                ],
            )
            if status == "Open":
                continue
            stored = conn.execute(
                "SELECT event_id FROM events WHERE case_id = ? ORDER BY event_id",
                (case_id,),
            ).fetchall()
            payload = []
            for row, saved in zip(rows, stored):
                item = dict(row)
                item["event_id"] = saved["event_id"]
                payload.append(item)
            result = analyze_case(payload, {"file_count": len(file_ids)})
            save_analysis(
                conn,
                case_id,
                result,
                uploader["user_id"],
                start + timedelta(hours=3),
                prior=status == "Closed" and kind == "breach",
            )
            conn.execute("UPDATE cases SET status = ? WHERE case_id = ?", (status, case_id))
        conn.commit()
        statuses, kind_count = check(conn)
        totals = conn.execute(
            """SELECT
                 (SELECT COUNT(*) FROM cases) AS cases,
                 (SELECT COUNT(*) FROM events) AS events,
                 (SELECT COUNT(*) FROM evidence_files) AS files,
                 (SELECT COUNT(*) FROM correlation_groups) AS groups,
                 (SELECT COUNT(*) FROM analysis_results) AS results"""
        ).fetchone()
        print(dict(totals))
        print(statuses, "event_types", kind_count)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
