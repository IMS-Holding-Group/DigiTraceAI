from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, url_for

from app.services.analysis import latest_result, previous_results, run_analysis
from app.services.cases import assigned_case, list_assigned
from app.services.evidence import list_files, save_upload

bp = Blueprint("investigator", __name__)

_OFFSETS = []
for _hour in range(-12, 15):
    if _hour == 0:
        _label = "UTC"
    elif _hour > 0:
        _label = f"UTC+{_hour}"
    else:
        _label = f"UTC{_hour}"
    _OFFSETS.append((_hour * 60, _label))


def _guard():
    if not g.user:
        return redirect(url_for("auth.login"))
    if g.user["role"] != "Investigator":
        abort(403)
    return None


def _case_or_404(case_id):
    row = assigned_case(g.db, case_id, g.user["user_id"])
    if row is None:
        abort(404)
    return row


@bp.get("/dashboard")
def dashboard():
    guard = _guard()
    if guard:
        return guard
    return render_template("investigator/dashboard.html", cases=list_assigned(g.db, g.user["user_id"]))


@bp.get("/cases")
def cases():
    guard = _guard()
    if guard:
        return guard
    return render_template("investigator/cases.html", cases=list_assigned(g.db, g.user["user_id"]))


@bp.get("/cases/<int:case_id>")
def case_detail(case_id):
    guard = _guard()
    if guard:
        return guard
    case_row = _case_or_404(case_id)
    return render_template(
        "investigator/case_detail.html",
        case_row=case_row,
        files=list_files(g.db, case_id),
        offsets=_OFFSETS,
    )


@bp.post("/cases/<int:case_id>/upload")
def upload(case_id):
    guard = _guard()
    if guard:
        return guard
    case_row = _case_or_404(case_id)
    try:
        offset = int(request.form.get("tz_offset", "0"))
    except ValueError:
        offset = 0
    if offset not in {item[0] for item in _OFFSETS}:
        offset = 0
    try:
        ok, message, reopened = save_upload(
            g.db,
            case_row,
            g.user,
            request.files.get("evidence_file"),
            request.form.get("source_type", ""),
            offset,
        )
    except Exception:
        g.db.rollback()
        flash("تعذر رفع الملف", "error")
        return redirect(url_for("investigator.case_detail", case_id=case_id))
    flash(message, "ok" if ok else "error")
    if ok and reopened:
        flash("النتائج الحالية لا تشمل الملف الجديد حتى إعادة التحليل", "error")
    return redirect(url_for("investigator.case_detail", case_id=case_id))


@bp.post("/cases/<int:case_id>/analyze")
def analyze(case_id):
    guard = _guard()
    if guard:
        return guard
    case_row = _case_or_404(case_id)
    try:
        ok, message = run_analysis(g.db, case_row, g.user)
    except Exception:
        g.db.rollback()
        return jsonify({"ok": False, "error": "تعذر إكمال التحليل، يمكن إعادة المحاولة"}), 500
    if not ok:
        return jsonify({"ok": False, "error": message}), 400
    return jsonify({"ok": True, "redirect": url_for("investigator.results", case_id=case_id)})


@bp.get("/cases/<int:case_id>/results")
def results(case_id):
    guard = _guard()
    if guard:
        return guard
    case_row = _case_or_404(case_id)
    latest = latest_result(g.db, case_id)
    ratio = 0
    if latest and latest["total_events"]:
        ratio = round((latest["removed_events"] / latest["total_events"]) * 100)
    return render_template(
        "investigator/results.html",
        case_row=case_row,
        latest=latest,
        previous=previous_results(g.db, case_id) if latest else [],
        ratio=ratio,
    )
