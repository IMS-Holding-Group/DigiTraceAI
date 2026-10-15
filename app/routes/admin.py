from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from app.security import valid_email, valid_name, valid_password, valid_username
from app.services.cases import (
    assigned_ids,
    assignment_map,
    create_case,
    dashboard_counts,
    delete_case,
    get_case,
    list_admin_cases,
    recent_cases,
    update_case,
)
from app.services.users import (
    all_investigators,
    create_investigator,
    delete_investigator,
    email_taken,
    get_user,
    list_investigators,
    update_investigator,
    username_taken,
)

bp = Blueprint("admin", __name__)


def _admin():
    if not g.user:
        return redirect(url_for("auth.login"))
    if g.user["role"] != "Admin":
        abort(403)
    return None


def _page():
    try:
        return max(1, int(request.args.get("page", "1")))
    except ValueError:
        return 1


def _account_errors(exclude_id=None, password_required=True):
    full_name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip().lower()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    errors = {}
    if not valid_name(full_name):
        errors["full_name"] = "الاسم يجب أن يكون بين 2 و100 حرف"
    if not valid_username(username):
        errors["username"] = "اسم المستخدم من 3 إلى 32 حرفاً لاتينياً أو رقماً أو . أو _ أو - وليس أرقاماً فقط"
    elif username_taken(g.db, username, exclude_id):
        errors["username"] = "اسم المستخدم مستخدم بالفعل"
    if not valid_email(email):
        errors["email"] = "أدخل بريداً إلكترونياً صالحاً"
    elif email_taken(g.db, email, exclude_id):
        errors["email"] = "البريد الإلكتروني مستخدم بالفعل"
    if password_required or password:
        if not valid_password(password):
            errors["password"] = "كلمة السر 10 أحرف على الأقل وتتضمن حرفاً كبيراً وصغيراً ورقماً"
    form = {"full_name": full_name, "username": username, "email": email}
    return form, password, errors


def _case_form():
    title = request.form.get("case_title", "").strip()
    description = request.form.get("description", "").strip()
    status = request.form.get("status", "Open")
    if status not in ("Open", "Analyzed", "Closed"):
        status = "Open"
    allowed = {row["user_id"] for row in all_investigators(g.db)}
    selected = []
    for raw in request.form.getlist("investigator_ids"):
        try:
            value = int(raw)
        except ValueError:
            continue
        if value in allowed and value not in selected:
            selected.append(value)
    errors = {}
    if len(title) < 2 or len(title) > 200:
        errors["case_title"] = "عنوان القضية يجب أن يكون بين 2 و200 حرف"
    if len(description) > 2000:
        errors["description"] = "الوصف أطول من الحد المسموح"
    return {"case_title": title, "description": description, "status": status, "investigator_ids": selected}, errors


@bp.get("/admin")
def dashboard():
    guard = _admin()
    if guard:
        return guard
    investigators, statuses, files = dashboard_counts(g.db)
    return render_template(
        "admin/dashboard.html",
        investigators=investigators,
        statuses=statuses,
        files=files,
        cases=recent_cases(g.db),
    )


@bp.get("/admin/investigators")
def investigators():
    guard = _admin()
    if guard:
        return guard
    rows, total, page, pages = list_investigators(g.db, _page())
    return render_template("admin/investigators.html", rows=rows, total=total, page=page, pages=pages)


@bp.route("/admin/investigators/new", methods=["GET", "POST"])
def investigator_new():
    guard = _admin()
    if guard:
        return guard
    form = {"full_name": "", "username": "", "email": ""}
    errors = {}
    if request.method == "POST":
        form, password, errors = _account_errors(password_required=True)
        if not errors:
            try:
                create_investigator(g.db, form["full_name"], form["username"], form["email"], password)
                flash("تمت إضافة المحقق", "ok")
                return redirect(url_for("admin.investigators"))
            except Exception:
                g.db.rollback()
                flash("تعذر إضافة المحقق", "error")
    return render_template("admin/investigator_form.html", form=form, errors=errors, mode="new")


@bp.route("/admin/investigators/<int:user_id>/edit", methods=["GET", "POST"])
def investigator_edit(user_id):
    guard = _admin()
    if guard:
        return guard
    row = get_user(g.db, user_id)
    if row is None or row["role"] != "Investigator":
        abort(404)
    form = {"full_name": row["full_name"], "username": row["username"], "email": row["email"]}
    errors = {}
    if request.method == "POST":
        form, password, errors = _account_errors(exclude_id=user_id, password_required=False)
        if not errors:
            try:
                update_investigator(g.db, user_id, form["full_name"], form["username"], form["email"], password)
                flash("تم تحديث المحقق", "ok")
                return redirect(url_for("admin.investigators"))
            except Exception:
                g.db.rollback()
                flash("تعذر تحديث المحقق", "error")
    return render_template("admin/investigator_form.html", form=form, errors=errors, mode="edit")


@bp.post("/admin/investigators/<int:user_id>/delete")
def investigator_delete(user_id):
    guard = _admin()
    if guard:
        return guard
    if user_id == g.user["user_id"]:
        flash("لا يمكن حذف الحساب الحالي", "error")
        return redirect(url_for("admin.investigators"))
    row = get_user(g.db, user_id)
    if row is None or row["role"] != "Investigator":
        abort(404)
    try:
        delete_investigator(g.db, user_id)
        flash("تم حذف المحقق", "ok")
    except Exception:
        g.db.rollback()
        flash("تعذر حذف المحقق", "error")
    return redirect(url_for("admin.investigators"))


@bp.get("/admin/cases")
def cases():
    guard = _admin()
    if guard:
        return guard
    rows, total, page, pages = list_admin_cases(g.db, _page())
    names = assignment_map(g.db, [row["case_id"] for row in rows])
    return render_template("admin/cases.html", rows=rows, names=names, total=total, page=page, pages=pages)


@bp.route("/admin/cases/new", methods=["GET", "POST"])
def case_new():
    guard = _admin()
    if guard:
        return guard
    investigators = all_investigators(g.db)
    form = {"case_title": "", "description": "", "status": "Open", "investigator_ids": []}
    errors = {}
    if request.method == "POST":
        form, errors = _case_form()
        if not errors:
            try:
                create_case(g.db, form["case_title"], form["description"], form["investigator_ids"], g.user["user_id"])
                flash("تمت إضافة القضية", "ok")
                return redirect(url_for("admin.cases"))
            except Exception:
                g.db.rollback()
                flash("تعذر إضافة القضية", "error")
    return render_template("admin/case_form.html", form=form, errors=errors, investigators=investigators, mode="new")


@bp.route("/admin/cases/<int:case_id>/edit", methods=["GET", "POST"])
def case_edit(case_id):
    guard = _admin()
    if guard:
        return guard
    row = get_case(g.db, case_id)
    if row is None:
        abort(404)
    investigators = all_investigators(g.db)
    form = {
        "case_title": row["case_title"],
        "description": row["description"] or "",
        "status": row["status"],
        "investigator_ids": assigned_ids(g.db, case_id),
    }
    errors = {}
    if request.method == "POST":
        form, errors = _case_form()
        if not errors:
            try:
                update_case(g.db, case_id, form["case_title"], form["description"], form["status"], form["investigator_ids"])
                flash("تم تحديث القضية", "ok")
                return redirect(url_for("admin.cases"))
            except Exception:
                g.db.rollback()
                flash("تعذر تحديث القضية", "error")
    return render_template("admin/case_form.html", form=form, errors=errors, investigators=investigators, mode="edit")


@bp.post("/admin/cases/<int:case_id>/delete")
def case_delete(case_id):
    guard = _admin()
    if guard:
        return guard
    if get_case(g.db, case_id) is None:
        abort(404)
    try:
        delete_case(g.db, case_id)
        flash("تم حذف القضية", "ok")
    except Exception:
        g.db.rollback()
        flash("تعذر حذف القضية", "error")
    return redirect(url_for("admin.cases"))
