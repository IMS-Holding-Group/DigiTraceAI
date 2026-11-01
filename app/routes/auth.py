from flask import Blueprint, abort, flash, g, make_response, redirect, render_template, request, url_for

from app import config
from app.security import (
    check_password,
    client_ip,
    dummy_check,
    issue_login_csrf,
    record_attempt,
    too_many_attempts,
    valid_email,
    valid_login_csrf,
    valid_name,
    valid_password,
    valid_username,
)
from app.services.users import create_investigator, email_taken, username_taken
from app.sessions import create_session, destroy_session

bp = Blueprint("auth", __name__)


def home_for(user):
    if user["role"] == "Admin":
        return url_for("admin.dashboard")
    return url_for("investigator.dashboard")


def _cookie_flags():
    return {
        "httponly": True,
        "samesite": "Lax",
        "secure": config.APP_ENV == "production",
        "path": "/",
    }


def _find_user(identifier):
    if "@" in identifier:
        return g.db.execute("SELECT * FROM users WHERE email = ?", (identifier,)).fetchone()
    return g.db.execute("SELECT * FROM users WHERE username = ?", (identifier,)).fetchone()


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(home_for(g.user))
    error = ""
    status = 200
    if request.method == "POST":
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("dt_login_csrf", "")
        identifier = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")
        if not valid_login_csrf(form_token, cookie_token):
            error = "تعذر تنفيذ الطلب"
            status = 400
        elif not identifier or not password:
            error = "أدخل البريد الإلكتروني أو اسم المستخدم وكلمة السر"
            status = 400
        elif too_many_attempts(g.db, identifier, client_ip()):
            error = "تم تجاوز عدد المحاولات المسموح به، حاول لاحقاً"
            status = 429
        else:
            user = _find_user(identifier)
            if user is None:
                dummy_check(password)
                matched = False
            else:
                matched = check_password(password, user["password_hash"])
            record_attempt(g.db, identifier, client_ip(), matched)
            g.db.commit()
            if not matched:
                error = "بيانات الدخول غير صحيحة"
                status = 401
            else:
                token = create_session(g.db, user["user_id"])
                g.db.commit()
                response = make_response(redirect(home_for(user)))
                response.set_cookie("dt_session", token, max_age=8 * 60 * 60, **_cookie_flags())
                response.delete_cookie("dt_login_csrf", path="/")
                return response
    token = issue_login_csrf()
    notice = "تم إنشاء الحساب، سجّل الدخول للمتابعة" if request.method == "GET" and request.args.get("registered") == "1" else ""
    response = make_response(render_template("login.html", error=error, notice=notice, login_csrf=token), status)
    response.set_cookie("dt_login_csrf", token, max_age=3600, **_cookie_flags())
    return response


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(home_for(g.user))
    form = {"full_name": "", "username": "", "email": ""}
    errors = {}
    status = 200
    if request.method == "POST":
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("dt_login_csrf", "")
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        form = {"full_name": full_name, "username": username, "email": email}
        if not valid_login_csrf(form_token, cookie_token):
            errors["form"] = "تعذر تنفيذ الطلب، أعد تحميل الصفحة وحاول مرة أخرى"
            status = 400
        else:
            if not valid_name(full_name):
                errors["full_name"] = "الاسم يجب أن يكون بين 2 و100 حرف"
            if not valid_username(username):
                errors["username"] = "اسم المستخدم من 3 إلى 32 حرفاً لاتينياً أو رقماً أو . أو _ أو - وليس أرقاماً فقط"
            elif username_taken(g.db, username):
                errors["username"] = "اسم المستخدم مستخدم بالفعل"
            if not valid_email(email):
                errors["email"] = "أدخل بريداً إلكترونياً صالحاً"
            elif email_taken(g.db, email):
                errors["email"] = "البريد الإلكتروني مستخدم بالفعل"
            if not valid_password(password):
                errors["password"] = "كلمة السر 10 أحرف على الأقل وتتضمن حرفاً كبيراً وصغيراً ورقماً"
            elif password != confirm:
                errors["confirm_password"] = "كلمتا السر غير متطابقتين"
            if errors:
                status = 400
            else:
                try:
                    create_investigator(g.db, full_name, username, email, password)
                    response = make_response(redirect(url_for("auth.login", registered=1)))
                    response.delete_cookie("dt_login_csrf", path="/")
                    return response
                except Exception:
                    g.db.rollback()
                    errors["form"] = "تعذر إنشاء الحساب"
                    status = 500
    token = issue_login_csrf()
    response = make_response(render_template("register.html", form=form, errors=errors, login_csrf=token), status)
    response.set_cookie("dt_login_csrf", token, max_age=3600, **_cookie_flags())
    return response


@bp.post("/logout")
def logout():
    if not g.user:
        abort(403)
    destroy_session(g.db, g.session_token)
    g.db.commit()
    response = make_response(redirect(url_for("auth.login")))
    response.delete_cookie("dt_session", path="/")
    return response
