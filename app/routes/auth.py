from flask import Blueprint, abort, flash, g, make_response, redirect, render_template, request, url_for

from app import config
from app.security import check_password, client_ip, dummy_check, issue_login_csrf, record_attempt, too_many_attempts, valid_login_csrf
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
    response = make_response(render_template("login.html", error=error, login_csrf=token), status)
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
