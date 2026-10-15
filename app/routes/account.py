from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from app.security import check_password, valid_email, valid_name, valid_password, valid_username
from app.services.users import email_taken, update_account, username_taken
from app.sessions import destroy_other_sessions

bp = Blueprint("account", __name__)


def _form():
    return {
        "full_name": request.form.get("full_name", ""),
        "username": request.form.get("username", ""),
        "email": request.form.get("email", ""),
    }


@bp.route("/account", methods=["GET", "POST"])
def account():
    if not g.user:
        return redirect(url_for("auth.login"))
    errors = {}
    form = {
        "full_name": g.user["full_name"],
        "username": g.user["username"],
        "email": g.user["email"],
    }
    if request.method == "POST":
        form = _form()
        full_name = form["full_name"].strip()
        username = form["username"].strip().lower()
        email = form["email"].strip().lower()
        current = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not valid_name(full_name):
            errors["full_name"] = "الاسم يجب أن يكون بين 2 و100 حرف"
        if not valid_username(username):
            errors["username"] = "اسم المستخدم من 3 إلى 32 حرفاً لاتينياً أو رقماً أو . أو _ أو - وليس أرقاماً فقط"
        elif username_taken(g.db, username, g.user["user_id"]):
            errors["username"] = "اسم المستخدم مستخدم بالفعل"
        if not valid_email(email):
            errors["email"] = "أدخل بريداً إلكترونياً صالحاً"
        elif email_taken(g.db, email, g.user["user_id"]):
            errors["email"] = "البريد الإلكتروني مستخدم بالفعل"
        changing = bool(current or new_password or confirm)
        if changing:
            row = g.db.execute("SELECT password_hash FROM users WHERE user_id = ?", (g.user["user_id"],)).fetchone()
            if not current or not check_password(current, row["password_hash"]):
                errors["current_password"] = "كلمة السر الحالية غير صحيحة"
            if not valid_password(new_password):
                errors["new_password"] = "كلمة السر 10 أحرف على الأقل وتتضمن حرفاً كبيراً وصغيراً ورقماً"
            if new_password != confirm:
                errors["confirm_password"] = "تأكيد كلمة السر غير مطابق"
        if not errors:
            try:
                update_account(g.db, g.user["user_id"], full_name, username, email, new_password if changing else None)
                if changing:
                    destroy_other_sessions(g.db, g.user["user_id"], g.session_token)
                    g.db.commit()
                flash("تم حفظ بيانات الحساب", "ok")
                return redirect(url_for("account.account"))
            except Exception:
                g.db.rollback()
                flash("تعذر حفظ البيانات", "error")
        form = {"full_name": full_name, "username": username, "email": email}
    return render_template("account.html", form=form, errors=errors)

