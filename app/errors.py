from flask import jsonify, render_template, request
from werkzeug.exceptions import HTTPException

_MESSAGES = {
    400: "تعذر تنفيذ الطلب",
    403: "ليست لديك صلاحية الوصول إلى هذه الصفحة",
    404: "الصفحة غير موجودة",
    405: "طريقة الطلب غير مدعومة",
    413: "حجم الطلب أكبر من المسموح",
    429: "تم تجاوز عدد المحاولات المسموح به، حاول لاحقاً",
    500: "حدث خطأ غير متوقع",
}


def render_error(code):
    message = _MESSAGES.get(code, _MESSAGES[500])
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": message}), code
    return render_template("error.html", message=message), code


def register_errors(app):
    for code in (400, 403, 404, 405, 413, 429, 500):
        app.register_error_handler(code, lambda error, status=code: render_error(status))

    @app.errorhandler(Exception)
    def unhandled(error):
        if isinstance(error, HTTPException):
            return render_error(error.code or 500)
        app.logger.exception("request failed")
        return render_error(500)

