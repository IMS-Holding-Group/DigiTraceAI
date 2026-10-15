import logging
import re
from logging.handlers import RotatingFileHandler

from flask import Flask, abort, g, jsonify, redirect, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from app import config
from app.database import connect
from app.errors import register_errors
from app.formatting import event_label, fmt_dt, source_label, stage_label
from app.sessions import csrf_valid, load_session

_BLOCKED = re.compile(r"(^|/)\.|requirements\.txt$|\.(env|db|sqlite|sql|bak|log|ini|py|md)$", re.I)
_LOGGER = logging.getLogger("digitrace")


def create_app():
    application = Flask(
        __name__,
        template_folder="templates",
        static_folder=str(config.ROOT / "assets"),
        static_url_path="/assets",
    )
    application.secret_key = config.SECRET_KEY or "dev-only-secret"
    application.config["MAX_CONTENT_LENGTH"] = (config.MAX_UPLOAD_MB + 1) * 1024 * 1024
    application.config["SESSION_COOKIE_NAME"] = "dt_flash"
    application.config["SESSION_COOKIE_HTTPONLY"] = True
    application.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    application.config["SESSION_COOKIE_SECURE"] = config.APP_ENV == "production"
    application.config["JSON_AS_ASCII"] = False
    if config.APP_ENV != "production":
        application.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
        application.config["TEMPLATES_AUTO_RELOAD"] = True
    application.json.ensure_ascii = False
    application.config["PROPAGATE_EXCEPTIONS"] = False
    if config.APP_ENV == "production":
        application.wsgi_app = ProxyFix(application.wsgi_app, x_for=1, x_proto=1, x_host=1)
    _setup_log(application)
    register_errors(application)
    application.add_template_filter(fmt_dt, "fmt_dt")
    application.add_template_filter(source_label, "source_label")
    application.add_template_filter(event_label, "event_label")
    application.add_template_filter(stage_label, "stage_label")

    @application.context_processor
    def inject():
        return {"current_user": g.get("user"), "csrf_token": g.get("csrf_token") or ""}

    @application.before_request
    def prepare():
        path = request.path or ""
        if _BLOCKED.search(path) or path.startswith(("/data", "/uploads", "/logs", "/sample_data", "/app", "/ai_engine")):
            abort(404)
        if config.APP_ENV == "production":
            proto = request.headers.get("X-Forwarded-Proto", request.scheme)
            if proto != "https" and request.method in ("GET", "HEAD"):
                target = request.url.replace("http://", "https://", 1)
                return redirect(target, 301)
        if request.endpoint == "static":
            return None
        g.db = connect()
        load_session()
        if request.method in ("POST", "PUT", "DELETE") and request.endpoint not in ("auth.login",):
            if g.user and not csrf_valid():
                if request.path.startswith("/api/") or request.path.endswith("/analyze"):
                    return jsonify({"ok": False, "error": "تعذر تنفيذ الطلب"}), 400
                abort(400)
        return None

    @application.teardown_request
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @application.after_request
    def headers(response):
        response.headers["Server"] = "web"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "form-action 'self'; base-uri 'self'"
        )
        if config.APP_ENV == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if not request.path.startswith("/assets"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @application.get("/")
    def home():
        if not g.user:
            return redirect(url_for("auth.login"))
        if g.user["role"] == "Admin":
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("investigator.dashboard"))

    @application.get("/robots.txt")
    def robots():
        return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    from app.routes.account import bp as account_bp
    from app.routes.admin import bp as admin_bp
    from app.routes.api import bp as api_bp
    from app.routes.auth import bp as auth_bp
    from app.routes.investigator import bp as investigator_bp

    application.register_blueprint(auth_bp)
    application.register_blueprint(account_bp)
    application.register_blueprint(admin_bp)
    application.register_blueprint(investigator_bp)
    application.register_blueprint(api_bp)
    return application


def _setup_log(application):
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    if any(isinstance(handler, RotatingFileHandler) for handler in _LOGGER.handlers):
        return
    handler = RotatingFileHandler(config.LOG_DIR / "app.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    _LOGGER.setLevel(logging.INFO)
    _LOGGER.addHandler(handler)
    application.logger.handlers = []
    application.logger.setLevel(logging.INFO)
    application.logger.addHandler(handler)
    application.logger.propagate = False
