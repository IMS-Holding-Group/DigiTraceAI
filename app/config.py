import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def _int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


APP_ENV = os.getenv("APP_ENV", "development").strip().lower() or "development"
SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
HOST = os.getenv("HOST", "0.0.0.0").strip() or "0.0.0.0"
PORT = _int("PORT", 5000)
DATABASE_PATH = ROOT / (os.getenv("DATABASE_PATH", "data/digitrace.db").strip() or "data/digitrace.db")
UPLOAD_DIR = ROOT / (os.getenv("UPLOAD_DIR", "uploads").strip() or "uploads")
LOG_DIR = ROOT / (os.getenv("LOG_DIR", "logs").strip() or "logs")
MAX_UPLOAD_MB = _int("MAX_UPLOAD_MB", 25)
SESSION_IDLE_MINUTES = _int("SESSION_IDLE_MINUTES", 20)
LOGIN_MAX_FAILURES = _int("LOGIN_MAX_FAILURES", 5)
LOGIN_LOCK_MINUTES = _int("LOGIN_LOCK_MINUTES", 15)
BCRYPT_ROUNDS = max(12, _int("BCRYPT_ROUNDS", 12))
