import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
APP_VERSION = "1.0.0"


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me-dev-secret-change-me")
    JWT_SECRET = os.getenv("JWT_SECRET", SECRET_KEY)
    JWT_ISSUER = "image-encryption-system"
    JWT_AUDIENCE = "image-encryption-system-api"
    JWT_LIFETIME_SECONDS = int(os.getenv("JWT_LIFETIME_SECONDS", "3600"))
    AUDIT_HMAC_KEY = os.getenv("AUDIT_HMAC_KEY")
    REQUIRE_STRONG_SECRETS = _env_bool(
        "IES_REQUIRE_STRONG_SECRETS", os.getenv("FLASK_ENV") == "production"
    )
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_bool(
        "SESSION_COOKIE_SECURE", os.getenv("FLASK_ENV") == "production"
    )
    PERMANENT_SESSION_LIFETIME_SECONDS = int(
        os.getenv("PERMANENT_SESSION_LIFETIME_SECONDS", "28800")
    )
    INSTANCE_DIR = Path(os.getenv("IES_INSTANCE_DIR", BASE_DIR / "instance"))
    DATABASE_PATH = INSTANCE_DIR / "vault.sqlite3"
    VAULT_DIR = INSTANCE_DIR / "vault"
    KEY_DIR = INSTANCE_DIR / "keys"
    MAX_CONTENT_LENGTH = int(os.getenv("IES_MAX_UPLOAD_BYTES", 8 * 1024 * 1024))
    LOGIN_RATE_LIMIT = int(os.getenv("IES_LOGIN_RATE_LIMIT", 5))
    LOGIN_RATE_WINDOW_SECONDS = int(os.getenv("IES_LOGIN_RATE_WINDOW", 600))
    LOGIN_LOCKOUT_THRESHOLD = int(os.getenv("IES_LOGIN_LOCKOUT_THRESHOLD", 8))
    LOGIN_LOCKOUT_SECONDS = int(os.getenv("IES_LOGIN_LOCKOUT_SECONDS", 900))
    SESSION_IDLE_SECONDS = int(os.getenv("IES_SESSION_IDLE_SECONDS", 1800))
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "bmp", "tif", "tiff"}
    AUTH_RATE_LIMIT_ATTEMPTS = int(os.getenv("AUTH_RATE_LIMIT_ATTEMPTS", "5"))
    AUTH_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("AUTH_RATE_LIMIT_WINDOW_SECONDS", "300"))
    AUTH_RATE_LIMIT_LOCKOUT_SECONDS = int(os.getenv("AUTH_RATE_LIMIT_LOCKOUT_SECONDS", "300"))
    DECRYPT_RATE_LIMIT_ATTEMPTS = int(os.getenv("DECRYPT_RATE_LIMIT_ATTEMPTS", "8"))
    DECRYPT_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("DECRYPT_RATE_LIMIT_WINDOW_SECONDS", "300"))
    DECRYPT_RATE_LIMIT_LOCKOUT_SECONDS = int(os.getenv("DECRYPT_RATE_LIMIT_LOCKOUT_SECONDS", "300"))
    REGISTER_RATE_LIMIT_ATTEMPTS = int(os.getenv("REGISTER_RATE_LIMIT_ATTEMPTS", "5"))
    REGISTER_RATE_LIMIT_WINDOW_SECONDS = int(
        os.getenv("REGISTER_RATE_LIMIT_WINDOW_SECONDS", "3600")
    )
    REGISTER_RATE_LIMIT_LOCKOUT_SECONDS = int(
        os.getenv("REGISTER_RATE_LIMIT_LOCKOUT_SECONDS", "3600")
    )
