from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parents[2]
VERSION = "1.0.0"


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me-dev-secret-change-me")
    JWT_SECRET = os.getenv("JWT_SECRET", SECRET_KEY)
    JWT_ISSUER = "image-encryption-system"
    INSTANCE_DIR = Path(os.getenv("IES_INSTANCE_DIR", BASE_DIR / "instance"))
    DATABASE_PATH = INSTANCE_DIR / "vault.sqlite3"
    VAULT_DIR = INSTANCE_DIR / "vault"
    KEY_DIR = INSTANCE_DIR / "keys"
    MAX_CONTENT_LENGTH = int(os.getenv("IES_MAX_UPLOAD_BYTES", str(16 * 1024 * 1024)))
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "bmp", "tif", "tiff"}
    AUTH_MAX_FAILURES = int(os.getenv("IES_AUTH_MAX_FAILURES", "5"))
    AUTH_WINDOW_SECONDS = int(os.getenv("IES_AUTH_WINDOW_SECONDS", "300"))
    AUTH_LOCKOUT_SECONDS = int(os.getenv("IES_AUTH_LOCKOUT_SECONDS", "900"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _as_bool(os.getenv("IES_SECURE_COOKIES"))
    SESSION_COOKIE_NAME = "ies_session"
    PREFERRED_URL_SCHEME = "https" if _as_bool(os.getenv("IES_SECURE_COOKIES")) else "http"
