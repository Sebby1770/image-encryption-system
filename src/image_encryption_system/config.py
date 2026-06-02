from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parents[2]


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me-dev-secret-change-me")
    JWT_SECRET = os.getenv("JWT_SECRET", SECRET_KEY)
    JWT_ISSUER = "image-encryption-system"
    REQUIRE_STRONG_SECRETS = _env_bool("IES_REQUIRE_STRONG_SECRETS", os.getenv("FLASK_ENV") == "production")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", os.getenv("FLASK_ENV") == "production")
    INSTANCE_DIR = Path(os.getenv("IES_INSTANCE_DIR", BASE_DIR / "instance"))
    DATABASE_PATH = INSTANCE_DIR / "vault.sqlite3"
    VAULT_DIR = INSTANCE_DIR / "vault"
    KEY_DIR = INSTANCE_DIR / "keys"
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    MAX_IMAGE_PIXELS = int(os.getenv("MAX_IMAGE_PIXELS", "20000000"))
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "bmp", "tif", "tiff"}
    AUTH_RATE_LIMIT_ATTEMPTS = int(os.getenv("AUTH_RATE_LIMIT_ATTEMPTS", "5"))
    AUTH_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("AUTH_RATE_LIMIT_WINDOW_SECONDS", "300"))
    AUTH_RATE_LIMIT_LOCKOUT_SECONDS = int(os.getenv("AUTH_RATE_LIMIT_LOCKOUT_SECONDS", "300"))
