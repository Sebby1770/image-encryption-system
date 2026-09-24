import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

# Values that have shipped in this repository as defaults or examples. A
# deployment that still uses one has a signing key anyone can read, so the app
# treats them exactly like an unset secret and generates a real one instead.
PLACEHOLDER_SECRETS = frozenset(
    {
        "dev-secret-change-me-dev-secret-change-me",
        "change-me-before-deploying-use-at-least-32-bytes",
        "change-me-too-use-at-least-32-bytes",
        "use-a-third-stable-secret-of-at-least-32-bytes",
    }
)

# The only image types the vault will store or serve, keyed by the format name
# Pillow reports. Served Content-Type always comes from this map, never from a
# stored or restored row.
IMAGE_MIME_TYPES = {
    "PNG": "image/png",
    "JPEG": "image/jpeg",
    "WEBP": "image/webp",
    "GIF": "image/gif",
    "BMP": "image/bmp",
    "TIFF": "image/tiff",
}


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    # Unset secrets are resolved in create_app(): a random key is generated
    # once and persisted under the instance directory.
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET = os.getenv("JWT_SECRET")
    AUDIT_HMAC_KEY = os.getenv("AUDIT_HMAC_KEY")
    JWT_ISSUER = "image-encryption-system"
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
    SESSION_MAX_AGE_SECONDS = int(os.getenv("IES_SESSION_MAX_AGE_SECONDS", 7 * 24 * 3600))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_flag("IES_SECURE_COOKIES")
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "bmp", "tif", "tiff"}
    # Decoded formats we are willing to load. The extension allow-list above is
    # only a filename check; this is matched against what Pillow actually
    # decoded, so a renamed file cannot smuggle in an unexpected decoder.
    ALLOWED_IMAGE_FORMATS = set(IMAGE_MIME_TYPES)
    # A few megabytes of compressed input can decode to gigabytes of pixels.
    # Metadata stripping fully decodes every upload, so cap the pixel count
    # (summed over all frames) rather than relying on the byte limit alone.
    # 64 MP ~= 256 MB at RGBA.
    MAX_IMAGE_PIXELS = int(os.getenv("IES_MAX_IMAGE_PIXELS", 64_000_000))
