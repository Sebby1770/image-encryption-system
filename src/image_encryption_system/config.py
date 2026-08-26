import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me-dev-secret-change-me")
    JWT_SECRET = os.getenv("JWT_SECRET", SECRET_KEY)
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
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "bmp", "tif", "tiff"}
    # Decoded formats we are willing to load. The extension allow-list above is
    # only a filename check; this is matched against what Pillow actually
    # decoded, so a renamed file cannot smuggle in an unexpected decoder.
    ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG", "WEBP", "GIF", "BMP", "TIFF"}
    # A few megabytes of compressed input can decode to gigabytes of pixels.
    # EXIF stripping fully decodes every upload, so cap the pixel count rather
    # than relying on the byte-length limit alone. 64 MP ~= 256 MB at RGBA.
    MAX_IMAGE_PIXELS = int(os.getenv("IES_MAX_IMAGE_PIXELS", 64_000_000))
