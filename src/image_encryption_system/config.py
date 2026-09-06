import os
import secrets
import stat
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

# The value earlier releases shipped as the built-in fallback. It is still
# recognised so a deployment that pinned it in an environment file gets a clear
# refusal rather than silently running on a published secret.
KNOWN_INSECURE_SECRETS = frozenset(
    {
        "dev-secret-change-me-dev-secret-change-me",
        "dev-secret-change-me",
        "change-me",
        "secret",
    }
)


def env_flag(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_or_create_secret_key(instance_dir: Path) -> str:
    """Return the configured secret, or mint and persist a random one.

    Sessions and API tokens are both signed with this value, so a predictable
    secret forges either. Earlier releases fell back to a constant published in
    the repository; generating a random secret on first run instead keeps the
    quick-start working without ever handing a deployment a known key.
    """
    configured = os.getenv("SECRET_KEY")
    if configured:
        return configured

    key_path = instance_dir / "secret.key"
    try:
        existing = key_path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    except OSError:
        pass

    minted = secrets.token_urlsafe(48)
    try:
        instance_dir.mkdir(parents=True, exist_ok=True)
        # Written before the content so the secret is never briefly world
        # readable on a shared host.
        handle = os.open(
            key_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            file.write(minted)
    except OSError:
        # An unwritable instance directory is survivable: the process still gets
        # a strong random secret, it just will not outlive a restart.
        pass
    return minted


class Config:
    INSTANCE_DIR = Path(os.getenv("IES_INSTANCE_DIR", BASE_DIR / "instance"))
    SECRET_KEY = load_or_create_secret_key(INSTANCE_DIR)
    JWT_SECRET = os.getenv("JWT_SECRET", SECRET_KEY)
    JWT_ISSUER = "image-encryption-system"
    DATABASE_PATH = INSTANCE_DIR / "vault.sqlite3"
    VAULT_DIR = INSTANCE_DIR / "vault"
    KEY_DIR = INSTANCE_DIR / "keys"
    MAX_CONTENT_LENGTH = int(os.getenv("IES_MAX_UPLOAD_BYTES", 8 * 1024 * 1024))
    LOGIN_RATE_LIMIT = int(os.getenv("IES_LOGIN_RATE_LIMIT", 5))
    LOGIN_RATE_WINDOW_SECONDS = int(os.getenv("IES_LOGIN_RATE_WINDOW", 600))
    LOGIN_LOCKOUT_THRESHOLD = int(os.getenv("IES_LOGIN_LOCKOUT_THRESHOLD", 8))
    LOGIN_LOCKOUT_SECONDS = int(os.getenv("IES_LOGIN_LOCKOUT_SECONDS", 900))
    SESSION_IDLE_SECONDS = int(os.getenv("IES_SESSION_IDLE_SECONDS", 1800))

    # Throttles for the unauthenticated and key-guessing surfaces that sit
    # outside the login flow. Registration matters because it generates an
    # RSA-3072 key pair, so an unbounded caller can burn CPU without an account;
    # decrypt and capability links matter because both take a secret as input.
    REGISTER_RATE_LIMIT = int(os.getenv("IES_REGISTER_RATE_LIMIT", 5))
    REGISTER_RATE_WINDOW_SECONDS = int(os.getenv("IES_REGISTER_RATE_WINDOW", 3600))
    DECRYPT_RATE_LIMIT = int(os.getenv("IES_DECRYPT_RATE_LIMIT", 30))
    DECRYPT_RATE_WINDOW_SECONDS = int(os.getenv("IES_DECRYPT_RATE_WINDOW", 300))
    LINK_RATE_LIMIT = int(os.getenv("IES_LINK_RATE_LIMIT", 20))
    LINK_RATE_WINDOW_SECONDS = int(os.getenv("IES_LINK_RATE_WINDOW", 300))

    MIN_PASSWORD_LENGTH = int(os.getenv("IES_MIN_PASSWORD_LENGTH", 10))

    # Session cookie hardening. Secure defaults on, because the cookie
    # authenticates access to a vault; local HTTP development opts out with
    # IES_SESSION_COOKIE_SECURE=0.
    SESSION_COOKIE_NAME = "ies_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("IES_SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = env_flag("IES_SESSION_COOKIE_SECURE", default=True)

    # Sent only over HTTPS requests, so a plain-HTTP development run is
    # unaffected and a proxied deployment still gets the header.
    HSTS_SECONDS = int(os.getenv("IES_HSTS_SECONDS", 31_536_000))

    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "bmp", "tif", "tiff"}
    # Decoded formats we are willing to load. The extension allow-list above is
    # only a filename check; this is matched against what Pillow actually
    # decoded, so a renamed file cannot smuggle in an unexpected decoder.
    ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG", "WEBP", "GIF", "BMP", "TIFF"}
    # A few megabytes of compressed input can decode to gigabytes of pixels.
    # EXIF stripping fully decodes every upload, so cap the pixel count rather
    # than relying on the byte-length limit alone. 64 MP ~= 256 MB at RGBA.
    MAX_IMAGE_PIXELS = int(os.getenv("IES_MAX_IMAGE_PIXELS", 64_000_000))
