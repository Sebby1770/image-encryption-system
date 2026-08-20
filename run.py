from pathlib import Path
import os
import sys


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from image_encryption_system.web import create_app


app = create_app()


def _debug_enabled() -> bool:
    return os.getenv("IES_DEBUG", os.getenv("FLASK_DEBUG", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


if __name__ == "__main__":
    debug = _debug_enabled()
    host = os.getenv("IES_HOST", "127.0.0.1")
    port = int(os.getenv("IES_PORT", "5000"))
    app.run(host=host, port=port, debug=debug)
