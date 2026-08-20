"""Image Encryption System package."""

from .config import VERSION
from .web import create_app

__all__ = ["VERSION", "create_app"]
__version__ = VERSION

