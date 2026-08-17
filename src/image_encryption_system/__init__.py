"""Image Encryption System — authenticated AES-GCM image vault."""

__version__ = "2.0.0"


def __getattr__(name: str):
    if name == "create_app":
        from .web import create_app

        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["create_app", "__version__"]
