"""Every colour in the stylesheet is a token, so dark mode stays one block.

A colour written inline would render the same in both themes, which in dark
mode usually means light text on a light patch or the reverse.
"""

from __future__ import annotations

import re
from pathlib import Path

CSS_DIR = Path(__file__).resolve().parents[1] / "src/image_encryption_system/static/css"
CSS = CSS_DIR / "styles.css"
# Colour keywords count only as whole values: "white-space" is a property name.
COLOUR = re.compile(
    r"#[0-9a-fA-F]{3,8}\b|\b(?:rgb|rgba|hsl|hsla)\(|(?<![\w-])(?:white|black)(?![\w-])"
)
TOKEN = re.compile(r"^\s*(--[a-z0-9-]+)\s*:", re.MULTILINE)
# Readable on the accent colour in both themes, so it needs no dark value.
SAME_IN_BOTH = {"--on-accent"}


def _blocks(text: str) -> tuple[str, str]:
    light = re.search(r"^:root\s*\{(.*?)^\}", text, re.MULTILINE | re.DOTALL)
    dark = re.search(
        r"@media \(prefers-color-scheme: dark\)\s*\{\s*:root\s*\{(.*?)\}\s*\}", text, re.DOTALL
    )
    assert light and dark, "expected a light :root block and a dark media block"
    return light.group(1), dark.group(1)


def test_no_colour_is_written_outside_a_token() -> None:
    inline = [
        f"{sheet.name}: {line.strip()}"
        for sheet in sorted(CSS_DIR.glob("*.css"))
        for line in sheet.read_text().splitlines()
        if COLOUR.search(line) and not line.strip().startswith("--")
    ]
    assert inline == []


def test_only_styles_css_defines_tokens() -> None:
    # Other sheets (lab.css) use the shared tokens, so dark mode stays one block.
    assert len(list(CSS_DIR.glob("*.css"))) >= 2
    for sheet in CSS_DIR.glob("*.css"):
        if sheet.name != "styles.css":
            assert TOKEN.findall(sheet.read_text()) == [], sheet.name


def test_every_token_has_a_dark_value() -> None:
    light, dark = _blocks(CSS.read_text())
    light_tokens = set(TOKEN.findall(light))
    dark_tokens = set(TOKEN.findall(dark))
    assert dark_tokens <= light_tokens, "dark mode sets a token light mode never defines"
    assert light_tokens - dark_tokens == SAME_IN_BOTH
