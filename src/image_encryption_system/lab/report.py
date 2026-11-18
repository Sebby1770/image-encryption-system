"""A lab report as one self-contained HTML file.

The scorecard partial is the same one the web page renders; here the
stylesheets are inlined and every image is a data URI, so the file opens
anywhere with no server and no network.
"""

from __future__ import annotations

from importlib import resources

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup

from .runner import LabReport

_ENVIRONMENT = Environment(
    loader=PackageLoader("image_encryption_system", "templates"),
    autoescape=select_autoescape(["html"]),
    keep_trailing_newline=True,
)


def _stylesheets() -> str:
    css = resources.files("image_encryption_system") / "static" / "css"
    return "\n".join((css / name).read_text(encoding="utf-8") for name in ("styles.css", "lab.css"))


def render_standalone_html(report: LabReport) -> str:
    template = _ENVIRONMENT.get_template("lab_report_standalone.html")
    return template.render(report=report.to_dict(), css=Markup(_stylesheets()))
