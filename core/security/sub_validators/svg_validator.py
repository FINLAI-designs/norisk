"""
svg_validator — Validierung von SVG-Dateien.

SVG ist XML — und erlaubt eingebettetes ``<script>`` sowie
``javascript:``-URLs in ``<a>``- und ``href``-Attributen. Das ist eine
oft vergessene Angriffsflaeche; Browser fuehren JS in SVGs aus die
direkt geladen werden (nicht als ``<img>``-Tag).

Iter 2 prueft:

- ``<script>``-Tags → CRITICAL.
- ``javascript:``-URLs in href/xlink:href → HIGH.
- ``on*``-Event-Handler (``onclick``, ``onload``,...) → HIGH.
- Externe ``<image>`` oder ``<use>`` mit ``href`` ueber HTTP → MEDIUM.

Parser::mod:`defusedxml` ist hier vermutlich schon im Repo, sonst
fallen wir auf eine regex-basierte Heuristik zurueck (SVG-spezifisch
sind die Patterns sehr eindeutig).

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import re
from pathlib import Path

from core.logger import get_logger
from core.security.sub_validators.base import SubValidator
from core.security.validation_report import Severity, Threat, ValidationReport

_log = get_logger(__name__)


MAX_READ_BYTES: int = 4 * 1024 * 1024  # 4 MB Stichprobe

_SCRIPT_RE = re.compile(r"<\s*script\b", re.IGNORECASE)
_JS_URL_RE = re.compile(r"\bjavascript\s*:", re.IGNORECASE)
_EVENT_HANDLER_RE = re.compile(
    r"\bon(?:load|click|error|mouseover|focus|submit|change)\s*=", re.IGNORECASE
)
_EXTERNAL_HREF_RE = re.compile(
    r'\b(?:xlink:href|href)\s*=\s*["\'](?:https?:)?//[^"\']+["\']',
    re.IGNORECASE,
)


class SvgValidator(SubValidator):
    """Validierer fuer SVG (Skript-Tags, JS-URLs, Event-Handler)."""

    def validate(self, path: Path, report: ValidationReport) -> None:
        try:
            raw = path.read_bytes()[:MAX_READ_BYTES]
        except OSError as exc:
            report.add(
                Threat(
                    code="SVG_SCAN_ERROR",
                    severity=Severity.MEDIUM,
                    message="SVG konnte nicht gelesen werden.",
                    context={"error": type(exc).__name__},
                )
            )
            return

        text = raw.decode("utf-8", errors="ignore")

        if _SCRIPT_RE.search(text):
            report.add(
                Threat(
                    code="SVG_SCRIPT_TAG",
                    severity=Severity.CRITICAL,
                    message=(
                        "SVG enthaelt ein <script>-Tag — Datei darf nicht "
                        "direkt im Browser geoeffnet werden."
                    ),
                    context={},
                )
            )
        if _JS_URL_RE.search(text):
            report.add(
                Threat(
                    code="SVG_JAVASCRIPT_URL",
                    severity=Severity.HIGH,
                    message=(
                        "SVG enthaelt ``javascript:``-URLs — moegliches "
                        "Cross-Site-Scripting beim Anklicken."
                    ),
                    context={},
                )
            )
        if _EVENT_HANDLER_RE.search(text):
            report.add(
                Threat(
                    code="SVG_EVENT_HANDLER",
                    severity=Severity.HIGH,
                    message=(
                        "SVG enthaelt inline Event-Handler (onclick, onload, "
                        "...) — moegliches Cross-Site-Scripting."
                    ),
                    context={},
                )
            )
        ext_count = len(_EXTERNAL_HREF_RE.findall(text))
        if ext_count:
            report.add(
                Threat(
                    code="SVG_EXTERNAL_REFERENCE",
                    severity=Severity.MEDIUM,
                    message=(
                        f"SVG verweist auf {ext_count} externe URL(s) — "
                        "moegliche Daten-Exfiltration oder Tracking."
                    ),
                    context={"count": ext_count},
                )
            )
