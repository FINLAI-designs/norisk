"""
pdf_fonts — Font-Registrierung für den FINLAI PDF-Report.

Registriert Raleway und JetBrains Mono für reportlab aus assets/fonts/.
Idempotent und thread-safe (kann mehrfach aufgerufen werden).

Schichtzugehörigkeit: core/ — keine Tool-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import threading
from pathlib import Path

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from core.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Pfad zu den Font-Dateien (relativ zum Projektroot)
# ---------------------------------------------------------------------------
_ASSETS_FONTS = Path(__file__).parent.parent.parent / "assets" / "fonts"

# ---------------------------------------------------------------------------
# Öffentliche Font-Namen (für Styles und Components verwenden)
# ---------------------------------------------------------------------------
FONT_RALEWAY: str = "Raleway"
FONT_RALEWAY_BOLD: str = "Raleway-Bold"
FONT_RALEWAY_LIGHT: str = "Raleway-Light"
FONT_MONO: str = "JetBrainsMono"
FONT_MONO_BOLD: str = "JetBrainsMono-Bold"

# ---------------------------------------------------------------------------
# Registrierungs-Lock
# ---------------------------------------------------------------------------
_registered: bool = False
_lock = threading.Lock()

# Font-Datei-Mapping: (Name, Dateiname)
_FONT_FILES: list[tuple[str, str]] = [
    (FONT_RALEWAY, "Raleway-Regular.ttf"),
    (FONT_RALEWAY_BOLD, "Raleway-Bold.ttf"),
    (FONT_RALEWAY_LIGHT, "Raleway-Light.ttf"),
    (FONT_MONO, "JetBrainsMono-Regular.ttf"),
    (FONT_MONO_BOLD, "JetBrainsMono-Bold.ttf"),
]


def register_fonts() -> None:
    """Registriert alle PDF-Fonts (idempotent, thread-safe).

    Muss vor dem ersten PDF-Build aufgerufen werden.
    Fehlende Font-Dateien werden mit Warnung übersprungen — Helvetica-Fallback.

    Raises:
        Keine Exception — fehlende Fonts werden nur geloggt.
    """
    global _registered
    with _lock:
        if _registered:
            return
        for name, filename in _FONT_FILES:
            font_path = _ASSETS_FONTS / filename
            if font_path.exists():
                try:
                    pdfmetrics.registerFont(TTFont(name, str(font_path)))
                except Exception as exc:  # noqa: BLE001 -- reportlab TTFError + OSError + ValueError, Helvetica-Fallback bei jedem Font-Bug
                    log.warning("Font '%s' konnte nicht geladen werden: %s", name, exc)
            else:
                log.warning(
                    "Font-Datei nicht gefunden: %s — Helvetica-Fallback aktiv",
                    font_path,
                )
        _registered = True
        log.debug("PDF-Fonts registriert.")
