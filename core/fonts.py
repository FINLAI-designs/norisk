"""
fonts — Schriftart-Loader für FinlAi

Lädt alle TTF-Dateien aus dem Verzeichnis ``assets/fonts/`` in die
Qt-Applikationsschriftart-Datenbank (QFontDatabase), bevor das
Hauptfenster erstellt wird. Dadurch stehen benutzerdefinierte
Schriftarten (z.B. Raleway, JetBrains Mono) in QSS und Widget-Stylesheets
zur Verfügung.

Das Laden schlägt still fehl, wenn das Verzeichnis nicht existiert.
Einzelne nicht ladbare Dateien werden auf stdout protokolliert.

Typical usage:
    from core import fonts

    fonts.load # einmalig vor app.exec

Author: Patrick Riederich
Version: 1.0
"""

from pathlib import Path

from PySide6.QtGui import QFontDatabase

_FONTS_DIR = Path(__file__).parent.parent / "assets" / "fonts"


def load() -> None:
    """Lädt alle TTF-Dateien aus assets/fonts/ in die Qt-Font-Datenbank.

    Durchsucht ``_FONTS_DIR`` nach ``*.ttf``-Dateien und registriert
    jede über ``QFontDatabase.addApplicationFont``. Wenn das Verzeichnis
    nicht existiert, wird die Funktion ohne Fehler beendet.

    Returns:
        None

    Side effects:
        Registriert Schriftarten in der globalen Qt-Font-Datenbank.
        Gibt für jede nicht ladbare Datei eine Meldung auf stdout aus.
    """
    if not _FONTS_DIR.exists():
        return
    for ttf in _FONTS_DIR.glob("*.ttf"):
        font_id = QFontDatabase.addApplicationFont(str(ttf))
        if font_id == -1:
            print(f"[fonts] Konnte nicht laden: {ttf.name}")
