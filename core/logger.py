"""
logger — Zentrales Logging-System für FinlAi

Singleton-Pattern: Die Initialisierung der Handler (Konsole + Datei)
erfolgt genau einmal beim ersten Aufruf von ``get_logger``. Alle
weiteren Aufrufe liefern lediglich einen benannten Unter-Logger des
``finlai``-Namespace zurück.

Zwei Handler werden konfiguriert:

  - **Konsole (stdout):** Farbige Ausgabe mittels ANSI-Escape-Codes
    (_ColorFormatter), Level DEBUG.
  - **Datei:** Tagesweise rotierendes Log-File unter
    ``<projekt-root>/logs/finlai_YYYYMMDD.log``, Level DEBUG.

Typical usage:
    from core.logger import get_logger

    log = get_logger(__name__)
    log.info("Modul geladen")
    log.error("Fehler: %s", exc)

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import logging
import re
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------
_LOG_DIR = Path(__file__).parent.parent / "logs"
_LOG_FILE = _LOG_DIR / f"finlai_{datetime.now().strftime('%Y%m%d')}.log"
_FMT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
_DATEFMT = "%H:%M:%S"

# ANSI-Farben für Konsole
_RESET = "\033[0m"
_COLORS = {
    logging.DEBUG: "\033[90m",  # grau
    logging.INFO: "\033[97m",  # weiß/hell
    logging.WARNING: "\033[93m",  # gelb
    logging.ERROR: "\033[91m",  # rot
    logging.CRITICAL: "\033[91m",  # rot
}

_initialized = False

# ---------------------------------------------------------------------------
# Log-Sanitisierung (/ SECURITY.md: kein IBAN, keine langen
# Nummernfolgen, keine Passwörter/Secrets/Token im Log).
# Greift am Format-Rand (Datei UND Konsole), damit die PERSISTIERTE Log-Zeile
# bereinigt ist. ``caplog``/Record.message bleiben roh (Tests unberührt).
# ---------------------------------------------------------------------------
_REDACTED = "[redacted]"
#: IBAN: 2 Buchstaben + 2 Prüfziffern + 11–30 alphanum. Zeichen, auch in
#: 4er-Gruppen mit Leerzeichen (Anzeige-/Kopier-Format, Review-Fix P1).
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")
#: ``Bearer <token>`` (Authorization-Header & Co.).
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]+=*")
#: Geheimnis-Schlüssel + Wert — ``key=value``, ``key: value`` UND
#: JSON/quoted ``"key": "value"`` (Review-Fix P1). Gruppe 1 = Schlüssel+Trenner
#: (+ evtl. öffnendes Wert-Quote), der Wert selbst wird verworfen.
_SECRET_KV_RE = re.compile(
    r'(?i)(\b(?:password|passwort|pwd|secret|token|api[_-]?key)\b["\']?\s*[:=]\s*["\']?)'
    r'([^\s"\',;}]+)'
)
#: Lange Nummernfolgen (≥12 Ziffern: Karten-/Kontonummern u.ä.). Bewusster
#: Trade-off: auch 12+-stellige interne IDs/Timestamps werden mitredigiert —
#: Sicherheit (kein Karten-/Kontonummern-Leak) vor Diagnose-Komfort.
_LONGNUM_RE = re.compile(r"\b\d{12,}\b")


def _redact(text: str) -> str:
    """Entfernt Secrets/IBAN/lange Nummern aus einer fertig formatierten Zeile."""
    text = _IBAN_RE.sub(_REDACTED, text)
    text = _BEARER_RE.sub(_REDACTED, text)
    text = _SECRET_KV_RE.sub(rf"\g<1>{_REDACTED}", text)
    text = _LONGNUM_RE.sub(_REDACTED, text)
    return text


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------
class _RedactingFormatter(logging.Formatter):
    """Formatter, der die fertige Zeile vor der Ausgabe sanitisiert."""

    def format(self, record: logging.LogRecord) -> str:
        return _redact(super().format(record))


class _ColorFormatter(_RedactingFormatter):
    """
    Logging-Formatter mit ANSI-Farbunterstützung für die Konsole.

    Erweitert:class:`_RedactingFormatter` (Sanitisierung) um die zum Level
    passende ANSI-Einfärbung. Wird ausschließlich für den Konsolen-Handler
    verwendet.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Sanitisiert + formatiert + färbt einen LogRecord ein.

        Args:
            record (logging.LogRecord): Der zu formatierende Log-Datensatz.

        Returns:
            str: Die bereinigte, formatierte, farbige Log-Zeile.
        """
        color = _COLORS.get(record.levelno, "")
        msg = super().format(record)  # bereits sanitisiert
        return f"{color}{msg}{_RESET}"


# ---------------------------------------------------------------------------
# Einmalige Initialisierung
# ---------------------------------------------------------------------------
def _init() -> None:
    """Initialisiert das Logging-System einmalig (Singleton-Guard).

    Erstellt das Log-Verzeichnis falls nötig, konfiguriert den
    Root-Logger ``finlai`` mit Konsolen- und Datei-Handler und setzt
    das globale Flag ``_initialized``. Weitere Aufrufe kehren sofort
    zurück, ohne Handler doppelt hinzuzufügen.
    """
    global _initialized
    if _initialized:
        return
    _initialized = True

    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger("finlai")
    root.setLevel(logging.DEBUG)

    if root.handlers:
        return  # bereits konfiguriert (z.B. durch Reload)

    formatter = _RedactingFormatter(_FMT, datefmt=_DATEFMT)

    # Konsole — UTF-8 erzwingen damit Unicode-Zeichen (→ etc.) nicht crashen
    # (Windows-Konsole nutzt standardmäßig cp1252)
    stdout = sys.stdout
    if hasattr(stdout, "reconfigure"):
        try:
            stdout.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError, AttributeError):
            pass  # Nicht unterbrechbar (z.B. in Pytest/IDE-Umgebungen)
    console = logging.StreamHandler(stdout)
    console.setLevel(logging.DEBUG)
    console.setFormatter(_ColorFormatter(_FMT, datefmt=_DATEFMT))
    root.addHandler(console)

    # Datei
    file_handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    root.info("Logger initialisiert — Logdatei: %s", _LOG_FILE)


# ---------------------------------------------------------------------------
# Öffentliche API
# ---------------------------------------------------------------------------
def get_logger(name: str) -> logging.Logger:
    """Gibt einen benannten Logger unter dem finlai-Namespace zurück.

    Stellt sicher, dass das Logging-System initialisiert ist, und
    liefert einen Unter-Logger des ``finlai``-Root-Loggers. Falls
    ``name`` nicht bereits mit ``"finlai."`` beginnt (z.B. bei
    Übergabe von ``__name__``), wird das Präfix automatisch ergänzt.

    Args:
        name (str): Modulname oder beliebiger Bezeichner, üblicherweise
            ``__name__`` des aufrufenden Moduls.

    Returns:
        logging.Logger: Konfigurierter Logger im finlai-Namespace,
            der alle Handler des Root-Loggers erbt.

    Example:
        log = get_logger(__name__)
        log.info("Initialisierung abgeschlossen")
    """
    _init()
    # Setzt den Namen als Unter-Logger von 'finlai'
    if not name.startswith("finlai."):
        name = f"finlai.{name}"
    return logging.getLogger(name)


def get_log_dir() -> Path:
    """Liefert das Log-Verzeichnis als ``Path``.

    Stable Public-API fuer Hilfe-Menue, Crash-Dialog und Diagnose-
    Bundle. Externe Caller sollen NICHT
    ``_LOG_DIR`` direkt importieren — das Modul-Private-Praefix
    darf jederzeit umziehen.
    """
    _init()
    return _LOG_DIR


def get_current_log_file() -> Path:
    """Liefert den Pfad zur aktiven Log-Datei (heutiges Datum).

    Vgl.:func:`get_log_dir` — gleicher API-Vertrag.
    """
    _init()
    return _LOG_FILE
