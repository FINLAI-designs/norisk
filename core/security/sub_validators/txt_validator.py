"""
txt_validator — Validierung von Text-Dateien (TXT, CSV).

Erkannte Angriffe:
  - **Trojan Source** (CVE-2021-42574): Bidi-Control-Chars kehren die
    Anzeigereihenfolge um, sodass Code anders aussieht als er ausgeführt
    wird. → HIGH.
  - **Homoglyph-Verwirrung**: Kyrillisches 'а' sieht aus wie lateinisches 'a'.
    Gemischter Einsatz in einem Wort deutet auf Täuschungsversuch. → MEDIUM.
  - **ANSI-Escape-Injection**: Steuersequenzen können Terminal-Logs
    manipulieren, wenn der Inhalt ungefiltert ausgegeben wird. → LOW.
  - **Nicht-UTF-8-Inhalt**: Strikter Decode verhindert stille Daten-
    korruption durch fehlerhafte Encoding-Annahmen. → HIGH.
  - **BOM-Präsenz**: Informativ — viele Parser scheitern stumm an BOMs.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

from core.security.magika_adapter import identify
from core.security.sub_validators.base import SubValidator
from core.security.validation_report import Severity, Threat, ValidationReport

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

# Max. Dateigröße für strikte Validierung. Gigabyte-TXTs deuten fast immer
# auf Log-Dumps oder SQL-Dumps hin — kein gültiger FINLAI-Import.
MAX_TXT_SIZE_BYTES: int = 100 * 1024 * 1024

# Bidi-Control-Chars (Trojan-Source, CVE-2021-42574).
# https://trojansource.codes/trojan-source.pdf
BIDI_CONTROL_CHARS: frozenset[str] = frozenset(
    [
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
    ]
)

# Byte-Grenzwert für Magika-Check (CSV wird häufig als TXT erkannt und vice
# versa — wir erlauben beide).
_SAMPLE_BYTES: int = 8192

# UTF-8 BOM
_UTF8_BOM: bytes = b"\xef\xbb\xbf"


def _has_mixed_scripts(word: str) -> bool:
    """Prüft ob ein Wort kyrillische UND lateinische Zeichen enthält.

    Homoglyph-Heuristik (typisches Phishing-/Täuschungsmuster).

    Args:
        word: Zu prüfendes Wort (bereits ohne Leerzeichen).

    Returns:
        True wenn beide Schrift-Systeme im Wort vorkommen.
    """
    has_latin = False
    has_cyrillic = False
    for ch in word:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch, "")
        except ValueError:
            continue
        if "LATIN" in name:
            has_latin = True
        elif "CYRILLIC" in name:
            has_cyrillic = True
        if has_latin and has_cyrillic:
            return True
    return False


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class TxtValidator(SubValidator):
    """Validierer für TXT / CSV — prüft Encoding, Bidi, Homoglyph, Größe."""

    def validate(self, path: Path, report: ValidationReport) -> None:
        """Führt alle Text-spezifischen Prüfungen durch.

        Args:
            path: Zu prüfender Pfad.
            report: Report zum Anhängen.
        """
        size = path.stat().st_size
        if size > MAX_TXT_SIZE_BYTES:
            report.add(
                Threat(
                    code="TXT_FILE_TOO_LARGE",
                    severity=Severity.HIGH,
                    message=(
                        f"Textdatei zu groß ({size // (1024 * 1024)} MB). "
                        f"Limit: {MAX_TXT_SIZE_BYTES // (1024 * 1024)} MB."
                    ),
                    context={"size_bytes": size},
                )
            )
            return

        # Magika-Check — verhindert, dass getarnter binärer Inhalt
        # (z. B. HTML-Exploits, JavaScript) als CSV durchrutscht.
        ident = identify(path)
        # ``is_text`` ist die stabile Kompatibilitäts-Flagge — CSV/JSON/TXT
        # sind alle textuell, alles andere ist verdächtig im TXT-Kontext.
        if not ident.is_text:
            report.add(
                Threat(
                    code="TXT_CONTENT_NOT_TEXT",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Inhalt ist kein Text — erkannt als '{ident.label}' "
                        f"({ident.description})."
                    ),
                    context={
                        "detected_label": ident.label,
                        "mime_type": ident.mime_type,
                    },
                )
            )
            return

        # BOM-Check auf rohen Bytes (Magika entfernt ggf. BOM vor Erkennung)
        try:
            with path.open("rb") as f:
                head = f.read(len(_UTF8_BOM))
        except OSError as exc:
            report.add(
                Threat(
                    code="TXT_SCAN_ERROR",
                    severity=Severity.MEDIUM,
                    message=f"Datei konnte nicht gelesen werden: {exc}",
                )
            )
            return

        if head == _UTF8_BOM:
            report.add(
                Threat(
                    code="TXT_BOM_PRESENT",
                    severity=Severity.INFO,
                    message=(
                        "UTF-8 BOM am Dateianfang erkannt — kann zu "
                        "Parser-Problemen führen."
                    ),
                )
            )

        # Strikter UTF-8 Decode — inhaltliche Analyse
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            report.add(
                Threat(
                    code="TXT_INVALID_UTF8",
                    severity=Severity.HIGH,
                    message=(
                        f"Datei ist nicht UTF-8-kodiert "
                        f"(Fehler an Byte-Offset {exc.start})."
                    ),
                    context={"byte_offset": exc.start, "reason": exc.reason},
                )
            )
            return
        except OSError as exc:
            report.add(
                Threat(
                    code="TXT_SCAN_ERROR",
                    severity=Severity.MEDIUM,
                    message=f"Datei konnte nicht gelesen werden: {exc}",
                )
            )
            return

        self._check_bidi(text, report)
        self._check_homoglyph(text, report)
        self._check_ansi_escape(text, report)

    @staticmethod
    def _check_bidi(text: str, report: ValidationReport) -> None:
        """Erkennt Trojan-Source / Bidi-Control-Chars (CVE-2021-42574)."""
        offenders: list[tuple[int, str]] = []
        for idx, ch in enumerate(text):
            if ch in BIDI_CONTROL_CHARS:
                offenders.append((idx, ch))
                if len(offenders) >= 5:
                    break
        if offenders:
            samples = [
                {"char_offset": off, "char_code": f"U+{ord(c):04X}"}
                for off, c in offenders
            ]
            report.add(
                Threat(
                    code="TXT_BIDI_CONTROL_CHARS",
                    severity=Severity.HIGH,
                    message=(
                        "Unicode-Bidi-Control-Zeichen erkannt "
                        "(Trojan-Source, CVE-2021-42574) — "
                        f"{len(offenders)} Fundstelle(n)."
                    ),
                    context={"occurrences": samples},
                )
            )

    @staticmethod
    def _check_homoglyph(text: str, report: ValidationReport) -> None:
        """Erkennt Wörter mit gemischt kyrillisch/lateinischen Zeichen."""
        suspicious: list[str] = []
        # Wort-Trennung per Whitespace — grob, aber stabil
        for word in text.split():
            # Lange Wörter abschneiden, um PII-Logging zu vermeiden
            compact = word[:20]
            if _has_mixed_scripts(compact) and compact not in suspicious:
                suspicious.append(compact)
                if len(suspicious) >= 5:
                    break
        if suspicious:
            report.add(
                Threat(
                    code="TXT_HOMOGLYPH_MIX",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Wörter mit gemischten Schriften erkannt "
                        f"(Homoglyph-Täuschung) — {len(suspicious)} Fundstelle(n)."
                    ),
                    context={"samples": suspicious},
                )
            )

    @staticmethod
    def _check_ansi_escape(text: str, report: ValidationReport) -> None:
        """Erkennt ANSI-Escape-Sequenzen (\\x1b[...)."""
        if "\x1b[" in text:
            count = text.count("\x1b[")
            report.add(
                Threat(
                    code="TXT_ANSI_ESCAPE",
                    severity=Severity.LOW,
                    message=(
                        f"ANSI-Escape-Sequenzen erkannt ({count} Fundstellen) — "
                        "können Terminal-Ausgaben manipulieren."
                    ),
                    context={"occurrences": count},
                )
            )
