"""
script_validator — Validierung von ausfuehrbaren Text-Skripten.

Abgedeckt: ``.js``, ``.vbs``, ``.ps1``, ``.bat``, ``.cmd``, ``.wsh``,
``.lnk`` (Windows-Shortcut, kein Text — wird ueber Magika erkannt).

Heuristik:

- **Allein das Vorhandensein** in einem E-Mail-Anhang oder Download
  ist ein Signal — fast nie ein gewollter Anwender-Fall in einer
  Kanzlei. → MEDIUM-Threat ``SCRIPT_FILE_RECEIVED``.
- **Obfuskations-Marker**: Base64-Blocks > 200 chars, Hex-Strings
  > 100 chars, ``Char(``- oder ``chr(``-Konstrukte gehaeuft,
  ``Invoke-Expression`` / ``IEX`` / ``eval(`` / ``execute(``. → HIGH.
- **Bekannte Loader-Patterns** (PowerShell Empire, msfvenom-Reste).
  → CRITICAL.
- **Hohe Entropie** (Shannon > 5.5 bei einer.ps1 ist verdaechtig —
  reines Skript hat ueblicherweise < 4.5). → MEDIUM.

LNK-Dateien lesen wir nur als Magika-Bestaetigung — der eigentliche
Inhalt (Target, Arguments) braucht eine LNK-Parser-Lib, die wir in
Iter 3 ergaenzen wenn noetig.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from core.logger import get_logger
from core.security.sub_validators.base import SubValidator
from core.security.validation_report import Severity, Threat, ValidationReport

_log = get_logger(__name__)


MAX_READ_BYTES: int = 1 * 1024 * 1024  # 1 MB Stichprobe reicht

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_HEX_RE = re.compile(r"(?:0x[0-9a-fA-F]{2}[\s,]*){50,}")
_OBFUSCATION_KEYWORDS: frozenset[str] = frozenset(
    {
        "invoke-expression",
        "iex",
        "downloadstring",
        "downloadfile",
        "frombase64string",
        "[char[]]",
        "char(",
        "chr(",
        "eval(",
        "execute(",
        "wscript.shell",
        "powershell -nop",
        "powershell -enc",
        "-encodedcommand",
        "set-executionpolicy bypass",
    }
)
_LOADER_PATTERNS: tuple[str, ...] = (
    "system.management.automation",
    "shellcode",
    "msfvenom",
    "$shellcode",
    "virtualalloc",
    "createremotethread",
)


def _shannon_entropy(data: bytes) -> float:
    """Berechnet die Shannon-Entropie eines Byte-Strings (0..8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class ScriptValidator(SubValidator):
    """Validierer fuer.js /.vbs /.ps1 /.bat /.cmd /.lnk."""

    def validate(self, path: Path, report: ValidationReport) -> None:
        # Erstmal: das Vorhandensein selbst ist ein Signal.
        report.add(
            Threat(
                code="SCRIPT_FILE_RECEIVED",
                severity=Severity.MEDIUM,
                message=(
                    f"Skript-Datei vom Typ '{path.suffix.lower()}' — solche "
                    "Dateien sollten in einer Kanzlei nur aus stark "
                    "vertrauenswuerdigen Quellen geoeffnet werden."
                ),
                context={"extension": path.suffix.lower()},
            )
        )

        if path.suffix.lower() == ".lnk":
            # LNK ist Binaer — Inhalts-Heuristik macht keinen Sinn ohne Parser.
            return

        try:
            raw = path.read_bytes()[:MAX_READ_BYTES]
        except OSError as exc:
            report.add(
                Threat(
                    code="SCRIPT_SCAN_ERROR",
                    severity=Severity.MEDIUM,
                    message="Skript konnte nicht gelesen werden.",
                    context={"error": type(exc).__name__},
                )
            )
            return

        text = raw.decode("utf-8", errors="ignore").lower()

        self._check_obfuscation(text, report)
        self._check_loaders(text, report)
        self._check_entropy(raw, report)

    # ------------------------------------------------------------------

    def _check_obfuscation(self, text: str, report: ValidationReport) -> None:
        markers: list[str] = []
        if _BASE64_RE.search(text):
            markers.append("Base64-Block (>=200 Zeichen)")
        if _HEX_RE.search(text):
            markers.append("Hex-Konstanten-Reihe")
        found_keywords = sorted({k for k in _OBFUSCATION_KEYWORDS if k in text})
        if found_keywords:
            markers.append(f"Keywords: {', '.join(found_keywords[:5])}")

        if markers:
            report.add(
                Threat(
                    code="SCRIPT_OBFUSCATION",
                    severity=Severity.HIGH,
                    message=(
                        "Skript zeigt Obfuskations-Indikatoren — moeglicher "
                        "Loader oder Malware-Dropper."
                    ),
                    context={"markers": markers},
                )
            )

    def _check_loaders(self, text: str, report: ValidationReport) -> None:
        hits = sorted({p for p in _LOADER_PATTERNS if p in text})
        if hits:
            report.add(
                Threat(
                    code="SCRIPT_KNOWN_LOADER_PATTERN",
                    severity=Severity.CRITICAL,
                    message=(
                        "Bekanntes Shellcode-/Loader-Pattern erkannt — Datei "
                        "vor Oeffnen vom IT-Fachmann pruefen lassen."
                    ),
                    context={"patterns": hits},
                )
            )

    def _check_entropy(self, raw: bytes, report: ValidationReport) -> None:
        if len(raw) < 256:
            return
        entropy = _shannon_entropy(raw)
        if entropy > 5.5:
            report.add(
                Threat(
                    code="SCRIPT_HIGH_ENTROPY",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Sehr hohe Entropie ({entropy:.2f}/8) — typisch fuer "
                        "verschluesselten oder gepackten Skript-Inhalt."
                    ),
                    context={"entropy": round(entropy, 2)},
                )
            )
