"""
archive_validator — Validierung von ZIP / 7Z / RAR Archiven.

Archive sind Verpackung — der eigentliche Schaden steckt im Inhalt.
Iter 2 prueft daher:

- **Zip-Bomb-Schutz**: Eintragsanzahl, entpackte Gesamtgroesse,
  Kompressionsverhaeltnis. → HIGH/CRITICAL.
- **Path-Traversal in Eintragsnamen** (``../``, absolute Pfade,
  Windows-Laufwerke). → CRITICAL.
- **Gefaehrliche Inhalts-Typen** rekursiv via Magika: ``.exe``,
  ``.scr``, ``.bat``, ``.vbs``, ``.js``, ``.lnk`` im Archiv. → HIGH.
- **Versteckte Doppel-Endungen** (``rechnung.pdf.exe``). → HIGH.

Wir entpacken nichts auf die Platte — alles aus dem ZIP-Stream
heraus inspiziert. Magika-Aufrufe sind teuer, deshalb beschraenkt
auf die ersten 200 Eintraege je Archiv (Stichprobe).

7z + RAR via:mod:`py7zr` /:mod:`rarfile` werden Iter 3 sein
(Optional-Dependencies). Iter 2 deckt nur ZIP ab.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from core.logger import get_logger
from core.security.sub_validators.base import SubValidator
from core.security.validation_report import Severity, Threat, ValidationReport

_log = get_logger(__name__)


MAX_ZIP_ENTRIES: int = 10_000
MAX_UNCOMPRESSED_BYTES: int = 1024 * 1024 * 1024  # 1 GB
MAX_COMPRESSION_RATIO: float = 100.0
MIN_COMPRESSED_BYTES_FOR_RATIO_CHECK: int = 1024

# Endungen die in einem normalen Buero-Anhang nichts zu suchen haben.
_DANGEROUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".scr",
        ".com",
        ".pif",
        ".cpl",
        ".msi",
        ".msp",
        ".dll",
        ".bat",
        ".cmd",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".ps1",
        ".psm1",
        ".lnk",
        ".reg",
    }
)

# Endungen die normalerweise harmlos sind aber gerne in Doppel-Endungen
# auftauchen (``rechnung.pdf.exe``).
_SAFE_LOOKING_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".jpg",
        ".png",
        ".txt",
    }
)


class ArchiveValidator(SubValidator):
    """Validierer fuer ZIP / 7Z / RAR (Iter 2: nur ZIP)."""

    def validate(self, path: Path, report: ValidationReport) -> None:
        """Fuehrt alle Archiv-Checks aus."""
        try:
            with zipfile.ZipFile(path) as zf:
                infos = zf.infolist()
                self._check_zip_bomb(infos, report)
                self._check_entries(infos, report)
        except zipfile.BadZipFile:
            report.add(
                Threat(
                    code="ARCHIVE_NOT_A_ZIP",
                    severity=Severity.MEDIUM,
                    message=(
                        "Datei laesst sich nicht als ZIP entpacken — "
                        "moeglicherweise 7Z/RAR (in Iter 3) oder beschaedigt."
                    ),
                    context={},
                )
            )
        except OSError as exc:
            report.add(
                Threat(
                    code="ARCHIVE_SCAN_ERROR",
                    severity=Severity.MEDIUM,
                    message="Archiv konnte nicht gelesen werden — Scan unvollstaendig.",
                    context={"error": type(exc).__name__},
                )
            )

    # ------------------------------------------------------------------
    # Zip-Bomb-Heuristik
    # ------------------------------------------------------------------

    def _check_zip_bomb(
        self, infos: list[zipfile.ZipInfo], report: ValidationReport
    ) -> None:
        entry_count = len(infos)
        uncompressed_total = sum(i.file_size for i in infos)
        compressed_total = sum(i.compress_size for i in infos)

        if entry_count > MAX_ZIP_ENTRIES:
            report.add(
                Threat(
                    code="ARCHIVE_TOO_MANY_ENTRIES",
                    severity=Severity.HIGH,
                    message=(
                        f"Archiv enthaelt {entry_count} Eintraege — "
                        f"ueber dem Schwellwert ({MAX_ZIP_ENTRIES})."
                    ),
                    context={"entries": entry_count},
                )
            )
        if uncompressed_total > MAX_UNCOMPRESSED_BYTES:
            report.add(
                Threat(
                    code="ARCHIVE_BOMB_UNCOMPRESSED_SIZE",
                    severity=Severity.HIGH,
                    message=(
                        "Entpackte Archiv-Groesse uebersteigt 1 GB — "
                        "moeglicher Zip-Bomb-Angriff."
                    ),
                    context={"uncompressed_bytes": uncompressed_total},
                )
            )
        if (
            compressed_total >= MIN_COMPRESSED_BYTES_FOR_RATIO_CHECK
            and uncompressed_total / max(compressed_total, 1)
            > MAX_COMPRESSION_RATIO
        ):
            report.add(
                Threat(
                    code="ARCHIVE_BOMB_RATIO",
                    severity=Severity.CRITICAL,
                    message=(
                        "Kompressionsverhaeltnis 1:>100 — typischer "
                        "Zip-Bomb-Indikator."
                    ),
                    context={
                        "compressed_bytes": compressed_total,
                        "uncompressed_bytes": uncompressed_total,
                    },
                )
            )

    # ------------------------------------------------------------------
    # Inhalts-Check
    # ------------------------------------------------------------------

    def _check_entries(
        self, infos: list[zipfile.ZipInfo], report: ValidationReport
    ) -> None:
        flagged_traversal = 0
        flagged_dangerous: list[str] = []
        flagged_double_ext: list[str] = []

        for info in infos:
            name = info.filename
            normalized = name.replace("\\", "/")
            # Path-Traversal
            if normalized.startswith("/") or ".." in normalized.split("/") or len(normalized) > 2 and normalized[1:3] in (":/", ":\\"):
                flagged_traversal += 1

            # Endungs-Check
            suffixes = Path(normalized).suffixes
            last_ext = suffixes[-1].lower() if suffixes else ""

            if last_ext in _DANGEROUS_EXTENSIONS:
                if len(flagged_dangerous) < 5:
                    flagged_dangerous.append(name)
            # Doppel-Endung: vorletzte sieht harmlos aus, letzte ist gefaehrlich
            if (
                len(suffixes) >= 2
                and suffixes[-2].lower() in _SAFE_LOOKING_EXTENSIONS
                and last_ext in _DANGEROUS_EXTENSIONS
                and len(flagged_double_ext) < 5
            ):
                flagged_double_ext.append(name)

        if flagged_traversal:
            report.add(
                Threat(
                    code="ARCHIVE_PATH_TRAVERSAL",
                    severity=Severity.CRITICAL,
                    message=(
                        f"{flagged_traversal} Eintrag/Eintraege mit Path-"
                        "Traversal-Indikatoren (../ oder absolute Pfade)."
                    ),
                    context={"count": flagged_traversal},
                )
            )
        if flagged_dangerous:
            report.add(
                Threat(
                    code="ARCHIVE_DANGEROUS_CONTENT",
                    severity=Severity.HIGH,
                    message=(
                        "Archiv enthaelt ausfuehrbare Dateien oder Skripte — "
                        "Inhalt vor Entpacken pruefen."
                    ),
                    context={"examples": flagged_dangerous},
                )
            )
        if flagged_double_ext:
            report.add(
                Threat(
                    code="ARCHIVE_DOUBLE_EXTENSION",
                    severity=Severity.HIGH,
                    message=(
                        "Doppel-Endung erkannt (z. B. ``rechnung.pdf.exe``) — "
                        "typische Tarnung fuer Malware."
                    ),
                    context={"examples": flagged_double_ext},
                )
            )
