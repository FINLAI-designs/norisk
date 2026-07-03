"""
office_validator — Validierung von DOCX / DOCM / PPTX / PPTM / ODT.

Alle modernen Office-Formate ausser dem alten DOC/.xls sind ZIP-
Container mit XML-Parts. Die Angriffsflaeche ist analog zu XLSX:

- **Zip-Bomb-Schutz** (uebermaessig komprimierte Container)
- **VBA-Makros** in DOCM/PPTM via:mod:`oletools.olevba` — HIGH
- **DDE-Links** in DOCX-Body via:mod:`oletools.msodde` — CRITICAL
- **OLE-Embedded-Objekte** (z. B. eingebettete.exe) — HIGH
- **Externe Template-Verknuepfungen** (``word/_rels/settings.xml.rels``
  attachedTemplate) — typischer Remote-Template-Injection-Vektor — HIGH

ODT ist ein OASIS-OpenDocument-ZIP-Container — gleiche Container-
Checks, kein VBA. Bei ODT gibt es Basic-Makros in
``Basic/Standard/*.xml`` — Iter 2 markiert das als HIGH wenn vorhanden.

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


# ZIP-Container-Grenzen (vgl. xlsx_validator)
MAX_ZIP_ENTRIES: int = 10_000
MAX_UNCOMPRESSED_BYTES: int = 500 * 1024 * 1024  # 500 MB
MAX_COMPRESSION_RATIO: float = 100.0
MIN_COMPRESSED_BYTES_FOR_RATIO_CHECK: int = 1024

# OOXML-Pfade die OLE-Embeddings enthalten (z. B. eingebettete.exe)
_OLE_EMBED_PREFIXES: tuple[str, ...] = (
    "word/embeddings/",
    "ppt/embeddings/",
    "xl/embeddings/",
)

# OOXML-Rels die externe Template-Verknuepfungen (attachedTemplate)
# enthalten — Remote-Template-Injection-Vektor.
_TEMPLATE_RELS: tuple[str, ...] = (
    "word/_rels/settings.xml.rels",
    "ppt/_rels/presentation.xml.rels",
)


class OfficeValidator(SubValidator):
    """Validierer fuer DOCX/DOCM/PPTX/PPTM/ODT."""

    def validate(self, path: Path, report: ValidationReport) -> None:
        """Fuehrt alle Office-Container-Checks aus."""
        try:
            self._check_zip_container(path, report)
        except (zipfile.BadZipFile, OSError) as exc:
            report.add(
                Threat(
                    code="OFFICE_SCAN_ERROR",
                    severity=Severity.MEDIUM,
                    message=(
                        "Office-Container konnte nicht gelesen werden — "
                        "Scan unvollstaendig."
                    ),
                    context={"error": type(exc).__name__},
                )
            )
            return

        self._check_vba(path, report)
        self._check_dde(path, report)

    # ------------------------------------------------------------------
    # ZIP-Container
    # ------------------------------------------------------------------

    def _check_zip_container(self, path: Path, report: ValidationReport) -> None:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            entry_count = len(infos)
            uncompressed_total = sum(i.file_size for i in infos)
            compressed_total = sum(i.compress_size for i in infos)

            if entry_count > MAX_ZIP_ENTRIES:
                report.add(
                    Threat(
                        code="OFFICE_ZIP_TOO_MANY_ENTRIES",
                        severity=Severity.HIGH,
                        message=(
                            f"Office-Container enthaelt {entry_count} Eintraege — "
                            f"ueber dem Schwellwert ({MAX_ZIP_ENTRIES})."
                        ),
                        context={"entries": entry_count},
                    )
                )
            if uncompressed_total > MAX_UNCOMPRESSED_BYTES:
                report.add(
                    Threat(
                        code="OFFICE_ZIP_BOMB_UNCOMPRESSED_SIZE",
                        severity=Severity.HIGH,
                        message=(
                            "Entpackte Container-Groesse uebersteigt 500 MB — "
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
                        code="OFFICE_ZIP_BOMB_RATIO",
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

            for info in infos:
                name = info.filename
                if any(name.startswith(p) for p in _OLE_EMBED_PREFIXES):
                    report.add(
                        Threat(
                            code="OFFICE_EMBEDDED_OLE",
                            severity=Severity.HIGH,
                            message=(
                                f"Eingebettetes OLE-Objekt in '{name}' — "
                                "moeglicherweise eine ausfuehrbare Datei."
                            ),
                            context={"path_in_zip": name},
                        )
                    )

            # Remote-Template-Injection
            for rel_path in _TEMPLATE_RELS:
                try:
                    raw = zf.read(rel_path).decode("utf-8", errors="ignore")
                except KeyError:
                    continue
                if 'TargetMode="External"' in raw and "attachedTemplate" in raw:
                    report.add(
                        Threat(
                            code="OFFICE_EXTERNAL_TEMPLATE",
                            severity=Severity.HIGH,
                            message=(
                                "Externe Template-Verknuepfung erkannt — "
                                "moeglicherweise Remote-Template-Injection."
                            ),
                            context={"rels": rel_path},
                        )
                    )

    # ------------------------------------------------------------------
    # VBA-Makros (oletools)
    # ------------------------------------------------------------------

    def _check_vba(self, path: Path, report: ValidationReport) -> None:
        """Sucht VBA-Makros via:mod:`oletools.olevba`."""
        try:
            from oletools.olevba import VBA_Parser  # noqa: PLC0415
        except ImportError:
            _log.debug("oletools nicht verfuegbar — VBA-Check uebersprungen")
            return

        try:
            parser = VBA_Parser(str(path))
        except Exception as exc:  # noqa: BLE001 -- olevba kann beliebige Fehler werfen
            _log.debug("olevba VBA_Parser fehlgeschlagen: %s", exc)
            return

        try:
            if parser.detect_vba_macros():
                report.add(
                    Threat(
                        code="OFFICE_VBA_MACRO",
                        severity=Severity.HIGH,
                        message=(
                            "VBA-Makros erkannt — Office-Dokumente mit Makros "
                            "sollten nur aus vertrauenswuerdigen Quellen geoeffnet "
                            "werden."
                        ),
                        context={},
                    )
                )
        finally:
            with _suppress_close_errors():
                parser.close()

    # ------------------------------------------------------------------
    # DDE-Links (oletools.msodde)
    # ------------------------------------------------------------------

    def _check_dde(self, path: Path, report: ValidationReport) -> None:
        """Sucht DDE-Links via:mod:`oletools.msodde`."""
        try:
            from oletools.msodde import process_file  # noqa: PLC0415
        except ImportError:
            return

        try:
            output = process_file(str(path))
        except Exception as exc:  # noqa: BLE001 -- msodde kann beliebige Fehler werfen
            _log.debug("msodde-Check fehlgeschlagen: %s", exc)
            return

        if output and "DDE" in str(output).upper():
            report.add(
                Threat(
                    code="OFFICE_DDE_LINK",
                    severity=Severity.CRITICAL,
                    message=(
                        "DDE-Link erkannt — Legacy-Feature zur Befehls-"
                        "ausfuehrung. Datei vor Oeffnen mit IT-Fachmann "
                        "klaeren."
                    ),
                    context={},
                )
            )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


class _suppress_close_errors:  # noqa: N801 — wir wollen den lower_case-Kontextmanager-Stil
    """Wie ``contextlib.suppress(Exception)``, aber explizit dokumentiert."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *_a) -> bool:  # noqa: ANN002
        return True
