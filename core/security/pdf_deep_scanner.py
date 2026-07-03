"""
pdf_deep_scanner — Tiefen-Scan für PDF-Objekt-Strukturen.

Dies ist die wiederverwendbare Engine hinter dem kommenden NoRisk-Tool
``pdf_risk_scanner`` (Prompt 2). Sie liest die PDF-Objekt-Grafik via
``pypdf`` und meldet aktive Inhalte, die in Phishing- und Malware-PDFs
üblich sind:

================== ========= =========================================
Fund Severity Begründung
================== ========= =========================================
/OpenAction / /AA HIGH Läuft ohne Benutzerinteraktion beim Öffnen
/JS, /JavaScript HIGH JavaScript-Engine des Readers — Exploit-Pfad
/Launch CRITICAL Startet externe Programme
/EmbeddedFile MEDIUM Angehängte Dateien (Office/ZIP/EXE)
/URI LOW URLs — in Kombination mit Auto-Action HIGH
/XFA MEDIUM XML-Forms — klassischer Adobe-Angriffsvektor
Encrypted MEDIUM Statischer Scan eingeschränkt
================== ========= =========================================

Der Scanner öffnet das PDF nur **lesend** und mit ``strict=False``, damit
bewusst fehlerhafte PDFs (Typ-Konfusion) nicht zum Crash führen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.logger import get_logger
from core.security.validation_report import Severity, Threat, ValidationReport

_log = get_logger(__name__)

# Schlüssel, die im Katalog-Dictionary Auto-Aktionen anstoßen.
_AUTO_ACTION_KEYS: frozenset[str] = frozenset({"/OpenAction", "/AA"})

# JavaScript-Indikatoren in Action-Objekten.
_JS_KEYS: frozenset[str] = frozenset({"/JS", "/JavaScript"})

# Action-Subtypen, die externen Code ausführen.
_LAUNCH_ACTION: str = "/Launch"

# Embedded-File-Indikatoren im Dokument-Katalog.
_EMBEDDED_FILE_KEYS: frozenset[str] = frozenset(
    {"/EmbeddedFile", "/EmbeddedFiles", "/Filespec"}
)

# XFA-Forms — historisch ein sehr reichhaltiger Adobe-Angriffsvektor.
_XFA_KEY: str = "/XFA"

# Obergrenze an Indirect-Objects, die gescannt werden (DoS-Schutz).
MAX_OBJECTS_SCANNED: int = 50_000


def _deep_scan_incomplete(phase: str, exc: Exception | None = None) -> Threat:
    """Markiert einen abgebrochenen Teil-Scan als unvollständige Inspektion.

    Fail-Closed: Bricht der Objektgraph-Walk (Katalog oder xref) ab,
    lief die Deep-Inspektion faktisch nicht — der Code ``PDF_DEEP_SCAN_ERROR``
    greift in:meth:`ValidationReport.scan_incomplete` und der Status fällt auf
    WARN statt fälschlich auf „sicher". Ohne diesen Marker würde ein PDF, das
    pypdf zwar öffnet, dessen Objektgraph aber unlesbar ist (während tolerante
    Reader es ausführen), als „sicher" durchgehen.

    Args:
        phase: Welcher Teil-Scan abbrach (z.B. ``"catalog"`` / ``"xref"``).
        exc: Optionale auslösende Ausnahme (nur der Typname wird vermerkt).

    Returns:
        Eine MEDIUM-``Threat`` mit Code ``PDF_DEEP_SCAN_ERROR``.
    """
    context: dict[str, Any] = {"phase": phase}
    if exc is not None:
        context["error"] = type(exc).__name__
    return Threat(
        code="PDF_DEEP_SCAN_ERROR",
        severity=Severity.MEDIUM,
        message=(
            f"PDF-Objektgraph konnte nicht vollständig gelesen werden ({phase}) — "
            "Inspektion unvollständig."
        ),
        context=context,
    )


def deep_scan_pdf(path: Path, report: ValidationReport) -> None:
    """Führt den PDF-Deep-Scan aus und hängt Funde an den Report.

    Args:
        path: Pfad einer bereits strukturell geprüften PDF-Datei.
        report: Report, an dem neue Threats angehängt werden.
    """
    try:
        import pypdf  # noqa: PLC0415
        from pypdf.errors import PdfReadError, PyPdfError  # noqa: PLC0415
    except ImportError as exc:
        _log.warning("pypdf nicht verfügbar — Deep-Scan übersprungen: %s", exc)
        report.add(
            Threat(
                code="PDF_DEEP_SCAN_UNAVAILABLE",
                severity=Severity.INFO,
                message="pypdf ist nicht installiert; Deep-Scan übersprungen.",
            )
        )
        return

    try:
        reader = pypdf.PdfReader(str(path), strict=False)
    except (PdfReadError, PyPdfError, OSError, ValueError) as exc:
        report.add(
            Threat(
                code="PDF_DEEP_SCAN_ERROR",
                severity=Severity.MEDIUM,
                message=f"PDF konnte nicht für Deep-Scan geöffnet werden: {exc}",
                context={"error": type(exc).__name__},
            )
        )
        return

    if getattr(reader, "is_encrypted", False):
        report.add(
            Threat(
                code="PDF_ENCRYPTED",
                severity=Severity.MEDIUM,
                message=(
                    "PDF ist verschlüsselt — statische Analyse eingeschränkt. "
                    "Aktive Inhalte können verborgen bleiben."
                ),
            )
        )
        # Ohne Passwort kein Objekt-Walk möglich — hier enden.
        return

    _scan_catalog(reader, report)
    _scan_objects(reader, report)


def _scan_catalog(reader: Any, report: ValidationReport) -> None:
    """Prüft den Root-Katalog auf Auto-Actions, URIs und EmbeddedFiles.

    Args:
        reader: Offenes ``pypdf.PdfReader``-Objekt.
        report: Report zum Anhängen.
    """
    try:
        root = reader.trailer.get("/Root", {})
        if hasattr(root, "get_object"):
            root = root.get_object()
        if not isinstance(root, dict):
            # /Root vorhanden, aber nicht auflösbar -> Katalog-Checks (Auto-
            # Action/XFA/EmbeddedFile) liefen nicht -> fail-closed.
            report.add(_deep_scan_incomplete("catalog"))
            return
    except Exception as exc:  # noqa: BLE001 — pypdf hat viele interne Fehler
        _log.debug("Katalog nicht lesbar: %s", exc)
        report.add(_deep_scan_incomplete("catalog", exc))
        return

    for key in _AUTO_ACTION_KEYS:
        if key in root:
            report.add(
                Threat(
                    code="PDF_AUTO_ACTION",
                    severity=Severity.HIGH,
                    message=(
                        f"Katalog enthält '{key}' — wird beim Öffnen ohne "
                        "Benutzerinteraktion ausgeführt."
                    ),
                    context={"catalog_key": key},
                )
            )

    names = root.get("/Names")
    if hasattr(names, "get_object"):
        names = names.get_object()
    if isinstance(names, dict):
        for key in _EMBEDDED_FILE_KEYS:
            if key in names:
                report.add(
                    Threat(
                        code="PDF_EMBEDDED_FILE",
                        severity=Severity.MEDIUM,
                        message=(
                            f"Dokument enthält angehängte Dateien ('{key}') — "
                            "beliebter Träger für Office-Malware."
                        ),
                        context={"names_key": key},
                    )
                )

    if _XFA_KEY in root or _xfa_in_acroform(root):
        report.add(
            Threat(
                code="PDF_XFA_FORM",
                severity=Severity.MEDIUM,
                message=(
                    "XFA-Forms erkannt — historisch ausgenutzter Adobe-Angriffsvektor."
                ),
            )
        )


def _xfa_in_acroform(root: dict[Any, Any]) -> bool:
    """Prüft, ob ``/AcroForm`` ein ``/XFA``-Feld enthält.

    Args:
        root: Bereits aufgelöstes Katalog-Dictionary.

    Returns:
        True, wenn XFA vorhanden ist.
    """
    acroform = root.get("/AcroForm")
    if hasattr(acroform, "get_object"):
        acroform = acroform.get_object()
    return isinstance(acroform, dict) and _XFA_KEY in acroform


def _scan_objects(reader: Any, report: ValidationReport) -> None:
    """Durchläuft Indirect-Objects und sucht nach aktiven Inhalten.

    Es werden bis zu ``MAX_OBJECTS_SCANNED`` Objekte gelesen, um DoS
    durch absichtlich aufgeblähte PDFs zu verhindern.

    Args:
        reader: Offenes ``pypdf.PdfReader``-Objekt.
        report: Report zum Anhängen.
    """
    from pypdf.generic import IndirectObject  # noqa: PLC0415

    js_found = False
    launch_found = False
    uri_count = 0

    try:
        # reader.xref ist {generation: {idnum: offset}} in pypdf 6.x
        idnums: list[tuple[int, int]] = [
            (idnum, gen)
            for gen, entries in reader.xref.items()
            for idnum in entries
            if idnum != 0
        ][:MAX_OBJECTS_SCANNED]
    except Exception as exc:  # noqa: BLE001 -- pypdf xref-Lookup kann unspezifizierte Errors werfen
        _log.debug("xref-Tabelle nicht lesbar: %s", exc)
        # Objekt-Walk (JS/Launch/URI) lief nicht -> fail-closed.
        report.add(_deep_scan_incomplete("xref", exc))
        return

    for idnum, gen in idnums:
        try:
            obj = IndirectObject(idnum, gen, reader).get_object()
        except Exception:  # noqa: BLE001 — PDF-Parsing ist fehleranfällig
            continue
        if not isinstance(obj, dict):
            continue

        if any(k in obj for k in _JS_KEYS):
            js_found = True
        if obj.get("/S") == _LAUNCH_ACTION:
            launch_found = True
        if "/URI" in obj:
            uri_count += 1

    if js_found:
        report.add(
            Threat(
                code="PDF_JAVASCRIPT",
                severity=Severity.HIGH,
                message=(
                    "PDF enthält JavaScript — häufiger Exploit-Pfad "
                    "(Reader-Schwachstellen, Social-Engineering)."
                ),
            )
        )

    if launch_found:
        report.add(
            Threat(
                code="PDF_LAUNCH_ACTION",
                severity=Severity.CRITICAL,
                message=(
                    "PDF enthält Launch-Action — startet externe Programme "
                    "beim Klick (Code-Execution-Risiko)."
                ),
            )
        )

    if uri_count > 0:
        report.add(
            Threat(
                code="PDF_URI_ACTIONS",
                severity=Severity.LOW,
                message=f"{uri_count} URI-Action(s) im Dokument — externe Links.",
                context={"count": uri_count},
            )
        )
