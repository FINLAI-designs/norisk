"""
import_validator — Einheitliches Gate vor jedem Datei-Parser in FINLAI.

``validate_import(path, expected)`` prüft eine Benutzer-gelieferte Datei
**bevor** sie von einem Parser angefasst wird. Das Ergebnis ist ein
``ValidationReport`` mit Threat-Liste, Risk-Score und ``safe_to_parse``.

Layer-Modell:
  0. Basis: Existenz, ``Path.resolve``, Größenheuristik
  1. Magika-Typ-Check (Spoofing-Schutz)
  2. Format-spezifischer Sub-Validator (``core.security.sub_validators``)

Security-Control (unbedingt):
  Der Deep-Content-Scan (Layer 2) läuft für JEDE Datei und ist an KEIN
  Lizenz-/Feature-Flag gekoppelt. Früher gated ein
  ``has_feature(FEATURE_FILE_CONTENT_VALIDATION)`` diesen Layer
  (Degraded-Mode mit INFO-Threat ``LICENSE_DEGRADED_MODE``); seit entfernt — der stärkste Import-Schutz einer Security-App darf
  nicht an einem kommerziellen Lizenz-Stub hängen.

Sicherheitsdesign:
  - Wirft keine Exception für Threats — meldet sie im Report.
  - Wirft ``FileNotFoundError`` / ``PermissionError`` nur für
    System-Fehler, die vor jeder Prüfung eintreten (Pfad invalid).
  - Kein Logging sensibler Inhalte (Dateinamen, Kontexte bleiben im
    Report, nicht im Log).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from core.exceptions import ValidationError
from core.logger import get_logger
from core.security.magika_adapter import identify, is_compatible
from core.security.sub_validators import get_sub_validator
from core.security.validation_report import (
    ImportType,
    Severity,
    Threat,
    ValidationReport,
)

_log = get_logger(__name__)


def validate_import(
    path: str | Path,
    expected: ImportType,
    *,
    json_schema: dict[str, Any] | None = None,
    deep_scan: bool = False,
) -> ValidationReport:
    """Zentrales Gate: Prüft eine Datei auf Typ-Spoofing und Format-Angriffe.

    Ablauf:
      1. Pfad auflösen (Path-Traversal schon hier sichtbar).
      2. Datei existiert? Sonst ``FileNotFoundError``.
      3. Magika-Identifikation — bestimmt ``detected_label``,
         ``detected_mime``, ``type_match``.
      4. Bei Type-Mismatch: CRITICAL-Threat hinzufügen.
      5. Sub-Validator ausführen (Deep-Content-Scan — unbedingt, kein
         Lizenz-Gate).
      6. Dauer messen und im Report vermerken.

    Args:
        path: Pfad zur Datei (String oder ``Path``).
        expected: Deklarierter Datei-Typ. ``ImportType.UNKNOWN`` erlaubt
            jeden Magika-Typ und läuft in den GenericValidator.
        json_schema: Optionales JSON-Schema. Wird nur bei
            ``ImportType.JSON`` / ``JSONL`` ausgewertet und an den
            JsonValidator durchgereicht.
        deep_scan: Aktiviert zusätzliche Tiefen-Analyse (aktuell nur für
            ``ImportType.PDF``: JavaScript, OpenAction, Launch,
            EmbeddedFile über ``core.security.pdf_deep_scanner``).

    Returns:
        ``ValidationReport`` mit Threats, Risk-Score, safe_to_parse.

    Raises:
        FileNotFoundError: Wenn die Datei nicht existiert.
        ValueError: Bei Path-Traversal-Indikatoren (``..`` im Pfad).
    """
    t0 = time.perf_counter()

    raw = Path(path)
    if ".." in raw.parts:
        # Path-Traversal-Vorzeichen — bricht sofort ab (keine Report-Rückgabe,
        # das ist ein programmatischer Fehler des Aufrufers).
        raise ValidationError(
            f"Path-Traversal erkannt: '..' nicht erlaubt in Pfad {str(path)!r}."
        )

    resolved = raw.resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Datei nicht gefunden: {resolved}")
    if not resolved.is_file():
        raise FileNotFoundError(f"Pfad ist keine Datei: {resolved}")

    report = ValidationReport(path=resolved, declared_type=expected)

    # Layer 1 — Magika-Typ-Check
    ident = identify(resolved)
    report.detected_label = ident.label
    report.detected_mime = ident.mime_type
    report.type_match = is_compatible(ident.label, expected)

    if not report.type_match:
        # Bei Täuschung: besonders harte Bewertung wenn das erkannte Label
        # ausführbaren Code enthält.
        if ident.is_dangerous:
            report.add(
                Threat(
                    code="TYPE_SPOOFING_DANGEROUS",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Datei tarnt sich als {expected.value.upper()}, ist aber "
                        f"ausführbarer Code ('{ident.label}')."
                    ),
                    context={
                        "declared_type": expected.value,
                        "detected_label": ident.label,
                        "mime_type": ident.mime_type,
                    },
                )
            )
        else:
            report.add(
                Threat(
                    code="TYPE_MISMATCH",
                    severity=Severity.HIGH,
                    message=(
                        f"Datei-Inhalt passt nicht zum erwarteten Typ "
                        f"{expected.value.upper()} — Magika erkannte "
                        f"'{ident.label}'."
                    ),
                    context={
                        "declared_type": expected.value,
                        "detected_label": ident.label,
                    },
                )
            )

    # Layer 2 — Format-spezifischer Sub-Validator (Deep-Content-Scan).
    #
    # Unbedingte Security-Control: läuft für JEDE Datei, an KEIN Lizenz-/
    # Feature-Flag gekoppelt. Früher stand hier ein
    # ``has_feature(FEATURE_FILE_CONTENT_VALIDATION)``-Gate, das ohne Lizenz
    # nur einen INFO-Threat ``LICENSE_DEGRADED_MODE`` setzte und den Scan
    # übersprang. Mit entfernt — der stärkste Import-Schutz
    # einer Security-App darf nicht an einem kommerziellen Lizenz-Stub hängen.
    # Regression: tests/security/test_license_degraded_mode.py ("deep scan immer an").
    try:
        sub = get_sub_validator(expected)
        # JsonValidator akzeptiert optional ein Schema. Wir rufen generisch
        # auf und reichen das Schema per Keyword-Argument durch — dank
        # **kwargs-Kompatibilität in Python landet es nur dann in der
        # Signatur, wenn der Validator es akzeptiert.
        if json_schema is not None and expected in (
            ImportType.JSON,
            ImportType.JSONL,
        ):
            sub.validate(resolved, report, schema=json_schema)  # type: ignore[call-arg]
        elif deep_scan and expected == ImportType.PDF:
            sub.validate(resolved, report, deep_scan=True)  # type: ignore[call-arg]
        else:
            sub.validate(resolved, report)
    except Exception as exc:  # noqa: BLE001 -- Sub-Validator-Bugs (third-party Lib-Errors) sollen den Import-Workflow nie crashen lassen
        _log.error(
            "Sub-Validator-Fehler (%s): %s",
            type(sub).__name__ if "sub" in locals() else "?",
            exc,
        )
        report.add(
            Threat(
                code="SUB_VALIDATOR_ERROR",
                severity=Severity.MEDIUM,
                message="Interner Fehler im Format-Validator — Scan unvollständig.",
                context={"error": type(exc).__name__},
            )
        )

    # Layer 3 — YARA-Pattern-Scan (typ-agnostisch)..
    # JSON/JSONL ueberspringen: strukturierte Daten ohne menschlesbare
    # Phishing-/Loader-Patterns. Der einmalige Regel-Compile kostet
    # spuerbar und macht hier keinen Sinn.
    if expected not in (ImportType.JSON, ImportType.JSONL):
        _run_yara_layer(resolved, report)

    _finalize(report, t0)
    return report


def _run_yara_layer(path: Path, report: ValidationReport) -> None:
    """Fuehrt den YARA-Pattern-Scan aus und mappt Matches auf Threats.

    Severity ergibt sich aus dem ``meta.severity``-Feld der Regel
    (critical/high/medium/low/info). Fehlendes Feld → MEDIUM.

    Wenn YARA-Lib oder Regeln nicht verfuegbar sind, wird nichts
    gemeldet — eine INFO-Threat haengen wir nicht an, weil das fuer
    jeden Validate-Aufruf Rauschen waere. Stattdessen entscheidet
    der Aufrufer (z. B. Document Scanner) ob er das prominent
    kommuniziert.
    """
    from core.security.yara_runner import is_available, scan_path  # noqa: PLC0415

    if not is_available():
        return

    matches = scan_path(path)
    if not matches:
        return

    for m in matches:
        sev_str = m.meta.get("severity", "medium").lower()
        try:
            severity = Severity[sev_str.upper()]
        except KeyError:
            severity = Severity.MEDIUM
        family = m.meta.get("family", "")
        description = m.meta.get("description", "YARA-Regel-Treffer")
        report.add(
            Threat(
                code=f"YARA_{m.rule}",
                severity=severity,
                message=description,
                context={
                    "rule": m.rule,
                    "family": family,
                    "strings_matched": m.strings_count,
                },
            )
        )


def _finalize(report: ValidationReport, t0: float) -> None:
    """Setzt Dauer und loggt Kurzergebnis (ohne sensible Daten)."""
    report.duration_ms = (time.perf_counter() - t0) * 1000.0
    _log.info(
        "Import-Validierung: %s | Typ=%s, Score=%d, Threats=%d, safe=%s, %.1f ms",
        report.path.name,
        report.declared_type.value,
        report.risk_score,
        len(report.threats),
        report.safe_to_parse,
        report.duration_ms,
    )
