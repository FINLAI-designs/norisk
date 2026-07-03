"""
json_validator — Validierung von JSON und JSONL.

Erkannte Angriffe:
  - **Tiefen-DoS**: Verschachtelte Strukturen > 100 Ebenen erschöpfen den
    rekursiven Parser. → HIGH.
  - **Größen-DoS**: Datei > 50 MB. → HIGH.
  - **Schema-Drift**: Wenn ein Schema übergeben wird, werden Verstöße
    als MEDIUM-Threats gemeldet.
  - **Zahlen-Overflows**: Integer > 2^53 (JS-Float-Limit) oder Float-
    Exponenten > 308 (double-max) → LOW.

Der Parser ist **streaming** (``ijson``), damit auch große Dateien ohne
Vollspeicherung geprüft werden.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import ijson

from core.security.magika_adapter import identify
from core.security.sub_validators.base import SubValidator
from core.security.validation_report import Severity, Threat, ValidationReport

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

# Hart-Limit für unkomprimierte JSON-Dateien
MAX_JSON_SIZE_BYTES: int = 50 * 1024 * 1024

# Tiefen-Limit — aus Erfahrung der Praxis. FinanzOnline / CSAF kommt auf
# maximal ~15 Ebenen; Werte > 100 sind immer Angriffs-Indikatoren.
MAX_JSON_DEPTH: int = 100

# Zahlen-Grenzen
MAX_SAFE_INTEGER: int = 2**53  # JavaScript Number.MAX_SAFE_INTEGER
MAX_FLOAT_EXPONENT: int = 308  # IEEE-754 double-Obergrenze

# Stichprobengrenze: Bei Schema-Verstößen nur max. 5 Fundstellen loggen
MAX_VIOLATIONS_REPORTED: int = 5


class JsonValidator(SubValidator):
    """Validierer für JSON / JSONL mit Streaming-basierter Tiefen-Analyse."""

    def validate(
        self,
        path: Path,
        report: ValidationReport,
        *,
        schema: dict[str, Any] | None = None,
    ) -> None:
        """Prüft JSON/JSONL auf Größe, Tiefe, Zahlen-Overflows, optional Schema.

        Args:
            path: Zu prüfender Pfad.
            report: Report zum Anhängen.
            schema: Optionales JSON-Schema — wenn gesetzt, wird eine
                Strikt-Validierung ausgeführt.
        """
        size = path.stat().st_size
        if size > MAX_JSON_SIZE_BYTES:
            report.add(
                Threat(
                    code="JSON_FILE_TOO_LARGE",
                    severity=Severity.HIGH,
                    message=(
                        f"JSON-Datei zu groß ({size // (1024 * 1024)} MB). "
                        f"Limit: {MAX_JSON_SIZE_BYTES // (1024 * 1024)} MB."
                    ),
                    context={"size_bytes": size},
                )
            )
            return

        # Magika-Check — getarnter Binärinhalt wird hier abgefangen.
        ident = identify(path)
        # Magika hat keine Extra-Klasse "jsonl" — Label "json" oder "txt"
        # sind beide akzeptabel für JSONL.
        if ident.label not in ("json", "jsonl", "txt") and not ident.is_text:
            report.add(
                Threat(
                    code="JSON_CONTENT_MISMATCH",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Inhalt ist kein JSON/Text — erkannt als '{ident.label}'."
                    ),
                    context={"detected_label": ident.label},
                )
            )
            return

        self._scan_depth_and_numbers(path, report)

        if schema is not None:
            self._validate_schema(path, report, schema)

    def _scan_depth_and_numbers(self, path: Path, report: ValidationReport) -> None:
        """Durchläuft JSON-Events via ijson und prüft Tiefe + Zahlen-Grenzen.

        Args:
            path: Zu prüfender Pfad.
            report: Report zum Anhängen.
        """
        depth = 0
        max_depth_seen = 0
        numeric_violations = 0

        try:
            with path.open("rb") as fh:
                for _prefix, event, value in ijson.parse(fh):
                    if event in ("start_map", "start_array"):
                        depth += 1
                        if depth > max_depth_seen:
                            max_depth_seen = depth
                        if depth > MAX_JSON_DEPTH:
                            report.add(
                                Threat(
                                    code="JSON_DEPTH_EXCEEDED",
                                    severity=Severity.HIGH,
                                    message=(
                                        f"JSON-Verschachtelung > {MAX_JSON_DEPTH} Ebenen "
                                        "— Parser-DoS-Risiko."
                                    ),
                                    context={"max_depth": max_depth_seen},
                                )
                            )
                            return  # Abbruch — weiteres Parsen bringt nichts
                    elif event in ("end_map", "end_array"):
                        depth -= 1
                    elif event == "number" and isinstance(value, int):
                        if abs(value) > MAX_SAFE_INTEGER:
                            numeric_violations += 1
                    elif event == "number" and isinstance(value, float):
                        if value != 0 and abs(value) > 10**MAX_FLOAT_EXPONENT:
                            numeric_violations += 1
        except ijson.JSONError as exc:
            report.add(
                Threat(
                    code="JSON_PARSE_ERROR",
                    severity=Severity.HIGH,
                    message=f"JSON nicht parsbar: {exc}",
                )
            )
            return
        except OSError as exc:
            report.add(
                Threat(
                    code="JSON_SCAN_ERROR",
                    severity=Severity.MEDIUM,
                    message=f"Datei konnte nicht gelesen werden: {exc}",
                )
            )
            return

        if numeric_violations:
            report.add(
                Threat(
                    code="JSON_NUMERIC_OVERFLOW",
                    severity=Severity.LOW,
                    message=(
                        f"{numeric_violations} Zahl(en) außerhalb des sicheren "
                        "IEEE-754 / JS-Integer-Bereichs erkannt."
                    ),
                    context={"count": numeric_violations},
                )
            )

    def _validate_schema(
        self,
        path: Path,
        report: ValidationReport,
        schema: dict[str, Any],
    ) -> None:
        """Validiert die Datei gegen ein JSON-Schema.

        Benutzt ``jsonschema.Draft202012Validator`` für stabile semver-
        Kompatibilität.

        Args:
            path: Zu prüfender Pfad.
            report: Report zum Anhängen.
            schema: JSON-Schema-Dokument.
        """
        import json  # noqa: PLC0415

        from jsonschema import Draft202012Validator  # noqa: PLC0415
        from jsonschema.exceptions import SchemaError  # noqa: PLC0415

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            report.add(
                Threat(
                    code="JSON_SCHEMA_READ_ERROR",
                    severity=Severity.MEDIUM,
                    message=f"JSON für Schema-Prüfung nicht lesbar: {exc}",
                )
            )
            return

        try:
            Draft202012Validator.check_schema(schema)
            validator = Draft202012Validator(schema)
        except SchemaError as exc:
            report.add(
                Threat(
                    code="JSON_SCHEMA_INVALID",
                    severity=Severity.MEDIUM,
                    message=f"Übergebenes JSON-Schema ist ungültig: {exc.message}",
                )
            )
            return

        violations = 0
        try:
            error_iter = list(validator.iter_errors(data))
        except Exception as exc:  # noqa: BLE001 — jsonschema UnknownType etc.
            report.add(
                Threat(
                    code="JSON_SCHEMA_INVALID",
                    severity=Severity.MEDIUM,
                    message=f"Schema-Validierung fehlgeschlagen: {exc}",
                )
            )
            return

        for err in error_iter:
            if violations < MAX_VIOLATIONS_REPORTED:
                report.add(
                    Threat(
                        code="JSON_SCHEMA_VIOLATION",
                        severity=Severity.MEDIUM,
                        message=(
                            f"Schema-Verstoß bei '{'/'.join(str(p) for p in err.path)}': "
                            f"{err.message}"
                        ),
                        context={
                            "path": list(err.path),
                            "validator": err.validator,
                        },
                    )
                )
            violations += 1

        if violations > MAX_VIOLATIONS_REPORTED:
            report.add(
                Threat(
                    code="JSON_SCHEMA_VIOLATION_OVERFLOW",
                    severity=Severity.MEDIUM,
                    message=(
                        f"{violations - MAX_VIOLATIONS_REPORTED} weitere "
                        "Schema-Verstöße unterdrückt."
                    ),
                    context={"total_violations": violations},
                )
            )
