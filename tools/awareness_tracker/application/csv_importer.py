"""
csv_importer — Bulk-Import fuer Mitarbeiter + Schulungen aus CSV.

Erwartet UTF-8-encoded CSV-Dateien mit Komma-Trennung und Header-Zeile.
Zwei separate Formate, eines pro Entitaet:

**Mitarbeiter-CSV** (Header):
    ``full_name,email,role,department,is_active,notes``

**Schulungen-CSV** (Header):
    ``employee_full_name,training_type,title,completed_at,valid_until,provider,custom_type_label,notes``

Beim Trainings-Import wird ``employee_full_name`` auf existierende Mitarbeiter
gematcht (case-insensitive). Unbekannte Mitarbeiter erscheinen in
``ImportResult.errors`` und werden nicht angelegt — Patrick-Direktive:
**erst Mitarbeiter, dann Schulungen** (keine Magic-Anlage waehrend des
Schulungs-Imports).

Sicherheits-Notes:
- ``csv.reader`` ist gegen CSV-Formula-Injection nicht geschuetzt — wir
  schreiben die Werte aber nicht in eine Excel-Datei zurueck, sondern in
  unsere DB. Stored-XSS-Aequivalente sind in unserer PySide6-GUI nicht
  moeglich (kein HTML-Rendering von DB-Werten).
- Maximale Zeilen-Anzahl: 10 000 (MAX_ROWS). Verhindert DOS via riesiger
  CSVs.

Schichtzugehoerigkeit: application/ — darf domain/ + data/ + core/
importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import UTC, datetime

from tools.awareness_tracker.application.awareness_service import (
    AwarenessService,
)
from tools.awareness_tracker.domain.models import (
    Employee,
    Training,
    TrainingType,
)

MAX_ROWS: int = 10_000

EMPLOYEE_HEADER: tuple[str, ...] = (
    "full_name",
    "email",
    "role",
    "department",
    "is_active",
    "notes",
)

TRAINING_HEADER: tuple[str, ...] = (
    "employee_full_name",
    "training_type",
    "title",
    "completed_at",
    "valid_until",
    "provider",
    "custom_type_label",
    "notes",
)


@dataclass(frozen=True)
class ImportResult:
    """Ergebnis eines Bulk-Imports.

    Attributes:
        added_count: Anzahl erfolgreich angelegter Entitaeten.
        skipped_count: Anzahl wegen Duplikat uebersprungener Zeilen.
        errors: Liste von ``(zeilennummer, grund)``-Tuples fuer
                        Zeilen, die nicht angelegt werden konnten.
        warnings: Liste von Hinweisen ohne Fehler (z. B. leere Notiz).
    """

    added_count: int = 0
    skipped_count: int = 0
    errors: list[tuple[int, str]] = field(default_factory=list)
    warnings: list[tuple[int, str]] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """``True`` wenn mindestens ein Datensatz angelegt + keine Errors."""
        return self.added_count > 0 and not self.errors


# ---------------------------------------------------------------------------
# Employee-Import
# ---------------------------------------------------------------------------


def import_employees_from_csv(
    csv_text: str,
    service: AwarenessService,
) -> ImportResult:
    """Importiert Mitarbeiter aus einem CSV-String.

    Dedup-Strategie: gleicher ``full_name`` (case-insensitive) wird
    uebersprungen, nicht ueberschrieben — der User soll Stammdaten bewusst
    via Edit-Dialog aendern.

    Args:
        csv_text: CSV-Inhalt als String (UTF-8 bereits dekodiert).
        service::class:`AwarenessService` fuer Persistierung + Lookup.

    Returns:
:class:`ImportResult` mit Zahlen + Diagnose pro Zeile.
    """
    added = 0
    skipped = 0
    errors: list[tuple[int, str]] = []
    warnings: list[tuple[int, str]] = []

    existing = {e.full_name.lower(): e for e in service.list_employees()}

    rows = _parse_with_header(csv_text, EMPLOYEE_HEADER)
    if isinstance(rows, str):
        # Header-Fehler — kein Row-Result, sondern eine Fehler-Message.
        return ImportResult(errors=[(1, rows)])

    for line_no, row in rows:
        full_name = row.get("full_name", "").strip()
        if not full_name:
            errors.append((line_no, "full_name fehlt"))
            continue
        if full_name.lower() in existing:
            skipped += 1
            warnings.append(
                (line_no, f"Mitarbeiter '{full_name}' existiert bereits.")
            )
            continue
        try:
            new_employee = service.add_employee(
                full_name=full_name,
                email=row.get("email", ""),
                role=row.get("role", ""),
                department=row.get("department", ""),
                is_active=_parse_bool(row.get("is_active", "true")),
                notes=row.get("notes", ""),
            )
        except ValueError as exc:
            errors.append((line_no, str(exc)))
            continue
        existing[new_employee.full_name.lower()] = new_employee
        added += 1

    return ImportResult(
        added_count=added,
        skipped_count=skipped,
        errors=errors,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Training-Import
# ---------------------------------------------------------------------------


def import_trainings_from_csv(
    csv_text: str,
    service: AwarenessService,
) -> ImportResult:
    """Importiert Schulungen aus einem CSV-String.

    ``employee_full_name`` wird gegen die existierende Mitarbeiter-Liste
    case-insensitive matched. Unbekannte Mitarbeiter sind Fehler — wir
    legen NICHT automatisch neue an (Patrick-Direktive: erst Mitarbeiter,
    dann Schulungen).

    Args:
        csv_text: CSV-Inhalt als String (UTF-8 bereits dekodiert).
        service::class:`AwarenessService`.

    Returns:
:class:`ImportResult` mit Zahlen + Diagnose pro Zeile.
    """
    added = 0
    skipped = 0
    errors: list[tuple[int, str]] = []
    warnings: list[tuple[int, str]] = []

    name_to_id = {
        e.full_name.lower(): e.id
        for e in service.list_employees()
        if e.id is not None
    }
    # Existing trainings je Mitarbeiter — Dedup-Schluessel ist
    # ``(employee_id, title.lower, completed_at.isoformat)``.
    existing_keys: set[tuple[int, str, str]] = set()
    for training in service.list_trainings():
        existing_keys.add(
            (
                training.employee_id,
                training.title.lower(),
                training.completed_at.isoformat(),
            )
        )

    rows = _parse_with_header(csv_text, TRAINING_HEADER)
    if isinstance(rows, str):
        return ImportResult(errors=[(1, rows)])

    for line_no, row in rows:
        emp_name = row.get("employee_full_name", "").strip()
        if not emp_name:
            errors.append((line_no, "employee_full_name fehlt"))
            continue
        employee_id = name_to_id.get(emp_name.lower())
        if employee_id is None:
            errors.append(
                (line_no, f"Mitarbeiter '{emp_name}' ist nicht angelegt.")
            )
            continue
        try:
            training_type = TrainingType.from_value(
                row.get("training_type", "").strip()
            )
        except (TypeError, AttributeError):
            errors.append((line_no, "training_type kann nicht geparst werden"))
            continue
        title = row.get("title", "").strip()
        if not title:
            errors.append((line_no, "title fehlt"))
            continue
        completed_at = _parse_dt(row.get("completed_at", ""))
        if completed_at is None:
            errors.append(
                (line_no, "completed_at ist kein gueltiger ISO-Timestamp")
            )
            continue
        valid_until = _parse_dt(row.get("valid_until", ""))
        # Dedup-Check.
        dedup_key = (employee_id, title.lower(), completed_at.isoformat())
        if dedup_key in existing_keys:
            skipped += 1
            warnings.append(
                (
                    line_no,
                    f"Schulung '{title}' fuer '{emp_name}' am "
                    f"{completed_at.date()} existiert bereits.",
                )
            )
            continue
        try:
            service.add_training(
                employee_id=employee_id,
                training_type=training_type,
                title=title,
                completed_at=completed_at,
                valid_until=valid_until,
                provider=row.get("provider", ""),
                custom_type_label=row.get("custom_type_label", ""),
                notes=row.get("notes", ""),
            )
        except ValueError as exc:
            errors.append((line_no, str(exc)))
            continue
        existing_keys.add(dedup_key)
        added += 1

    return ImportResult(
        added_count=added,
        skipped_count=skipped,
        errors=errors,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Parser-Helper
# ---------------------------------------------------------------------------


def _parse_with_header(
    csv_text: str,
    expected_header: tuple[str, ...],
) -> list[tuple[int, dict[str, str]]] | str:
    """Liest CSV-Text + Header-Validierung, liefert ``(zeile, dict)`` oder Fehler-String."""
    if not csv_text.strip():
        return "CSV ist leer."
    reader = csv.DictReader(io.StringIO(csv_text))
    if not reader.fieldnames:
        return "CSV hat keinen Header."
    header_set = {name.strip().lower() for name in reader.fieldnames}
    missing = [h for h in expected_header if h not in header_set]
    if missing:
        return (
            "CSV-Header passt nicht. Fehlend: " + ", ".join(missing) + "."
        )

    rows: list[tuple[int, dict[str, str]]] = []
    for offset, raw_row in enumerate(reader, start=2):  # Zeile 1 = Header
        if offset > MAX_ROWS + 1:
            rows.append(
                (offset, {"__error__": f"Mehr als {MAX_ROWS} Zeilen — Rest wird ignoriert."})
            )
            break
        # Normalisiere Keys auf lowercase + strip.
        norm = {
            (k.strip().lower() if isinstance(k, str) else k): (
                v.strip() if isinstance(v, str) else ""
            )
            for k, v in raw_row.items()
            if k is not None
        }
        rows.append((offset, norm))
    return rows


def _parse_bool(value: str) -> bool:
    cleaned = value.strip().lower()
    return cleaned in {"1", "true", "yes", "ja", "y", "x", "wahr"}


def _parse_dt(value: str) -> datetime | None:
    cleaned = (value or "").strip()
    if not cleaned:
        return None
    # Akzeptiere YYYY-MM-DD (Date-only) und volle ISO-Stamps.
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    # Fallback: fromisoformat (Python 3.11+) versteht viele Varianten.
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


# Re-Export der Domain-Klassen damit Test-Module nicht doppelt importieren muessen.
__all__ = [
    "EMPLOYEE_HEADER",
    "Employee",
    "ImportResult",
    "MAX_ROWS",
    "TRAINING_HEADER",
    "Training",
    "TrainingType",
    "import_employees_from_csv",
    "import_trainings_from_csv",
]
