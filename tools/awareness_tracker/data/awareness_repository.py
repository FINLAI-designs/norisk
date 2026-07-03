"""
awareness_repository — EncryptedDatabase-Repository fuer Mitarbeiter +
Schulungen.

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren, keine
application/gui-Importe.

Schema-Version 1: Zwei Tabellen
- ``employees``: Mitarbeiter-Stamm.
- ``trainings``: Absolvierte Schulungen (FK auf employees, ON DELETE CASCADE).

Phishing-Sim-Tabelle (``phishing_sim_events``) folgt in 3c. Bestehende
Daten bleiben durch additive Schema-Migration unberuehrt.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.awareness_tracker.domain.models import (
    Employee,
    PhishingSimEvent,
    PhishingSimVendor,
    Training,
    TrainingType,
)

_log = get_logger(__name__)

DB_NAME: str = "awareness_tracker"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS employees (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name   TEXT NOT NULL,
    email       TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL DEFAULT '',
    department  TEXT NOT NULL DEFAULT '',
    is_active   INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
    notes       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_employees_full_name ON employees(full_name);
CREATE INDEX IF NOT EXISTS idx_employees_is_active ON employees(is_active);

CREATE TABLE IF NOT EXISTS trainings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id         INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    training_type       TEXT NOT NULL,
    title               TEXT NOT NULL,
    completed_at        TEXT NOT NULL,
    valid_until         TEXT,
    provider            TEXT NOT NULL DEFAULT '',
    custom_type_label   TEXT NOT NULL DEFAULT '',
    notes               TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trainings_employee_id ON trainings(employee_id);
CREATE INDEX IF NOT EXISTS idx_trainings_valid_until ON trainings(valid_until);

CREATE TABLE IF NOT EXISTS phishing_sim_events (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT NOT NULL,
    vendor               TEXT NOT NULL,
    run_date             TEXT NOT NULL,
    target_count         INTEGER NOT NULL CHECK(target_count >= 1),
    click_count          INTEGER NOT NULL CHECK(click_count >= 0),
    report_count         INTEGER NOT NULL DEFAULT 0 CHECK(report_count >= 0),
    training_assigned    INTEGER NOT NULL DEFAULT 0 CHECK(training_assigned IN (0, 1)),
    custom_vendor_label  TEXT NOT NULL DEFAULT '',
    notes                TEXT NOT NULL DEFAULT '',
    created_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_phishing_sim_run_date ON phishing_sim_events(run_date);
CREATE INDEX IF NOT EXISTS idx_phishing_sim_vendor   ON phishing_sim_events(vendor);
"""


class AwarenessRepository:
    """CRUD-Repository fuer:class:`Employee` und:class:`Training`.

    Beide Entitaeten liegen in einer DB (``awareness_tracker``), weil sie
    semantisch eng verschraenkt sind (Schulung gehoert immer zu einem
    Mitarbeiter) und ``ON DELETE CASCADE`` die Aufraeumarbeit beim Off-
    Boarding uebernimmt.
    """

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        """Initialisiert das Repository und legt das Schema an (idempotent).

        Args:
            db: Optional vorgefertigte:class:`EncryptedDatabase`-Instanz
                (typischerweise nur in Tests mit eigener Test-DB). Default:
                ``EncryptedDatabase("awareness_tracker")``.
        """
        self._db = db or EncryptedDatabase(DB_NAME)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._db.connection() as conn:
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)
            # Fremdschluessel-Enforcement (ON DELETE CASCADE) braucht
            # explizit aktivierten PRAGMA.
            conn.execute("PRAGMA foreign_keys = ON")
            conn.commit()

    # ------------------------------------------------------------------
    # Employee
    # ------------------------------------------------------------------

    def add_employee(self, employee: Employee) -> int:
        """Fuegt einen neuen Mitarbeiter ein.

        Args:
            employee::class:`Employee` (id wird ignoriert).

        Returns:
            Die neu vergebene Datenbank-ID.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO employees
                    (full_name, email, role, department, is_active, notes,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    employee.full_name,
                    employee.email,
                    employee.role,
                    employee.department,
                    1 if employee.is_active else 0,
                    employee.notes,
                    employee.created_at.isoformat(),
                    employee.updated_at.isoformat(),
                ),
            )
            conn.commit()
            new_id = int(cur.lastrowid or 0)
        _log.info("employee_added id=%s name=%r", new_id, employee.full_name)
        return new_id

    def get_employee(self, employee_id: int) -> Employee | None:
        """Liefert einen Mitarbeiter anhand seiner ID oder ``None``."""
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT id, full_name, email, role, department, is_active,
                       notes, created_at, updated_at
                FROM employees
                WHERE id = ?
                """,
                (int(employee_id),),
            ).fetchone()
        return self._row_to_employee(row) if row else None

    def list_employees(self, include_inactive: bool = True) -> list[Employee]:
        """Liefert alle Mitarbeiter, sortiert nach Name (Collate NOCASE).

        Args:
            include_inactive: Wenn ``False``, werden Off-Boarded-Eintraege
                (``is_active=0``) ausgefiltert. Default: ``True``.
        """
        with self._db.connection() as conn:
            if include_inactive:
                rows = conn.execute(
                    """
                    SELECT id, full_name, email, role, department, is_active,
                           notes, created_at, updated_at
                    FROM employees
                    ORDER BY full_name COLLATE NOCASE ASC
                    """
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, full_name, email, role, department, is_active,
                           notes, created_at, updated_at
                    FROM employees
                    WHERE is_active = 1
                    ORDER BY full_name COLLATE NOCASE ASC
                    """
                ).fetchall()
        return [self._row_to_employee(row) for row in rows]

    def update_employee(self, employee: Employee) -> None:
        """Aktualisiert einen bestehenden Mitarbeiter.

        ``updated_at`` wird auf ``datetime.now(UTC)`` gesetzt — ein
        manuell uebergebener Stamp wird ignoriert.

        Raises:
            ValueError: Wenn ``employee.id`` fehlt oder kein Datensatz
                mit dieser ID existiert.
        """
        if employee.id is None:
            raise ValueError("Employee.update braucht eine gesetzte id.")
        now_iso = datetime.now(UTC).isoformat()
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                UPDATE employees
                SET full_name = ?, email = ?, role = ?, department = ?,
                    is_active = ?, notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    employee.full_name,
                    employee.email,
                    employee.role,
                    employee.department,
                    1 if employee.is_active else 0,
                    employee.notes,
                    now_iso,
                    int(employee.id),
                ),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise ValueError(f"Kein Employee mit id={employee.id} gefunden.")
        _log.info("employee_updated id=%s", employee.id)

    def delete_employee(self, employee_id: int) -> bool:
        """Loescht einen Mitarbeiter (samt aller Trainings via CASCADE).

        Returns:
            ``True`` wenn eine Zeile geloescht wurde, sonst ``False``.
        """
        with self._db.connection() as conn:
            # ``PRAGMA foreign_keys = ON`` muss pro-Connection gesetzt
            # werden — wir wiederholen das hier defensiv, damit auch
            # Pool-getrennte Verbindungen den CASCADE-Pfad ziehen.
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.execute(
                "DELETE FROM employees WHERE id = ?",
                (int(employee_id),),
            )
            conn.commit()
            deleted = (cur.rowcount or 0) > 0
        if deleted:
            _log.info("employee_deleted id=%s", employee_id)
        return deleted

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def add_training(self, training: Training) -> int:
        """Fuegt eine neue Schulung ein.

        Args:
            training::class:`Training` (id wird ignoriert).

        Returns:
            Die neu vergebene Datenbank-ID.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO trainings
                    (employee_id, training_type, title, completed_at,
                     valid_until, provider, custom_type_label, notes,
                     created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(training.employee_id),
                    training.training_type.value,
                    training.title,
                    training.completed_at.isoformat(),
                    (
                        training.valid_until.isoformat()
                        if training.valid_until is not None
                        else None
                    ),
                    training.provider,
                    training.custom_type_label,
                    training.notes,
                    training.created_at.isoformat(),
                ),
            )
            conn.commit()
            new_id = int(cur.lastrowid or 0)
        _log.info(
            "training_added id=%s employee_id=%s title=%r",
            new_id,
            training.employee_id,
            training.title,
        )
        return new_id

    def update_training(self, training: Training) -> None:
        """Aktualisiert eine bestehende Schulung.

        Args:
            training::class:`Training` mit gesetzter ``id``.

        Raises:
            ValueError: Wenn ``training.id`` fehlt oder kein Datensatz mit
                dieser ID existiert.
        """
        if training.id is None:
            raise ValueError("Training.update braucht eine gesetzte id.")
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                UPDATE trainings
                SET employee_id = ?, training_type = ?, title = ?,
                    completed_at = ?, valid_until = ?, provider = ?,
                    custom_type_label = ?, notes = ?
                WHERE id = ?
                """,
                (
                    int(training.employee_id),
                    training.training_type.value,
                    training.title,
                    training.completed_at.isoformat(),
                    (
                        training.valid_until.isoformat()
                        if training.valid_until is not None
                        else None
                    ),
                    training.provider,
                    training.custom_type_label,
                    training.notes,
                    int(training.id),
                ),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise ValueError(f"Kein Training mit id={training.id} gefunden.")
        _log.info("training_updated id=%s", training.id)

    def get_training(self, training_id: int) -> Training | None:
        """Liefert eine Schulung anhand ihrer ID oder ``None``."""
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT id, employee_id, training_type, title, completed_at,
                       valid_until, provider, custom_type_label, notes,
                       created_at
                FROM trainings
                WHERE id = ?
                """,
                (int(training_id),),
            ).fetchone()
        return self._row_to_training(row) if row else None

    def list_trainings_for_employee(self, employee_id: int) -> list[Training]:
        """Liefert alle Schulungen eines Mitarbeiters, neueste zuerst."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, employee_id, training_type, title, completed_at,
                       valid_until, provider, custom_type_label, notes,
                       created_at
                FROM trainings
                WHERE employee_id = ?
                ORDER BY completed_at DESC, id DESC
                """,
                (int(employee_id),),
            ).fetchall()
        return [self._row_to_training(row) for row in rows]

    def list_trainings(self) -> list[Training]:
        """Liefert alle Schulungen (alle Mitarbeiter), neueste zuerst."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, employee_id, training_type, title, completed_at,
                       valid_until, provider, custom_type_label, notes,
                       created_at
                FROM trainings
                ORDER BY completed_at DESC, id DESC
                """
            ).fetchall()
        return [self._row_to_training(row) for row in rows]

    def delete_training(self, training_id: int) -> bool:
        """Loescht eine Schulung.

        Returns:
            ``True`` wenn eine Zeile geloescht wurde, sonst ``False``.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM trainings WHERE id = ?",
                (int(training_id),),
            )
            conn.commit()
            deleted = (cur.rowcount or 0) > 0
        if deleted:
            _log.info("training_deleted id=%s", training_id)
        return deleted

    # ------------------------------------------------------------------
    # Phishing-Sim CRUD (Iter 3c)
    # ------------------------------------------------------------------

    def add_phishing_sim(self, event: PhishingSimEvent) -> int:
        """Fuegt eine neue Phishing-Sim-Kampagne ein.

        Returns:
            Die neu vergebene Datenbank-ID.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO phishing_sim_events
                    (name, vendor, run_date, target_count, click_count,
                     report_count, training_assigned, custom_vendor_label,
                     notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.name,
                    event.vendor.value,
                    event.run_date.isoformat(),
                    int(event.target_count),
                    int(event.click_count),
                    int(event.report_count),
                    1 if event.training_assigned else 0,
                    event.custom_vendor_label,
                    event.notes,
                    event.created_at.isoformat(),
                ),
            )
            conn.commit()
            new_id = int(cur.lastrowid or 0)
        _log.info(
            "phishing_sim_added id=%s name=%r vendor=%s",
            new_id,
            event.name,
            event.vendor.value,
        )
        return new_id

    def get_phishing_sim(self, event_id: int) -> PhishingSimEvent | None:
        """Liefert eine Phishing-Sim-Kampagne anhand ihrer ID oder ``None``."""
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT id, name, vendor, run_date, target_count,
                       click_count, report_count, training_assigned,
                       custom_vendor_label, notes, created_at
                FROM phishing_sim_events
                WHERE id = ?
                """,
                (int(event_id),),
            ).fetchone()
        return self._row_to_phishing_sim(row) if row else None

    def list_phishing_sims(self) -> list[PhishingSimEvent]:
        """Liefert alle Kampagnen, neueste run_date zuerst."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, name, vendor, run_date, target_count,
                       click_count, report_count, training_assigned,
                       custom_vendor_label, notes, created_at
                FROM phishing_sim_events
                ORDER BY run_date DESC, id DESC
                """
            ).fetchall()
        return [self._row_to_phishing_sim(row) for row in rows]

    def update_phishing_sim(self, event: PhishingSimEvent) -> None:
        """Aktualisiert eine bestehende Kampagne.

        Raises:
            ValueError: Bei fehlender ID oder unbekanntem Datensatz.
        """
        if event.id is None:
            raise ValueError("PhishingSimEvent.update braucht eine gesetzte id.")
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                UPDATE phishing_sim_events
                SET name = ?, vendor = ?, run_date = ?, target_count = ?,
                    click_count = ?, report_count = ?, training_assigned = ?,
                    custom_vendor_label = ?, notes = ?
                WHERE id = ?
                """,
                (
                    event.name,
                    event.vendor.value,
                    event.run_date.isoformat(),
                    int(event.target_count),
                    int(event.click_count),
                    int(event.report_count),
                    1 if event.training_assigned else 0,
                    event.custom_vendor_label,
                    event.notes,
                    int(event.id),
                ),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise ValueError(
                    f"Kein PhishingSimEvent mit id={event.id} gefunden."
                )
        _log.info("phishing_sim_updated id=%s", event.id)

    def delete_phishing_sim(self, event_id: int) -> bool:
        """Loescht eine Kampagne. Returns ``True`` bei Hit."""
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM phishing_sim_events WHERE id = ?",
                (int(event_id),),
            )
            conn.commit()
            deleted = (cur.rowcount or 0) > 0
        if deleted:
            _log.info("phishing_sim_deleted id=%s", event_id)
        return deleted

    # ------------------------------------------------------------------
    # Row-Konverter
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_employee(row) -> Employee:  # noqa: ANN001 — sqlite3.Row tuple-like
        return Employee(
            id=int(row[0]),
            full_name=row[1],
            email=row[2] or "",
            role=row[3] or "",
            department=row[4] or "",
            is_active=bool(int(row[5])),
            notes=row[6] or "",
            created_at=_parse_iso_utc(row[7]),
            updated_at=_parse_iso_utc(row[8]),
        )

    @staticmethod
    def _row_to_phishing_sim(row) -> PhishingSimEvent:  # noqa: ANN001
        return PhishingSimEvent(
            id=int(row[0]),
            name=row[1],
            vendor=PhishingSimVendor.from_value(row[2]),
            run_date=_parse_iso_utc(row[3]),
            target_count=int(row[4]),
            click_count=int(row[5]),
            report_count=int(row[6]),
            training_assigned=bool(int(row[7])),
            custom_vendor_label=row[8] or "",
            notes=row[9] or "",
            created_at=_parse_iso_utc(row[10]),
        )

    @staticmethod
    def _row_to_training(row) -> Training:  # noqa: ANN001
        valid_until_raw = row[5]
        return Training(
            id=int(row[0]),
            employee_id=int(row[1]),
            training_type=TrainingType.from_value(row[2]),
            title=row[3],
            completed_at=_parse_iso_utc(row[4]),
            valid_until=(
                _parse_iso_utc(valid_until_raw)
                if valid_until_raw
                else None
            ),
            provider=row[6] or "",
            custom_type_label=row[7] or "",
            notes=row[8] or "",
            created_at=_parse_iso_utc(row[9]),
        )


def _parse_iso_utc(value: str | None) -> datetime:
    """Parst einen ISO-Timestamp, Fallback ``datetime.now(UTC)``."""
    if not value:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(UTC)
