"""workflow_progress_repository — Persistenz des Workflow-Fortschritts.

Speichert Status + Notiz je Workflow-Schritt PRO SUBJEKT in einer Tabelle. Die
Schritt-Definition selbst ist Code-Konstante (:mod:`tools.norisk_dashboard.domain.workflow_definition`) — hier liegt nur der
veraenderliche Fortschritt.

DB: ``EncryptedDatabase("norisk_dashboard")`` -> wird per
(``_resolve_consolidated_db_name``) physisch auf ``norisk.db`` gelenkt (kein
neues DB-File). At-rest verschluesselt (SQLCipher); die ``note`` kann PII
enthalten und teilt den Schutz der uebrigen Spalten.

Schicht: ``data/`` — darf ``domain/`` + ``core/`` importieren, keine
application/gui-Importe.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.norisk_dashboard.domain.exceptions import WorkflowDataError
from tools.norisk_dashboard.domain.workflow_models import (
    WorkflowStepProgress,
    WorkflowStepStatus,
    normalize_status,
)

_log = get_logger(__name__)

DB_NAME: str = "norisk_dashboard"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS workflow_step_progress (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id  TEXT NOT NULL,
    step_key    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'offen'
                CHECK (status IN ('offen','in_arbeit','erledigt',
                                  'uebersprungen','nicht_relevant')),
    note        TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_workflow_step
    ON workflow_step_progress(subject_id, step_key);
CREATE INDEX IF NOT EXISTS idx_workflow_subject
    ON workflow_step_progress(subject_id);
"""

#: UPSERT — INSERT oder (bei bestehendem subject_id+step_key) UPDATE. Der
#: UNIQUE-Index ``uq_workflow_step`` ist das ON-CONFLICT-Ziel.
_SQL_UPSERT = """
    INSERT INTO workflow_step_progress
        (subject_id, step_key, status, note, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(subject_id, step_key) DO UPDATE SET
        status = excluded.status,
        note = excluded.note,
        updated_at = excluded.updated_at
"""


class WorkflowProgressRepository:
    """CRUD-Repository fuer den Workflow-Fortschritt (Status + Notiz je Schritt)."""

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        """Initialisiert das Repository und legt das Schema an (idempotent).

        Args:
            db: Optionale:class:`EncryptedDatabase` (typischerweise in Tests).
                Default: die konsolidierte NoRisk-DB.
        """
        self._db = db or EncryptedDatabase(DB_NAME)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._db.connection() as conn:
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)
            conn.commit()

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_progress(self, subject_id: str) -> dict[str, WorkflowStepProgress]:
        """Liest den kompletten Fortschritt eines Subjekts in EINEM Query.

        Args:
            subject_id: Das Subjekt (eigenes System = regulaere UUID).

        Returns:
            Abbildung ``step_key -> WorkflowStepProgress``. Schritte ohne Eintrag
            fehlen bewusst — der Aufrufer merged gegen die Code-Definition
            (Default-Status ``offen``).
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT subject_id, step_key, status, note, updated_at "
                "FROM workflow_step_progress WHERE subject_id = ?",
                (subject_id,),
            ).fetchall()
        return {
            row[1]: WorkflowStepProgress(
                subject_id=row[0],
                step_key=row[1],
                status=row[2],
                note=row[3],
                updated_at=row[4],
            )
            for row in rows
        }

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def set_status(
        self,
        subject_id: str,
        step_key: str,
        status: str | WorkflowStepStatus,
        *,
        note: str | None = None,
    ) -> None:
        """Setzt den Status eines Schritts (UPSERT).

        Args:
            subject_id: Zielsubjekt.
            step_key: Schritt-Schluessel (siehe ``WorkflowStepDef.step_key``).
            status: Neuer Status (Enum oder roher String; wird validiert).
            note: Optionale Notiz. ``None`` laesst eine bestehende Notiz
                unveraendert (``note`` ist nie ein gueltiger Dateninhalt ``None``
                — ``""`` bedeutet „keine Notiz"; R25-konform).

        Raises:
            WorkflowDataError: Wenn ``status`` kein gueltiger Statuswert ist
                (die ``data/``-Schicht uebersetzt das rohe ``ValueError`` aus
:func:`normalize_status` R-Exc).
        """
        try:
            status_value = normalize_status(status).value
        except ValueError as exc:
            raise WorkflowDataError(
                f"Ungueltiger Workflow-Status: {status!r}"
            ) from exc
        now = datetime.now(UTC).isoformat()
        with self._db.connection() as conn:
            if note is None:
                existing = conn.execute(
                    "SELECT note FROM workflow_step_progress "
                    "WHERE subject_id = ? AND step_key = ?",
                    (subject_id, step_key),
                ).fetchone()
                note_value = existing[0] if existing else ""
            else:
                note_value = note
            conn.execute(
                _SQL_UPSERT, (subject_id, step_key, status_value, note_value, now)
            )
            conn.commit()

    def set_note(self, subject_id: str, step_key: str, note: str) -> None:
        """Setzt die Notiz eines Schritts (UPSERT), Status bleibt erhalten.

        Args:
            subject_id: Zielsubjekt.
            step_key: Schritt-Schluessel.
            note: Notiztext (``""`` loescht die Notiz).
        """
        now = datetime.now(UTC).isoformat()
        with self._db.connection() as conn:
            existing = conn.execute(
                "SELECT status FROM workflow_step_progress "
                "WHERE subject_id = ? AND step_key = ?",
                (subject_id, step_key),
            ).fetchone()
            status_value = existing[0] if existing else WorkflowStepStatus.OFFEN.value
            conn.execute(
                _SQL_UPSERT, (subject_id, step_key, status_value, note, now)
            )
            conn.commit()

    def delete_for_subject(self, subject_id: str) -> int:
        """Loescht den kompletten Fortschritt eines Subjekts.

        Gemeinsame Basis fuer den Nutzer-„Zuruecksetzen"-Knopf UND den
        DSGVO-Loeschpfad (Kunde entfernt). Getrennter Methodenname erlaubt
        spaetere Divergenz ohne Signatur-Bruch.

        Args:
            subject_id: Zielsubjekt.

        Returns:
            Anzahl geloeschter Zeilen.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM workflow_step_progress WHERE subject_id = ?",
                (subject_id,),
            )
            conn.commit()
            deleted = int(cur.rowcount or 0)
        if deleted:
            _log.info(
                "workflow_progress_reset subject=%s deleted=%s",
                subject_id[:8],
                deleted,
            )
        return deleted

    #: Alias — der Nutzer-„Zuruecksetzen"-Knopf ist semantisch dasselbe DELETE.
    reset = delete_for_subject


__all__ = ["DB_NAME", "WorkflowProgressRepository"]
