"""
customer_avv_repository — Persistierung der KUNDEN-AVV-Metadaten.

Gegenstueck zu:mod:`avv_repository` fuer die zweite Perspektive: WIR sind
Auftragsverarbeiter, der Kunde ist Verantwortlicher. Statt ``vendor_id`` haengt
ein Datensatz an einer ``subject_id`` (kanonische Kunden-Identitaet
``Subject``/``kind=KUNDE`` aus ``core/security_subject`` — Cross-DB-Soft-FK, da
das ``Subject`` in der ``security_scoring``-DB lebt; kein DB-FK, kein JOIN).

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren.

Schema (rein additiv, idempotent E3, R-Mig):
- ``customer_avv_documents`` — eine Zeile pro Kunden-AVV-PDF, Soft-FK
  ``subject_id``. PDF-Bytes liegen NICHT in der DB, nur Pfad + SHA256 + Metadaten
  (gleiche Direktive wie Lieferanten-AVVs).
- ``customer_avv_checklist_entries`` — pro AVV n Eintraege (10 Art-28-Defaults +
  User-Customs); identische Struktur + Domain-Klasse wie die Lieferanten-Sicht.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.supply_chain_monitor.data._avv_row_parsing import parse_iso_utc, safe_status
from tools.supply_chain_monitor.domain.models import (
    Art28Check,
    AvvChecklistEntry,
    CustomerAvvDocument,
)

_log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS customer_avv_documents (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id          TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    sha256              TEXT NOT NULL,
    size_bytes          INTEGER NOT NULL,
    original_filename   TEXT NOT NULL,
    valid_from          TEXT NOT NULL,
    valid_until         TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'active',
    notes               TEXT NOT NULL DEFAULT '',
    uploaded_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_customer_avv_subject
  ON customer_avv_documents(subject_id);
CREATE INDEX IF NOT EXISTS idx_customer_avv_valid_until
  ON customer_avv_documents(valid_until);

CREATE TABLE IF NOT EXISTS customer_avv_checklist_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    avv_id          INTEGER NOT NULL,
    art28_check     TEXT,
    custom_label    TEXT NOT NULL DEFAULT '',
    is_custom       INTEGER NOT NULL DEFAULT 0,
    is_present      INTEGER,
    notes           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_customer_avv_checklist_avv
  ON customer_avv_checklist_entries(avv_id);
"""


class CustomerAvvRepository:
    """CRUD-Repository fuer:class:`CustomerAvvDocument` und ihre Checklist.

    Liegt in derselben ``EncryptedDatabase("supply_chain_monitor")`` wie die
    Lieferanten-AVVs-Konsolidierung), nur in eigenen Tabellen.
    """

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        self._db = db or EncryptedDatabase("supply_chain_monitor")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._db.connection() as conn:
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)
            conn.commit()

    # ------------------------------------------------------------------
    # CustomerAvvDocument
    # ------------------------------------------------------------------

    def add(self, doc: CustomerAvvDocument) -> int:
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO customer_avv_documents
                    (subject_id, file_path, sha256, size_bytes, original_filename,
                     valid_from, valid_until, status, notes, uploaded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    doc.subject_id,
                    doc.file_path,
                    doc.sha256,
                    int(doc.size_bytes),
                    doc.original_filename,
                    doc.valid_from.isoformat(),
                    doc.valid_until.isoformat(),
                    doc.status.value,
                    doc.notes,
                    doc.uploaded_at.isoformat(),
                ),
            )
            conn.commit()
            new_id = int(cur.lastrowid or 0)
        # subject_id nur gekuerzt loggen (Datensparsamkeit, analog manage_profiles).
        _log.info(
            "customer_avv_added id=%s subject_id=%s", new_id, doc.subject_id[:8]
        )
        return new_id

    def get_by_id(self, avv_id: int) -> CustomerAvvDocument | None:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM customer_avv_documents WHERE id = ?",
                (int(avv_id),),
            ).fetchone()
        return self._row_to_doc(row) if row else None

    def list_for_customer(self, subject_id: str) -> list[CustomerAvvDocument]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM customer_avv_documents WHERE subject_id = ? "
                "ORDER BY valid_until DESC",
                (subject_id,),
            ).fetchall()
        return [self._row_to_doc(r) for r in rows]

    def list_all(self) -> list[CustomerAvvDocument]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM customer_avv_documents ORDER BY valid_until ASC"
            ).fetchall()
        return [self._row_to_doc(r) for r in rows]

    def update(self, doc: CustomerAvvDocument) -> None:
        if doc.id is None:
            raise ValueError("CustomerAvvDocument.update braucht eine gesetzte id.")
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                UPDATE customer_avv_documents
                SET file_path = ?, sha256 = ?, size_bytes = ?, original_filename = ?,
                    valid_from = ?, valid_until = ?, status = ?, notes = ?
                WHERE id = ?
                """,
                (
                    doc.file_path,
                    doc.sha256,
                    int(doc.size_bytes),
                    doc.original_filename,
                    doc.valid_from.isoformat(),
                    doc.valid_until.isoformat(),
                    doc.status.value,
                    doc.notes,
                    int(doc.id),
                ),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise ValueError(f"Kein Kunden-AVV-Dokument mit id={doc.id}.")

    def delete(self, avv_id: int) -> bool:
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM customer_avv_checklist_entries WHERE avv_id = ?",
                (int(avv_id),),
            )
            cur = conn.execute(
                "DELETE FROM customer_avv_documents WHERE id = ?",
                (int(avv_id),),
            )
            conn.commit()
            return (cur.rowcount or 0) > 0

    # ------------------------------------------------------------------
    # DSGVO-Lösch-Block E4): Referenz-Check vor Subject-Löschung
    # ------------------------------------------------------------------

    def count_for_subject(self, subject_id: str) -> int:
        """Zaehlt die archivierten Kunden-AVVs eines Subjekts.

        Args:
            subject_id: UUID des Kunden-``Subject``.

        Returns:
            Anzahl der ``customer_avv_documents``-Zeilen fuer das Subjekt.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM customer_avv_documents WHERE subject_id = ?",
                (subject_id,),
            ).fetchone()
        return int(row[0]) if row else 0

    def has_references(self, subject_id: str) -> bool:
        """True, wenn das Subjekt noch Kunden-AVVs haelt (blockiert Loeschung).

        Dient dem DSGVO-Art.-17-Loesch-Block E4): ein Kunde darf nicht
        geloescht werden, solange ein aufbewahrungspflichtiger AVV existiert.

        Args:
            subject_id: UUID des Kunden-``Subject``.

        Returns:
            True bei mindestens einer Referenz, sonst False.
        """
        return self.count_for_subject(subject_id) > 0

    # ------------------------------------------------------------------
    # CustomerAvvChecklistEntry
    # ------------------------------------------------------------------

    def replace_checklist(
        self,
        avv_id: int,
        entries: list[AvvChecklistEntry],
    ) -> None:
        """Ersetzt alle Checklist-Eintraege eines Kunden-AVV in einer Transaktion.

        Vor dem Insert werden alle bestehenden Eintraege fuer ``avv_id``
        geloescht — atomar pro AVV (keine Halb-States bei Update-Fehlern). Die
        Domain-Klasse:class:`AvvChecklistEntry` ist mit der Lieferanten-Sicht
        identisch (dieselben 10 Art-28-Checks).
        """
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM customer_avv_checklist_entries WHERE avv_id = ?",
                (int(avv_id),),
            )
            for entry in entries:
                conn.execute(
                    """
                    INSERT INTO customer_avv_checklist_entries
                        (avv_id, art28_check, custom_label, is_custom,
                         is_present, notes)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(avv_id),
                        entry.art28_check.value if entry.art28_check else None,
                        entry.custom_label,
                        1 if entry.is_custom else 0,
                        None
                        if entry.is_present is None
                        else (1 if entry.is_present else 0),
                        entry.notes,
                    ),
                )
            conn.commit()

    def list_checklist(self, avv_id: int) -> list[AvvChecklistEntry]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT id, avv_id, art28_check, custom_label, is_custom, "
                "is_present, notes FROM customer_avv_checklist_entries "
                "WHERE avv_id = ? ORDER BY is_custom ASC, id ASC",
                (int(avv_id),),
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    # ------------------------------------------------------------------
    # Row-Mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_doc(row) -> CustomerAvvDocument:  # noqa: ANN001
        return CustomerAvvDocument(
            id=int(row[0]),
            subject_id=row[1],
            file_path=row[2],
            sha256=row[3],
            size_bytes=int(row[4]),
            original_filename=row[5],
            valid_from=parse_iso_utc(row[6]),
            valid_until=parse_iso_utc(row[7]),
            status=safe_status(row[8]),
            notes=row[9] or "",
            uploaded_at=parse_iso_utc(row[10]),
        )

    @staticmethod
    def _row_to_entry(row) -> AvvChecklistEntry:  # noqa: ANN001
        art28_value = row[2]
        return AvvChecklistEntry(
            id=int(row[0]),
            avv_id=int(row[1]),
            art28_check=Art28Check.from_value(art28_value) if art28_value else None,
            custom_label=row[3] or "",
            is_custom=bool(row[4]),
            is_present=None if row[5] is None else bool(row[5]),
            notes=row[6] or "",
        )
