"""
avv_repository — Persistierung der AVV-Dokument-Metadaten.

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren.

Schema-Version 3:

- ``avv_documents`` — eine Zeile pro AVV-PDF, FK auf ``vendors(id)``.
  PDF-Bytes liegen NICHT in der DB (Patrick-Direktive 2026-05-15), nur
  Pfad + SHA256 + Metadaten.
- ``avv_checklist_entries`` — pro AVV n Eintraege (10 Art-28-Defaults +
  User-Customs).

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
    AvvDocument,
)

_log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS avv_documents (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id           INTEGER NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_avv_documents_vendor
  ON avv_documents(vendor_id);
CREATE INDEX IF NOT EXISTS idx_avv_documents_valid_until
  ON avv_documents(valid_until);

CREATE TABLE IF NOT EXISTS avv_checklist_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    avv_id          INTEGER NOT NULL,
    art28_check     TEXT,
    custom_label    TEXT NOT NULL DEFAULT '',
    is_custom       INTEGER NOT NULL DEFAULT 0,
    is_present      INTEGER,
    notes           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_avv_checklist_avv
  ON avv_checklist_entries(avv_id);
"""


class AvvRepository:
    """CRUD-Repository fuer:class:`AvvDocument` und ihre Checklist-Eintraege."""

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
    # AvvDocument
    # ------------------------------------------------------------------

    def add(self, doc: AvvDocument) -> int:
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO avv_documents
                    (vendor_id, file_path, sha256, size_bytes, original_filename,
                     valid_from, valid_until, status, notes, uploaded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(doc.vendor_id),
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
        _log.info("avv_added id=%s vendor_id=%s", new_id, doc.vendor_id)
        return new_id

    def get_by_id(self, avv_id: int) -> AvvDocument | None:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM avv_documents WHERE id = ?",
                (int(avv_id),),
            ).fetchone()
        return self._row_to_doc(row) if row else None

    def list_for_vendor(self, vendor_id: int) -> list[AvvDocument]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM avv_documents WHERE vendor_id = ? "
                "ORDER BY valid_until DESC",
                (int(vendor_id),),
            ).fetchall()
        return [self._row_to_doc(r) for r in rows]

    def list_all(self) -> list[AvvDocument]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM avv_documents ORDER BY valid_until ASC"
            ).fetchall()
        return [self._row_to_doc(r) for r in rows]

    def update(self, doc: AvvDocument) -> None:
        if doc.id is None:
            raise ValueError("AvvDocument.update braucht eine gesetzte id.")
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                UPDATE avv_documents
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
                raise ValueError(f"Kein AVV-Dokument mit id={doc.id}.")

    def delete(self, avv_id: int) -> bool:
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM avv_checklist_entries WHERE avv_id = ?",
                (int(avv_id),),
            )
            cur = conn.execute(
                "DELETE FROM avv_documents WHERE id = ?",
                (int(avv_id),),
            )
            conn.commit()
            return (cur.rowcount or 0) > 0

    # ------------------------------------------------------------------
    # AvvChecklistEntry
    # ------------------------------------------------------------------

    def replace_checklist(
        self,
        avv_id: int,
        entries: list[AvvChecklistEntry],
    ) -> None:
        """Ersetzt alle Checklist-Eintraege eines AVV in einer Transaktion.

        Vor dem Insert werden alle bestehenden Eintraege fuer ``avv_id``
        geloescht — atomar pro AVV. Damit bleibt die Checklist immer
        konsistent (keine Halb-States bei Update-Fehlern).
        """
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM avv_checklist_entries WHERE avv_id = ?",
                (int(avv_id),),
            )
            for entry in entries:
                conn.execute(
                    """
                    INSERT INTO avv_checklist_entries
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
                "is_present, notes FROM avv_checklist_entries "
                "WHERE avv_id = ? ORDER BY is_custom ASC, id ASC",
                (int(avv_id),),
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    # ------------------------------------------------------------------
    # Row-Mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_doc(row) -> AvvDocument:  # noqa: ANN001
        return AvvDocument(
            id=int(row[0]),
            vendor_id=int(row[1]),
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
