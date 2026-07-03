"""
subprocessor_repository — Persistierung von Sub-Auftragsverarbeitern.

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren.

Schema-Version 4 (H, Live-Test 2026-07-01):

- ``subprocessors`` — Stamm-Tabelle.
- ``vendor_subprocessors`` — n:m-Linktable Vendor ↔ Subprocessor + Rolle.
- ``customer_subprocessors`` — n:m-Linktable Kunde (``subject_id``,
  Cross-DB-Soft-FK) ↔ Subprocessor + Rolle. Rein additiv: die neue Tabelle
  wird via ``CREATE TABLE IF NOT EXISTS`` auch auf Bestands-DBs angelegt,
  der Vendor-Pfad bleibt unberuehrt.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.supply_chain_monitor.domain.models import (
    CustomerSubprocessorLink,
    Subprocessor,
    VendorCategory,
    VendorSubprocessorLink,
)

_log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS subprocessors (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    country      TEXT NOT NULL,
    category     TEXT NOT NULL,
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subprocessors_name
  ON subprocessors(name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS vendor_subprocessors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id       INTEGER NOT NULL,
    subprocessor_id INTEGER NOT NULL,
    role            TEXT NOT NULL DEFAULT '',
    linked_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vendor_subprocessors_vendor
  ON vendor_subprocessors(vendor_id);
CREATE INDEX IF NOT EXISTS idx_vendor_subprocessors_sub
  ON vendor_subprocessors(subprocessor_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_vendor_subprocessor_role
  ON vendor_subprocessors(vendor_id, subprocessor_id, role);

CREATE TABLE IF NOT EXISTS customer_subprocessors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id      TEXT NOT NULL,
    subprocessor_id INTEGER NOT NULL,
    role            TEXT NOT NULL DEFAULT '',
    linked_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_customer_subprocessors_subject
  ON customer_subprocessors(subject_id);
CREATE INDEX IF NOT EXISTS idx_customer_subprocessors_sub
  ON customer_subprocessors(subprocessor_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_customer_subprocessor_role
  ON customer_subprocessors(subject_id, subprocessor_id, role);
"""


class SubprocessorRepository:
    """CRUD-Repository fuer:class:`Subprocessor` + n:m-Links."""

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
    # Subprocessor CRUD
    # ------------------------------------------------------------------

    def add(self, sub: Subprocessor) -> int:
        with self._db.connection() as conn:
            try:
                cur = conn.execute(
                    """
                    INSERT INTO subprocessors
                        (name, country, category, notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sub.name,
                        sub.country,
                        sub.category.value,
                        sub.notes,
                        sub.created_at.isoformat(),
                        sub.updated_at.isoformat(),
                    ),
                )
                conn.commit()
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).lower()
                if "unique" in msg and "name" in msg:
                    raise ValueError(
                        f"Subprocessor '{sub.name}' existiert bereits."
                    ) from exc
                raise
        return int(cur.lastrowid or 0)

    def get_by_id(self, sub_id: int) -> Subprocessor | None:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM subprocessors WHERE id = ?",
                (int(sub_id),),
            ).fetchone()
        return self._row_to_sub(row) if row else None

    def list_all(self) -> list[Subprocessor]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM subprocessors ORDER BY name COLLATE NOCASE ASC"
            ).fetchall()
        return [self._row_to_sub(r) for r in rows]

    def update(self, sub: Subprocessor) -> None:
        if sub.id is None:
            raise ValueError("Subprocessor.update braucht eine gesetzte id.")
        now_iso = datetime.now(UTC).isoformat()
        with self._db.connection() as conn:
            try:
                cur = conn.execute(
                    """
                    UPDATE subprocessors
                    SET name = ?, country = ?, category = ?, notes = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        sub.name,
                        sub.country,
                        sub.category.value,
                        sub.notes,
                        now_iso,
                        int(sub.id),
                    ),
                )
                conn.commit()
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).lower()
                if "unique" in msg and "name" in msg:
                    raise ValueError(
                        f"Subprocessor '{sub.name}' existiert bereits."
                    ) from exc
                raise
            if cur.rowcount == 0:
                raise ValueError(f"Kein Subprocessor mit id={sub.id}.")

    def delete(self, sub_id: int) -> bool:
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM vendor_subprocessors WHERE subprocessor_id = ?",
                (int(sub_id),),
            )
            # Kunden-Verknuepfungen desselben Subs ebenfalls entfernen (H).
            conn.execute(
                "DELETE FROM customer_subprocessors WHERE subprocessor_id = ?",
                (int(sub_id),),
            )
            cur = conn.execute(
                "DELETE FROM subprocessors WHERE id = ?",
                (int(sub_id),),
            )
            conn.commit()
            return (cur.rowcount or 0) > 0

    # ------------------------------------------------------------------
    # n:m-Links
    # ------------------------------------------------------------------

    def link(self, vendor_id: int, subprocessor_id: int, role: str = "") -> int:
        """Erzeugt einen neuen Link Vendor ↔ Subprocessor mit Rolle.

        Existiert der Link (gleiche vendor_id+subprocessor_id+role) bereits,
        wird die existierende ID zurueckgegeben (Idempotenz).
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT id FROM vendor_subprocessors
                 WHERE vendor_id = ? AND subprocessor_id = ? AND role = ?
                """,
                (int(vendor_id), int(subprocessor_id), role),
            ).fetchone()
            if row:
                return int(row[0])
            cur = conn.execute(
                """
                INSERT INTO vendor_subprocessors
                    (vendor_id, subprocessor_id, role, linked_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    int(vendor_id),
                    int(subprocessor_id),
                    role,
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def unlink(self, link_id: int) -> bool:
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM vendor_subprocessors WHERE id = ?",
                (int(link_id),),
            )
            conn.commit()
            return (cur.rowcount or 0) > 0

    def list_links_for_vendor(self, vendor_id: int) -> list[VendorSubprocessorLink]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT id, vendor_id, subprocessor_id, role, linked_at "
                "FROM vendor_subprocessors WHERE vendor_id = ? "
                "ORDER BY linked_at DESC",
                (int(vendor_id),),
            ).fetchall()
        return [self._row_to_link(r) for r in rows]

    def list_links_for_subprocessor(
        self, subprocessor_id: int
    ) -> list[VendorSubprocessorLink]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT id, vendor_id, subprocessor_id, role, linked_at "
                "FROM vendor_subprocessors WHERE subprocessor_id = ? "
                "ORDER BY linked_at DESC",
                (int(subprocessor_id),),
            ).fetchall()
        return [self._row_to_link(r) for r in rows]

    # ------------------------------------------------------------------
    # Kunden-Links (H, Live-Test 2026-07-01) — subject_id ist Cross-DB-Soft-FK
    # ------------------------------------------------------------------

    def link_customer(
        self, subject_id: str, subprocessor_id: int, role: str = ""
    ) -> int:
        """Erzeugt einen Link Kunde (``subject_id``) ↔ Subprocessor mit Rolle.

        Existiert der Link (gleiche subject_id+subprocessor_id+role) bereits,
        wird die existierende ID zurueckgegeben (Idempotenz, analog
:meth:`link`).
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT id FROM customer_subprocessors
                 WHERE subject_id = ? AND subprocessor_id = ? AND role = ?
                """,
                (subject_id, int(subprocessor_id), role),
            ).fetchone()
            if row:
                return int(row[0])
            cur = conn.execute(
                """
                INSERT INTO customer_subprocessors
                    (subject_id, subprocessor_id, role, linked_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    subject_id,
                    int(subprocessor_id),
                    role,
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def unlink_customer(self, link_id: int) -> bool:
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM customer_subprocessors WHERE id = ?",
                (int(link_id),),
            )
            conn.commit()
            return (cur.rowcount or 0) > 0

    def list_customer_links_for_subprocessor(
        self, subprocessor_id: int
    ) -> list[CustomerSubprocessorLink]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT id, subject_id, subprocessor_id, role, linked_at "
                "FROM customer_subprocessors WHERE subprocessor_id = ? "
                "ORDER BY linked_at DESC",
                (int(subprocessor_id),),
            ).fetchall()
        return [self._row_to_customer_link(r) for r in rows]

    def has_customer_references(self, subject_id: str) -> bool:
        """True, wenn der Kunde (``subject_id``) noch Subprocessor-Links haelt.

        DSGVO-Loesch-Block (H): analog zum Kunden-AVV-Referenz-Check
 E4) — ein Kunde soll nicht geloescht werden, solange
        Subunternehmer-Verknuepfungen auf ihn verweisen, sonst verwaisen die
        Links mit toter ``subject_id``. Wird ueber den core-Resolver
        (``create_avv_reference_check``, Composite) in den bestehenden
        fail-closed Loesch-Block eingehaengt.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM customer_subprocessors WHERE subject_id = ?",
                (subject_id,),
            ).fetchone()
        return bool(row and row[0])

    def concentration(self) -> dict[int, int]:
        """Konzentrationsrisiko-Aggregat: pro Subprocessor-ID die Anzahl
        Vendoren, die ihn nutzen.

        Returns:
            Mapping ``subprocessor_id → distinct vendor count``.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT subprocessor_id, COUNT(DISTINCT vendor_id) as cnt
                  FROM vendor_subprocessors
                 GROUP BY subprocessor_id
                """
            ).fetchall()
        return {int(r[0]): int(r[1]) for r in rows}

    # ------------------------------------------------------------------
    # Row-Mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_sub(row) -> Subprocessor:  # noqa: ANN001
        return Subprocessor(
            id=int(row[0]),
            name=row[1],
            country=row[2],
            category=VendorCategory.from_value(row[3]),
            notes=row[4] or "",
            created_at=_parse_iso_utc(row[5]),
            updated_at=_parse_iso_utc(row[6]),
        )

    @staticmethod
    def _row_to_link(row) -> VendorSubprocessorLink:  # noqa: ANN001
        return VendorSubprocessorLink(
            id=int(row[0]),
            vendor_id=int(row[1]),
            subprocessor_id=int(row[2]),
            role=row[3] or "",
            linked_at=_parse_iso_utc(row[4]),
        )

    @staticmethod
    def _row_to_customer_link(row) -> CustomerSubprocessorLink:  # noqa: ANN001
        return CustomerSubprocessorLink(
            id=int(row[0]),
            subject_id=row[1],
            subprocessor_id=int(row[2]),
            role=row[3] or "",
            linked_at=_parse_iso_utc(row[4]),
        )


def _parse_iso_utc(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(UTC)
