"""
vendor_detection_repository — Persistente Detection-Treffer + Status-Lifecycle.

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren, keine
application/gui-Importe.

Schema-Version 2: Tabelle ``vendor_detections``. Pro
Treffer eine Zeile mit ``UNIQUE(catalog_entry_id, source, raw_match)``,
damit Re-Scans bestehende Treffer aktualisieren statt zu duplizieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.supply_chain_monitor.domain.models import (
    DetectionSource,
    DetectionStatus,
    VendorDetection,
)

_log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vendor_detections (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    catalog_entry_id   INTEGER NOT NULL,
    source             TEXT NOT NULL,
    raw_match          TEXT NOT NULL,
    detected_at        TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    status_changed_at  TEXT NOT NULL,
    vendor_id          INTEGER
);
CREATE INDEX IF NOT EXISTS idx_vendor_detections_catalog
  ON vendor_detections(catalog_entry_id);
CREATE INDEX IF NOT EXISTS idx_vendor_detections_status
  ON vendor_detections(status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_vendor_detections_match
  ON vendor_detections(catalog_entry_id, source, raw_match);
"""


class VendorDetectionRepository:
    """CRUD + Upsert fuer:class:`VendorDetection`."""

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

    def upsert(self, detection: VendorDetection) -> int:
        """Fuegt einen Treffer ein oder aktualisiert nur ``detected_at``.

        Verhalten:
        - Wenn (catalog_entry_id, source, raw_match) noch nicht existiert:
          INSERT mit ``status = PENDING`` und gegebenem Detection-Stamp.
        - Wenn der Eintrag existiert: NUR ``detected_at`` wird auf den
          neuen Wert gesetzt — Status (insbesondere ``REJECTED``) und
          ``status_changed_at`` bleiben erhalten. So kommen einmal
          abgelehnte Vorschlaege nicht durch Re-Scans zurueck.

        Returns:
            Die ID des Detection-Eintrags (neu oder existierend).
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT id FROM vendor_detections
                 WHERE catalog_entry_id = ? AND source = ? AND raw_match = ?
                """,
                (
                    int(detection.catalog_entry_id),
                    detection.source.value,
                    detection.raw_match,
                ),
            ).fetchone()
            if row:
                existing_id = int(row[0])
                conn.execute(
                    "UPDATE vendor_detections SET detected_at = ? WHERE id = ?",
                    (detection.detected_at.isoformat(), existing_id),
                )
                conn.commit()
                return existing_id
            cur = conn.execute(
                """
                INSERT INTO vendor_detections
                    (catalog_entry_id, source, raw_match, detected_at,
                     status, status_changed_at, vendor_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(detection.catalog_entry_id),
                    detection.source.value,
                    detection.raw_match,
                    detection.detected_at.isoformat(),
                    detection.status.value,
                    detection.status_changed_at.isoformat(),
                    detection.vendor_id,
                ),
            )
            conn.commit()
            new_id = int(cur.lastrowid or 0)
        _log.info(
            "detection_upserted id=%s catalog_entry_id=%s source=%s",
            new_id,
            detection.catalog_entry_id,
            detection.source.value,
        )
        return new_id

    def get_by_id(self, detection_id: int) -> VendorDetection | None:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM vendor_detections WHERE id = ?",
                (int(detection_id),),
            ).fetchone()
        return self._row_to_detection(row) if row else None

    def list_for_catalog_entry(self, catalog_entry_id: int) -> list[VendorDetection]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM vendor_detections WHERE catalog_entry_id = ? "
                "ORDER BY detected_at DESC",
                (int(catalog_entry_id),),
            ).fetchall()
        return [self._row_to_detection(row) for row in rows]

    def list_actionable(self) -> list[VendorDetection]:
        """Alle Treffer mit Status ``PENDING`` oder ``DEFERRED``."""
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM vendor_detections "
                "WHERE status IN ('pending', 'deferred') "
                "ORDER BY detected_at DESC"
            ).fetchall()
        return [self._row_to_detection(row) for row in rows]

    def list_all(self) -> list[VendorDetection]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM vendor_detections ORDER BY detected_at DESC"
            ).fetchall()
        return [self._row_to_detection(row) for row in rows]

    def set_status(
        self,
        detection_id: int,
        new_status: DetectionStatus,
        vendor_id: int | None = None,
    ) -> None:
        """Aendert den Status eines Detection-Eintrags.

        Bei ``new_status = ACCEPTED`` MUSS ``vendor_id`` gesetzt sein —
        sonst ``ValueError``.

        Args:
            detection_id: ID des Detection-Eintrags.
            new_status: Neuer Status.
            vendor_id: Pflicht bei ``ACCEPTED``, sonst optional.

        Raises:
            ValueError: Bei ``ACCEPTED`` ohne ``vendor_id`` oder wenn der
                Detection-Eintrag nicht existiert.
        """
        if new_status is DetectionStatus.ACCEPTED and vendor_id is None:
            raise ValueError(
                "VendorDetectionRepository.set_status(ACCEPTED) braucht vendor_id."
            )
        now_iso = datetime.now(UTC).isoformat()
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                UPDATE vendor_detections
                SET status = ?, status_changed_at = ?, vendor_id = ?
                WHERE id = ?
                """,
                (
                    new_status.value,
                    now_iso,
                    vendor_id if new_status is DetectionStatus.ACCEPTED else None,
                    int(detection_id),
                ),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise ValueError(
                    f"Kein Detection-Eintrag mit id={detection_id} gefunden."
                )

    def delete_all_for_catalog_entry(self, catalog_entry_id: int) -> int:
        """Hilfsfunktion fuer Catalog-Cascade (nicht via FK gemacht).

        Returns:
            Anzahl geloeschter Zeilen.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM vendor_detections WHERE catalog_entry_id = ?",
                (int(catalog_entry_id),),
            )
            conn.commit()
        return int(cur.rowcount or 0)

    # ------------------------------------------------------------------
    # Row-Mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_detection(row) -> VendorDetection:  # noqa: ANN001
        return VendorDetection(
            id=int(row[0]),
            catalog_entry_id=int(row[1]),
            source=_safe_source(row[2]),
            raw_match=row[3],
            detected_at=_parse_iso_utc(row[4]),
            status=_safe_status(row[5]),
            status_changed_at=_parse_iso_utc(row[6]),
            vendor_id=int(row[7]) if row[7] is not None else None,
        )


def _safe_source(value: str) -> DetectionSource:
    try:
        return DetectionSource(value)
    except ValueError:
        # Unbekannter DB-Wert → behandelt wie INSTALLED_APP (geringstes Gewicht).
        return DetectionSource.INSTALLED_APP


def _safe_status(value: str) -> DetectionStatus:
    try:
        return DetectionStatus(value)
    except ValueError:
        return DetectionStatus.PENDING


def _parse_iso_utc(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(UTC)
