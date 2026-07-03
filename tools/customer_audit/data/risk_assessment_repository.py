"""
risk_assessment_repository — Persistierung der BSI-200-3-Risiko-Matrix.

Iter 2e: Tabelle ``audit_risk_assessments`` in der
``customer_audit``-DB. Atomarer Replace pro Audit.

Schichtzugehoerigkeit: data/ — darf DB-Zugriff nutzen.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.customer_audit.domain.risk_entities import (
    RiskAssessment,
    RiskCategory,
    RiskImpact,
    RiskProbability,
)

_log = get_logger(__name__)

_DB_NAME = "customer_audit"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_risk_assessments (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id            TEXT NOT NULL,
    catalog_key         TEXT NOT NULL DEFAULT '',
    custom_title        TEXT NOT NULL DEFAULT '',
    custom_description  TEXT NOT NULL DEFAULT '',
    custom_category     TEXT,
    probability         INTEGER NOT NULL,
    impact              INTEGER NOT NULL,
    notes               TEXT NOT NULL DEFAULT '',
    is_custom           INTEGER NOT NULL DEFAULT 0,
    is_accepted         INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_audit
  ON audit_risk_assessments(audit_id);
"""


class DbRiskAssessmentRepository:
    """SQLCipher-Implementation des:class:`RiskAssessmentRepository`-Ports."""

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        self._db = db or EncryptedDatabase(_DB_NAME)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._db.connection() as conn:
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)
            conn.commit()

    def upsert_for_audit(
        self, audit_id: str, assessments: list[RiskAssessment]
    ) -> None:
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM audit_risk_assessments WHERE audit_id = ?",
                (audit_id,),
            )
            for assessment in assessments:
                conn.execute(
                    """
                    INSERT INTO audit_risk_assessments
                        (audit_id, catalog_key, custom_title, custom_description,
                         custom_category, probability, impact, notes,
                         is_custom, is_accepted, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_id,
                        assessment.catalog_key,
                        assessment.custom_title,
                        assessment.custom_description,
                        assessment.custom_category.value
                        if assessment.custom_category
                        else None,
                        int(assessment.probability.value),
                        int(assessment.impact.value),
                        assessment.notes,
                        1 if assessment.is_custom else 0,
                        1 if assessment.is_accepted else 0,
                        assessment.created_at.isoformat(),
                        assessment.updated_at.isoformat(),
                    ),
                )
            conn.commit()
        _log.info(
            "risk_assessments_upserted audit_id=%s count=%s",
            audit_id,
            len(assessments),
        )

    def list_for_audit(self, audit_id: str) -> list[RiskAssessment]:
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, audit_id, catalog_key, custom_title, custom_description,
                       custom_category, probability, impact, notes,
                       is_custom, is_accepted, created_at, updated_at
                FROM audit_risk_assessments
                WHERE audit_id = ?
                ORDER BY (probability * impact) DESC, custom_title ASC
                """,
                (audit_id,),
            ).fetchall()
        return [self._row_to_assessment(r) for r in rows]

    def delete_for_audit(self, audit_id: str) -> int:
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM audit_risk_assessments WHERE audit_id = ?",
                (audit_id,),
            )
            conn.commit()
        return int(cur.rowcount or 0)

    @staticmethod
    def _row_to_assessment(row) -> RiskAssessment:  # noqa: ANN001
        category_value = row[5]
        custom_category: RiskCategory | None
        if category_value:
            try:
                custom_category = RiskCategory(category_value)
            except ValueError:
                custom_category = None
        else:
            custom_category = None
        return RiskAssessment(
            id=int(row[0]),
            audit_id=row[1],
            catalog_key=row[2] or "",
            custom_title=row[3] or "",
            custom_description=row[4] or "",
            custom_category=custom_category,
            probability=_safe_probability(row[6]),
            impact=_safe_impact(row[7]),
            notes=row[8] or "",
            is_custom=bool(row[9]),
            is_accepted=bool(row[10]),
            created_at=_parse_iso_utc(row[11]),
            updated_at=_parse_iso_utc(row[12]),
        )


def _safe_probability(value: int) -> RiskProbability:
    try:
        return RiskProbability(int(value))
    except ValueError:
        return RiskProbability.MITTEL


def _safe_impact(value: int) -> RiskImpact:
    try:
        return RiskImpact(int(value))
    except ValueError:
        return RiskImpact.BEGRENZT


def _parse_iso_utc(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(UTC)
