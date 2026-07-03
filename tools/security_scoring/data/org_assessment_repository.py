"""
org_assessment_repository — Persistenz für Org-Security-Assessments.

Nutzt EncryptedDatabase (SQLCipher, AES-256-CBC). Assessments werden als
JSON-Blob pro Eintrag gespeichert — strukturelle Änderungen erfordern keine
Schema-Migration.

Schichtzugehörigkeit: data/ — kapselt EncryptedDatabase-Zugriff.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json

from core.database.encrypted_db import EncryptedDatabase
from core.database.schema_utils import ensure_column
from core.logger import get_logger
from tools.security_scoring.domain.org_security import (
    OrgAntwort,
    OrgAssessment,
    OrgMetrikErgebnis,
)

log = get_logger(__name__)

_DB_NAME = "security_scoring"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS org_assessments (
    audit_id TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    data_json     TEXT NOT NULL,
    subject_id    TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_org_assessments_ts
    ON org_assessments(timestamp DESC);
"""


def _metrik_zu_dict(m: OrgMetrikErgebnis) -> dict:
    """Serialisiert eine OrgMetrikErgebnis in ein JSON-Dict."""
    return {
        "metrik": m.metrik,
        "antworten": {k: v.value for k, v in m.antworten.items()},
        "auto_status": m.auto_status,
        "auto_details": m.auto_details,
        "custom_pm_name": m.custom_pm_name,
    }


def _dict_zu_metrik(data: dict) -> OrgMetrikErgebnis:
    """Deserialisiert ein Dict zurück in OrgMetrikErgebnis."""
    antworten = {
        k: OrgAntwort(v) if v in {a.value for a in OrgAntwort} else OrgAntwort.UNBEKANNT
        for k, v in data.get("antworten", {}).items()
    }
    return OrgMetrikErgebnis(
        metrik=data["metrik"],
        antworten=antworten,
        auto_status=data.get("auto_status", ""),
        auto_details=data.get("auto_details", ""),
        custom_pm_name=data.get("custom_pm_name", ""),
    )


def _assessment_zu_dict(a: OrgAssessment) -> dict:
    return {
        "audit_id": a.audit_id,
        "timestamp": a.timestamp,
        "dsgvo": _metrik_zu_dict(a.dsgvo),
        "phishing": _metrik_zu_dict(a.phishing),
        "mfa": _metrik_zu_dict(a.mfa),
        "passwort_manager": _metrik_zu_dict(a.passwort_manager),
    }


def _dict_zu_assessment(data: dict) -> OrgAssessment:
    return OrgAssessment(
        audit_id=data["audit_id"],
        timestamp=data["timestamp"],
        dsgvo=_dict_zu_metrik(data["dsgvo"]),
        phishing=_dict_zu_metrik(data["phishing"]),
        mfa=_dict_zu_metrik(data["mfa"]),
        passwort_manager=_dict_zu_metrik(data["passwort_manager"]),
    )


class OrgAssessmentRepository:
    """EncryptedDatabase-Repository für Org-Security-Assessments."""

    def __init__(self) -> None:
        """Initialisiert die Datenbank und das Schema."""
        self._db = EncryptedDatabase(_DB_NAME)
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)
            # additive subject_id-Spalte für Bestands-DBs. MUSS vor dem
            # subject_id-Index laufen: auf einer Pre--DB ist das CREATE
            # TABLE oben ein No-op (Tabelle existiert ohne subject_id), sodass
            # ein Index in _SCHEMA mit "no such column: subject_id" abbräche.
            ensure_column(conn, "org_assessments", "subject_id", "TEXT DEFAULT ''")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_org_assessments_subject "
                "ON org_assessments(subject_id)"
            )
        log.debug("OrgAssessmentRepository bereit.")

    def list_audit_ids(self) -> list[str]:
        """Gibt alle audit_ids zurück (für Subjekt-Backfill)."""
        with self._db.connection() as conn:
            rows = conn.execute("SELECT audit_id FROM org_assessments").fetchall()
        return [r[0] for r in rows]

    def set_subject_id(self, audit_id: str, subject_id: str) -> None:
        """Verknüpft ein Org-Assessment mit einem Subjekt.

        Args:
            audit_id: PK des Assessments.
            subject_id: UUID des Subjekts.
        """
        with self._db.connection() as conn:
            conn.execute(
                "UPDATE org_assessments SET subject_id = ? WHERE audit_id = ?",
                (subject_id, audit_id),
            )

    def count_without_subject(self) -> int:
        """Anzahl Org-Assessments ohne verknuepftes Subjekt (NULL/leer).

        Konsistenz-Assertion nach dem Subjekt-Backfill: nach einem
        erfolgreichen Lauf muss JEDES Org-Assessment ein Subjekt tragen
        (Selbstbewertungen der eigenen Org -> eigenes Subjekt, kein Skip) ->
        Rueckgabe 0. Ein Wert > 0 signalisiert eine uebersehene Zeile.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM org_assessments "
                "WHERE subject_id IS NULL OR subject_id = ''"
            ).fetchone()
        return int(row[0]) if row else 0

    def count_for_subject(self, subject_id: str) -> int:
        """Anzahl Org-Assessments, die ein Subjekt referenzieren (Orphan-Check)."""
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM org_assessments WHERE subject_id = ?",
                (subject_id,),
            ).fetchone()
        return int(row[0]) if row else 0

    def speichere(self, assessment: OrgAssessment) -> None:
        """Speichert ein Assessment (Insert oder Replace anhand der ID).

        Args:
            assessment: Zu persistierendes OrgAssessment.
        """
        data_json = json.dumps(_assessment_zu_dict(assessment), ensure_ascii=False)
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO org_assessments
                    (audit_id, timestamp, data_json)
                VALUES (?, ?, ?)
                """,
                (assessment.audit_id, assessment.timestamp, data_json),
            )
        log.debug("Org-Assessment gespeichert: %s", assessment.audit_id)

    def lade_letztes(self) -> OrgAssessment | None:
        """Gibt das zuletzt gespeicherte Assessment zurück oder None.

        Hinweis F-5): liefert das GLOBAL juengste Assessment, ohne
        Subjekt-Filter — heute korrekt, weil Org-Assessments SELF-only sind.
        Fuer Multi-Subjekt-Kontexte (Phase C/D) ist
:meth:`lade_letztes_by_subject` zu verwenden (sonst IDOR/Cross-Subjekt).
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT data_json FROM org_assessments
                ORDER BY timestamp DESC
                LIMIT 1
                """
            ).fetchone()
        if not row:
            return None
        try:
            return _dict_zu_assessment(json.loads(row[0]))
        except (json.JSONDecodeError, KeyError) as exc:
            log.warning("Org-Assessment nicht lesbar: %s", type(exc).__name__)
            return None

    def lade_letztes_by_subject(self, subject_id: str) -> OrgAssessment | None:
        """Juengstes Assessment EINES Subjekts F-5 / IDOR-Fix).

        Filtert hart auf ``subject_id`` — anders als:meth:`lade_letztes`
        (global juengstes). Pflicht in Multi-Subjekt-Kontexten, damit die
        Bewertung eines Kunden nie das Assessment eines anderen Subjekts zeigt.

        Args:
            subject_id: UUID des Subjekts. Leer -> ``None``.

        Returns:
            Das juengste Assessment des Subjekts oder ``None``.
        """
        if not subject_id:
            return None
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT data_json FROM org_assessments "
                "WHERE subject_id = ? ORDER BY timestamp DESC LIMIT 1",
                (subject_id,),
            ).fetchone()
        if not row:
            return None
        try:
            return _dict_zu_assessment(json.loads(row[0]))
        except (json.JSONDecodeError, KeyError) as exc:
            log.warning("Org-Assessment nicht lesbar: %s", type(exc).__name__)
            return None
