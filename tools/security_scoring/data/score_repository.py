"""
score_repository — Persistenz für Security-Score-Verlauf.

Implementiert IScoreRepository mit EncryptedDatabase (SQLCipher).
Scores werden als JSON-Blob gespeichert.

Sicherheitsdesign:
  - AES-256-CBC Vollverschlüsselung via EncryptedDatabase
  - Kein sqlite3.connect direkt — nur EncryptedDatabase

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.database.schema_utils import ensure_column
from core.herkunft import Herkunft
from core.logger import get_logger
from tools.security_scoring.domain.interfaces import IScoreRepository
from tools.security_scoring.domain.models import ScoreComponent, SecurityScore

log = get_logger(__name__)

_DB_NAME = "security_scoring"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scores (
    score_id     TEXT PRIMARY KEY,
    target_name  TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    overall      REAL NOT NULL,
    grade        TEXT NOT NULL,
    data_json    TEXT NOT NULL,
    subject_id   TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scores_target_ts
    ON scores(target_name, timestamp DESC);
"""


def _score_zu_dict(score: SecurityScore) -> dict:
    """Serialisiert einen SecurityScore in ein JSON-serialisierbares Dict."""
    return {
        "id": score.id,
        "target_name": score.target_name,
        "subject_id": score.subject_id,
        "herkunft": score.herkunft.value,
        "timestamp": score.timestamp,
        "overall_score": score.overall_score,
        "grade": score.grade,
        "summary": score.summary,
        "components": [
            {
                "name": c.name,
                "score": c.score,
                "weight": c.weight,
                "findings_critical": c.findings_critical,
                "findings_high": c.findings_high,
                "findings_medium": c.findings_medium,
                "last_scan": c.last_scan,
                "source_tool": c.source_tool,
            }
            for c in score.components
        ],
    }


def _dict_zu_score(data: dict) -> SecurityScore:
    """Deserialisiert einen SecurityScore aus einem Dict."""
    components = [
        ScoreComponent(
            name=c["name"],
            score=c["score"],
            weight=c["weight"],
            findings_critical=c.get("findings_critical", 0),
            findings_high=c.get("findings_high", 0),
            findings_medium=c.get("findings_medium", 0),
            last_scan=c.get("last_scan", ""),
            source_tool=c.get("source_tool", ""),
        )
        for c in data.get("components", [])
    ]
    return SecurityScore(
        id=data.get("id", str(uuid.uuid4())),
        target_name=data["target_name"],
        timestamp=data["timestamp"],
        overall_score=data["overall_score"],
        grade=data["grade"],
        components=components,
        summary=data.get("summary", ""),
        subject_id=data.get("subject_id", ""),
        herkunft=Herkunft.from_value(data.get("herkunft", "gemessen")),
    )


class ScoreRepository(IScoreRepository):
    """SQLCipher-basiertes Repository für Security-Score-Verlauf."""

    def __init__(self) -> None:
        """Initialisiert die Datenbank und das Schema."""
        self._db = EncryptedDatabase(_DB_NAME)
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)
            # additive subject_id-Spalte für Bestands-DBs. MUSS vor dem
            # subject_id-Index laufen: auf einer Pre--DB ist das CREATE
            # TABLE oben ein No-op (Tabelle existiert ohne subject_id), sodass
            # ein Index in _SCHEMA mit "no such column: subject_id" abbräche.
            ensure_column(conn, "scores", "subject_id", "TEXT DEFAULT ''")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scores_subject "
                "ON scores(subject_id)"
            )
            # E5: additive Provenance-Spalte (Bestand = SELF = 'gemessen').
            ensure_column(conn, "scores", "herkunft", "TEXT DEFAULT 'gemessen'")
        log.debug("ScoreRepository bereit.")

    def distinct_targets(self) -> list[str]:
        """Alle distinkten target_name-Werte (für Subjekt-Backfill)."""
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT target_name FROM scores"
            ).fetchall()
        return [r[0] for r in rows]

    def set_subject_id_for_target(self, target_name: str, subject_id: str) -> None:
        """Verknüpft alle Scores eines target_name mit einem Subjekt.

        Args:
            target_name: Bisheriger Freitext-Ziel-Name.
            subject_id: UUID des Subjekts.
        """
        with self._db.connection() as conn:
            conn.execute(
                "UPDATE scores SET subject_id = ? WHERE target_name = ?",
                (subject_id, target_name),
            )

    def count_targets_without_subject(self) -> int:
        """Anzahl distinkter NICHT-leerer ``target_name`` ohne Subjekt.

        Konsistenz-Assertion nach dem Backfill: jeder benennbare Ziel-Name
        (nicht leer/whitespace) muss verknuepft sein -> Rueckgabe 0. Leere Namen
        sind bewusst nicht verknuepfbar und daher ausgeschlossen.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT target_name) FROM scores "
                "WHERE (subject_id IS NULL OR subject_id = '') "
                "AND TRIM(target_name) <> ''"
            ).fetchone()
        return int(row[0]) if row else 0

    def count_for_subject(self, subject_id: str, name: str = "") -> int:
        """Anzahl Scores, die ein Subjekt referenzieren (Orphan-Check).

        Zaehlt ueber die ``subject_id``-Verknuepfung) ODER — defensiv fuer
        noch unverknuepfte Alt-Scores — ueber ``target_name`` == Subjekt-Name. So
        wird ein scoring-seitig noch genutztes Subjekt im DSGVO-Art.17-Loeschpfad
        nicht faelschlich als verwaist eingestuft.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM scores "
                "WHERE subject_id = ? OR (target_name = ? AND ? <> '')",
                (subject_id, name, name),
            ).fetchone()
        return int(row[0]) if row else 0

    def speichere_score(self, score: SecurityScore) -> None:
        """Speichert einen Security-Score.

        Args:
            score: Zu persistierender SecurityScore.
        """
        data_json = json.dumps(_score_zu_dict(score), ensure_ascii=False)
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scores
                    (score_id, target_name, timestamp, overall, grade,
                     data_json, subject_id, herkunft)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    score.id,
                    score.target_name,
                    score.timestamp,
                    score.overall_score,
                    score.grade,
                    data_json,
                    score.subject_id,
                    score.herkunft.value,
                ),
            )
        # F-3/F-6: kein ``target_name`` ins Log (kann ein Firmenname =
        # PII sein). Nur die nicht-personenbezogene ``subject_id`` (bzw. leer).
        log.debug(
            "Score gespeichert: subj=%s — %.1f (%s)",
            score.subject_id or "-",
            score.overall_score,
            score.grade,
        )

    def lade_letzte_scores(
        self,
        target_name: str,
        limit: int = 10,
    ) -> list[SecurityScore]:
        """Lädt die letzten Scores für ein Ziel.

        Args:
            target_name: Name des Ziels.
            limit: Maximale Anzahl.

        Returns:
            Scores neueste zuerst.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT data_json FROM scores
                WHERE target_name = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (target_name, limit),
            ).fetchall()
        result = []
        for (data_json,) in rows:
            try:
                result.append(_dict_zu_score(json.loads(data_json)))
            except Exception as exc:  # noqa: BLE001
                log.warning("Score-Deserialisierung fehlgeschlagen: %s", exc)
        return result

    def lade_letzte_scores_by_subject(
        self,
        subject_id: str,
        limit: int = 10,
    ) -> list[SecurityScore]:
        """Lädt die letzten Scores eines Subjekts.

        Subjekt-bewusster Lese-Pfad (stabil über eine Umbenennung des
        ``target_name``). Leeres ``subject_id`` liefert nichts — der
        Aufrufer fällt dann auf den ``target_name``-Pfad zurück.

        Args:
            subject_id: UUID des Subjekts.
            limit: Maximale Anzahl.

        Returns:
            Scores neueste zuerst (leer bei unbekanntem/leerem Subjekt).
        """
        if not subject_id:
            return []
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT data_json FROM scores
                WHERE subject_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (subject_id, limit),
            ).fetchall()
        result = []
        for (data_json,) in rows:
            try:
                result.append(_dict_zu_score(json.loads(data_json)))
            except Exception as exc:  # noqa: BLE001
                log.warning("Score-Deserialisierung fehlgeschlagen: %s", exc)
        return result

    def lade_bekannte_targets(self) -> list[str]:
        """Gibt alle bekannten Target-Namen zurück.

        Returns:
            Alphabetisch sortierte Liste.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT target_name FROM scores ORDER BY target_name"
            ).fetchall()
        return [row[0] for row in rows]

    def loesche_target(self, target_name: str) -> int:
        """Löscht alle Scores eines Targets.

        Args:
            target_name: Name des Ziels das entfernt werden soll.

        Returns:
            Anzahl gelöschter Einträge.
        """
        with self._db.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM scores WHERE target_name = ?", (target_name,)
            )
            count = cursor.rowcount
        # F-6: kein ``target_name`` (PII) im Loesch-Log — nur die Anzahl.
        log.info("Target gelöscht (%d Scores entfernt)", count)
        return count

    def loesche_scores_vor(self, cutoff: str) -> int:
        """Löscht Scores die älter als ein Cutoff-Datum sind.

        Args:
            cutoff: ISO-Datetime-String. Scores mit timestamp < cutoff werden gelöscht.

        Returns:
            Anzahl gelöschter Einträge.
        """
        with self._db.connection() as conn:
            cursor = conn.execute("DELETE FROM scores WHERE timestamp < ?", (cutoff,))
            return cursor.rowcount

    @staticmethod
    def _jetzt_iso() -> str:
        return datetime.now(UTC).isoformat()
