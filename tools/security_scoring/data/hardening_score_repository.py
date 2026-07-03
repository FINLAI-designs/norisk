"""
hardening_score_repository — Persistenz fuer den Hardening-Score-Verlauf (Phase 4d).

Schreibt:class:`HardeningScoreResult`-Snapshots in eine eigene Tabelle
``hardening_scores`` der bestehenden ``security_scoring``-EncryptedDatabase
(SQLCipher). Liegt **neben** dem alten:class:`ScoreRepository`
(``SecurityScore`` legacy model) — kein Replace, kein Schema-Merge.

Begruendung der getrennten Tabelle:

* ``SecurityScore`` (Per-Tool-Aggregat, Schulnoten A-F) und
  ``HardeningScoreResult`` (5-Kategorien-Modell, 4 Stufen) sind zwei
  unterschiedliche Datenmodelle, die in unterschiedlichen Pfaden (alt:
  ``scoring_engine.calculate_overall_score`` / neu:
  ``hardening_score.compute_hardening_score``) entstehen.
* Spaeterer Schema-Bump fuer den Hardening-Score (z. B. Cap-Schema-V2)
  beruehrt die alte ``scores``-Tabelle nicht.

Sicherheitsdesign — identisch zu:class:`ScoreRepository`:

* AES-256-CBC Vollverschluesselung via:class:`EncryptedDatabase`.
* Kein ``sqlite3.connect`` direkt — Zugriff nur ueber die zentrale
  Encryption-Schicht.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from core.database.encrypted_db import EncryptedDatabase
from core.database.schema_utils import ensure_column
from core.herkunft import Herkunft
from core.logger import get_logger

if TYPE_CHECKING:
    from tools.security_scoring.domain.hardening_score import HardeningScoreResult

log = get_logger(__name__)

_DB_NAME = "security_scoring"

#: Retention pro Target: Es wird genau EIN Eintrag pro Target und
#: (UTC-)Tag gehalten — beim Speichern werden vorhandene Eintraege desselben
#: Tages ersetzt (neuester gewinnt) — und insgesamt nur die juengsten
#: ``_RETENTION_DAYS`` Eintraege (= Tage, nach Tages-Dedup) pro Target.
#: Daten-Hygiene / DSGVO-Datenminimierung; verhindert monoton wachsende
#: Tabelle bei haeufigem "Berechnen". 90 > alle Lese-Limits (load_history
#: Default 20, lade_hardening_verlauf 10) → Trend/Verlauf bleiben vollstaendig.
_RETENTION_DAYS = 90

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hardening_scores (
    score_id      TEXT PRIMARY KEY,
    target_name   TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    overall       REAL NOT NULL,
    raw_weighted  REAL NOT NULL,
    stage_label   TEXT NOT NULL,
    data_json     TEXT NOT NULL,
    subject_id    TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_h_scores_target_ts
    ON hardening_scores(target_name, timestamp DESC);
"""


class HardeningScoreRepository:
    """SQLCipher-Persistenz fuer den Hardening-Score-Verlauf.

    Schreibt eine eigene Tabelle ``hardening_scores`` parallel zur
    Legacy-``scores``-Tabelle aus:class:`ScoreRepository`.
    """

    def __init__(self) -> None:
        """Initialisiert DB-Verbindung und Schema."""
        self._db = EncryptedDatabase(_DB_NAME)
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)
            # additive subject_id-Spalte für Bestands-DBs. MUSS vor dem
            # subject_id-Index laufen: auf einer Pre--DB ist das CREATE
            # TABLE oben ein No-op (Tabelle existiert ohne subject_id), sodass
            # ein Index in _SCHEMA mit "no such column: subject_id" abbräche.
            ensure_column(conn, "hardening_scores", "subject_id", "TEXT DEFAULT ''")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_h_scores_subject "
                "ON hardening_scores(subject_id)"
            )
            # E5: additive Provenance-Spalte. Bestandszeilen sind
            # SELF-Live-Messungen -> Default 'gemessen' (fail-closed: ein
            # fehlender Wert ist nie 'erfasst'). Kein Index (reiner Filter,
            # kein Join-Key).
            ensure_column(
                conn, "hardening_scores", "herkunft", "TEXT DEFAULT 'gemessen'"
            )
        log.debug("HardeningScoreRepository bereit.")

    def set_subject_id_for_target(self, target_name: str, subject_id: str) -> None:
        """Verknüpft alle Hardening-Scores eines target_name mit einem Subjekt.

        Args:
            target_name: Bisheriger Freitext-Ziel-Name.
            subject_id: UUID des Subjekts.
        """
        with self._db.connection() as conn:
            conn.execute(
                "UPDATE hardening_scores SET subject_id = ? WHERE target_name = ?",
                (subject_id, target_name),
            )

    def count_targets_without_subject(self) -> int:
        """Anzahl distinkter NICHT-leerer ``target_name`` ohne Subjekt.

        Konsistenz-Assertion nach dem Backfill: jeder benennbare Ziel-Name
        muss verknuepft sein -> Rueckgabe 0 (leere Namen ausgeschlossen).
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT target_name) FROM hardening_scores "
                "WHERE (subject_id IS NULL OR subject_id = '') "
                "AND TRIM(target_name) <> ''"
            ).fetchone()
        return int(row[0]) if row else 0

    def count_for_subject(self, subject_id: str, name: str = "") -> int:
        """Anzahl Hardening-Scores, die ein Subjekt referenzieren (Orphan-Check).

        Zaehlt ueber ``subject_id`` ODER — defensiv — ``target_name`` == Name,
        damit ein scoring-seitig noch genutztes Subjekt im DSGVO-Loeschpfad nicht
        faelschlich als verwaist gilt.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM hardening_scores "
                "WHERE subject_id = ? OR (target_name = ? AND ? <> '')",
                (subject_id, name, name),
            ).fetchone()
        return int(row[0]) if row else 0

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save_score(
        self,
        target_name: str,
        result: HardeningScoreResult,
        *,
        timestamp: str | None = None,
        score_id: str | None = None,
        subject_id: str = "",
    ) -> str:
        """Speichert ein ``HardeningScoreResult`` als History-Eintrag.

        Retention: pro **Subjekt** wird genau EIN Eintrag pro (UTC-)Tag
        gehalten — vorhandene Eintraege desselben Tages werden zuerst
        entfernt, sodass der neueste gewinnt — und insgesamt nur die juengsten
:data:`_RETENTION_DAYS` Eintraege (= Tage). Verhindert eine monoton
        wachsende Tabelle bei haeufigem "Berechnen" (Daten-Hygiene/DSGVO-
        Datenminimierung) und haelt den Verlauf-Chart als Tages-Trend sauber.

        Retention-Schluessel: ``COALESCE(NULLIF(subject_id,''),
        target_name)`` — ist ``subject_id`` gesetzt, gilt das stabile Subjekt
        als Trend-Achse (uebersteht eine Umbenennung des ``target_name``); ist
        es leer (Bestandsdaten vor dem Backfill), faellt der Schluessel auf den
        bisherigen ``target_name`` zurueck. So bleiben gemischte Bestaende
        korrekt getrennt.

        Args:
            target_name: Identifier fuer das gescannte System (z. B.
                Hostname, Workstation-ID). Bleibt als Anzeige-/Back-Compat-
                Spalte erhalten.
            result: Berechnetes Ergebnis aus
:func:`tools.security_scoring.domain.hardening_score.compute_hardening_score`.
            timestamp: Optionaler ISO-8601-UTC-Timestamp; default ist
                ``datetime.now(UTC).isoformat``. Muss UTC-ISO sein — der
                Tages-Bucket (Dedup, ``substr(...,1,10)``) und die
                Cap-Sortierung (``ORDER BY timestamp``) leiten sich daraus ab.
            score_id: Optional eigenes Score-ID. Default ist
                ``uuid.uuid4.hex``.
            subject_id: UUID des kanonischen Subjekts. Leer =
                Retention faellt auf ``target_name`` zurueck.

        Returns:
            Die verwendete ``score_id`` — Caller kann sie z. B. fuer
            spaetere Cross-References speichern.
        """
        ts = timestamp or _now_iso()
        day = ts[:10]  # ISO-8601-Datumsteil "YYYY-MM-DD" (Tages-Schluessel)
        sid = score_id or uuid.uuid4().hex
        data_json = json.dumps(_result_to_dict(result), ensure_ascii=False)

        with self._db.connection() as conn:
            # 1. Tages-Dedup: bestehende Eintraege desselben Tages/Subjekts
            # entfernen, damit der jetzt gespeicherte (neueste) gewinnt.
            conn.execute(
                "DELETE FROM hardening_scores "
                "WHERE COALESCE(NULLIF(subject_id, ''), target_name) "
                "      = COALESCE(NULLIF(?, ''), ?) "
                "  AND substr(timestamp, 1, 10) = ?",
                (subject_id, target_name, day),
            )
            # 2. Neuen Eintrag schreiben (OR REPLACE deckt einen erneut
            # uebergebenen score_id ab).
            conn.execute(
                """
                INSERT OR REPLACE INTO hardening_scores
                    (score_id, target_name, timestamp, overall, raw_weighted,
                     stage_label, data_json, subject_id, herkunft)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sid,
                    target_name,
                    ts,
                    float(result.overall_score),
                    float(result.raw_weighted_score),
                    result.stage.label,
                    data_json,
                    subject_id,
                    result.herkunft.value,
                ),
            )
            # 3. Cap: nur die juengsten _RETENTION_DAYS Eintraege pro Subjekt
            # behalten (nach Tages-Dedup = ein Eintrag/Tag → N Tage).
            conn.execute(
                """
                DELETE FROM hardening_scores
                WHERE COALESCE(NULLIF(subject_id, ''), target_name)
                      = COALESCE(NULLIF(?, ''), ?)
                  AND score_id NOT IN (
                    SELECT score_id FROM hardening_scores
                    WHERE COALESCE(NULLIF(subject_id, ''), target_name)
                          = COALESCE(NULLIF(?, ''), ?)
                    ORDER BY timestamp DESC
                    LIMIT ?
                  )
                """,
                (subject_id, target_name, subject_id, target_name, _RETENTION_DAYS),
            )
        # F-3: kein ``target_name`` ins Log (potenziell Firmenname/PII).
        log.debug(
            "Hardening-Score gespeichert: subj=%s — %.1f (%s)",
            subject_id or "-",
            result.overall_score,
            result.stage.label,
        )
        return sid

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_last_two_scores(
        self,
        target_name: str,
    ) -> tuple[float, float] | None:
        """Holt die zwei juengsten Scores fuer ein Target.

        Args:
            target_name: Target-Identifier.

        Returns:
            Tuple ``(previous, current)`` mit den letzten zwei
            ``overall_score``-Werten — current ist das neueste.
            ``None`` wenn weniger als 2 Eintraege fuer ``target_name``
            existieren (Trend-Pfeil zeigt dann "kein Vergleich").
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT overall FROM hardening_scores
                WHERE target_name = ?
                ORDER BY timestamp DESC
                LIMIT 2
                """,
                (target_name,),
            ).fetchall()
        if len(rows) < 2:
            return None
        current_score = float(rows[0][0])
        previous_score = float(rows[1][0])
        return previous_score, current_score

    def load_history(
        self,
        target_name: str,
        *,
        limit: int = 20,
    ) -> list[tuple[str, float]]:
        """Holt einen Verlauf ``(timestamp, overall_score)`` pro Target.

        Args:
            target_name: Target-Identifier.
            limit: Maximale Anzahl. Default 20.

        Returns:
            Liste neueste zuerst, leer wenn unbekanntes Target.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT timestamp, overall FROM hardening_scores
                WHERE target_name = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (target_name, limit),
            ).fetchall()
        return [(ts, float(score)) for ts, score in rows]

    def load_latest_result(
        self,
        target_name: str | None = None,
    ) -> HardeningScoreResult | None:
        """Rehydriert den juengsten persistierten Hardening-Score.

        Liest den neuesten ``hardening_scores``-Eintrag und baut aus dem
        ``data_json``-Blob ein vollstaendiges:class:`HardeningScoreResult`
        zurueck (inkl. Kategorie-Breakdown, fehlende Kategorien und
        Hard-Cap-Events). Inverse zu:func:`_result_to_dict`.

        Hintergrund: Das ``norisk_dashboard`` zeigt damit den zuletzt im
        Security-Scoring-Tab berechneten Score, ohne pro ``aggregate``
        einen vollen Live-Compute (Sub-Service-Stack) auf dem GUI-Thread
        aufzubauen, P2-Finding aus dem-Security-Review).

        Args:
            target_name: Optionaler Ziel-Filter. ``None`` (Default) liefert
                den global juengsten Eintrag — in der Praxis schreibt nur
                der Scoring-Tab (ein eigenes System, ein stabiler
                ``target_name``), daher entspricht "global juengster" dem
                eigenen System.

        Returns:
            Das rehydrierte:class:`HardeningScoreResult` oder ``None`` wenn
            (noch) kein passender Eintrag existiert.
        """
        if target_name is None:
            sql = (
                "SELECT data_json FROM hardening_scores "
                "ORDER BY timestamp DESC LIMIT 1"
            )
            params: tuple[str, ...] = ()
        else:
            sql = (
                "SELECT data_json FROM hardening_scores "
                "WHERE target_name = ? ORDER BY timestamp DESC LIMIT 1"
            )
            params = (target_name,)

        with self._db.connection() as conn:
            row = conn.execute(sql, params).fetchone()
        if row is None:
            return None
        return _dict_to_result(json.loads(row[0]))

    def load_latest_measured_result(self) -> HardeningScoreResult | None:
        """Juengster GEMESSENER Hardening-Score P0-A, SELF-Kachel).

        Filtert auf ``herkunft = 'gemessen'`` — also ausschliesslich Live-
        Messungen des eigenen Systems. Manuell fuer Kunden erfasste Werte
        (``herkunft = 'erfasst'``) sind ausgeschlossen, damit die Cockpit-
        Kachel „Messung (Hardening)" nie versehentlich Kundendaten zeigt: ohne
        diesen Filter wuerde ein Kunden-Eintrag mit neuerem Timestamp den global
        juengsten Eintrag stellen. Nur das eigene System ist messbar
/ E2) -> ``GEMESSEN`` ist aequivalent zu SELF.

        Returns:
            Das rehydrierte:class:`HardeningScoreResult` oder ``None`` wenn
            (noch) kein gemessener Eintrag existiert.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT data_json FROM hardening_scores "
                "WHERE herkunft = 'gemessen' "
                "ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return _dict_to_result(json.loads(row[0]))

    def load_latest_result_by_subject(
        self, subject_id: str
    ) -> HardeningScoreResult | None:
        """Juengster Hardening-Score EINES Subjekts Phase A).

        Subjekt-gefilterter Lese-Pfad fuer die Kunden-Ansicht. Leeres
        ``subject_id`` -> ``None``.
        """
        if not subject_id:
            return None
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT data_json FROM hardening_scores "
                "WHERE subject_id = ? ORDER BY timestamp DESC LIMIT 1",
                (subject_id,),
            ).fetchone()
        if row is None:
            return None
        return _dict_to_result(json.loads(row[0]))

    def load_history_by_subject(
        self, subject_id: str, *, limit: int = 20
    ) -> list[tuple[str, float]]:
        """Verlauf ``(timestamp, overall)`` eines Subjekts Phase A)."""
        if not subject_id:
            return []
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT timestamp, overall FROM hardening_scores "
                "WHERE subject_id = ? ORDER BY timestamp DESC LIMIT ?",
                (subject_id, limit),
            ).fetchall()
        return [(ts, float(score)) for ts, score in rows]

    def get_last_two_scores_by_subject(
        self, subject_id: str
    ) -> tuple[float, float] | None:
        """Zwei juengste Scores eines Subjekts ``(previous, current)`` (Trend)."""
        if not subject_id:
            return None
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT overall FROM hardening_scores "
                "WHERE subject_id = ? ORDER BY timestamp DESC LIMIT 2",
                (subject_id,),
            ).fetchall()
        if len(rows) < 2:
            return None
        return float(rows[1][0]), float(rows[0][0])

    def list_targets(self) -> list[str]:
        """Alle bekannten Target-Namen (sortiert, deduped)."""
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT target_name FROM hardening_scores "
                "ORDER BY target_name"
            ).fetchall()
        return [row[0] for row in rows]

    def delete_target(self, target_name: str) -> int:
        """Loescht alle Eintraege eines Targets.

        Args:
            target_name: Target-Identifier.

        Returns:
            Anzahl geloeschter Zeilen.
        """
        with self._db.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM hardening_scores WHERE target_name = ?",
                (target_name,),
            )
            return int(cursor.rowcount)


# ---------------------------------------------------------------------------
# Serialisierung
# ---------------------------------------------------------------------------


def _result_to_dict(result: HardeningScoreResult) -> dict:
    """Serialisiert ein ``HardeningScoreResult`` zu einem JSON-Dict.

    Stage wird als Label gespeichert; Beim Read sind nur die Skalar-Felder
    (overall, raw, stage_label) ueber Spalten direkt zugaenglich — das
    JSON-Blob ist optional fuer Re-Hydration (z. B. spaeterer Drill-Down).
    """
    return {
        "overall_score": float(result.overall_score),
        "raw_weighted_score": float(result.raw_weighted_score),
        "stage_label": result.stage.label,
        "stage_color_key": result.stage.color_key,
        "herkunft": result.herkunft.value,
        "category_scores": [
            {
                "category": cs.category.value,
                "score": float(cs.score),
                "weight": float(cs.weight),
                "components_count": int(cs.components_count),
            }
            for cs in result.category_scores
        ],
        "missing_categories": [c.value for c in result.missing_categories],
        "hard_cap_events": [
            {
                "label": e.label,
                "cap_value": int(e.cap_value),
                "triggered_by": e.triggered_by,
                "details": e.details,
            }
            for e in result.hard_cap_events
        ],
    }


def _dict_to_result(payload: dict) -> HardeningScoreResult:
    """Rehydriert ein:class:`HardeningScoreResult` aus einem JSON-Dict.

    Inverse zu:func:`_result_to_dict`. Die Stage wird kanonisch ueber
:func:`score_to_stage` aus dem ``overall_score`` rekonstruiert (sie ist
    per Design eine reine Funktion des gecappten Scores) — das stellt die
    Anzeige-Konsistenz mit dem Scoring-Tab sicher und kommt ohne die nicht
    persistierten ``min_score``/``max_score``-Schwellen aus.

    Args:
        payload: Das aus ``data_json`` geparste Dict.

    Returns:
        Das rekonstruierte:class:`HardeningScoreResult`.
    """
    from tools.security_scoring.domain.hardening_caps import (  # noqa: PLC0415
        HardCapEvent,
    )
    from tools.security_scoring.domain.hardening_categories import (  # noqa: PLC0415
        HardeningCategory,
    )
    from tools.security_scoring.domain.hardening_score import (  # noqa: PLC0415
        CategoryScore,
    )
    from tools.security_scoring.domain.hardening_score import (
        HardeningScoreResult as _Result,
    )
    from tools.security_scoring.domain.hardening_stages import (  # noqa: PLC0415
        score_to_stage,
    )

    # Pflicht-Skalare (overall/raw) werden hart gelesen — fehlen sie, ist das
    # JSON korrupt und soll fail-loud brechen (kein stiller Default-Wert). Die
    # Listen-Felder sind leer-tolerant (``.get(..., [])``), weil "keine
    # Kategorien/Caps" ein gueltiger Zustand ist. ``ValueError``/``KeyError``
    # faengt der application-Wrapper ``lade_letztes_hardening_result`` fail-soft.
    overall = float(payload["overall_score"])
    category_scores = tuple(
        CategoryScore(
            category=HardeningCategory(cs["category"]),
            score=float(cs["score"]),
            weight=float(cs["weight"]),
            components_count=int(cs["components_count"]),
        )
        for cs in payload.get("category_scores", [])
    )
    missing = tuple(
        HardeningCategory(value)
        for value in payload.get("missing_categories", [])
    )
    hard_cap_events = tuple(
        HardCapEvent(
            label=str(e["label"]),
            cap_value=int(e["cap_value"]),
            triggered_by=str(e["triggered_by"]),
            details=str(e.get("details", "")),
        )
        for e in payload.get("hard_cap_events", [])
    )
    return _Result(
        overall_score=overall,
        stage=score_to_stage(overall),
        category_scores=category_scores,
        missing_categories=missing,
        hard_cap_events=hard_cap_events,
        raw_weighted_score=float(payload["raw_weighted_score"]),
        # Fehlt der Key (Bestandszeile vor) -> 'gemessen' (= SELF);
        # from_value ist fail-closed (unbekannt -> nie GEMESSEN).
        herkunft=Herkunft.from_value(payload.get("herkunft", "gemessen")),
    )


def _now_iso() -> str:
    """ISO-8601-UTC-Timestamp — extrahiert fuer Test-Mockability."""
    return datetime.now(UTC).isoformat()
