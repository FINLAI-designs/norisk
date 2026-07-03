"""
advisory_repository_impl — EncryptedDatabase-Implementierung des Advisory-Repositories.

Alle Tabellen werden bei erster Nutzung angelegt (CREATE TABLE IF NOT EXISTS).
Verwendet ausschließlich EncryptedDatabase — kein direkter sqlite3-Zugriff.

Schichtzugehörigkeit: data/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.csaf_advisor.data.provider_registry import CURATED_CSAF_PROVIDERS
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch
from tools.csaf_advisor.domain.advisory_repository import IAdvisoryRepository
from tools.csaf_advisor.domain.csaf_provider import CsafProvider

log = get_logger(__name__)

_DB_NAME = "csaf_advisor"

_DDL_ADVISORIES = """
CREATE TABLE IF NOT EXISTS csaf_advisories (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    publisher TEXT NOT NULL,
    tracking_id TEXT NOT NULL,
    tracking_version TEXT DEFAULT '1',
    initial_release TEXT DEFAULT '',
    current_release TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    cvss_score REAL,
    cve_ids TEXT DEFAULT '[]',
    affected_products TEXT DEFAULT '[]',
    summary TEXT DEFAULT '',
    source_url TEXT DEFAULT '',
    raw_json TEXT DEFAULT '',
    fetched_at TEXT DEFAULT (datetime('now')),
    UNIQUE(tracking_id, tracking_version)
)
"""

_DDL_PROVIDERS = """
CREATE TABLE IF NOT EXISTS csaf_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    provider_url TEXT NOT NULL,
    feed_url TEXT DEFAULT '',
    source TEXT DEFAULT 'user',
    enabled INTEGER DEFAULT 1,
    last_fetch TEXT DEFAULT '',
    advisory_count INTEGER DEFAULT 0
)
"""

_DDL_MATCHES = """
CREATE TABLE IF NOT EXISTS csaf_matches (
    id TEXT PRIMARY KEY,
    advisory_id TEXT NOT NULL,
    component_name TEXT NOT NULL,
    component_version TEXT DEFAULT '',
    confidence REAL DEFAULT 0.0,
    action_required TEXT DEFAULT 'monitor',
    matched_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (advisory_id) REFERENCES csaf_advisories(id)
)
"""


class AdvisoryRepository(IAdvisoryRepository):
    """EncryptedDatabase-Implementierung des Advisory-Repositories.

    Legt die Tabellen beim ersten Zugriff an und befüllt sie mit
    kuratierten Providern wenn sie noch nicht vorhanden sind.

    Attributes:
        _db: EncryptedDatabase-Instanz für den DB-Zugriff.
    """

    def __init__(self) -> None:
        """Initialisiert das Repository und legt Tabellen + Seeding an."""
        self._db = EncryptedDatabase(_DB_NAME)
        self._ensure_schema()
        self._seed_curated_providers()

    # ------------------------------------------------------------------
    # Schema + Seeding
    # ------------------------------------------------------------------

    def _ensure_schema(self) -> None:
        """Legt alle Tabellen an wenn sie noch nicht existieren."""
        with self._db.connection() as conn:
            conn.execute(_DDL_ADVISORIES)
            conn.execute(_DDL_PROVIDERS)
            conn.execute(_DDL_MATCHES)

    def _seed_curated_providers(self) -> None:
        """Synchronisiert kuratierte Provider mit ``CURATED_CSAF_PROVIDERS``.

        Verhalten:
          * Neuer Eintrag → INSERT (mit Default-``enabled``-Wert).
          * Existierender Eintrag → UPDATE auf aktuelle ``name``-,
            ``provider_url``- und ``feed_url``-Werte. Das
            ``enabled``-Flag bleibt unangetastet, damit der User
            manuell de-/aktivierte Provider behält.
          * ``last_fetch`` und ``advisory_count`` werden ebenfalls
            unangetastet — nur die Identitäts-/URL-Felder migrieren.

        Hintergrund follow-up, 2026-05-14): Mehrere Provider-
        URLs sind veraltet (BSI ``white/feed.json`` → 404, CISA
        well-known → 404, Red Hat ``access.redhat.com`` → migriert).
        Ohne diese Migration würden bestehende Patrick-Installationen
        weiter mit den toten URLs fetchen.
        """
        with self._db.connection() as conn:
            for provider in CURATED_CSAF_PROVIDERS:
                existing = conn.execute(
                    "SELECT id FROM csaf_providers WHERE id = ?",
                    (provider.id,),
                ).fetchone()
                if existing is None:
                    conn.execute(
                        """
                        INSERT INTO csaf_providers
                            (id, name, provider_url, feed_url, source, enabled,
                             last_fetch, advisory_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            provider.id,
                            provider.name,
                            provider.provider_url,
                            provider.feed_url,
                            provider.source,
                            1 if provider.enabled else 0,
                            provider.last_fetch,
                            provider.advisory_count,
                        ),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE csaf_providers
                           SET name = ?,
                               provider_url = ?,
                               feed_url = ?
                         WHERE id = ?
                        """,
                        (
                            provider.name,
                            provider.provider_url,
                            provider.feed_url,
                            provider.id,
                        ),
                    )

    # ------------------------------------------------------------------
    # Advisory-Persistenz
    # ------------------------------------------------------------------

    def save_advisory(self, advisory: CsafAdvisory) -> None:
        """Speichert oder aktualisiert ein Advisory (UPSERT).

        Args:
            advisory: Das zu speichernde Advisory.
        """
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO csaf_advisories
                    (id, title, publisher, tracking_id, tracking_version,
                     initial_release, current_release, severity, cvss_score,
                     cve_ids, affected_products, summary, source_url, raw_json, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tracking_id, tracking_version) DO UPDATE SET
                    title = excluded.title,
                    publisher = excluded.publisher,
                    severity = excluded.severity,
                    cvss_score = excluded.cvss_score,
                    cve_ids = excluded.cve_ids,
                    affected_products = excluded.affected_products,
                    summary = excluded.summary,
                    source_url = excluded.source_url,
                    fetched_at = excluded.fetched_at
                """,
                (
                    advisory.id,
                    advisory.title,
                    advisory.publisher,
                    advisory.tracking_id,
                    advisory.tracking_version,
                    advisory.initial_release,
                    advisory.current_release,
                    advisory.severity,
                    advisory.cvss_score,
                    json.dumps(advisory.cve_ids),
                    json.dumps(advisory.affected_products),
                    advisory.summary,
                    advisory.source_url,
                    advisory.raw_json,
                    advisory.fetched_at,
                ),
            )

    def get_advisory(self, advisory_id: str) -> CsafAdvisory | None:
        """Gibt ein Advisory anhand seiner ID zurück.

        Args:
            advisory_id: Eindeutige Advisory-ID.

        Returns:
            CsafAdvisory oder None wenn nicht gefunden.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM csaf_advisories WHERE id = ?",
                (advisory_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_advisory(row)

    def list_advisories(
        self,
        severity: str | None = None,
        publisher: str | None = None,
        days: int | None = None,
    ) -> list[CsafAdvisory]:
        """Gibt gefilterte Advisories zurück.

        Args:
            severity: Schweregrad-Filter (oder None = alle).
            publisher: Publisher-Filter (oder None = alle).
            days: Zeitraum-Filter in Tagen — bezogen auf
                       ``current_release`` (Veröffentlichungsdatum des
                       Advisories), **nicht** auf ``fetched_at`` (Download-
                       Zeitpunkt). follow-up 2026-05-14: vorher hat
                       der Filter auf ``fetched_at`` geprueft, was bei
                       einem initialen Bulk-Download alle Advisories als
                       "neu" markierte — auch 2020er Eintraege landeten
                       im 7-Tage-Filter.

        Returns:
            Liste der passenden Advisories.
        """
        conditions: list[str] = []
        params: list[object] = []

        if severity:
            conditions.append("LOWER(severity) = LOWER(?)")
            params.append(severity)

        if publisher:
            conditions.append("LOWER(publisher) = LOWER(?)")
            params.append(publisher)

        if days is not None:
            cutoff = (datetime.now(tz=UTC) - timedelta(days=days)).isoformat()
            # current_release ist ISO-8601 UTC (CSAF-Spec) — lexikograph.
            # Vergleich genuegt fuer den Cutoff.
            conditions.append("current_release >= ?")
            params.append(cutoff)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        # Conditions sind ausschließlich hartcodierte Strings — kein User-Input in der Query
        query = f"SELECT * FROM csaf_advisories {where} ORDER BY current_release DESC"  # noqa: S608 # nosec B608

        with self._db.connection() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_advisory(r) for r in rows]

    def advisory_count(self) -> int:
        """Gibt die Gesamtanzahl gespeicherter Advisories zurück.

        Returns:
            Anzahl der Advisories.
        """
        with self._db.connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM csaf_advisories").fetchone()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Provider-Persistenz
    # ------------------------------------------------------------------

    def save_provider(self, provider: CsafProvider) -> None:
        """Speichert oder aktualisiert einen Provider (UPSERT).

        Args:
            provider: Der zu speichernde Provider.
        """
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO csaf_providers
                    (id, name, provider_url, feed_url, source, enabled,
                     last_fetch, advisory_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    provider_url = excluded.provider_url,
                    feed_url = excluded.feed_url,
                    enabled = excluded.enabled,
                    last_fetch = excluded.last_fetch,
                    advisory_count = excluded.advisory_count
                """,
                (
                    provider.id,
                    provider.name,
                    provider.provider_url,
                    provider.feed_url,
                    provider.source,
                    1 if provider.enabled else 0,
                    provider.last_fetch,
                    provider.advisory_count,
                ),
            )

    def list_providers(self) -> list[CsafProvider]:
        """Gibt alle gespeicherten Provider zurück.

        Returns:
            Liste aller Provider.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM csaf_providers ORDER BY source DESC, name ASC"
            ).fetchall()
        return [self._row_to_provider(r) for r in rows]

    def get_provider(self, provider_id: str) -> CsafProvider | None:
        """Gibt einen Provider anhand seiner ID zurück.

        Args:
            provider_id: Eindeutige Provider-ID.

        Returns:
            CsafProvider oder None wenn nicht gefunden.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM csaf_providers WHERE id = ?",
                (provider_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_provider(row)

    def delete_provider(self, provider_id: str) -> None:
        """Löscht einen Provider (nur user-definierte).

        Kuratierte Provider werden nicht gelöscht (nur stillschweigend ignoriert).

        Args:
            provider_id: Eindeutige Provider-ID.
        """
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM csaf_providers WHERE id = ? AND source = 'user'",
                (provider_id,),
            )

    # ------------------------------------------------------------------
    # Match-Persistenz
    # ------------------------------------------------------------------

    def save_match(self, match: AdvisoryMatch) -> None:
        """Speichert einen Advisory-Treffer.

        Args:
            match: Der zu speichernde Treffer.
        """
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO csaf_matches
                    (id, advisory_id, component_name, component_version,
                     confidence, action_required, matched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    match.id,
                    match.advisory_id,
                    match.matched_component,
                    match.matched_version,
                    match.confidence,
                    match.action_required,
                    match.matched_at,
                ),
            )

    def list_matches(self) -> list[AdvisoryMatch]:
        """Gibt alle gespeicherten Treffer zurück.

        Returns:
            Liste aller Treffer sortiert nach Confidence (absteigend).
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM csaf_matches ORDER BY confidence DESC"
            ).fetchall()
        return [self._row_to_match(r) for r in rows]

    def clear_matches(self) -> None:
        """Löscht alle gespeicherten Treffer."""
        with self._db.connection() as conn:
            conn.execute("DELETE FROM csaf_matches")

    # ------------------------------------------------------------------
    # Hilfsmethoden — Row-Mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_advisory(row: object) -> CsafAdvisory:
        """Konvertiert eine DB-Zeile in ein CsafAdvisory-Objekt.

        Args:
            row: sqlite3.Row oder Tuple.

        Returns:
            CsafAdvisory-Instanz.
        """
        cve_ids: list[str] = []
        affected: list[str] = []
        try:
            cve_ids = json.loads(row[9])
        except (json.JSONDecodeError, IndexError, TypeError):
            pass
        try:
            affected = json.loads(row[10])
        except (json.JSONDecodeError, IndexError, TypeError):
            pass

        return CsafAdvisory(
            id=row[0],
            title=row[1],
            publisher=row[2],
            tracking_id=row[3],
            tracking_version=row[4],
            initial_release=row[5] or "",
            current_release=row[6] or "",
            severity=row[7] or "medium",
            cvss_score=row[8],
            cve_ids=cve_ids,
            affected_products=affected,
            summary=row[11] or "",
            source_url=row[12] or "",
            raw_json=row[13] or "",
            fetched_at=row[14] or "",
        )

    @staticmethod
    def _row_to_provider(row: object) -> CsafProvider:
        """Konvertiert eine DB-Zeile in ein CsafProvider-Objekt.

        Args:
            row: sqlite3.Row oder Tuple.

        Returns:
            CsafProvider-Instanz.
        """
        return CsafProvider(
            id=row[0],
            name=row[1],
            provider_url=row[2],
            feed_url=row[3] or "",
            source=row[4] or "user",
            enabled=bool(row[5]),
            last_fetch=row[6] or "",
            advisory_count=row[7] or 0,
        )

    @staticmethod
    def _row_to_match(row: object) -> AdvisoryMatch:
        """Konvertiert eine DB-Zeile in ein AdvisoryMatch-Objekt.

        Args:
            row: sqlite3.Row oder Tuple.

        Returns:
            AdvisoryMatch-Instanz.
        """
        return AdvisoryMatch(
            id=row[0],
            advisory_id=row[1],
            matched_component=row[2],
            matched_version=row[3] or "",
            confidence=row[4] or 0.0,
            action_required=row[5] or "monitor",
            matched_at=row[6] or "",
        )
