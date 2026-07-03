"""
cache_repository — Lokaler Cache für Cyber-Meldungen und YouTube-Videos.

Implementiert ICacheRepository mit EncryptedDatabase (SQLCipher).
Ermöglicht Offline-Betrieb und verhindert unnötige Feed-Abrufe
durch eine 1-Stunden-TTL.

Sicherheitsdesign:
  - AES-256-CBC Vollverschlüsselung via EncryptedDatabase
  - Kein sqlite3.connect direkt — nur EncryptedDatabase
  - Meldungsinhalte werden nicht geloggt

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.cyber_dashboard.domain.interfaces import ICacheRepository
from tools.cyber_dashboard.domain.models import (
    CveEintrag,
    CyberMeldung,
    QuelleTyp,
    Schweregrad,
    YouTubeVideo,
)

log = get_logger(__name__)

_DB_NAME = "cyber_dashboard"
_CACHE_TTL = timedelta(hours=1)


def _zu_utc(dt: datetime) -> datetime:
    """Normalisiert einen datetime-Wert auf UTC-aware.

    Naive datetimes (aus alten DB-Eintraegen) erhalten UTC als Timezone.
    Aware datetimes werden in UTC konvertiert.

    Args:
        dt: Zu normalisierender datetime-Wert.

    Returns:
        UTC-aware datetime.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meldungen (
    guid             TEXT PRIMARY KEY,
    titel            TEXT NOT NULL,
    beschreibung     TEXT NOT NULL,
    url              TEXT NOT NULL,
    quelle           TEXT NOT NULL,
    schweregrad      TEXT NOT NULL,
    veroeffentlicht  TEXT NOT NULL,
    geladen_am       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_meldungen_datum
    ON meldungen(veroeffentlicht DESC);

CREATE TABLE IF NOT EXISTS videos (
    video_id         TEXT PRIMARY KEY,
    titel            TEXT NOT NULL,
    beschreibung     TEXT NOT NULL,
    url              TEXT NOT NULL,
    veroeffentlicht  TEXT NOT NULL,
    geladen_am       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id               TEXT PRIMARY KEY,
    beschreibung         TEXT,
    schweregrad          TEXT,
    cvss_score           REAL,
    veroeffentlicht      TEXT,
    geaendert            TEXT,
    url                  TEXT,
    cisa_kev             INTEGER DEFAULT 0,
    cisa_frist           TEXT,
    betroffene_produkte  TEXT,
    geladen_am           TEXT
);

CREATE INDEX IF NOT EXISTS idx_cves_schweregrad
    ON cves(schweregrad);

-- 2026-05-28 Phishing-Radar-Refactor: Read/Unread/Snooze-State pro
-- Meldung. Schluessel ist die GUID; ``gelesen_am`` und ``snooze_bis``
-- bleiben NULL, solange der User die Meldung nicht beruehrt hat.
CREATE TABLE IF NOT EXISTS meldung_state (
    guid        TEXT PRIMARY KEY,
    gelesen_am  TEXT,
    snooze_bis  TEXT,
    quelle      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_state_quelle
    ON meldung_state(quelle);
"""


class CacheRepository(ICacheRepository):
    """Lokaler SQLCipher-Cache für Cyber-Meldungen und Videos.

    Implementiert ICacheRepository. Alle Daten werden AES-256-CBC
    verschlüsselt gespeichert.
    """

    def __init__(self) -> None:
        """Initialisiert die Datenbank und erstellt das Schema."""
        self._db = EncryptedDatabase(_DB_NAME)
        self._init_schema()

    def _init_schema(self) -> None:
        """Erstellt die Tabellen falls sie noch nicht existieren."""
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # Meldungen
    # ------------------------------------------------------------------

    def speichere_meldungen(self, meldungen: list[CyberMeldung]) -> None:
        """Speichert Meldungen im verschlüsselten Cache.

        Bereinigt automatisch Einträge die älter als 90 Tage sind oder
        den Schweregrad INFO haben, damit der Cache aktuell bleibt.

        Args:
            meldungen: Liste der zu speichernden Meldungen.
        """
        if not meldungen:
            return
        jetzt = datetime.now(UTC).isoformat()
        grenze = (
            (datetime.now(UTC) - timedelta(days=90)).replace(tzinfo=None).isoformat()
        )
        with self._db.connection() as conn:
            # Veraltete und INFO-Einträge vor dem Speichern bereinigen
            conn.execute(
                "DELETE FROM meldungen WHERE veroeffentlicht < ? OR schweregrad = 'info'",
                (grenze,),
            )
            conn.executemany(
                """
                INSERT OR REPLACE INTO meldungen
                    (guid, titel, beschreibung, url, quelle,
                     schweregrad, veroeffentlicht, geladen_am)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        m.guid,
                        m.titel,
                        m.beschreibung,
                        m.url,
                        m.quelle.value,
                        m.schweregrad.value,
                        m.veroeffentlicht.isoformat(),
                        jetzt,
                    )
                    for m in meldungen
                ],
            )
        log.debug("Cache: %d Meldungen gespeichert", len(meldungen))

    def lade_meldungen(
        self,
        schweregrad: Schweregrad | None = None,
        quelle: QuelleTyp | None = None,
        limit: int = 100,
    ) -> list[CyberMeldung]:
        """Lädt Meldungen aus dem verschlüsselten Cache.

        Args:
            schweregrad: Optionaler Filter nach Schweregrad.
            quelle: Optionaler Filter nach Quelle.
            limit: Maximale Anzahl zurückgegebener Meldungen.

        Returns:
            Meldungen, neueste zuerst.
        """
        grenze_90 = (
            (datetime.now(UTC) - timedelta(days=90)).replace(tzinfo=None).isoformat()
        )
        query = """
            SELECT guid, titel, beschreibung, url,
                   quelle, schweregrad, veroeffentlicht
            FROM meldungen
            WHERE schweregrad != 'info'
              AND veroeffentlicht >= ?
        """
        params: list = [grenze_90]
        if schweregrad:
            query += " AND schweregrad = ?"
            params.append(schweregrad.value)
        if quelle:
            query += " AND quelle = ?"
            params.append(quelle.value)
        query += " ORDER BY veroeffentlicht DESC LIMIT ?"
        params.append(limit)

        result: list[CyberMeldung] = []
        with self._db.connection() as conn:
            rows = conn.execute(query, params).fetchall()

        for row in rows:
            try:
                result.append(
                    CyberMeldung(
                        guid=row[0],
                        titel=row[1],
                        beschreibung=row[2],
                        url=row[3],
                        quelle=QuelleTyp(row[4]),
                        schweregrad=Schweregrad(row[5]),
                        veroeffentlicht=_zu_utc(datetime.fromisoformat(row[6])),
                    )
                )
            except (ValueError, KeyError, TypeError):
                pass  # Korrupter oder veralteter Eintrag — überspringen
        return result

    # ------------------------------------------------------------------
    # Videos
    # ------------------------------------------------------------------

    def speichere_videos(self, videos: list[YouTubeVideo]) -> None:
        """Speichert Videos im verschlüsselten Cache.

        Args:
            videos: Liste der zu speichernden Videos.
        """
        if not videos:
            return
        jetzt = datetime.now(UTC).isoformat()
        with self._db.connection() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO videos
                    (video_id, titel, beschreibung, url,
                     veroeffentlicht, geladen_am)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        v.video_id,
                        v.titel,
                        v.beschreibung,
                        v.url,
                        v.veroeffentlicht.isoformat(),
                        jetzt,
                    )
                    for v in videos
                ],
            )
        log.debug("Cache: %d Videos gespeichert", len(videos))

    def lade_videos(self, limit: int = 10) -> list[YouTubeVideo]:
        """Lädt Videos aus dem verschlüsselten Cache.

        Args:
            limit: Maximale Anzahl zurückgegebener Videos.

        Returns:
            Videos, neueste zuerst.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT video_id, titel, beschreibung, url, veroeffentlicht
                FROM videos
                ORDER BY veroeffentlicht DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            YouTubeVideo(
                video_id=row[0],
                titel=row[1],
                beschreibung=row[2],
                url=row[3],
                veroeffentlicht=_zu_utc(datetime.fromisoformat(row[4])),
            )
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Cache-Zustand
    # ------------------------------------------------------------------

    def ist_frisch(self) -> bool:
        """Prüft ob der Cache innerhalb der 1-Stunden-TTL liegt.

        Returns:
            True wenn der Cache weniger als 1 Stunde alt ist.
        """
        try:
            with self._db.connection() as conn:
                row = conn.execute("SELECT MAX(geladen_am) FROM meldungen").fetchone()
            if not row or not row[0]:
                return False
            geladen = _zu_utc(datetime.fromisoformat(row[0]))
            return (datetime.now(UTC) - geladen) < _CACHE_TTL
        except (OSError, RuntimeError, ValueError):
            return False

    # ------------------------------------------------------------------
    # CVEs
    # ------------------------------------------------------------------

    def speichere_cves(self, cves: list[CveEintrag]) -> None:
        """Speichert CVE-Einträge im verschlüsselten Cache.

        Entfernt automatisch Einträge die älter als 180 Tage sind, damit
        keine veralteten CVEs aus 2023 oder früher im Cache verbleiben.

        Args:
            cves: Liste der zu speichernden CVE-Einträge.
        """
        if not cves:
            return
        jetzt = datetime.now(UTC).isoformat()
        grenze = (
            (datetime.now(UTC) - timedelta(days=180)).replace(tzinfo=None).isoformat()
        )
        with self._db.connection() as conn:
            # Veraltete Einträge vor dem Speichern bereinigen
            conn.execute(
                "DELETE FROM cves WHERE veroeffentlicht < ?",
                (grenze,),
            )
            conn.executemany(
                """
                INSERT OR REPLACE INTO cves
                    (cve_id, beschreibung, schweregrad, cvss_score,
                     veroeffentlicht, geaendert, url, cisa_kev,
                     cisa_frist, betroffene_produkte, geladen_am)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        c.cve_id,
                        c.beschreibung,
                        c.schweregrad,
                        c.cvss_score,
                        c.veroeffentlicht.isoformat(),
                        c.geaendert.isoformat(),
                        c.url,
                        int(c.cisa_kev),
                        c.cisa_frist,
                        json.dumps(c.betroffene_produkte),
                        jetzt,
                    )
                    for c in cves
                ],
            )
        log.debug("Cache: %d CVEs gespeichert", len(cves))

    def lade_cves(
        self,
        schweregrad: str | None = None,
        nur_kev: bool = False,
        limit: int = 50,
    ) -> list[CveEintrag]:
        """Lädt CVE-Einträge aus dem verschlüsselten Cache.

        Args:
            schweregrad: Optionaler Filter (CRITICAL/HIGH/MEDIUM/LOW).
            nur_kev: True = nur CISA KEV CVEs zurückgeben.
            limit: Maximale Anzahl zurückgegebener Einträge.

        Returns:
            CVE-Einträge, neueste zuerst.
        """
        query = """
            SELECT cve_id, beschreibung, schweregrad, cvss_score,
                   veroeffentlicht, geaendert, url, cisa_kev,
                   cisa_frist, betroffene_produkte
            FROM cves WHERE 1=1
        """
        params: list = []
        if schweregrad:
            query += " AND schweregrad = ?"
            params.append(schweregrad.upper())
        if nur_kev:
            query += " AND cisa_kev = 1"
        query += " ORDER BY veroeffentlicht DESC LIMIT ?"
        params.append(limit)

        result: list[CveEintrag] = []
        skipped = 0
        first_skip_reason: str = ""
        with self._db.connection() as conn:
            rows = conn.execute(query, params).fetchall()

        for row in rows:
            try:
                produkte = json.loads(row[9]) if row[9] else []
                result.append(
                    CveEintrag(
                        cve_id=row[0],
                        beschreibung=row[1] or "",
                        schweregrad=row[2] or "INFO",
                        cvss_score=float(row[3] or 0.0),
                        veroeffentlicht=_zu_utc(datetime.fromisoformat(row[4])),
                        geaendert=_zu_utc(datetime.fromisoformat(row[5])),
                        url=row[6] or "",
                        cisa_kev=bool(row[7]),
                        cisa_frist=row[8] or "",
                        betroffene_produkte=produkte,
                    )
                )
            except (ValueError, KeyError, TypeError) as exc:
                skipped += 1
                if not first_skip_reason:
                    # Row-Werte werden auf 32 Zeichen gecappt — Schutz
                    # gegen Log-Injection bei manipulierten DB-Inhalten
                    # (Security-Review).
                    first_skip_reason = (
                        f"{type(exc).__name__}: {str(exc)[:64]} | "
                        f"cve_id={str(row[0])[:32]!r} "
                        f"ver={str(row[4])[:32]!r} ge={str(row[5])[:32]!r}"
                    )
        # DEBUG-Level: lade_cves wird oft aufgerufen (Combobox-Filter,
        # Auto-Refresh). Auf INFO würde der Log in Production zugemüllt.
        # Für Diagnose das Log-Level temporär hochziehen.
        log.debug(
            "lade_cves: query_filter=schweregrad=%s nur_kev=%s limit=%d → "
            "rows=%d parsed=%d skipped=%d%s",
            schweregrad,
            nur_kev,
            limit,
            len(rows),
            len(result),
            skipped,
            f" first_skip={first_skip_reason}" if first_skip_reason else "",
        )
        return result

    def zaehle_cves_nach_schweregrad(self) -> dict[str, int]:
        """Zählt CVEs der letzten 24h nach Schweregrad.

        Filter auf ``veroeffentlicht`` statt
        ``geladen_am`` umgestellt. ``geladen_am`` ist der Sync-Zeit-
        stempel und hat keine semantische Bedeutung fuer den User —
        nach dem Erst-Sync zaehlte der Counter ALLE CVEs als
        "letzte 24h", was den Dashboard-Kachelwert wertlos machte.
        Analog zum CSAF-Filter-Fix in.

        Returns:
            Dict mit Schweregrad-Keys und Zählwerten.
            Enthält zusätzlich "kev" für CISA KEV CVEs.
        """
        result: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "kev": 0,
        }
        seit = (
            (datetime.now(UTC) - timedelta(hours=24)).replace(tzinfo=None).isoformat()
        )
        try:
            with self._db.connection() as conn:
                rows = conn.execute(
                    """
                    SELECT schweregrad, COUNT(*) as cnt
                    FROM cves
                    WHERE veroeffentlicht >= ?
                    GROUP BY schweregrad
                    """,
                    (seit,),
                ).fetchall()
                for row in rows:
                    key = (row[0] or "").upper()
                    if key in result:
                        result[key] = row[1]

                kev_row = conn.execute(
                    "SELECT COUNT(*) FROM cves "
                    "WHERE cisa_kev = 1 AND veroeffentlicht >= ?",
                    (seit,),
                ).fetchone()
                if kev_row:
                    result["kev"] = kev_row[0]
        except (OSError, RuntimeError):
            pass
        return result

    # ------------------------------------------------------------------
    # Read/Unread/Snooze-State (2026-05-28 Phishing-Radar-Refactor)
    # ------------------------------------------------------------------

    def markiere_gelesen(self, guids: Iterable[str]) -> None:
        """Markiert Meldungen als gelesen. Idempotent."""

        gelesen_am = datetime.now(UTC).isoformat()
        rows = [(g, gelesen_am, g, g) for g in guids if g]
        if not rows:
            return
        with self._db.connection() as conn:
            # ON CONFLICT-Pattern: erst INSERT, sonst UPDATE — gelesen_am
            # wird nur gesetzt, wenn vorher NULL (Idempotenz).
            # Quelle aus der Meldung selbst aufloesen (echte Quelle statt
            # Platzhalter); 'unbekannt' nur, wenn die Meldung nicht im Cache
            # liegt (seltener Edge-Case, Spalte ist NOT NULL).
            conn.executemany(
                """
                INSERT INTO meldung_state (guid, gelesen_am, quelle)
                VALUES (?, ?, COALESCE(
                    (SELECT quelle FROM meldung_state WHERE guid = ?),
                    (SELECT quelle FROM meldungen WHERE guid = ?),
                    'unbekannt'
                ))
                ON CONFLICT(guid) DO UPDATE
                    SET gelesen_am = COALESCE(meldung_state.gelesen_am, excluded.gelesen_am)
                """,
                rows,
            )
        log.debug("State: %d Meldungen als gelesen markiert", len(rows))

    def markiere_ungelesen(self, guids: Iterable[str]) -> None:
        """Setzt den Gelesen-Status zurueck (gelesen_am = NULL)."""

        liste = [(g,) for g in guids if g]
        if not liste:
            return
        with self._db.connection() as conn:
            conn.executemany(
                "UPDATE meldung_state SET gelesen_am = NULL WHERE guid = ?",
                liste,
            )
        log.debug("State: %d Meldungen auf ungelesen gesetzt", len(liste))

    def schiebe_auf(
        self,
        guid: str,
        bis: datetime,
        quelle: QuelleTyp,
    ) -> None:
        """Schiebt eine Meldung bis ``bis`` (UTC) auf."""

        if not guid:
            return
        bis_iso = _zu_utc(bis).isoformat()
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO meldung_state (guid, snooze_bis, quelle)
                VALUES (?, ?, ?)
                ON CONFLICT(guid) DO UPDATE SET snooze_bis = excluded.snooze_bis
                """,
                (guid, bis_iso, quelle.value),
            )
        log.debug("State: %s aufgeschoben bis %s", guid[:32], bis_iso)

    def lade_state_fuer(
        self,
        guids: Iterable[str],
    ) -> dict[str, tuple[datetime | None, datetime | None]]:
        """Lädt Read/Snooze-State fuer eine Menge von GUIDs."""

        liste = [g for g in guids if g]
        if not liste:
            return {}
        # SQLite-Parameter-Liste — Sicherheit durch Platzhalter, nicht
        # durch String-Interpolation (kein SQL-Injection-Risiko).
        platzhalter = ",".join("?" for _ in liste)
        # noqa S608: ``platzhalter`` ist ausschliesslich "?,?,..." — die
        # Werte gehen als Bind-Parameter, kein String-Injection-Risiko.
        query = (
            "SELECT guid, gelesen_am, snooze_bis FROM meldung_state "  # noqa: S608 # nosec B608
            f"WHERE guid IN ({platzhalter})"
        )
        result: dict[str, tuple[datetime | None, datetime | None]] = {}
        with self._db.connection() as conn:
            rows = conn.execute(query, liste).fetchall()
        for row in rows:
            guid = row[0]
            gelesen = (
                _zu_utc(datetime.fromisoformat(row[1])) if row[1] else None
            )
            snooze = (
                _zu_utc(datetime.fromisoformat(row[2])) if row[2] else None
            )
            result[guid] = (gelesen, snooze)
        # Fehlende GUIDs explizit auf (None, None) setzen, damit Caller
        # nicht jedes Mal ``.get(g, (None, None))`` schreiben muss.
        for g in liste:
            result.setdefault(g, (None, None))
        return result

    def zaehle_ungelesene(self, quellen: Iterable[QuelleTyp]) -> int:
        """Zaehlt Meldungen aus ``quellen``, die NICHT in state als
        gelesen markiert UND nicht aufgeschoben sind."""

        quellen_liste = [q.value for q in quellen]
        if not quellen_liste:
            return 0
        jetzt = datetime.now(UTC).isoformat()
        grenze_90 = (
            (datetime.now(UTC) - timedelta(days=90))
            .replace(tzinfo=None)
            .isoformat()
        )
        platzhalter = ",".join("?" for _ in quellen_liste)
        # LEFT JOIN: Meldungen ohne State-Eintrag gelten als ungelesen.
        # ``platzhalter`` ist nur "?,?,..." — Werte gehen als Bind-Params.
        query = (
            "SELECT COUNT(*) "  # noqa: S608 # nosec B608
            "FROM meldungen m "
            "LEFT JOIN meldung_state s ON s.guid = m.guid "
            f"WHERE m.quelle IN ({platzhalter}) "
            "AND m.schweregrad != 'info' "
            "AND m.veroeffentlicht >= ? "
            "AND s.gelesen_am IS NULL "
            "AND (s.snooze_bis IS NULL OR s.snooze_bis < ?)"
        )
        params: list = list(quellen_liste) + [grenze_90, jetzt]
        with self._db.connection() as conn:
            row = conn.execute(query, params).fetchone()
        return int(row[0]) if row else 0

    def zaehle_seit(
        self,
        quellen: Iterable[QuelleTyp],
        cutoff: datetime,
    ) -> int:
        """Zaehlt nicht-aufgeschobene Meldungen aus ``quellen`` seit ``cutoff``.

        Reiner SQL-COUNT — entschluesselt keine Volltexte und ersetzt das
        Laden+Filtern aller Cache-Zeilen nur zum Zaehlen. INFO-Meldungen sind
        ausgeschlossen (analog ``zaehle_ungelesene``); der Read-Status spielt
        hier keine Rolle.

        Args:
            quellen: Quellen, deren Meldungen gezaehlt werden.
            cutoff: Untere Zeitgrenze (UTC-aware) — nur juengere zaehlen.

        Returns:
            Anzahl passender, nicht aktiv aufgeschobener Meldungen.
        """

        quellen_liste = [q.value for q in quellen]
        if not quellen_liste:
            return 0
        jetzt = datetime.now(UTC).isoformat()
        # Naiver ISO-String wie bei ``zaehle_ungelesene`` — passt zum
        # Speicherformat von ``veroeffentlicht`` (lexikografischer Vergleich).
        cutoff_iso = cutoff.replace(tzinfo=None).isoformat()
        platzhalter = ",".join("?" for _ in quellen_liste)
        # ``platzhalter`` ist nur "?,?,..." — Werte gehen als Bind-Params.
        query = (
            "SELECT COUNT(*) "  # noqa: S608 # nosec B608
            "FROM meldungen m "
            "LEFT JOIN meldung_state s ON s.guid = m.guid "
            f"WHERE m.quelle IN ({platzhalter}) "
            "AND m.schweregrad != 'info' "
            "AND m.veroeffentlicht >= ? "
            "AND (s.snooze_bis IS NULL OR s.snooze_bis < ?)"
        )
        params: list = list(quellen_liste) + [cutoff_iso, jetzt]
        with self._db.connection() as conn:
            row = conn.execute(query, params).fetchone()
        return int(row[0]) if row else 0
