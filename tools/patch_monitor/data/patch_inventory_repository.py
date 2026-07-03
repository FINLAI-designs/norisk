"""patch_inventory_repository — Persistente Patch-Datenbasis fuer das
Tier-Modell (Initial / Monthly-Full / Daily-Refresh).

 (PM-PERSIST). Brain-Konzept: [[NoRisk_PATCH_PERSISTENCE]].
Adressiert die "20-min-Vollscan ist nicht taeglich realistisch"-Realitaet
aus Patrick-Smoke 2026-05-12. Statt jeden Scan from-scratch zu fahren,
persistiert die ``patch_inventory``-DB:

1. **inventory_snapshot** — letzter bekannter Stand pro winget_id (Name,
   CPE, Channel, etc.). Wird beim Vollscan vollstaendig befuellt, beim
   Daily-Refresh unveraendert gelassen.
2. **available_versions** — neueste verfuegbare Version pro winget_id.
   Daily-Refresh-Target (~5-10 s subprocess ``winget list``).
3. **cve_matches** — CVE-Verlinkung pro CPE (cvss/exploit/eol/ts).
   Daily-Refresh-Target fuer Eintraege aelter als 24 h (NVD-API).
4. **scan_history** — Timeline aller Scans (initial / monthly_full /
   daily_refresh / manual). Dashboard-Trend, Compliance-Reports.

Designziele (analog ``cyber_dashboard/data/briefing_history_repository.py``):

* EncryptedDatabase-Pflicht (SQLCipher, separate DB ``patch_inventory``)
* Append-only fuer ``scan_history`` (Audit)
* In-Place-Update fuer ``inventory_snapshot``, ``available_versions``,
  ``cve_matches`` (Soll-Stand spiegelt Wirklichkeit)
* ``PRAGMA user_version`` fuer Migrations-Pattern)

Schichtzugehoerigkeit: ``data/`` (Repository-Adapter — Service-Schicht
in ``application/patch_inventory_service.py`` folgt in Stop-Step B).
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from core.patch_custom_source import DEFAULT_PLATFORM, CustomSource, Platform
from core.patch_strategy import DEFAULT_PATCH_STRATEGY, PatchStrategy

log = get_logger(__name__)

_DB_NAME: Final[str] = "patch_inventory"
#: Schema-Versionen:
#: * V2: ``inventory_snapshot.patch_strategy`` (ALTER, in
#::meth:`PatchInventoryRepository._migrate_v1_to_v2`).
#: * V3: neue Tabelle ``custom_sources`` — als neue Tabelle bereits
#: vom ``_SCHEMA``-Skript (``CREATE TABLE IF NOT EXISTS``) fuer frische UND
#: bestehende V2-DBs angelegt; die V3-Migration ist daher nur der
#: Versions-Stempel (kein ALTER noetig).
_SCHEMA_VERSION: Final[int] = 3

#: Erlaubte Werte fuer ``scan_history.scan_type``.
ScanType = Literal["initial", "monthly_full", "daily_refresh", "manual"]


_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS inventory_snapshot (
    winget_id            TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    normalized_name      TEXT NOT NULL,
    vendor               TEXT,
    source               TEXT NOT NULL,
    installed_version    TEXT NOT NULL,
    cpe_string           TEXT,
    channel              TEXT NOT NULL,
    policy_source        TEXT NOT NULL,
    confidence_score     REAL NOT NULL,
    last_seen_at         INTEGER NOT NULL,
    last_full_scan_at    INTEGER NOT NULL,
    -- T-102 (Schema-V2): user-eigene Patch-Strategie pro App.
    -- DEFAULT spiegelt core.patch_strategy.DEFAULT_PATCH_STRATEGY.
    -- Wird NUR von update_strategy() geschrieben — upsert_inventory()
    -- laesst die Spalte unangetastet, damit Vollscans die User-Wahl
    -- nicht ueberschreiben.
    patch_strategy       TEXT NOT NULL DEFAULT 'stable'
);

CREATE INDEX IF NOT EXISTS idx_inventory_last_seen
    ON inventory_snapshot(last_seen_at DESC);

CREATE TABLE IF NOT EXISTS available_versions (
    winget_id            TEXT PRIMARY KEY,
    available_version    TEXT,
    is_update_available  INTEGER NOT NULL DEFAULT 0,
    last_checked_at      INTEGER NOT NULL,
    FOREIGN KEY (winget_id) REFERENCES inventory_snapshot(winget_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_matches (
    cpe_string           TEXT NOT NULL,
    cve_id               TEXT NOT NULL,
    cvss_score           REAL,
    exploit_available    INTEGER NOT NULL DEFAULT 0,
    eol                  INTEGER NOT NULL DEFAULT 0,
    fetched_at           INTEGER NOT NULL,
    PRIMARY KEY (cpe_string, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_cve_matches_cpe
    ON cve_matches(cpe_string);

CREATE INDEX IF NOT EXISTS idx_cve_matches_fetched
    ON cve_matches(fetched_at);

CREATE TABLE IF NOT EXISTS scan_history (
    id                   TEXT PRIMARY KEY,
    started_at           INTEGER NOT NULL,
    finished_at          INTEGER,
    scan_type            TEXT NOT NULL,
    items_total          INTEGER,
    items_with_updates   INTEGER,
    items_with_cves      INTEGER,
    duration_ms          INTEGER,
    error                TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_history_started
    ON scan_history(started_at DESC);

-- T-103 (Schema-V3): manuell gepflegte Patch-Quellen (Notify-Only).
-- ``platform`` DEFAULT spiegelt core.patch_custom_source.DEFAULT_PLATFORM.
-- available_version / last_checked_at / last_error werden vom
-- custom_source_checker (Stop-Step B) befuellt.
CREATE TABLE IF NOT EXISTS custom_sources (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    vendor_url         TEXT NOT NULL,
    version_regex      TEXT NOT NULL,
    platform           TEXT NOT NULL DEFAULT 'win',
    installed_version  TEXT,
    available_version  TEXT,
    last_checked_at    INTEGER,
    last_error         TEXT,
    notes              TEXT,
    created_at         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_custom_sources_name
    ON custom_sources(name);
"""


# ---------------------------------------------------------------------------
# Frozen Entry-Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InventoryEntry:
    """Zeile aus ``inventory_snapshot`` (1:1 Mapping).

    ``patch_strategy`` ist user-eigene Metadaten und hat einen
    Default, weil scan-abgeleitete Eintraege (gebaut im
    ``patch_inventory_service``) die Strategie nicht kennen: beim Upsert
    bleibt die Spalte unangetastet, gelesen wird der persistierte Wert.
    """

    winget_id: str
    name: str
    normalized_name: str
    vendor: str | None
    source: str
    installed_version: str
    cpe_string: str | None
    channel: str
    policy_source: str
    confidence_score: float
    last_seen_at: datetime
    last_full_scan_at: datetime
    patch_strategy: PatchStrategy = DEFAULT_PATCH_STRATEGY


@dataclass(frozen=True)
class AvailableVersionEntry:
    """Zeile aus ``available_versions``.

    ``is_update_available`` ist die autoritative Quelle dafuer ob ein
    Update fuer dieses Item verfuegbar ist:
    winget meldet diesen Bool im Modul-Pfad, und unsere
    ``_recommend``-Logik nutzt ihn statt eines fragilen
    String-Versions-Vergleichs.
    """

    winget_id: str
    available_version: str | None
    is_update_available: bool
    last_checked_at: datetime


@dataclass(frozen=True)
class CveMatchEntry:
    """Zeile aus ``cve_matches``."""

    cpe_string: str
    cve_id: str
    cvss_score: float | None
    exploit_available: bool
    eol: bool
    fetched_at: datetime


@dataclass(frozen=True)
class AffectedCveRow:
    """Eine (App, CVE)-Zeile aus dem JOIN ``inventory_snapshot`` x
    ``cve_matches`` x ``available_versions`` (read-only, kein Schreib-Pfad).

    Das ist das praeziseste "System betroffen"-Signal des Patch-Monitors:
    nur Apps mit bekanntem CPE (``cpe_string IS NOT NULL``), deren CPE einen
    CVE-Treffer hat — CPE-genau, aus echtem winget-Inventar, rein lokal
    (kein NVD-HTTP). Speist Tab 1 ("bestaetigt betroffen") des Risikobriefings.
    """

    winget_id: str
    app_name: str
    cpe_string: str
    installed_version: str
    is_update_available: bool
    available_version: str | None
    cve_id: str
    cvss_score: float | None
    exploit_available: bool
    eol: bool
    fetched_at: datetime


@dataclass(frozen=True)
class ScanHistoryEntry:
    """Zeile aus ``scan_history``."""

    id: str
    started_at: datetime
    finished_at: datetime | None
    scan_type: ScanType
    items_total: int | None
    items_with_updates: int | None
    items_with_cves: int | None
    duration_ms: int | None
    error: str | None


# ---------------------------------------------------------------------------
# Upsert-SQL + Param-Builder — Single Source of Truth fuer Einzel- UND
# Batch-Pfad (Perf: der Batch nutzt executemany in EINER Connection statt N
# Einzel-Opens; ein Vollscan mit Hunderten Paketen zahlte sonst je Zeile einen
# Connection-Open inkl. PRAGMA-Setup).
# ---------------------------------------------------------------------------

_SQL_UPSERT_INVENTORY: Final[str] = """
    INSERT INTO inventory_snapshot(
        winget_id, name, normalized_name, vendor, source,
        installed_version, cpe_string, channel, policy_source,
        confidence_score, last_seen_at, last_full_scan_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(winget_id) DO UPDATE SET
        name              = excluded.name,
        normalized_name   = excluded.normalized_name,
        vendor            = excluded.vendor,
        source            = excluded.source,
        installed_version = excluded.installed_version,
        cpe_string        = excluded.cpe_string,
        channel           = excluded.channel,
        policy_source     = excluded.policy_source,
        confidence_score  = excluded.confidence_score,
        last_seen_at      = excluded.last_seen_at,
        last_full_scan_at = excluded.last_full_scan_at
"""


def _inventory_params(entry: InventoryEntry) -> tuple:
    """Bindings fuer:data:`_SQL_UPSERT_INVENTORY`.

    ``patch_strategy`` wird BEWUSST nicht geschrieben: Vollscans duerfen
    die user-eigene Strategie nicht ueberschreiben — einziger Schreibpfad ist
:meth:`PatchInventoryRepository.update_strategy`.
    """
    return (
        entry.winget_id,
        entry.name,
        entry.normalized_name,
        entry.vendor,
        entry.source,
        entry.installed_version,
        entry.cpe_string,
        entry.channel,
        entry.policy_source,
        entry.confidence_score,
        int(entry.last_seen_at.timestamp()),
        int(entry.last_full_scan_at.timestamp()),
    )


_SQL_UPSERT_AVAILABLE: Final[str] = """
    INSERT INTO available_versions(
        winget_id, available_version, is_update_available, last_checked_at
    ) VALUES (?, ?, ?, ?)
    ON CONFLICT(winget_id) DO UPDATE SET
        available_version   = excluded.available_version,
        is_update_available = excluded.is_update_available,
        last_checked_at     = excluded.last_checked_at
"""


def _available_params(entry: AvailableVersionEntry) -> tuple:
    """Bindings fuer:data:`_SQL_UPSERT_AVAILABLE`."""
    return (
        entry.winget_id,
        entry.available_version,
        int(entry.is_update_available),
        int(entry.last_checked_at.timestamp()),
    )


_SQL_UPSERT_CVE: Final[str] = """
    INSERT INTO cve_matches(
        cpe_string, cve_id, cvss_score, exploit_available, eol, fetched_at
    ) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(cpe_string, cve_id) DO UPDATE SET
        cvss_score        = excluded.cvss_score,
        exploit_available = excluded.exploit_available,
        eol               = excluded.eol,
        fetched_at        = excluded.fetched_at
"""


def _cve_params(entry: CveMatchEntry) -> tuple:
    """Bindings fuer:data:`_SQL_UPSERT_CVE`."""
    return (
        entry.cpe_string,
        entry.cve_id,
        entry.cvss_score,
        int(entry.exploit_available),
        int(entry.eol),
        int(entry.fetched_at.timestamp()),
    )


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


class PatchInventoryRepository:
    """Persistente Patch-Datenbasis (EncryptedDB ``patch_inventory``).

    Nutzung::

        repo = PatchInventoryRepository

        # Vollscan: alles ueberschreiben
        repo.upsert_inventory_batch(inventory_entries, full_scan_at=now)
        repo.upsert_available_versions_batch(available_entries, now)
        repo.upsert_cve_matches_batch(cve_entries, fetched_at=now)
        repo.record_scan_start("initial") # → returns scan_id
        repo.record_scan_end(scan_id, items_total=311, items_with_updates=11)

        # Daily-Refresh: nur available_versions + cve_matches updaten
        repo.upsert_available_versions_batch(refreshed_versions, now)
        stale_cpes = repo.list_stale_cpes(older_than_hours=24)
        #... NVD-Lookup...
        repo.upsert_cve_matches_batch(fresh_cves, fetched_at=now)

        # UI-Load: aus DB lesen statt scannen
        inventory = repo.list_inventory
        versions = repo.list_available_versions
    """

    def __init__(self) -> None:
        """Initialisiert die DB, legt das Schema an und migriert Bestands-DBs.

        Frische DBs werden vollstaendig vom ``_SCHEMA``-Skript angelegt
        (inkl. aller V2-Spalten). Bestehende DBs werden von
:meth:`_migrate_schema` additiv auf:data:`_SCHEMA_VERSION`
        gezogen. Danach wird ``PRAGMA user_version`` gestempelt.
        """
        self._db = EncryptedDatabase(_DB_NAME)
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)
            self._migrate_schema(conn)
            # PRAGMA user_version akzeptiert keine Parameter-Bindings —
            # sicher hier, weil _SCHEMA_VERSION ein Modul-Konstante ist.
            conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")  # noqa: S608

    @staticmethod
    def _migrate_schema(conn: Any) -> None:
        """Zieht eine bestehende DB additiv auf:data:`_SCHEMA_VERSION`.

        Idempotent: liest ``PRAGMA user_version`` und fuehrt nur die noch
        fehlenden Migrationsschritte aus. Frische DBs (Version 0, aber
        bereits via ``_SCHEMA`` vollstaendig angelegt) durchlaufen die
        Schritte ebenfalls, sind aber durch die Spalten-Existenzpruefung
        gegen Doppel-Anwendung geschuetzt.

        Args:
            conn: Offene DB-Connection im selben ``with``-Block wie das
                Schema-Setup (Commit erfolgt beim Block-Ende).
        """
        row = conn.execute("PRAGMA user_version").fetchone()
        current = int(row[0]) if row else 0
        if current < 2:
            PatchInventoryRepository._migrate_v1_to_v2(conn)
        # V3, custom_sources) braucht KEINEN ALTER-Schritt: die neue
        # Tabelle wird bereits von ``_SCHEMA`` (CREATE TABLE IF NOT EXISTS) auf
        # frischen UND bestehenden V2-DBs angelegt. Der V3-Stempel erfolgt am
        # Ende von ``__init__`` ueber ``PRAGMA user_version``.

    @staticmethod
    def _migrate_v1_to_v2(conn: Any) -> None:
        """V1 → V2: ergaenzt ``inventory_snapshot.patch_strategy``.

        Bestehende Zeilen bekommen via ``DEFAULT 'stable'`` automatisch die
        Standard-Strategie. Die Spalten-Existenzpruefung haelt den Schritt
        idempotent, falls er auf einer bereits migrierten DB laeuft.
        """
        columns = {r[1] for r in conn.execute("PRAGMA table_info(inventory_snapshot)")}
        if "patch_strategy" not in columns:
            conn.execute(
                "ALTER TABLE inventory_snapshot "
                "ADD COLUMN patch_strategy TEXT NOT NULL DEFAULT 'stable'"
            )
            log.info("patch_inventory: Schema-Migration V1→V2 angewendet")

    def get_schema_version(self) -> int:
        """Liefert die aktuelle ``PRAGMA user_version`` der DB."""
        with self._db.connection() as conn:
            row = conn.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row else 0

    # ------------------------------------------------------------------
    # inventory_snapshot
    # ------------------------------------------------------------------

    def upsert_inventory(self, entry: InventoryEntry) -> None:
        """Schreibt oder aktualisiert eine ``inventory_snapshot``-Zeile.

        ``entry.patch_strategy`` wird hier BEWUSST nicht geschrieben: Vollscans duerfen die user-eigene Strategie nicht
        ueberschreiben. Neue Zeilen bekommen den Spalten-DEFAULT
        (``stable``), bestehende behalten ihren Wert. Einziger Schreibpfad
        fuer die Spalte ist:meth:`update_strategy`.
        """
        with self._db.connection() as conn:
            conn.execute(_SQL_UPSERT_INVENTORY, _inventory_params(entry))

    def upsert_inventory_batch(self, entries: Iterable[InventoryEntry]) -> int:
        """Bulk-Upsert in EINER Connection. Liefert verarbeitete Zeilen.

        executemany statt N Einzel-``upsert_inventory``-Opens (Perf): ein
        Vollscan mit Hunderten Paketen zahlte sonst je Zeile einen
        Connection-Open inkl. PRAGMA-Setup. ``patch_strategy`` bleibt unberuehrt
        (:func:`_inventory_params`).
        """
        params = [_inventory_params(e) for e in entries]
        if not params:
            return 0
        with self._db.connection() as conn:
            conn.executemany(_SQL_UPSERT_INVENTORY, params)
        return len(params)

    def get_inventory(self, winget_id: str) -> InventoryEntry | None:
        """Liest eine einzelne ``inventory_snapshot``-Zeile."""
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT winget_id, name, normalized_name, vendor, source,
                       installed_version, cpe_string, channel, policy_source,
                       confidence_score, last_seen_at, last_full_scan_at,
                       patch_strategy
                FROM inventory_snapshot WHERE winget_id = ?
                """,
                (winget_id,),
            ).fetchone()
        return _row_to_inventory(row) if row else None

    def list_inventory(self) -> list[InventoryEntry]:
        """Gibt alle ``inventory_snapshot``-Zeilen zurueck."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT winget_id, name, normalized_name, vendor, source,
                       installed_version, cpe_string, channel, policy_source,
                       confidence_score, last_seen_at, last_full_scan_at,
                       patch_strategy
                FROM inventory_snapshot
                ORDER BY name
                """,
            ).fetchall()
        return [_row_to_inventory(r) for r in rows]

    def update_strategy(self, winget_id: str, strategy: PatchStrategy) -> bool:
        """Setzt die Patch-Strategie einer App.

        Einziger Schreibpfad fuer ``inventory_snapshot.patch_strategy`` —
        Vollscans (:meth:`upsert_inventory`) lassen die Spalte bewusst
        unangetastet, damit die User-Wahl erhalten bleibt.

        Args:
            winget_id: Identifiziert die Inventar-Zeile.
            strategy: Neue Strategie.

        Returns:
            ``True`` wenn eine Zeile aktualisiert wurde, ``False`` wenn die
            ``winget_id`` nicht im Inventar existiert.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                "UPDATE inventory_snapshot SET patch_strategy = ? WHERE winget_id = ?",
                (strategy.value, winget_id),
            )
            return cur.rowcount > 0

    def update_channel(
        self, winget_id: str, channel: str, policy_source: str = "user"
    ) -> bool:
        """Setzt den Update-Kanal einer App im persistierten Inventar.

        Sofort-Reflektion fuer den GUI-Channel-Selektor: ``load_from_db`` liest
        ``inventory_snapshot.channel`` (kein Re-Resolve), darum schreiben wir den
        neuen Kanal direkt in die Zeile, damit die Empfehlung beim naechsten
        Reload neu abgeleitet wird. Der DAUERHAFTE Override lebt zusaetzlich in
:class:`core.patch_policy.PolicyDB` (von jedem Vollscan re-resolved).

        Args:
            winget_id: Identifiziert die Inventar-Zeile.
            channel: Neuer Kanal (latest/stable/patch_only/pinned/notify_only).
            policy_source: Herkunft, Default ``"user"`` (User-Override).

        Returns:
            ``True`` wenn eine Zeile aktualisiert wurde, ``False`` sonst.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                "UPDATE inventory_snapshot SET channel = ?, policy_source = ? "
                "WHERE winget_id = ?",
                (channel, policy_source, winget_id),
            )
            return cur.rowcount > 0

    def delete_inventory_not_in(self, winget_ids: Iterable[str]) -> int:
        """Loescht alle Eintraege deren ``winget_id`` nicht in der
        uebergebenen Menge ist. Wird vom Monthly-Full-Scan benutzt um
        deinstallierte Apps zu entfernen.

        Wenn ``winget_ids`` leer ist, wird NICHTS geloescht (Schutz vor
        versehentlichem Wegspuelen — der Caller muss explizit
:meth:`clear_inventory` aufrufen).

        Returns:
            Anzahl geloeschter Zeilen.
        """
        id_set = set(winget_ids)
        if not id_set:
            return 0
        placeholders = ",".join("?" * len(id_set))
        # SQLi-frei: ``placeholders`` ist eine count-bounded "?,?,..."-Sequenz,
        # ``winget_ids`` werden ausschliesslich via Parameter-Binding eingesetzt.
        sql = f"DELETE FROM inventory_snapshot WHERE winget_id NOT IN ({placeholders})"  # noqa: S608 # nosec B608
        with self._db.connection() as conn:
            cur = conn.execute(sql, tuple(id_set))
            return cur.rowcount

    def clear_inventory(self) -> None:
        """Loescht **alle** ``inventory_snapshot``-Zeilen. Nur fuer
        Tests / Reset-Workflows. Daily-Refresh nutzt das NIE."""
        with self._db.connection() as conn:
            conn.execute("DELETE FROM inventory_snapshot")

    # ------------------------------------------------------------------
    # available_versions
    # ------------------------------------------------------------------

    def upsert_available_version(self, entry: AvailableVersionEntry) -> None:
        """Schreibt oder aktualisiert eine ``available_versions``-Zeile."""
        with self._db.connection() as conn:
            conn.execute(_SQL_UPSERT_AVAILABLE, _available_params(entry))

    def upsert_available_versions_batch(
        self, entries: Iterable[AvailableVersionEntry]
    ) -> int:
        """Bulk-Upsert fuer Daily-Refresh in EINER Connection (executemany).

        Liefert verarbeitete Zeilen.
        """
        params = [_available_params(e) for e in entries]
        if not params:
            return 0
        with self._db.connection() as conn:
            conn.executemany(_SQL_UPSERT_AVAILABLE, params)
        return len(params)

    def get_available_version(self, winget_id: str) -> AvailableVersionEntry | None:
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT winget_id, available_version, is_update_available, last_checked_at
                FROM available_versions WHERE winget_id = ?
                """,
                (winget_id,),
            ).fetchone()
        return _row_to_available(row) if row else None

    def list_available_versions(self) -> list[AvailableVersionEntry]:
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT winget_id, available_version, is_update_available, last_checked_at
                FROM available_versions
                """,
            ).fetchall()
        return [_row_to_available(r) for r in rows]

    # ------------------------------------------------------------------
    # cve_matches
    # ------------------------------------------------------------------

    def upsert_cve_match(self, entry: CveMatchEntry) -> None:
        """Schreibt oder aktualisiert eine ``cve_matches``-Zeile."""
        with self._db.connection() as conn:
            conn.execute(_SQL_UPSERT_CVE, _cve_params(entry))

    def upsert_cve_matches_batch(self, entries: Iterable[CveMatchEntry]) -> int:
        """Bulk-Upsert in EINER Connection (executemany). Liefert verarbeitete Zeilen."""
        params = [_cve_params(e) for e in entries]
        if not params:
            return 0
        with self._db.connection() as conn:
            conn.executemany(_SQL_UPSERT_CVE, params)
        return len(params)

    def list_cve_matches_for_cpe(self, cpe_string: str) -> list[CveMatchEntry]:
        """Alle CVEs zu einem CPE. Reihenfolge: nach cvss_score DESC."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT cpe_string, cve_id, cvss_score, exploit_available, eol, fetched_at
                FROM cve_matches
                WHERE cpe_string = ?
                ORDER BY cvss_score DESC NULLS LAST, cve_id
                """,
                (cpe_string,),
            ).fetchall()
        return [_row_to_cve(r) for r in rows]

    def list_stale_cpes(self, older_than_hours: int = 24) -> list[str]:
        """CPEs deren juengster CVE-Eintrag aelter als ``older_than_hours``
        Stunden ist. Daily-Refresh-Target — diese CPEs werden via NVD
        neu gefragt.

        Returns:
            Distinct-Liste der CPE-Strings. Reihenfolge nach
            ``MIN(fetched_at)`` ASC (aelteste zuerst).
        """
        cutoff = int(time.time()) - older_than_hours * 3600
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT cpe_string
                FROM cve_matches
                GROUP BY cpe_string
                HAVING MAX(fetched_at) < ?
                ORDER BY MIN(fetched_at) ASC
                """,
                (cutoff,),
            ).fetchall()
        return [str(r[0]) for r in rows]

    def list_known_cpes(self) -> list[str]:
        """Alle CPE-Strings die wir in ``cve_matches`` schon kennen."""
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT cpe_string FROM cve_matches ORDER BY cpe_string"
            ).fetchall()
        return [str(r[0]) for r in rows]

    def list_cve_matches_for_cpes(
        self, cpe_strings: Iterable[str]
    ) -> list[CveMatchEntry]:
        """Batch-Variante von:meth:`list_cve_matches_for_cpe`.

        Liest die CVEs zu mehreren CPEs in EINER Connection via einem
        ``WHERE cpe_string IN`` — statt N Einzel-Opens inkl.
        SQLCipher-PRAGMA-Setup pro CPE (Perf-Hebel /).

        Args:
            cpe_strings: CPE-Strings. Duplikate und leere Strings werden
                ignoriert; leere Eingabe liefert ``[]`` ohne DB-Zugriff.

        Returns:
            Sortiert ``cpe_string, cvss_score DESC NULLS LAST, cve_id``.
        """
        cpes = sorted({c for c in cpe_strings if c})
        if not cpes:
            return []
        # ``placeholders`` ist ausschliesslich eine Folge von '?'-Bind-Markern
        # (kein User-String) — die CPE-Werte werden parametrisiert uebergeben.
        placeholders = ",".join("?" * len(cpes))
        with self._db.connection() as conn:
            rows = conn.execute(
                f"""
                SELECT cpe_string, cve_id, cvss_score, exploit_available, eol, fetched_at
                FROM cve_matches
                WHERE cpe_string IN ({placeholders})
                ORDER BY cpe_string, cvss_score DESC NULLS LAST, cve_id
                """,  # noqa: S608 # nosec B608
                cpes,
            ).fetchall()
        return [_row_to_cve(r) for r in rows]

    def list_affected_cves(
        self, *, min_cvss: float = 0.0, limit: int = 200
    ) -> list[AffectedCveRow]:
        """Betroffene CVEs aus dem JOIN ``inventory_snapshot`` x ``cve_matches``.

        Liefert pro (App, CVE)-Paar eine Zeile — nur fuer Apps mit bekanntem
        CPE (``cpe_string IS NOT NULL``). Das praeziseste "System betroffen"-
        Signal fuer Tab 1 des Risikobriefings, rein lokal (kein
        NVD-HTTP). Apps ohne CPE (Registry/MSIX/Custom) fehlen designbedingt
        — der Aufrufer macht diese Recall-Luecke transparent (Hinweis +
        techstack-"moeglicherweise betroffen"-Bucket).

        Args:
            min_cvss: Mindest-CVSS-Score. ``0.0`` (Default) liefert alle
                Treffer inkl. solcher ohne Score; ``> 0`` filtert auf
                ``cvss_score >= min_cvss`` (Zeilen ohne Score fallen dann raus).
            limit: Obergrenze der Rueckgabe-Zeilen.

        Returns:
            Sortiert ``cvss_score DESC NULLS LAST, exploit_available DESC,
            app_name, cve_id``. Pro (winget_id, cve_id)-Paar eine Zeile.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT
                    i.winget_id, i.name, i.cpe_string, i.installed_version,
                    COALESCE(av.is_update_available, 0), av.available_version,
                    c.cve_id, c.cvss_score, c.exploit_available, c.eol, c.fetched_at
                FROM inventory_snapshot i
                JOIN cve_matches c ON c.cpe_string = i.cpe_string
                LEFT JOIN available_versions av ON av.winget_id = i.winget_id
                WHERE i.cpe_string IS NOT NULL
                  AND (? <= 0 OR c.cvss_score >= ?)
                ORDER BY c.cvss_score DESC NULLS LAST,
                         c.exploit_available DESC, i.name, c.cve_id
                LIMIT ?
                """,
                (min_cvss, min_cvss, limit),
            ).fetchall()
        return [_row_to_affected(r) for r in rows]

    def count_apps_without_cpe(self) -> int:
        """Anzahl inventarisierter Apps OHNE CPE (``cpe_string IS NULL``).

        Diese Apps koennen nicht per CPE auf CVEs geprueft werden — Tab 1
        zeigt damit einen ehrlichen Hinweis ("N Apps konnten nicht geprueft
        werden"), statt die Recall-Luecke still zu verschweigen.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM inventory_snapshot WHERE cpe_string IS NULL"
            ).fetchone()
        return int(row[0]) if row else 0

    # ------------------------------------------------------------------
    # scan_history
    # ------------------------------------------------------------------

    def record_scan_start(self, scan_type: ScanType) -> str:
        """Legt eine neue ``scan_history``-Zeile mit ``started_at = now``
        und ``finished_at = NULL`` an.

        Args:
            scan_type: Eins aus:data:`ScanType`.

        Returns:
            Die generierte UUID4 als Hex-String (Caller braucht das fuer
            den anschliessenden:meth:`record_scan_end`-Aufruf).
        """
        scan_id = uuid.uuid4().hex
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO scan_history(id, started_at, scan_type)
                VALUES (?, ?, ?)
                """,
                (scan_id, int(time.time()), scan_type),
            )
        return scan_id

    def record_scan_end(
        self,
        scan_id: str,
        *,
        items_total: int | None = None,
        items_with_updates: int | None = None,
        items_with_cves: int | None = None,
        error: str | None = None,
    ) -> None:
        """Schliesst eine ``scan_history``-Zeile mit Outcome-Statistiken.

        Berechnet ``duration_ms`` aus ``finished_at - started_at``.
        ``error`` ist optional — bei nicht-None bleiben die Statistik-
        Felder typischerweise leer.
        """
        now = int(time.time())
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT started_at FROM scan_history WHERE id = ?",
                (scan_id,),
            ).fetchone()
            if row is None:
                log.warning("record_scan_end: unbekannte scan_id %s", scan_id)
                return
            started_at = int(row[0])
            duration_ms = (now - started_at) * 1000
            conn.execute(
                """
                UPDATE scan_history SET
                    finished_at        = ?,
                    items_total        = ?,
                    items_with_updates = ?,
                    items_with_cves    = ?,
                    duration_ms        = ?,
                    error              = ?
                WHERE id = ?
                """,
                (
                    now,
                    items_total,
                    items_with_updates,
                    items_with_cves,
                    duration_ms,
                    error,
                    scan_id,
                ),
            )

    def list_scan_history(self, limit: int = 50) -> list[ScanHistoryEntry]:
        """Letzte ``limit`` Scan-History-Eintraege (started_at DESC)."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, started_at, finished_at, scan_type,
                       items_total, items_with_updates, items_with_cves,
                       duration_ms, error
                FROM scan_history
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_row_to_scan_history(r) for r in rows]

    def get_last_full_scan_at(self) -> datetime | None:
        """Zeitpunkt des juengsten erfolgreichen Vollscans
        (initial / monthly_full / manual mit error=None).

        Wird vom Scheduler genutzt um "is monthly full due?" zu
        beantworten.

        Returns:
            UTC-datetime des juengsten Vollscans oder ``None``.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT MAX(finished_at)
                FROM scan_history
                WHERE scan_type IN ('initial', 'monthly_full', 'manual')
                  AND error IS NULL
                  AND finished_at IS NOT NULL
                """,
            ).fetchone()
        if row is None or row[0] is None:
            return None
        return datetime.fromtimestamp(int(row[0]), tz=UTC)

    def get_last_daily_refresh_at(self) -> datetime | None:
        """Zeitpunkt des juengsten erfolgreichen Daily-Refresh."""
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT MAX(finished_at)
                FROM scan_history
                WHERE scan_type = 'daily_refresh'
                  AND error IS NULL
                  AND finished_at IS NOT NULL
                """,
            ).fetchone()
        if row is None or row[0] is None:
            return None
        return datetime.fromtimestamp(int(row[0]), tz=UTC)

    def count_inventory(self) -> int:
        """Anzahl Eintraege in ``inventory_snapshot``. Wird genutzt um
        zu pruefen ob ueberhaupt schon ein Vollscan lief."""
        with self._db.connection() as conn:
            return int(
                conn.execute("SELECT COUNT(*) FROM inventory_snapshot").fetchone()[0]
            )

    # ------------------------------------------------------------------
    # custom_sources, Notify-Only Patch-Quellen)
    # ------------------------------------------------------------------

    def add_custom_source(
        self,
        *,
        name: str,
        vendor_url: str,
        version_regex: str,
        platform: Platform = DEFAULT_PLATFORM,
        installed_version: str | None = None,
        notes: str | None = None,
    ) -> CustomSource:
        """Legt eine neue ``custom_sources``-Zeile an.

        Vergibt ``id`` (UUID4-Hex) und ``created_at`` selbst — analog
:meth:`record_scan_start`. Die Check-Felder (``available_version`` /
        ``last_checked_at`` / ``last_error``) bleiben ``None``, bis der
        custom_source_checker (Stop-Step B) sie befuellt.

        Returns:
            Die angelegte:class:`CustomSource`.
        """
        source_id = uuid.uuid4().hex
        created_at = datetime.now(tz=UTC)
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO custom_sources(
                    id, name, vendor_url, version_regex, platform,
                    installed_version, available_version, last_checked_at,
                    last_error, notes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
                """,
                (
                    source_id,
                    name,
                    vendor_url,
                    version_regex,
                    platform.value,
                    installed_version,
                    notes,
                    int(created_at.timestamp()),
                ),
            )
        return CustomSource(
            id=source_id,
            name=name,
            vendor_url=vendor_url,
            version_regex=version_regex,
            platform=platform,
            installed_version=installed_version,
            available_version=None,
            last_checked_at=None,
            last_error=None,
            notes=notes,
            created_at=created_at,
        )

    def get_custom_source(self, source_id: str) -> CustomSource | None:
        """Liest eine einzelne ``custom_sources``-Zeile."""
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT id, name, vendor_url, version_regex, platform,
                       installed_version, available_version, last_checked_at,
                       last_error, notes, created_at
                FROM custom_sources WHERE id = ?
                """,
                (source_id,),
            ).fetchone()
        return _row_to_custom_source(row) if row else None

    def list_custom_sources(self) -> list[CustomSource]:
        """Alle ``custom_sources``-Zeilen, sortiert nach Name."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, name, vendor_url, version_regex, platform,
                       installed_version, available_version, last_checked_at,
                       last_error, notes, created_at
                FROM custom_sources
                ORDER BY name
                """,
            ).fetchall()
        return [_row_to_custom_source(r) for r in rows]

    def update_custom_source(self, source: CustomSource) -> bool:
        """Aktualisiert eine bestehende ``custom_sources``-Zeile vollstaendig.

        Schreibpfad sowohl fuer User-Edits (Name/URL/Regex/Plattform/Notes/
        installed_version) als auch fuer Check-Ergebnisse aus Stop-Step B
        (available_version / last_checked_at / last_error). ``id`` und
        ``created_at`` bleiben unveraendert.

        Returns:
            ``True`` wenn eine Zeile aktualisiert wurde, ``False`` wenn die
            ``id`` nicht existiert.
        """
        last_checked = (
            int(source.last_checked_at.timestamp())
            if source.last_checked_at is not None
            else None
        )
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                UPDATE custom_sources SET
                    name              = ?,
                    vendor_url        = ?,
                    version_regex     = ?,
                    platform          = ?,
                    installed_version = ?,
                    available_version = ?,
                    last_checked_at   = ?,
                    last_error        = ?,
                    notes             = ?
                WHERE id = ?
                """,
                (
                    source.name,
                    source.vendor_url,
                    source.version_regex,
                    source.platform.value,
                    source.installed_version,
                    source.available_version,
                    last_checked,
                    source.last_error,
                    source.notes,
                    source.id,
                ),
            )
            return cur.rowcount > 0

    def delete_custom_source(self, source_id: str) -> bool:
        """Loescht eine ``custom_sources``-Zeile.

        Returns:
            ``True`` wenn eine Zeile geloescht wurde, ``False`` sonst.
        """
        with self._db.connection() as conn:
            cur = conn.execute("DELETE FROM custom_sources WHERE id = ?", (source_id,))
            return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Row-Mapper
# ---------------------------------------------------------------------------


def _row_to_inventory(row: Iterable) -> InventoryEntry:
    (
        winget_id,
        name,
        normalized_name,
        vendor,
        source,
        installed_version,
        cpe_string,
        channel,
        policy_source,
        confidence_score,
        last_seen_at,
        last_full_scan_at,
        patch_strategy,
    ) = row
    return InventoryEntry(
        winget_id=winget_id,
        name=name,
        normalized_name=normalized_name,
        vendor=vendor,
        source=source,
        installed_version=installed_version,
        cpe_string=cpe_string,
        channel=channel,
        policy_source=policy_source,
        confidence_score=confidence_score,
        last_seen_at=datetime.fromtimestamp(int(last_seen_at), tz=UTC),
        last_full_scan_at=datetime.fromtimestamp(int(last_full_scan_at), tz=UTC),
        patch_strategy=PatchStrategy(patch_strategy),
    )


def _row_to_available(row: Iterable) -> AvailableVersionEntry:
    winget_id, available_version, is_update_available, last_checked_at = row
    return AvailableVersionEntry(
        winget_id=winget_id,
        available_version=available_version,
        is_update_available=bool(is_update_available),
        last_checked_at=datetime.fromtimestamp(int(last_checked_at), tz=UTC),
    )


def _row_to_cve(row: Iterable) -> CveMatchEntry:
    cpe_string, cve_id, cvss_score, exploit_available, eol, fetched_at = row
    return CveMatchEntry(
        cpe_string=cpe_string,
        cve_id=cve_id,
        cvss_score=cvss_score,
        exploit_available=bool(exploit_available),
        eol=bool(eol),
        fetched_at=datetime.fromtimestamp(int(fetched_at), tz=UTC),
    )


def _row_to_affected(row: Iterable) -> AffectedCveRow:
    (
        winget_id,
        app_name,
        cpe_string,
        installed_version,
        is_update_available,
        available_version,
        cve_id,
        cvss_score,
        exploit_available,
        eol,
        fetched_at,
    ) = row
    return AffectedCveRow(
        winget_id=winget_id,
        app_name=app_name,
        cpe_string=cpe_string,
        installed_version=installed_version,
        is_update_available=bool(is_update_available),
        available_version=available_version,
        cve_id=cve_id,
        cvss_score=cvss_score,
        exploit_available=bool(exploit_available),
        eol=bool(eol),
        fetched_at=datetime.fromtimestamp(int(fetched_at), tz=UTC),
    )


def _row_to_scan_history(row: Iterable) -> ScanHistoryEntry:
    (
        scan_id,
        started_at,
        finished_at,
        scan_type,
        items_total,
        items_with_updates,
        items_with_cves,
        duration_ms,
        error,
    ) = row
    return ScanHistoryEntry(
        id=scan_id,
        started_at=datetime.fromtimestamp(int(started_at), tz=UTC),
        finished_at=(
            datetime.fromtimestamp(int(finished_at), tz=UTC)
            if finished_at is not None
            else None
        ),
        scan_type=scan_type,
        items_total=items_total,
        items_with_updates=items_with_updates,
        items_with_cves=items_with_cves,
        duration_ms=duration_ms,
        error=error,
    )


def _row_to_custom_source(row: Iterable) -> CustomSource:
    (
        source_id,
        name,
        vendor_url,
        version_regex,
        platform,
        installed_version,
        available_version,
        last_checked_at,
        last_error,
        notes,
        created_at,
    ) = row
    return CustomSource(
        id=source_id,
        name=name,
        vendor_url=vendor_url,
        version_regex=version_regex,
        platform=Platform(platform),
        installed_version=installed_version,
        available_version=available_version,
        last_checked_at=(
            datetime.fromtimestamp(int(last_checked_at), tz=UTC)
            if last_checked_at is not None
            else None
        ),
        last_error=last_error,
        notes=notes,
        created_at=datetime.fromtimestamp(int(created_at), tz=UTC),
    )
