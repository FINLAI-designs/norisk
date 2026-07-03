"""
tech_stack_repository — Persistenz für System-Profile via EncryptedDatabase.

Schema (system_profiles-Tabelle):
  profile_id TEXT PRIMARY KEY
  name TEXT NOT NULL
  system_type TEXT NOT NULL ('eigenes' | 'kunde')
  description TEXT
  contact TEXT
  tech_stack TEXT (JSON-Blob)
  created_at TEXT
  updated_at TEXT
  branche TEXT (additiv — Subjekt-Stammdaten)
  groesse TEXT (additiv)
  fte INTEGER (additiv — Einstiegs-Scoping; NULL = unbekannt)
  umsatz_eur INTEGER (additiv; NULL = unbekannt)
  bilanzsumme_eur INTEGER (additiv; NULL = unbekannt)
  sektor_key TEXT (additiv — NIS2-Sektor-Schlüssel)
  nis2_anhang TEXT (additiv — aus sektor_key abgeleitet: 'I'|'II'|'')
  rolle TEXT (additiv — Rolle der erfassenden Person)
  segment TEXT (additiv — W1-Segment des eigenen Systems)
  hat_eigene_website INTEGER (additiv; 0/1/NULL — gated cert_monitor)
  hat_eigene_api INTEGER (additiv; 0/1/NULL — gated api_security)
  ist_entwickler INTEGER (additiv; 0/1/NULL — gated dependency_auditor)
  hat_server_infrastruktur INTEGER (additiv; 0/1/NULL)

WICHTIG (P0): Die SELECT-Projektion folgt NICHT der physischen Spalten-
reihenfolge — tech_stack/created_at/updated_at stehen im SELECT VOR dem additiven
Block. Neue Spalten werden daher konsistent ans ENDE von SELECT, INSERT, UPDATE
und ``_row_to_profile`` (mit ``len(row)``-Guards) angehängt. Ein Index-Shift-
Detektor-Test (charakteristischer Wert je Feld) sichert die Synchronität.

Schichtzugehörigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.database.schema_utils import ensure_column
from core.escape import unescape_legacy_html
from core.exceptions import ValidationError
from core.logger import get_logger
from tools.security_scoring.domain.tech_stack.entities import (
    BrowserEntry,
    OSEntry,
    SecurityTool,
    SystemProfile,
    TechStack,
)
from tools.security_scoring.domain.tech_stack.enums import SystemType, ToolStatus

log = get_logger(__name__)

_DB_NAME = "security_scoring"

#/: Kunden-Subjekte tragen den Audit-Firmennamen — der wurde
# bis escaped persistiert (sanitize_text-Altverhalten) und via
# find_or_create_client hierher denormalisiert. Einmaliger Unescape-
# Backfill, sonst bricht die Name-basierte Dedup (Klartext-Name matcht
# escaped Bestand nicht → Duplikat-Subjekte).
_UNESCAPE_NAMES_MIGRATION_ID = "t315_unescape_profile_names_v1"


class TechStackRepository:
    """CRUD-Repository für SystemProfile-Objekte (EncryptedDatabase).

    Teilt die DB mit score_repository.py ('security_scoring').
    """

    def __init__(self) -> None:
        """Initialisiert das Repository und erstellt die Tabelle falls nötig."""
        self._db = EncryptedDatabase(_DB_NAME)
        self._ensure_table()
        self._migrate_unescape_names()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _ensure_table(self) -> None:
        """Erstellt die system_profiles-Tabelle + additive Subjekt-Spalten."""
        with self._db.connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS system_profiles (
                    profile_id  TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    system_type TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    contact     TEXT DEFAULT '',
                    tech_stack  TEXT DEFAULT '{}',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_system_profiles_type
                    ON system_profiles(system_type);
                """
            )
            # Additive Subjekt-/Scoping-/W1-Spalten. SQLite kennt kein
            # ADD COLUMN IF NOT EXISTS → die idempotente Hilfe ``ensure_column``
            # prüft PRAGMA table_info und legt nur fehlende Spalten an (Regel 2:
            # keine zweite ALTER-Schleife, Entduplizierung). Forward-only, kein
            # user_version-Stempel (Idempotenz allein aus dem Existenz-Guard).
            # Geld/FTE + W1-Booleans als nullable INTEGER (kein DEFAULT): NULL =
            # "nicht erfasst", sauber getrennt von 0. (branche/groesse:;
            # fte..rolle:; segment..hat_server_infrastruktur: W1.)
            additive_columns = (
                ("branche", "TEXT DEFAULT ''"),
                ("groesse", "TEXT DEFAULT ''"),
                ("fte", "INTEGER"),
                ("umsatz_eur", "INTEGER"),
                ("bilanzsumme_eur", "INTEGER"),
                ("sektor_key", "TEXT DEFAULT ''"),
                ("nis2_anhang", "TEXT DEFAULT ''"),
                ("rolle", "TEXT DEFAULT ''"),
                ("segment", "TEXT DEFAULT ''"),
                ("hat_eigene_website", "INTEGER"),
                ("hat_eigene_api", "INTEGER"),
                ("ist_entwickler", "INTEGER"),
                ("hat_server_infrastruktur", "INTEGER"),
            )
            for column, ddl in additive_columns:
                ensure_column(conn, "system_profiles", column, ddl)

    def _migrate_unescape_names(self) -> None:
        """/: einmaliger Unescape-Backfill der Profil-Namen.

        Subjekt-Namen (= Audit-Firmennamen) wurden bis escaped
        denormalisiert. Ohne Backfill zeigt der Subjekt-Selector
        ``&amp;``-Artefakte und ``find_or_create_client`` legt beim
        nächsten Audit-Speichern ein Duplikat-Subjekt an (Dedup per Name).
        Marker-idempotent in EINER Transaktion; forward-only ohne Backup
        (Altdaten = Testdaten/022).
        """
        with self._db.connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS profile_migration_log ("
                " migration_id TEXT PRIMARY KEY,"
                " completed_at TEXT NOT NULL,"
                " rows_copied  INTEGER NOT NULL,"
                " source       TEXT NOT NULL)"
            )
            done = conn.execute(
                "SELECT 1 FROM profile_migration_log WHERE migration_id = ?",
                (_UNESCAPE_NAMES_MIGRATION_ID,),
            ).fetchone()
            if done:
                return
            rows = conn.execute(
                "SELECT profile_id, name FROM system_profiles"
            ).fetchall()
            migrated = 0
            for profile_id, name in rows:
                klartext = unescape_legacy_html(name or "")
                if klartext != name:
                    conn.execute(
                        "UPDATE system_profiles SET name = ? WHERE profile_id = ?",
                        (klartext, profile_id),
                    )
                    migrated += 1
            conn.execute(
                "INSERT OR REPLACE INTO profile_migration_log "
                "(migration_id, completed_at, rows_copied, source) "
                "VALUES (?, ?, ?, ?)",
                (
                    _UNESCAPE_NAMES_MIGRATION_ID,
                    datetime.now(tz=UTC).isoformat(),
                    migrated,
                    "t315_escape_at_render",
                ),
            )
        log.info("T-315-Profilnamen-Migration: %d Namen ent-escaped", migrated)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create(self, profile: SystemProfile) -> None:
        """Speichert ein neues SystemProfile.

        Args:
            profile: Das zu speichernde Profil.

        Raises:
            RuntimeError: Bei DB-Schreibfehler.
        """
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO system_profiles
                    (profile_id, name, system_type, description, contact,
                     branche, groesse, fte, umsatz_eur, bilanzsumme_eur,
                     sektor_key, nis2_anhang, rolle,
                     tech_stack, created_at, updated_at,
                     segment, hat_eigene_website, hat_eigene_api,
                     ist_entwickler, hat_server_infrastruktur)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?)
                """,
                (
                    profile.id,
                    profile.name,
                    profile.system_type.value,
                    profile.description,
                    profile.contact,
                    profile.branche,
                    profile.groesse,
                    profile.fte,
                    profile.umsatz_eur,
                    profile.bilanzsumme_eur,
                    profile.sektor_key,
                    profile.nis2_anhang,
                    profile.rolle,
                    _tech_stack_to_json(profile.tech_stack),
                    profile.created_at,
                    profile.updated_at,
                    profile.segment,
                    profile.hat_eigene_website,
                    profile.hat_eigene_api,
                    profile.ist_entwickler,
                    profile.hat_server_infrastruktur,
                ),
            )
        log.debug("SystemProfile erstellt: %s (%s)", profile.name, profile.system_type)

    def get_all(self) -> list[SystemProfile]:
        """Gibt alle Profile zurück (eigenes System zuerst, dann alphabetisch).

        Returns:
            Sortierte Liste aller SystemProfile.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT profile_id, name, system_type, description, contact,
                       tech_stack, created_at, updated_at,
                       COALESCE(branche, ''), COALESCE(groesse, ''),
                       fte, umsatz_eur, bilanzsumme_eur,
                       COALESCE(sektor_key, ''), COALESCE(nis2_anhang, ''),
                       COALESCE(rolle, ''), COALESCE(segment, ''),
                       hat_eigene_website, hat_eigene_api, ist_entwickler,
                       hat_server_infrastruktur
                FROM system_profiles
                ORDER BY
                    CASE system_type WHEN 'eigenes' THEN 0 ELSE 1 END,
                    name COLLATE NOCASE
                """
            ).fetchall()
        return [_row_to_profile(r) for r in rows]

    def get_by_id(self, profile_id: str) -> SystemProfile | None:
        """Gibt ein Profil anhand der ID zurück.

        Args:
            profile_id: UUID des Profils.

        Returns:
            SystemProfile oder None wenn nicht gefunden.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT profile_id, name, system_type, description, contact,
                       tech_stack, created_at, updated_at,
                       COALESCE(branche, ''), COALESCE(groesse, ''),
                       fte, umsatz_eur, bilanzsumme_eur,
                       COALESCE(sektor_key, ''), COALESCE(nis2_anhang, ''),
                       COALESCE(rolle, ''), COALESCE(segment, ''),
                       hat_eigene_website, hat_eigene_api, ist_entwickler,
                       hat_server_infrastruktur
                FROM system_profiles WHERE profile_id = ?
                """,
                (profile_id,),
            ).fetchone()
        return _row_to_profile(row) if row else None

    def get_by_name(self, name: str) -> SystemProfile | None:
        """Sucht ein Profil nach Name (case-insensitive).

        Args:
            name: Profilname.

        Returns:
            SystemProfile oder None.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT profile_id, name, system_type, description, contact,
                       tech_stack, created_at, updated_at,
                       COALESCE(branche, ''), COALESCE(groesse, ''),
                       fte, umsatz_eur, bilanzsumme_eur,
                       COALESCE(sektor_key, ''), COALESCE(nis2_anhang, ''),
                       COALESCE(rolle, ''), COALESCE(segment, ''),
                       hat_eigene_website, hat_eigene_api, ist_entwickler,
                       hat_server_infrastruktur
                FROM system_profiles WHERE name = ? COLLATE NOCASE
                """,
                (name,),
            ).fetchone()
        return _row_to_profile(row) if row else None

    def get_customer_by_name(self, name: str) -> SystemProfile | None:
        """Sucht ein KUNDE-Profil nach Name (case-insensitive).

        Im Gegensatz zu:meth:`get_by_name` wird auf ``system_type='kunde'``
        gefiltert — verhindert, dass ein gleichnamiges eigenes System einen
        Kunden-Treffer vortäuscht (Subjekt-Dedup).

        Args:
            name: Profilname.

        Returns:
            SystemProfile (KUNDE) oder None.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT profile_id, name, system_type, description, contact,
                       tech_stack, created_at, updated_at,
                       COALESCE(branche, ''), COALESCE(groesse, ''),
                       fte, umsatz_eur, bilanzsumme_eur,
                       COALESCE(sektor_key, ''), COALESCE(nis2_anhang, ''),
                       COALESCE(rolle, ''), COALESCE(segment, ''),
                       hat_eigene_website, hat_eigene_api, ist_entwickler,
                       hat_server_infrastruktur
                FROM system_profiles
                WHERE name = ? COLLATE NOCASE AND system_type = 'kunde'
                LIMIT 1
                """,
                (name,),
            ).fetchone()
        return _row_to_profile(row) if row else None

    def get_own_system(self) -> SystemProfile | None:
        """Gibt das eigene System zurück (nur eines existiert).

        Returns:
            SystemProfile mit system_type=EIGENES oder None.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT profile_id, name, system_type, description, contact,
                       tech_stack, created_at, updated_at,
                       COALESCE(branche, ''), COALESCE(groesse, ''),
                       fte, umsatz_eur, bilanzsumme_eur,
                       COALESCE(sektor_key, ''), COALESCE(nis2_anhang, ''),
                       COALESCE(rolle, ''), COALESCE(segment, ''),
                       hat_eigene_website, hat_eigene_api, ist_entwickler,
                       hat_server_infrastruktur
                FROM system_profiles WHERE system_type = 'eigenes' LIMIT 1
                """
            ).fetchone()
        return _row_to_profile(row) if row else None

    def update(self, profile: SystemProfile) -> None:
        """Aktualisiert ein bestehendes Profil.

        Args:
            profile: Profil mit aktualisierten Daten.

        Raises:
            RuntimeError: Bei DB-Schreibfehler.
        """
        now = datetime.now(UTC).isoformat()
        with self._db.connection() as conn:
            conn.execute(
                """
                UPDATE system_profiles
                SET name = ?, description = ?, contact = ?,
                    branche = ?, groesse = ?, fte = ?, umsatz_eur = ?,
                    bilanzsumme_eur = ?, sektor_key = ?, nis2_anhang = ?,
                    rolle = ?, tech_stack = ?, updated_at = ?,
                    segment = ?, hat_eigene_website = ?, hat_eigene_api = ?,
                    ist_entwickler = ?, hat_server_infrastruktur = ?
                WHERE profile_id = ?
                """,
                (
                    profile.name,
                    profile.description,
                    profile.contact,
                    profile.branche,
                    profile.groesse,
                    profile.fte,
                    profile.umsatz_eur,
                    profile.bilanzsumme_eur,
                    profile.sektor_key,
                    profile.nis2_anhang,
                    profile.rolle,
                    _tech_stack_to_json(profile.tech_stack),
                    now,
                    profile.segment,
                    profile.hat_eigene_website,
                    profile.hat_eigene_api,
                    profile.ist_entwickler,
                    profile.hat_server_infrastruktur,
                    profile.id,
                ),
            )
        log.debug("SystemProfile aktualisiert: %s", profile.name)

    def delete(self, profile_id: str) -> None:
        """Löscht ein Kundenprofil (EIGENES-System kann nicht gelöscht werden).

        Args:
            profile_id: UUID des zu löschenden Profils.

        Raises:
            ValueError: Wenn versucht wird, das eigene System zu löschen.
        """
        profile = self.get_by_id(profile_id)
        if profile and profile.system_type == SystemType.EIGENES:
            raise ValidationError("Das eigene System kann nicht gelöscht werden.")
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM system_profiles WHERE profile_id = ?",
                (profile_id,),
            )
        log.debug("SystemProfile gelöscht: %s", profile_id)

    def count(self) -> int:
        """Gibt die Anzahl aller Profile zurück."""
        with self._db.connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM system_profiles").fetchone()[0]


# ------------------------------------------------------------------
# Serialisierungs-Hilfsfunktionen
# ------------------------------------------------------------------


def _tech_stack_to_json(ts: TechStack) -> str:
    """Konvertiert TechStack in JSON-String.

    Args:
        ts: TechStack-Objekt.

    Returns:
        JSON-String.
    """
    data = {
        "operating_systems": [asdict(o) for o in ts.operating_systems],
        "antivirus": {"name": ts.antivirus.name, "status": ts.antivirus.status.value},
        "firewall": {"name": ts.firewall.name, "status": ts.firewall.status.value},
        "browsers": [asdict(b) for b in ts.browsers],
        "encryption": ts.encryption,
        "vpn": ts.vpn,
        "remote_access": ts.remote_access,
        "server_infra": ts.server_infra,
        "custom_software": ts.custom_software,
    }
    return json.dumps(data, ensure_ascii=False)


def _tech_stack_from_json(raw: str) -> TechStack:
    """Deserialisiert TechStack aus JSON-String.

    Args:
        raw: JSON-String.

    Returns:
        TechStack-Objekt (leeres TechStack bei Fehler).
    """
    try:
        data = json.loads(raw)
        return TechStack(
            operating_systems=[
                OSEntry(o["name"], o.get("version", ""))
                for o in data.get("operating_systems", [])
            ],
            antivirus=SecurityTool(
                name=data.get("antivirus", {}).get("name", ""),
                status=ToolStatus(data.get("antivirus", {}).get("status", "unbekannt")),
            ),
            firewall=SecurityTool(
                name=data.get("firewall", {}).get("name", ""),
                status=ToolStatus(data.get("firewall", {}).get("status", "unbekannt")),
            ),
            browsers=[
                BrowserEntry(b["name"], b.get("version", ""))
                for b in data.get("browsers", [])
            ],
            encryption=data.get("encryption", []),
            vpn=data.get("vpn"),
            remote_access=data.get("remote_access", []),
            server_infra=data.get("server_infra", ""),
            custom_software=data.get("custom_software", []),
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        log.warning("TechStack-Deserialisierung fehlgeschlagen — leeres Objekt zurück")
        return TechStack()


def _row_to_profile(row: tuple) -> SystemProfile:
    """Konvertiert eine DB-Zeile in ein SystemProfile-Objekt.

    Args:
        row: Tupel in der **SELECT-Projektionsreihenfolge** (NICHT der physischen
            Spaltenreihenfolge — P0): (profile_id, name, system_type,
            description, contact, tech_stack, created_at, updated_at, branche,
            groesse, fte, umsatz_eur, bilanzsumme_eur, sektor_key, nis2_anhang,
            rolle, segment, hat_eigene_website, hat_eigene_api, ist_entwickler,
            hat_server_infrastruktur). Die ``len(row)``-Guards halten
            ältere/kürzere Zeilen kompatibel (Defaults: TEXT→"", INT→None).

    Returns:
        SystemProfile-Objekt.
    """
    return SystemProfile(
        id=row[0],
        name=row[1],
        system_type=SystemType(row[2]),
        description=row[3] or "",
        contact=row[4] or "",
        tech_stack=_tech_stack_from_json(row[5] or "{}"),
        created_at=row[6] or "",
        updated_at=row[7] or "",
        branche=row[8] or "" if len(row) > 8 else "",
        groesse=row[9] or "" if len(row) > 9 else "",
        fte=row[10] if len(row) > 10 else None,
        umsatz_eur=row[11] if len(row) > 11 else None,
        bilanzsumme_eur=row[12] if len(row) > 12 else None,
        sektor_key=(row[13] or "") if len(row) > 13 else "",
        nis2_anhang=(row[14] or "") if len(row) > 14 else "",
        rolle=(row[15] or "") if len(row) > 15 else "",
        segment=(row[16] or "") if len(row) > 16 else "",
        hat_eigene_website=row[17] if len(row) > 17 else None,
        hat_eigene_api=row[18] if len(row) > 18 else None,
        ist_entwickler=row[19] if len(row) > 19 else None,
        hat_server_infrastruktur=row[20] if len(row) > 20 else None,
    )
