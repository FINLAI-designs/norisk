"""nis2_incident_repository — Persistierung der NIS2-Incident-Tabellen.

Tabellen in der bestehenden ``customer_audit``-DB (Schluessel-Reuse ueber den
HKDF-Sub-Key ``db:customer_audit``):

- ``nis2_incidents``: ein Datensatz pro Vorfall (mutabel: current_phase,
  closed_at, personenbezug, updated_at).
- ``nis2_phase_events``: Append-only, manipulationssicher verketteter
  Audit-Trail jeder Statusaenderung (HMAC-Hashkette pro Incident §3).
  Append-only wird hart durch BEFORE-UPDATE/DELETE-Trigger erzwungen
  (RAISE ABORT) — Wartungs-Bypass nur ueber die Kontroll-Row
  ``nis2_chain_control``.
- ``nis2_phase_drafts``: editierbarer Draft je (incident, phase). "Einreichen"
  schiebt den Draft atomar in ein unveraenderliches ``nis2_phase_events``-Event
  und loescht die Draft-Zeile §2).
- ``nis2_chain_control``: Single-Row-Kontrolltabelle fuer den
  ``maintenance_bypass`` (autorisierte Anonymisierung).

Schichtzugehoerigkeit: data/ — DB-Zugriff erlaubt.

ADR-Bezug: docs/adr/-nis2-incident-tracker.md §2.2,
docs/adr/-nis2-tracker-revisionssicher.md.

Author: Patrick Riederich
Version: 0.2 (NIS2-revisionssicher, Schicht 1 Backend)
"""

from __future__ import annotations

import contextlib
import json
import shutil
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from core.database.encrypted_db import EncryptedDatabase
from core.database.schema_utils import ensure_column
from core.logger import get_logger
from tools.customer_audit.data import nis2_tamper
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    Nis2Incident,
    PhaseEvent,
    PhaseStatus,
)

_log = get_logger(__name__)

_DB_NAME = "customer_audit"

#: Schwaerzungs-Marker fuer anonymisierte Freitext-/PII-Felder.
_REDACTED = "[anonymisiert]"


def _redact_payload(payload: dict) -> dict:
    """Schwaerzt ALLE Freitext-Werte eines Event-Payloads (DSGVO Art.17, §5).

    Robust statt Whitelist: jeder ``str``-Wert wird zu:data:`_REDACTED`, jede
    ``list`` zu ``['[anonymisiert]']`` — das deckt note/beschreibung/iocs/
    sofortmassnahmen/kommunikationsstatus/ursache/massnahmen UND kuenftige
    Freitext-Keys ab, ohne dass die Whitelist nachgezogen werden muss. ``bool``/
    ``int``/``float`` (severity-Zahlen, Flags) BLEIBEN — sie tragen keinen
    Personenbezug und werden fuer Auswertung/Compliance benoetigt.

    Args:
        payload: Der zu schwaerzende Event-Payload (geparstes Dict).

    Returns:
        Neues Dict mit geschwaerzten Freitext-Werten, numerische Werte intakt.
    """
    redacted: dict = {}
    for key, value in payload.items():
        if isinstance(value, (bool, int, float)):
            # bool/int/float (Flags, severity-Zahlen) bleiben — kein Personenbezug.
            # bool ist Subklasse von int, faellt hier korrekt mit hinein.
            redacted[key] = value
        elif isinstance(value, list):
            redacted[key] = [_REDACTED]
        else:
            # str / dict / None / sonstige: als Freitext-Verdacht schwaerzen.
            redacted[key] = _REDACTED
    return redacted


_SCHEMA = """
CREATE TABLE IF NOT EXISTS nis2_incidents (
    incident_id      TEXT PRIMARY KEY,
    audit_id         TEXT NOT NULL,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    severity         TEXT NOT NULL,
    detected_at      TEXT NOT NULL,
    current_phase    TEXT NOT NULL,
    closed_at        TEXT,
    personenbezug    INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nis2_incidents_audit
    ON nis2_incidents(audit_id);
CREATE INDEX IF NOT EXISTS idx_nis2_incidents_phase
    ON nis2_incidents(current_phase);

CREATE TABLE IF NOT EXISTS nis2_phase_events (
    event_id                INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id             TEXT NOT NULL,
    phase                   TEXT NOT NULL,
    status                  TEXT NOT NULL,
    actor                   TEXT NOT NULL DEFAULT '',
    note                    TEXT NOT NULL DEFAULT '',
    occurred_at             TEXT NOT NULL,
    payload                 TEXT NOT NULL DEFAULT '{}',
    payload_schema_version  INTEGER NOT NULL DEFAULT 1,
    prev_hash               TEXT NOT NULL DEFAULT '',
    event_hash              TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_nis2_phase_events_incident
    ON nis2_phase_events(incident_id, occurred_at);

CREATE TABLE IF NOT EXISTS nis2_phase_drafts (
    incident_id             TEXT NOT NULL,
    phase                   TEXT NOT NULL,
    payload                 TEXT NOT NULL DEFAULT '{}',
    payload_schema_version  INTEGER NOT NULL DEFAULT 1,
    actor                   TEXT NOT NULL DEFAULT '',
    updated_at              TEXT NOT NULL,
    PRIMARY KEY (incident_id, phase)
);

CREATE TABLE IF NOT EXISTS nis2_chain_control (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    maintenance_bypass  INTEGER NOT NULL DEFAULT 0
);
"""

#: Append-only-Trigger. Beide tragen den maintenance_bypass-Guard, damit die
#: autorisierte Anonymisierung (DSGVO Art.17) UPDATEN/re-ketten darf — sonst
#: koennte die Hashkette der geschwaerzten Events nicht neu gerechnet werden
#: §5).
_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS trg_nis2_events_no_update
BEFORE UPDATE ON nis2_phase_events
WHEN (SELECT maintenance_bypass FROM nis2_chain_control WHERE id = 1) IS NOT 1
BEGIN
    SELECT RAISE(ABORT, 'append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_nis2_events_no_delete
BEFORE DELETE ON nis2_phase_events
WHEN (SELECT maintenance_bypass FROM nis2_chain_control WHERE id = 1) IS NOT 1
BEGIN
    SELECT RAISE(ABORT, 'append-only');
END;
"""


class DbNis2IncidentRepository:
    """SQLCipher-Persistenz fuer NIS2-Incidents + verketteter Append-only-Trail."""

    def __init__(
        self,
        db: EncryptedDatabase | None = None,
        *,
        chain_key: bytes | None = None,
        key_manager: object | None = None,
    ) -> None:
        """Initialisiert das Repository und migriert das Schema idempotent.

        Args:
            db: Optionale:class:`EncryptedDatabase`. Default: ``customer_audit``.
            chain_key: Optionaler 32-Byte HMAC-Ketten-Schluessel (Test-Injektion).
                Default: lazy via:func:`nis2_tamper.load_chain_key`.
            key_manager: Optionaler expliziter KeyManager fuer die Ketten-
                Schluessel-Ableitung (Constructor-Injection). Wird ignoriert,
                wenn ``chain_key`` gesetzt ist.
        """
        self._db = db or EncryptedDatabase(_DB_NAME)
        self._chain_key = chain_key
        self._key_manager = key_manager
        self._init_schema()

    # ------------------------------------------------------------------
    # Schema / Migration
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Legt Tabellen an, migriert additiv und installiert die Trigger.

        Idempotent: ``CREATE... IF NOT EXISTS`` + Spaltenexistenz-Check
        (PRAGMA table_info via:func:`ensure_column`). KEIN ``PRAGMA
        user_version`` — die ``customer_audit``-DB ist geteilt §5).
        """
        # Best-effort-Backup VOR der ersten Migration (Spalte fehlt noch).
        self._maybe_backup_before_migration()
        with self._db.connection() as conn:
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)
            # Additive Migration auf Alt-DBs (Spalten existieren ggf. nicht).
            ensure_column(
                conn, "nis2_phase_events", "payload", "TEXT NOT NULL DEFAULT '{}'"
            )
            ensure_column(
                conn,
                "nis2_phase_events",
                "payload_schema_version",
                "INTEGER NOT NULL DEFAULT 1",
            )
            ensure_column(
                conn, "nis2_phase_events", "prev_hash", "TEXT NOT NULL DEFAULT ''"
            )
            ensure_column(
                conn, "nis2_phase_events", "event_hash", "TEXT NOT NULL DEFAULT ''"
            )
            ensure_column(
                conn,
                "nis2_incidents",
                "personenbezug",
                "INTEGER NOT NULL DEFAULT 0",
            )
            # Index auf personenbezug ERST NACH dem ALTER anlegen: Bestands-DBs
            # haben die Spalte vor der Migration nicht, ein Index im Basis-_SCHEMA
            # wuerde auf der Alt-Tabelle mit 'no such column' crashen (Hotfix).
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_nis2_incidents_personenbezug "
                "ON nis2_incidents(personenbezug)"
            )
            conn.execute(
                "INSERT OR IGNORE INTO nis2_chain_control (id, maintenance_bypass) "
                "VALUES (1, 0)"
            )
            # Trigger via executescript: ihr BEGIN..END-Block enthaelt interne
            # Semikola, die ein naives split(';') zerreissen wuerde.
            conn.executescript(_TRIGGERS)
            conn.commit()

    def _maybe_backup_before_migration(self) -> None:
        """Best-effort: ``.bak``-Kopie der DB-Datei vor der ERSTEN Migration.

        Nur, wenn die ``payload``-Spalte in ``nis2_phase_events`` noch fehlt
        (erster Migrationslauf) UND die DB eine echte Datei hat. Nicht
        blockierend — jeder Fehler wird verschluckt (try/except), die
        Migration laeuft trotzdem.
        """
        db_path = getattr(self._db, "db_path", None)
        if db_path is None:
            return
        try:
            with self._db.connection() as conn:
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                if "nis2_phase_events" not in tables:
                    return  # Frische DB — nichts zu sichern.
                cols = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info(nis2_phase_events)"
                    ).fetchall()
                }
            if "payload" in cols:
                return  # Bereits migriert — kein Backup noetig.
            if not db_path.exists():
                return
            backup = db_path.with_suffix(db_path.suffix + ".nis2_tamper_v1.bak")
            if not backup.exists():
                shutil.copy2(db_path, backup)
                _log.info("nis2-Migration: DB-Backup angelegt -> %s", backup.name)
        except Exception as exc:  # noqa: BLE001 -- Backup ist best-effort.
            _log.warning(
                "nis2-Migration: DB-Backup uebersprungen (%s).",
                type(exc).__name__,
            )

    # ------------------------------------------------------------------
    # Chain-Key
    # ------------------------------------------------------------------

    def _get_chain_key(self) -> bytes:
        """Liefert den 32-Byte HMAC-Ketten-Schluessel (lazy, gecacht, fail-closed)."""
        if self._chain_key is None:
            self._chain_key = nis2_tamper.load_chain_key(self._key_manager)
        return self._chain_key

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add_incident(self, incident: Nis2Incident) -> None:
        """Legt einen neuen Vorfall an (kollidiert bei doppeltem incident_id)."""
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO nis2_incidents
                    (incident_id, audit_id, title, description, severity,
                     detected_at, current_phase, closed_at, personenbezug,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.audit_id,
                    incident.title,
                    incident.description,
                    incident.severity.value,
                    incident.detected_at.isoformat(),
                    incident.current_phase.value,
                    incident.closed_at.isoformat() if incident.closed_at else None,
                    int(incident.personenbezug),
                    incident.created_at.isoformat(),
                    incident.updated_at.isoformat(),
                ),
            )
            conn.commit()
        _log.info(
            "nis2_incident_added id=%s audit=%s severity=%s",
            incident.incident_id,
            incident.audit_id,
            incident.severity.value,
        )

    def append_phase_event(self, event: PhaseEvent) -> int:
        """APPEND-ONLY + verkettet: schreibt ein Event und gibt event_id zurueck.

        Die einzige Schreib-API fuer ``nis2_phase_events``. In EINER Transaktion
        (``BEGIN IMMEDIATE`` gegen TOCTOU-Ketten-Fork bei parallelen Appends):
        letzten ``event_hash`` des Incidents holen (sonst:data:`GENESIS`),
        ``event_hash`` berechnen und mit ``prev_hash``/``payload`` einfuegen
 §3). ``personenbezug`` ist Header-Eigenschaft und geht NICHT in
        den Event-Hash ein (sonst bricht ``set_personenbezug`` die Kette, P0).
        """
        payload_json = json.dumps(event.payload, ensure_ascii=False)
        with self._db.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            prev_hash = self._last_event_hash(conn, event.incident_id)
            ev_map = {
                "incident_id": event.incident_id,
                "phase": event.phase.value,
                "status": event.status.value,
                "actor": event.actor,
                "note": event.note,
                "occurred_at": event.occurred_at.isoformat(),
                "payload_schema_version": event.payload_schema_version,
                "payload": event.payload,
            }
            event_hash = nis2_tamper.compute_event_hash(
                self._get_chain_key(), prev_hash, ev_map
            )
            cur = conn.execute(
                """
                INSERT INTO nis2_phase_events
                    (incident_id, phase, status, actor, note, occurred_at,
                     payload, payload_schema_version, prev_hash, event_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.incident_id,
                    event.phase.value,
                    event.status.value,
                    event.actor,
                    event.note,
                    event.occurred_at.isoformat(),
                    payload_json,
                    event.payload_schema_version,
                    prev_hash,
                    event_hash,
                ),
            )
            conn.commit()
            event_id = int(cur.lastrowid or 0)
        _log.info(
            "nis2_phase_event_appended incident=%s phase=%s status=%s event_id=%s",
            event.incident_id,
            event.phase.value,
            event.status.value,
            event_id,
        )
        return event_id

    def update_incident_header(
        self,
        incident_id: str,
        *,
        current_phase: IncidentPhase | None = None,
        closed_at: datetime | None = None,
        personenbezug: bool | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Mutiert die ``nis2_incidents``-Zeile (Read-Modify-Write).

        ``None`` bedeutet "Wert beibehalten". Statisches ``UPDATE``-Statement
        (kein S608-Risiko, weil der Befehl zur Compile-Zeit feststeht).
        """
        if (
            current_phase is None
            and closed_at is None
            and personenbezug is None
            and updated_at is None
        ):
            return
        existing = self.get_incident(incident_id)
        if existing is None:
            return
        new_phase = (
            current_phase.value
            if current_phase is not None
            else existing.current_phase.value
        )
        new_closed = (
            closed_at.isoformat()
            if closed_at is not None
            else (existing.closed_at.isoformat() if existing.closed_at else None)
        )
        new_pb = (
            int(personenbezug)
            if personenbezug is not None
            else int(existing.personenbezug)
        )
        new_updated = (updated_at or existing.updated_at).isoformat()
        with self._db.connection() as conn:
            conn.execute(
                "UPDATE nis2_incidents SET current_phase = ?, closed_at = ?, "
                "personenbezug = ?, updated_at = ? WHERE incident_id = ?",
                (new_phase, new_closed, new_pb, new_updated, incident_id),
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Drafts (mutabel §2)
    # ------------------------------------------------------------------

    def save_draft(
        self,
        incident_id: str,
        phase: IncidentPhase,
        payload: dict,
        actor: str = "",
        payload_schema_version: int = 1,
    ) -> None:
        """UPSERT eines editierbaren Drafts je (incident, phase)."""
        with self._db.connection() as conn:
            self._save_draft(
                conn, incident_id, phase, payload, actor, payload_schema_version
            )
            conn.commit()

    def _save_draft(
        self,
        conn,  # noqa: ANN001
        incident_id: str,
        phase: IncidentPhase,
        payload: dict,
        actor: str,
        payload_schema_version: int,
    ) -> None:
        conn.execute(
            """
            INSERT INTO nis2_phase_drafts
                (incident_id, phase, payload, payload_schema_version,
                 actor, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id, phase) DO UPDATE SET
                payload = excluded.payload,
                payload_schema_version = excluded.payload_schema_version,
                actor = excluded.actor,
                updated_at = excluded.updated_at
            """,
            (
                incident_id,
                phase.value,
                json.dumps(payload, ensure_ascii=False),
                payload_schema_version,
                actor,
                datetime.now(UTC).isoformat(),
            ),
        )

    def load_draft(
        self, incident_id: str, phase: IncidentPhase
    ) -> dict | None:
        """Laedt den Draft-Payload je (incident, phase) oder ``None``."""
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT payload FROM nis2_phase_drafts "
                "WHERE incident_id = ? AND phase = ?",
                (incident_id, phase.value),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def delete_draft(self, incident_id: str, phase: IncidentPhase) -> None:
        """Loescht den Draft je (incident, phase) (idempotent)."""
        with self._db.connection() as conn:
            self._delete_draft(conn, incident_id, phase)
            conn.commit()

    def _delete_draft(
        self, conn, incident_id: str, phase: IncidentPhase  # noqa: ANN001
    ) -> None:
        conn.execute(
            "DELETE FROM nis2_phase_drafts WHERE incident_id = ? AND phase = ?",
            (incident_id, phase.value),
        )

    def submit_draft(
        self,
        incident_id: str,
        phase: IncidentPhase,
        status: PhaseStatus,
        actor: str = "",
    ) -> int:
        """Reicht einen Draft atomar ein: Draft → append-only Event → Draft weg.

        EINE Transaktion §2): Draft lesen, als verkettetes
        ``nis2_phase_events``-Event anhaengen, Draft-Zeile loeschen.

        Returns:
            ``event_id`` des angehaengten Events.

        Raises:
            ValueError: Kein Draft fuer (incident, phase) vorhanden.
        """
        now = datetime.now(UTC)
        with self._db.connection() as conn:
            # BEGIN IMMEDIATE: Tip-Read + Append atomar (TOCTOU/Ketten-Fork
            # bei parallelen Submits/Appends).
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT payload, payload_schema_version, actor "
                "FROM nis2_phase_drafts WHERE incident_id = ? AND phase = ?",
                (incident_id, phase.value),
            ).fetchone()
            if row is None:
                raise ValueError(
                    f"Kein Draft fuer incident={incident_id} phase={phase.value}."
                )
            payload = json.loads(row[0])
            schema_version = int(row[1])
            draft_actor = actor or str(row[2] or "")
            prev_hash = self._last_event_hash(conn, incident_id)
            ev_map = {
                "incident_id": incident_id,
                "phase": phase.value,
                "status": status.value,
                "actor": draft_actor,
                "note": "",
                "occurred_at": now.isoformat(),
                "payload_schema_version": schema_version,
                "payload": payload,
            }
            event_hash = nis2_tamper.compute_event_hash(
                self._get_chain_key(), prev_hash, ev_map
            )
            cur = conn.execute(
                """
                INSERT INTO nis2_phase_events
                    (incident_id, phase, status, actor, note, occurred_at,
                     payload, payload_schema_version, prev_hash, event_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    phase.value,
                    status.value,
                    draft_actor,
                    "",
                    now.isoformat(),
                    json.dumps(payload, ensure_ascii=False),
                    schema_version,
                    prev_hash,
                    event_hash,
                ),
            )
            event_id = int(cur.lastrowid or 0)
            self._delete_draft(conn, incident_id, phase)
            conn.commit()
        _log.info(
            "nis2_draft_submitted incident=%s phase=%s event_id=%s",
            incident_id,
            phase.value,
            event_id,
        )
        return event_id

    # ------------------------------------------------------------------
    # Anonymisierung (DSGVO Art.17, autorisierte Wartungsoperation)
    # ------------------------------------------------------------------

    def anonymize_for_audit(self, audit_id: str) -> int:
        """Schwaerzt PII aller Incidents eines Audits + re-kettet §5).

        EINE Transaktion mit aktivem ``maintenance_bypass``:

        1. Ueber alle Incidents des Audits: ``note=''`` setzen, PII-payload-
           Felder auf:data:`_REDACTED` schwaerzen.
        2. Die Hashkette der betroffenen Events pro Incident NEU rechnen
           (der UPDATE-Trigger laesst das via Bypass zu).
        3. Je Incident ein ``anonymisiert``-Marker-Event (verkettet) anhaengen.
        4. Bypass wieder deaktivieren.

        Returns:
            Anzahl der anonymisierten Incidents.
        """
        marker_note = "DSGVO Art.17 / Audit-Loeschung"
        marker_payload = {"grund": "audit_delete"}
        now = datetime.now(UTC)
        with self._db.connection() as conn:
            incident_ids = [
                str(r[0])
                for r in conn.execute(
                    "SELECT incident_id FROM nis2_incidents WHERE audit_id = ?",
                    (audit_id,),
                ).fetchall()
            ]
            if not incident_ids:
                return 0
            conn.execute(
                "UPDATE nis2_chain_control SET maintenance_bypass = 1 WHERE id = 1"
            )
            try:
                for incident_id in incident_ids:
                    self._anonymize_one(conn, incident_id, marker_note,
                                        marker_payload, now)
            finally:
                conn.execute(
                    "UPDATE nis2_chain_control SET maintenance_bypass = 0 "
                    "WHERE id = 1"
                )
            conn.commit()
        _log.info(
            "nis2_audit_anonymized audit=%s incidents=%d",
            audit_id,
            len(incident_ids),
        )
        return len(incident_ids)

    def _anonymize_one(
        self,
        conn,  # noqa: ANN001
        incident_id: str,
        marker_note: str,
        marker_payload: dict,
        now: datetime,
    ) -> None:
        """Schwaerzt + re-kettet einen Incident und haengt den Marker an.

        Schwaerzt sowohl die Event-Freitexte (note + ALLE Freitext-payload-Werte
        via:func:`_redact_payload`) ALS AUCH die Header-Freitextfelder
        ``title``/``description`` (DSGVO Art.17 §5) — diese tragen
        ebenfalls Klartext-PII. ``title`` darf nicht leer sein (Domain-Constraint),
        daher der Platzhalter:data:`_REDACTED`. Numerische Header-Flags
        (``severity``, ``personenbezug``) bleiben unveraendert.
        """
        rows = conn.execute(
            "SELECT event_id, phase, status, actor, note, occurred_at, "
            "payload, payload_schema_version "
            "FROM nis2_phase_events WHERE incident_id = ? "
            "ORDER BY occurred_at ASC, event_id ASC",
            (incident_id,),
        ).fetchall()
        prev_hash = nis2_tamper.GENESIS
        last_occurred = now
        for r in rows:
            event_id = int(r[0])
            payload = json.loads(r[6]) if r[6] else {}
            redacted_payload = _redact_payload(payload)
            occurred_at = str(r[5])
            ev_map = {
                "incident_id": incident_id,
                "phase": str(r[1]),
                "status": str(r[2]),
                "actor": str(r[3]),
                "note": "",
                "occurred_at": occurred_at,
                "payload_schema_version": int(r[7]),
                "payload": redacted_payload,
            }
            event_hash = nis2_tamper.compute_event_hash(
                self._get_chain_key(), prev_hash, ev_map
            )
            conn.execute(
                "UPDATE nis2_phase_events SET note = '', payload = ?, "
                "prev_hash = ?, event_hash = ? WHERE event_id = ?",
                (
                    json.dumps(redacted_payload, ensure_ascii=False),
                    prev_hash,
                    event_hash,
                    event_id,
                ),
            )
            prev_hash = event_hash
            with contextlib.suppress(ValueError):
                last_occurred = max(
                    last_occurred, datetime.fromisoformat(occurred_at)
                )
        # Marker-Event anhaengen: occurred_at strikt nach dem juengsten Event,
        # damit der Marker beim Sortieren in verify_chain garantiert ZULETZT
        # steht (sonst kann ein in der Zukunft liegendes Bestands-Event die
        # Kette beim Re-Verify drehen).
        marker_at = max(now, last_occurred + timedelta(microseconds=1))
        marker_map = {
            "incident_id": incident_id,
            "phase": IncidentPhase.POST_INCIDENT.value,
            "status": PhaseStatus.DONE.value,
            "actor": "",
            "note": marker_note,
            "occurred_at": marker_at.isoformat(),
            "payload_schema_version": 1,
            "payload": marker_payload,
        }
        marker_hash = nis2_tamper.compute_event_hash(
            self._get_chain_key(), prev_hash, marker_map
        )
        conn.execute(
            """
            INSERT INTO nis2_phase_events
                (incident_id, phase, status, actor, note, occurred_at,
                 payload, payload_schema_version, prev_hash, event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                IncidentPhase.POST_INCIDENT.value,
                PhaseStatus.DONE.value,
                "",
                marker_note,
                marker_at.isoformat(),
                json.dumps(marker_payload, ensure_ascii=False),
                1,
                prev_hash,
                marker_hash,
            ),
        )
        # Header-Freitext (title/description) schwaerzen + Header konsistent zum
        # Marker setzen: current_phase=POST_INCIDENT, closed_at=marker_at (P2-b).
        conn.execute(
            "UPDATE nis2_incidents SET title = ?, description = ?, "
            "current_phase = ?, closed_at = ?, updated_at = ? "
            "WHERE incident_id = ?",
            (
                _REDACTED,
                _REDACTED,
                IncidentPhase.POST_INCIDENT.value,
                marker_at.isoformat(),
                marker_at.isoformat(),
                incident_id,
            ),
        )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_incident(self, incident_id: str) -> Nis2Incident | None:
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT incident_id, audit_id, title, description, severity,
                       detected_at, current_phase, closed_at, personenbezug,
                       created_at, updated_at
                FROM nis2_incidents
                WHERE incident_id = ?
                """,
                (incident_id,),
            ).fetchone()
            if row is None:
                return None
            events = self._fetch_events(conn, incident_id)
        return self._row_to_incident(row, events)

    def list_open_incidents(
        self, audit_id: str | None = None
    ) -> list[Nis2Incident]:
        return self._list_incidents(audit_id=audit_id, only_closed=False)

    def list_closed_incidents(
        self, audit_id: str | None = None
    ) -> list[Nis2Incident]:
        return self._list_incidents(audit_id=audit_id, only_closed=True)

    # Statische Statements (kein f-string, kein S608): die Spaltenliste steht
    # zur Compile-Zeit fest. Nur ORDER BY / audit_id-Filter werden in
    # ``_list_incidents`` mit Platzhaltern angehaengt.
    _SQL_LIST_OPEN: str = (
        "SELECT incident_id, audit_id, title, description, severity, "
        "detected_at, current_phase, closed_at, personenbezug, "
        "created_at, updated_at "
        "FROM nis2_incidents WHERE closed_at IS NULL"
    )
    _SQL_LIST_CLOSED: str = (
        "SELECT incident_id, audit_id, title, description, severity, "
        "detected_at, current_phase, closed_at, personenbezug, "
        "created_at, updated_at "
        "FROM nis2_incidents WHERE closed_at IS NOT NULL"
    )

    def _list_incidents(
        self, *, audit_id: str | None, only_closed: bool
    ) -> list[Nis2Incident]:
        base = self._SQL_LIST_CLOSED if only_closed else self._SQL_LIST_OPEN
        params: tuple[object, ...] = ()
        if audit_id is not None:
            sql = base + " AND audit_id = ? ORDER BY detected_at DESC"
            params = (audit_id,)
        else:
            sql = base + " ORDER BY detected_at DESC"
        with self._db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            # Events fuer ALLE Incidents in EINER Query laden (statt 1 pro
            # Incident -> N+1) und nach incident_id gruppieren.
            events_by_incident = self._fetch_events_grouped(
                conn, [str(row[0]) for row in rows]
            )
            return [
                self._row_to_incident(
                    row, events_by_incident.get(str(row[0]), [])
                )
                for row in rows
            ]

    def list_events_for(self, incident_id: str) -> list[PhaseEvent]:
        with self._db.connection() as conn:
            return self._fetch_events(conn, incident_id)

    def verify_chain(self, incident_id: str) -> tuple[bool, int | None]:
        """Verifiziert die HMAC-Hashkette eines Incidents §3).

        Returns:
            ``(True, None)`` bei intakter Kette, sonst ``(False, event_id)``.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT event_id, incident_id, phase, status, actor, note, "
                "occurred_at, payload, payload_schema_version, prev_hash, "
                "event_hash FROM nis2_phase_events WHERE incident_id = ?",
                (incident_id,),
            ).fetchall()
        # personenbezug ist BEWUSST nicht Teil der Kanonik (Header-Flag, kein
        # Event-Inhalt) — sonst wuerde set_personenbezug die Kette brechen (P0).
        events = [
            {
                "event_id": int(r[0]),
                "incident_id": str(r[1]),
                "phase": str(r[2]),
                "status": str(r[3]),
                "actor": str(r[4]),
                "note": str(r[5]),
                "occurred_at": str(r[6]),
                "payload": r[7],
                "payload_schema_version": int(r[8]),
                "prev_hash": str(r[9]),
                "event_hash": str(r[10]),
            }
            for r in rows
        ]
        return nis2_tamper.verify_chain(events, self._get_chain_key())

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _last_event_hash(self, conn, incident_id: str) -> str:  # noqa: ANN001
        """Liefert den ``event_hash`` des juengsten Events oder GENESIS."""
        row = conn.execute(
            "SELECT event_hash FROM nis2_phase_events WHERE incident_id = ? "
            "ORDER BY occurred_at DESC, event_id DESC LIMIT 1",
            (incident_id,),
        ).fetchone()
        if row is None or not row[0]:
            return nis2_tamper.GENESIS
        return str(row[0])

    _SQL_SELECT_EVENTS: str = (
        "SELECT event_id, incident_id, phase, status, actor, note, "
        "occurred_at, payload, payload_schema_version, prev_hash, event_hash "
        "FROM nis2_phase_events"
    )

    def _fetch_events(self, conn, incident_id: str) -> list[PhaseEvent]:  # noqa: ANN001
        rows = conn.execute(
            self._SQL_SELECT_EVENTS
            + " WHERE incident_id = ? ORDER BY occurred_at ASC, event_id ASC",
            (incident_id,),
        ).fetchall()
        return [self._row_to_phase_event(r) for r in rows]

    def _fetch_events_grouped(
        self, conn, incident_ids: list[str]  # noqa: ANN001
    ) -> dict[str, list[PhaseEvent]]:
        """Laedt Events fuer MEHRERE Incidents in EINER Query (vermeidet N+1).

        Ersetzt das 1+N-Muster in:meth:`_list_incidents` (eine Query pro
        Incident) durch eine ``IN``-Query + Python-Gruppierung. Die globale
        ``ORDER BY occurred_at ASC, event_id ASC`` erhaelt je Incident dieselbe
        Reihenfolge wie der Einzel-Fetch (relative Ordnung pro incident_id bleibt
        beim Gruppieren erhalten).
        """
        if not incident_ids:
            return {}
        placeholders = ",".join("?" * len(incident_ids))
        # SQLi-frei: ``placeholders`` ist eine count-bounded "?,?,..."-Sequenz;
        # die ids kommen ausschliesslich ueber Parameter-Binding.
        rows = conn.execute(
            self._SQL_SELECT_EVENTS
            + f" WHERE incident_id IN ({placeholders})"  # noqa: S608 # nosec B608
            + " ORDER BY occurred_at ASC, event_id ASC",
            tuple(incident_ids),
        ).fetchall()
        grouped: dict[str, list[PhaseEvent]] = {}
        for r in rows:
            grouped.setdefault(str(r[1]), []).append(self._row_to_phase_event(r))
        return grouped

    @staticmethod
    def _row_to_phase_event(r: tuple) -> PhaseEvent:
        """Mappt eine ``nis2_phase_events``-Zeile auf:class:`PhaseEvent`."""
        return PhaseEvent(
            event_id=int(r[0]),
            incident_id=str(r[1]),
            phase=IncidentPhase(r[2]),
            status=PhaseStatus(r[3]),
            actor=str(r[4]),
            note=str(r[5]),
            occurred_at=datetime.fromisoformat(r[6]),
            payload=json.loads(r[7]) if r[7] else {},
            payload_schema_version=int(r[8]),
            prev_hash=str(r[9]),
            event_hash=str(r[10]),
        )

    def _row_to_incident(
        self, row: Iterable, events: list[PhaseEvent]
    ) -> Nis2Incident:
        r = tuple(row)
        return Nis2Incident(
            incident_id=str(r[0]),
            audit_id=str(r[1]),
            title=str(r[2]),
            description=str(r[3]),
            severity=IncidentSeverity(r[4]),
            detected_at=datetime.fromisoformat(r[5]),
            current_phase=IncidentPhase(r[6]),
            closed_at=datetime.fromisoformat(r[7]) if r[7] else None,
            personenbezug=bool(r[8]),
            created_at=datetime.fromisoformat(r[9]),
            updated_at=datetime.fromisoformat(r[10]),
            events=tuple(events),
        )
