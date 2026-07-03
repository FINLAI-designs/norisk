"""Tests fuer die NIS2-Tamper-Evidence-Schicht §1-§5).

Deckt ab:

- Migration idempotent (2x auf Kopie, PRAGMA table_info).
- HMAC verify_chain: Inhalts-Mutation / Reorder / geloeschtes Mittel-Event.
- Append-only-Trigger blockt direktes UPDATE/DELETE ohne Bypass.
- Draft-Roundtrip (save -> load -> submit -> append-only Event, Draft weg).
- anonymize_for_audit: PII geschwaerzt, Marker-Event, verify_chain gruen nach
  Re-Chain, Trail + Phasen erhalten.
- advance_phase Pflichtfeld-Validierung.

Nutzt eine echte SQLCipher-DB (Datei) ueber EncryptedDatabase, damit Trigger,
Transaktionen und das DB-Backup realistisch greifen. Der KeyManager kommt aus
der globalen conftest-Fixture (InMemoryDPAPIBackend), der Ketten-Schluessel
wird ueber den aktiven KeyManager abgeleitet.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from core.database.encrypted_db import EncryptedDatabase, FinLaiDatabaseError
from tools.customer_audit.application.nis2_incident_service import (
    Nis2IncidentService,
)
from tools.customer_audit.data import nis2_tamper
from tools.customer_audit.data.nis2_incident_repository import (
    DbNis2IncidentRepository,
)
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    Nis2Incident,
    PhaseEvent,
    PhaseStatus,
)
from tools.customer_audit.domain.nis2_phase_schema import validate

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def repo(tmp_path):
    """Echtes SQLCipher-Repo auf einer tmp-Datei (Trigger + Transaktionen real)."""
    db = EncryptedDatabase("customer_audit", db_path=tmp_path / "customer_audit.db")
    return DbNis2IncidentRepository(db=db)


@pytest.fixture
def service(repo):
    return Nis2IncidentService(repository=repo)


def _make_incident(repo, *, personenbezug: bool = False, audit_id: str = "aud-1"):
    now = datetime.now(UTC)
    incident = Nis2Incident(
        incident_id=str(uuid.uuid4()),
        audit_id=audit_id,
        title="Ransomware-Verdacht",
        description="Verdaechtige Verschluesselung",
        severity=IncidentSeverity.HIGH,
        detected_at=now,
        current_phase=IncidentPhase.DETECT,
        personenbezug=personenbezug,
        created_at=now,
        updated_at=now,
    )
    repo.add_incident(incident)
    return incident


def _append(repo, incident_id, *, phase=IncidentPhase.DETECT,
            status=PhaseStatus.IN_PROGRESS, note="n", payload=None, offset=0):
    repo.append_phase_event(
        PhaseEvent(
            event_id=None,
            incident_id=incident_id,
            phase=phase,
            status=status,
            actor="patrick",
            note=note,
            occurred_at=datetime.now(UTC) + timedelta(seconds=offset),
            payload=payload or {},
        )
    )


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


class TestMigration:
    def test_migration_adds_columns(self, repo):
        with repo._db.connection() as conn:
            cols = {
                r[1]
                for r in conn.execute(
                    "PRAGMA table_info(nis2_phase_events)"
                ).fetchall()
            }
        assert {"payload", "payload_schema_version", "prev_hash", "event_hash"} <= cols
        with repo._db.connection() as conn:
            inc_cols = {
                r[1]
                for r in conn.execute(
                    "PRAGMA table_info(nis2_incidents)"
                ).fetchall()
            }
        assert "personenbezug" in inc_cols

    def test_migration_idempotent_second_instance(self, repo):
        # Zweite Repo-Instanz auf derselben DB darf nicht crashen und nichts
        # doppelt anlegen.
        before = self._table_info(repo)
        DbNis2IncidentRepository(db=repo._db)
        after = self._table_info(repo)
        assert before == after

    def test_migration_from_legacy_schema_pre_d1(self, tmp_path):
        """Echter Upgrade-Pfad: Bestands-DB (Mai-Schema OHNE die neuen Spalten +
        OHNE personenbezug-Index) wird beim Repo-Bau migriert, ohne
        'no such column: personenbezug' (Hotfix-Regression — der bisherige
        Idempotenz-Test lief nur gegen die bereits neue Tabelle).
        """
        db = EncryptedDatabase(
            "customer_audit", db_path=tmp_path / "customer_audit.db"
        )
        # Vor-D1-Schema (Mai) direkt anlegen: nis2_incidents OHNE personenbezug,
        # nis2_phase_events OHNE payload/prev_hash/event_hash, KEIN neuer Index.
        with db.connection() as conn:
            conn.executescript(
                """
                CREATE TABLE nis2_incidents (
                    incident_id TEXT PRIMARY KEY, audit_id TEXT NOT NULL,
                    title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL, detected_at TEXT NOT NULL,
                    current_phase TEXT NOT NULL, closed_at TEXT,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE INDEX idx_nis2_incidents_audit
                    ON nis2_incidents(audit_id);
                CREATE INDEX idx_nis2_incidents_phase
                    ON nis2_incidents(current_phase);
                CREATE TABLE nis2_phase_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL, phase TEXT NOT NULL,
                    status TEXT NOT NULL, actor TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '', occurred_at TEXT NOT NULL
                );
                CREATE INDEX idx_nis2_phase_events_incident
                    ON nis2_phase_events(incident_id, occurred_at);
                INSERT INTO nis2_incidents (incident_id, audit_id, title,
                    description, severity, detected_at, current_phase, closed_at,
                    created_at, updated_at)
                  VALUES ('inc-legacy','aud-1','Alt-Vorfall','','HIGH',
                    '2026-05-01T00:00:00Z','detect',NULL,
                    '2026-05-01T00:00:00Z','2026-05-01T00:00:00Z');
                """
            )
            conn.commit()
        # Die Migration darf NICHT crashen (genau das war der Live-Bug).
        migrated = DbNis2IncidentRepository(db=db)
        with migrated._db.connection() as conn:
            inc_cols = {
                r[1]
                for r in conn.execute(
                    "PRAGMA table_info(nis2_incidents)"
                ).fetchall()
            }
            ev_cols = {
                r[1]
                for r in conn.execute(
                    "PRAGMA table_info(nis2_phase_events)"
                ).fetchall()
            }
            indexes = {
                r[1]
                for r in conn.execute(
                    "PRAGMA index_list(nis2_incidents)"
                ).fetchall()
            }
            title = conn.execute(
                "SELECT title FROM nis2_incidents WHERE incident_id = 'inc-legacy'"
            ).fetchone()[0]
        assert "personenbezug" in inc_cols
        assert {"payload", "prev_hash", "event_hash"} <= ev_cols
        assert "idx_nis2_incidents_personenbezug" in indexes
        assert title == "Alt-Vorfall"  # Bestandsdaten erhalten

    def test_chain_control_row_exists(self, repo):
        with repo._db.connection() as conn:
            row = conn.execute(
                "SELECT id, maintenance_bypass FROM nis2_chain_control"
            ).fetchone()
        assert row == (1, 0)

    @staticmethod
    def _table_info(repo):
        with repo._db.connection() as conn:
            return tuple(
                conn.execute(
                    "PRAGMA table_info(nis2_phase_events)"
                ).fetchall()
            )


# ---------------------------------------------------------------------------
# HMAC verify_chain
# ---------------------------------------------------------------------------


class TestVerifyChain:
    def test_clean_chain_is_valid(self, repo):
        inc = _make_incident(repo)
        _append(repo, inc.incident_id, status=PhaseStatus.IN_PROGRESS, offset=0)
        _append(repo, inc.incident_id, phase=IncidentPhase.TRIAGE,
                status=PhaseStatus.DONE, offset=1)
        ok, bad = repo.verify_chain(inc.incident_id)
        assert ok is True
        assert bad is None

    def test_content_mutation_breaks_chain(self, repo):
        inc = _make_incident(repo)
        _append(repo, inc.incident_id, note="original", offset=0)
        # Direkt am Datentraeger den note-Inhalt aendern (mit Bypass, damit der
        # Trigger nicht blockt — simuliert eine Manipulation des DB-Inhalts).
        with repo._db.connection() as conn:
            conn.execute(
                "UPDATE nis2_chain_control SET maintenance_bypass = 1 WHERE id = 1"
            )
            conn.execute(
                "UPDATE nis2_phase_events SET note = 'GEFAELSCHT' "
                "WHERE incident_id = ?",
                (inc.incident_id,),
            )
            conn.execute(
                "UPDATE nis2_chain_control SET maintenance_bypass = 0 WHERE id = 1"
            )
            conn.commit()
        ok, bad = repo.verify_chain(inc.incident_id)
        assert ok is False
        assert bad is not None

    def test_reorder_breaks_chain(self, repo):
        inc = _make_incident(repo)
        _append(repo, inc.incident_id, note="first", offset=0)
        _append(repo, inc.incident_id, phase=IncidentPhase.TRIAGE, note="second",
                offset=1)
        # occurred_at der beiden Events tauschen (Reorder) — bricht die
        # prev_hash-Verkettung, weil sich die kanonische Reihenfolge dreht.
        with repo._db.connection() as conn:
            rows = conn.execute(
                "SELECT event_id, occurred_at FROM nis2_phase_events "
                "WHERE incident_id = ? ORDER BY occurred_at ASC",
                (inc.incident_id,),
            ).fetchall()
            conn.execute(
                "UPDATE nis2_chain_control SET maintenance_bypass = 1 WHERE id = 1"
            )
            conn.execute(
                "UPDATE nis2_phase_events SET occurred_at = ? WHERE event_id = ?",
                (rows[1][1], rows[0][0]),
            )
            conn.execute(
                "UPDATE nis2_phase_events SET occurred_at = ? WHERE event_id = ?",
                (rows[0][1], rows[1][0]),
            )
            conn.execute(
                "UPDATE nis2_chain_control SET maintenance_bypass = 0 WHERE id = 1"
            )
            conn.commit()
        ok, _bad = repo.verify_chain(inc.incident_id)
        assert ok is False

    def test_deleted_middle_event_breaks_chain(self, repo):
        inc = _make_incident(repo)
        _append(repo, inc.incident_id, note="a", offset=0)
        _append(repo, inc.incident_id, phase=IncidentPhase.TRIAGE, note="b",
                offset=1)
        _append(repo, inc.incident_id, phase=IncidentPhase.EARLY_WARNING,
                note="c", offset=2)
        with repo._db.connection() as conn:
            mid = conn.execute(
                "SELECT event_id FROM nis2_phase_events WHERE incident_id = ? "
                "ORDER BY occurred_at ASC LIMIT 1 OFFSET 1",
                (inc.incident_id,),
            ).fetchone()[0]
            conn.execute(
                "UPDATE nis2_chain_control SET maintenance_bypass = 1 WHERE id = 1"
            )
            conn.execute(
                "DELETE FROM nis2_phase_events WHERE event_id = ?", (mid,)
            )
            conn.execute(
                "UPDATE nis2_chain_control SET maintenance_bypass = 0 WHERE id = 1"
            )
            conn.commit()
        ok, _bad = repo.verify_chain(inc.incident_id)
        assert ok is False

    def test_legacy_empty_hash_events_are_skipped(self, repo):
        # Alt-Events ohne event_hash brechen die Kette nicht.
        events = [
            {
                "event_id": 1,
                "incident_id": "x",
                "phase": "detect",
                "status": "done",
                "actor": "a",
                "note": "legacy",
                "occurred_at": "2026-01-01T00:00:00+00:00",
                "payload": "{}",
                "payload_schema_version": 1,
                "prev_hash": "",
                "event_hash": "",
                "personenbezug": 0,
            }
        ]
        ok, bad = nis2_tamper.verify_chain(events, b"\x00" * 32)
        assert ok is True
        assert bad is None

    def test_empty_hash_after_hashed_event_breaks_chain(self):
        # P1 (Legacy-Skip-Loch): ein leeres event_hash NACH einem gehashten
        # Event ist KEIN Legacy-Praefix mehr -> Angreifer ohne chain_key
        # koennte ein Fake-Event mit event_hash='' einschleusen. Muss brechen.
        key = b"\x00" * 32
        real = {
            "event_id": 1,
            "incident_id": "x",
            "phase": "detect",
            "status": "in_progress",
            "actor": "a",
            "note": "echt",
            "occurred_at": "2026-01-01T00:00:00+00:00",
            "payload": "{}",
            "payload_schema_version": 1,
            "personenbezug": 0,
        }
        real["prev_hash"] = nis2_tamper.GENESIS
        real["event_hash"] = nis2_tamper.compute_event_hash(
            key, nis2_tamper.GENESIS, real
        )
        fake = {
            "event_id": 2,
            "incident_id": "x",
            "phase": "triage",
            "status": "done",
            "actor": "angreifer",
            "note": "eingeschleust ohne chain_key",
            "occurred_at": "2026-01-02T00:00:00+00:00",
            "payload": "{}",
            "payload_schema_version": 1,
            "prev_hash": "",
            "event_hash": "",
            "personenbezug": 0,
        }
        ok, bad = nis2_tamper.verify_chain([real, fake], key)
        assert ok is False
        assert bad == 2

    def test_empty_hash_between_hashed_events_breaks_chain(self):
        # Leeres Event ZWISCHEN zwei gehashten Events -> ebenfalls Bruch.
        key = b"\x00" * 32
        first = {
            "event_id": 1,
            "incident_id": "x",
            "phase": "detect",
            "status": "in_progress",
            "actor": "a",
            "note": "erst",
            "occurred_at": "2026-01-01T00:00:00+00:00",
            "payload": "{}",
            "payload_schema_version": 1,
            "personenbezug": 0,
        }
        first["prev_hash"] = nis2_tamper.GENESIS
        first["event_hash"] = nis2_tamper.compute_event_hash(
            key, nis2_tamper.GENESIS, first
        )
        fake = {
            "event_id": 2,
            "incident_id": "x",
            "phase": "triage",
            "status": "done",
            "actor": "angreifer",
            "note": "leer eingeschoben",
            "occurred_at": "2026-01-02T00:00:00+00:00",
            "payload": "{}",
            "payload_schema_version": 1,
            "prev_hash": "",
            "event_hash": "",
            "personenbezug": 0,
        }
        third = {
            "event_id": 3,
            "incident_id": "x",
            "phase": "early_warning",
            "status": "done",
            "actor": "a",
            "note": "danach",
            "occurred_at": "2026-01-03T00:00:00+00:00",
            "payload": "{}",
            "payload_schema_version": 1,
            "personenbezug": 0,
        }
        third["prev_hash"] = first["event_hash"]
        third["event_hash"] = nis2_tamper.compute_event_hash(
            key, first["event_hash"], third
        )
        ok, bad = nis2_tamper.verify_chain([first, fake, third], key)
        assert ok is False
        assert bad == 2


# ---------------------------------------------------------------------------
# Personenbezug darf die HMAC-Kette nicht brechen (P0-1 + P0-3)
# ---------------------------------------------------------------------------


class TestPersonenbezugChain:
    def test_set_personenbezug_after_append_keeps_chain_green(self, repo):
        # P0-1 + P0-3: personenbezug ist MUTABLES Header-Flag, war aber in jeden
        # Event-Hash gebacken. open(personenbezug=False) -> Event schreiben ->
        # set_personenbezug(True) -> verify_chain MUSS gruen bleiben.
        inc = _make_incident(repo, personenbezug=False)
        _append(
            repo, inc.incident_id, phase=IncidentPhase.NOTIFICATION,
            status=PhaseStatus.DONE,
            payload={"schweregrad": "high", "personenbezug": True},
            offset=1,
        )
        # Header-Flag nachtraeglich kippen (wie das NOTIFICATION-Formular).
        repo.update_incident_header(inc.incident_id, personenbezug=True)
        ok, bad = repo.verify_chain(inc.incident_id)
        assert ok is True, f"Kette gebrochen bei {bad} nach set_personenbezug"
        assert bad is None


# ---------------------------------------------------------------------------
# Append-only-Trigger
# ---------------------------------------------------------------------------


class TestAppendOnlyTrigger:
    def test_direct_update_blocked(self, repo):
        inc = _make_incident(repo)
        _append(repo, inc.incident_id)
        with (
            pytest.raises(FinLaiDatabaseError, match="append-only"),
            repo._db.connection() as conn,
        ):
            conn.execute(
                "UPDATE nis2_phase_events SET note = 'x' WHERE incident_id = ?",
                (inc.incident_id,),
            )

    def test_direct_delete_blocked(self, repo):
        inc = _make_incident(repo)
        _append(repo, inc.incident_id)
        with (
            pytest.raises(FinLaiDatabaseError, match="append-only"),
            repo._db.connection() as conn,
        ):
            conn.execute(
                "DELETE FROM nis2_phase_events WHERE incident_id = ?",
                (inc.incident_id,),
            )

    def test_bypass_allows_update(self, repo):
        inc = _make_incident(repo)
        _append(repo, inc.incident_id)
        with repo._db.connection() as conn:
            conn.execute(
                "UPDATE nis2_chain_control SET maintenance_bypass = 1 WHERE id = 1"
            )
            conn.execute(
                "UPDATE nis2_phase_events SET note = 'wartung' WHERE incident_id = ?",
                (inc.incident_id,),
            )
            conn.execute(
                "UPDATE nis2_chain_control SET maintenance_bypass = 0 WHERE id = 1"
            )
            conn.commit()
        events = repo.list_events_for(inc.incident_id)
        assert events[0].note == "wartung"


# ---------------------------------------------------------------------------
# Drafts
# ---------------------------------------------------------------------------


class TestDraftRoundtrip:
    def test_save_load_submit(self, repo):
        inc = _make_incident(repo)
        payload = {"ersteinschaetzung": "verdaechtig", "erheblich": "ja"}
        repo.save_draft(inc.incident_id, IncidentPhase.TRIAGE, payload, actor="p")
        # Draft erhalten (Tab-Wechsel-Simulation: frische Lese-Operation).
        loaded = repo.load_draft(inc.incident_id, IncidentPhase.TRIAGE)
        assert loaded == payload
        # Einreichen -> append-only Event mit payload, Draft weg.
        event_id = repo.submit_draft(
            inc.incident_id, IncidentPhase.TRIAGE, PhaseStatus.DONE, actor="p"
        )
        assert event_id > 0
        assert repo.load_draft(inc.incident_id, IncidentPhase.TRIAGE) is None
        events = repo.list_events_for(inc.incident_id)
        triage = [e for e in events if e.phase is IncidentPhase.TRIAGE]
        assert len(triage) == 1
        assert triage[0].payload == payload
        # Kette bleibt valide.
        ok, _ = repo.verify_chain(inc.incident_id)
        assert ok is True

    def test_save_draft_upsert_overwrites(self, repo):
        inc = _make_incident(repo)
        repo.save_draft(inc.incident_id, IncidentPhase.TRIAGE, {"a": 1})
        repo.save_draft(inc.incident_id, IncidentPhase.TRIAGE, {"a": 2})
        assert repo.load_draft(inc.incident_id, IncidentPhase.TRIAGE) == {"a": 2}

    def test_submit_without_draft_raises(self, repo):
        inc = _make_incident(repo)
        with pytest.raises(ValueError, match="Kein Draft"):
            repo.submit_draft(
                inc.incident_id, IncidentPhase.TRIAGE, PhaseStatus.DONE
            )


# ---------------------------------------------------------------------------
# Anonymisierung
# ---------------------------------------------------------------------------


class TestAnonymizeForAudit:
    def test_pii_redacted_marker_and_chain_green(self, repo):
        inc = _make_incident(repo, personenbezug=True, audit_id="aud-x")
        _append(
            repo, inc.incident_id, phase=IncidentPhase.NOTIFICATION,
            status=PhaseStatus.DONE, note="Max Mustermann meldete IBAN-Abfluss",
            payload={
                "beschreibung": "Datenabfluss bei Max Mustermann",
                "schweregrad": "high",
                "personenbezug": True,
            },
            offset=1,
        )
        count = repo.anonymize_for_audit("aud-x")
        assert count == 1
        events = repo.list_events_for(inc.incident_id)
        # note geschwaerzt (leer), alle Freitext-payload-Felder [anonymisiert].
        for ev in events:
            assert ev.note == "" or ev.note == "DSGVO Art.17 / Audit-Loeschung"
        notif = [e for e in events if e.phase is IncidentPhase.NOTIFICATION]
        assert notif[0].payload.get("beschreibung") == "[anonymisiert]"
        # Freitext-Wert (str) wird ebenfalls geschwaerzt (robust statt Whitelist).
        assert notif[0].payload.get("schweregrad") == "[anonymisiert]"
        # Bool-Flag bleibt erhalten.
        assert notif[0].payload.get("personenbezug") is True
        # Marker-Event vorhanden.
        markers = [
            e for e in events if e.note == "DSGVO Art.17 / Audit-Loeschung"
        ]
        assert len(markers) == 1
        assert markers[0].payload.get("grund") == "audit_delete"
        # Kette nach Re-Chain gruen.
        ok, bad = repo.verify_chain(inc.incident_id)
        assert ok is True, f"Kette gebrochen bei {bad}"

    def test_trail_and_phases_preserved(self, repo):
        inc = _make_incident(repo, audit_id="aud-y")
        _append(repo, inc.incident_id, phase=IncidentPhase.TRIAGE,
                status=PhaseStatus.DONE, offset=1)
        before = repo.list_events_for(inc.incident_id)
        repo.anonymize_for_audit("aud-y")
        after = repo.list_events_for(inc.incident_id)
        # Trail bleibt erhalten + 1 Marker-Event.
        assert len(after) == len(before) + 1
        # Incident selbst bleibt (nicht geloescht).
        assert repo.get_incident(inc.incident_id) is not None

    def test_no_incidents_returns_zero(self, repo):
        assert repo.anonymize_for_audit("does-not-exist") == 0

    def test_header_title_description_and_all_freitext_redacted(self, repo):
        # P0-2 + P1-iocs: Header title/description (Freitext mit PII!) UND alle
        # Freitext-payload-Werte (inkl. iocs, kommunikationsstatus) muessen
        # geschwaerzt werden, nicht nur eine Whitelist. Numerische/Bool-Flags
        # (severity, personenbezug) bleiben. Struktur + Kette erhalten.
        inc = _make_incident(repo, personenbezug=True, audit_id="aud-z")
        # Header traegt PII-Freitext.
        with repo._db.connection() as conn:
            conn.execute(
                "UPDATE nis2_incidents SET title = ?, description = ? "
                "WHERE incident_id = ?",
                ("Max Mustermann Vorfall", "IBAN AT01 1234 abgeflossen",
                 inc.incident_id),
            )
            conn.commit()
        _append(
            repo, inc.incident_id, phase=IncidentPhase.NOTIFICATION,
            status=PhaseStatus.DONE,
            payload={
                "schweregrad": "high",          # bleibt (kein Freitext-Key? -> str bleibt? nein: str wird geschwaerzt)
                "severity_num": 3,              # int bleibt
                "personenbezug": True,          # bool bleibt
                "iocs": ["1.2.3.4", "evil.example"],  # Liste -> geschwaerzt
                "kommunikationsstatus": "CSIRT informiert",  # Freitext -> geschwaerzt
                "ursache": "Phishing auf hans@example.com",  # Freitext -> geschwaerzt
            },
            offset=1,
        )
        count = repo.anonymize_for_audit("aud-z")
        assert count == 1

        reloaded = repo.get_incident(inc.incident_id)
        assert reloaded.title == "[anonymisiert]"
        assert reloaded.description == "[anonymisiert]"

        events = repo.list_events_for(inc.incident_id)
        notif = [e for e in events if e.phase is IncidentPhase.NOTIFICATION][0]
        # Alle Freitext-Werte (str + list) geschwaerzt.
        assert notif.payload.get("iocs") == ["[anonymisiert]"]
        assert notif.payload.get("kommunikationsstatus") == "[anonymisiert]"
        assert notif.payload.get("ursache") == "[anonymisiert]"
        assert notif.payload.get("schweregrad") == "[anonymisiert]"
        # Numerische/Bool-Flags bleiben.
        assert notif.payload.get("severity_num") == 3
        assert notif.payload.get("personenbezug") is True
        # Struktur erhalten: Phasen-/Frist-Anker (detected_at) unveraendert.
        assert reloaded.detected_at == inc.detected_at
        # Kette gruen.
        ok, bad = repo.verify_chain(inc.incident_id)
        assert ok is True, f"Kette gebrochen bei {bad}"


# ---------------------------------------------------------------------------
# Pflichtfeld-Validierung
# ---------------------------------------------------------------------------


class TestPhaseValidation:
    def test_validate_reports_missing(self):
        missing = validate(IncidentPhase.EARLY_WARNING, {})
        assert "verdacht_rechtswidrig" in missing
        assert "grenzueberschreitend" in missing
        assert "betroffene_dienste" in missing
        # Optionalfeld nicht gemeldet.
        assert "sofortmassnahmen" not in missing

    def test_validate_complete_payload_passes(self):
        payload = {
            "verdacht_rechtswidrig": "unbekannt",
            "grenzueberschreitend": "nein",
            "betroffene_dienste": "Mailserver",
        }
        assert validate(IncidentPhase.EARLY_WARNING, payload) == []

    def test_bool_false_is_valid(self):
        # personenbezug=False ist ein gueltiger Pflichtwert.
        payload = {
            "schweregrad": "low",
            "impact_verfuegbarkeit": "kein Ausfall",
            "erste_ursache": "Phishing",
            "personenbezug": False,
        }
        assert validate(IncidentPhase.NOTIFICATION, payload) == []

    def test_advance_phase_missing_payload_raises(self, service):
        inc = service.open_incident("aud", "t", IncidentSeverity.HIGH)
        with pytest.raises(ValueError, match="Pflichtfelder"):
            service.advance_phase(
                inc.incident_id,
                IncidentPhase.EARLY_WARNING,
                PhaseStatus.DONE,
                payload={},  # leer -> Pflichtfelder fehlen
            )

    def test_advance_phase_skipped_skips_validation(self, service):
        inc = service.open_incident("aud", "t", IncidentSeverity.HIGH)
        # SKIPPED ueberspringt die Pflichtpruefung trotz leerem payload.
        service.advance_phase(
            inc.incident_id,
            IncidentPhase.EARLY_WARNING,
            PhaseStatus.SKIPPED,
            payload={},
        )
        reloaded = service.load_incident(inc.incident_id)
        assert reloaded is not None

    def test_advance_phase_without_payload_still_works(self, service):
        # Rueckwaertskompat: ohne payload keine Validierung (einfacher Wechsel).
        inc = service.open_incident("aud", "t", IncidentSeverity.HIGH)
        service.advance_phase(
            inc.incident_id, IncidentPhase.DETECT, PhaseStatus.DONE
        )
        reloaded = service.load_incident(inc.incident_id)
        assert reloaded is not None
        assert reloaded.current_phase is IncidentPhase.TRIAGE
