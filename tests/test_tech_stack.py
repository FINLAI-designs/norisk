"""
test_tech_stack — Unit-Tests für Tech-Stack-Domain, Repository und Use Case.

Testet:
  - SystemProfile- und TechStack-Entities
  - TechStackRepository (CRUD via tmp_path)
  - ManageProfilesUseCase (ensure_own_system, create/delete, migration)

Schichtzugehörigkeit: tests/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

import core.database.encrypted_db as edb
from tools.security_scoring.application.tech_stack.manage_profiles_use_case import (
    ManageProfilesUseCase,
)
from tools.security_scoring.data.tech_stack_repository import (
    TechStackRepository,
    _row_to_profile,
    _tech_stack_from_json,
    _tech_stack_to_json,
)
from tools.security_scoring.domain.tech_stack.entities import (
    BrowserEntry,
    OSEntry,
    SecurityTool,
    SystemProfile,
    TechStack,
)
from tools.security_scoring.domain.tech_stack.enums import SystemType, ToolStatus

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def repo(tmp_path: Path) -> TechStackRepository:
    """TechStackRepository mit isolierter Test-DB."""
    with patch.object(edb, "DB_DIR", tmp_path):
        r = TechStackRepository()
        yield r


@pytest.fixture()
def use_case(tmp_path: Path) -> ManageProfilesUseCase:
    """ManageProfilesUseCase mit isolierter Test-DB."""
    with patch.object(edb, "DB_DIR", tmp_path):
        r = TechStackRepository()
        yield ManageProfilesUseCase(r)


# ---------------------------------------------------------------------------
# Domain-Entities
# ---------------------------------------------------------------------------


class TestSystemProfileEntity:
    """Tests für SystemProfile-Dataclass."""

    def test_is_own_system_eigenes(self) -> None:
        p = SystemProfile(
            id=str(uuid.uuid4()), name="Test", system_type=SystemType.EIGENES
        )
        assert p.is_own_system is True

    def test_is_own_system_kunde(self) -> None:
        p = SystemProfile(
            id=str(uuid.uuid4()), name="Kunde", system_type=SystemType.KUNDE
        )
        assert p.is_own_system is False

    def test_display_name_eigenes(self) -> None:
        p = SystemProfile(
            id=str(uuid.uuid4()), name="Mein PC", system_type=SystemType.EIGENES
        )
        assert "Eigenes System" in p.display_name

    def test_display_name_kunde(self) -> None:
        p = SystemProfile(
            id=str(uuid.uuid4()), name="Kunde GmbH", system_type=SystemType.KUNDE
        )
        assert p.display_name == "Kunde GmbH"

    def test_tech_stack_defaults(self) -> None:
        ts = TechStack()
        assert ts.operating_systems == []
        assert ts.antivirus.status == ToolStatus.UNBEKANNT
        assert ts.vpn is None


class TestTechStackSerialization:
    """Tests für JSON-Serialisierung von TechStack."""

    def test_roundtrip_empty(self) -> None:
        ts = TechStack()
        result = _tech_stack_from_json(_tech_stack_to_json(ts))
        assert result.operating_systems == []
        assert result.encryption == []

    def test_roundtrip_with_data(self) -> None:
        ts = TechStack(
            operating_systems=[OSEntry("Windows 11", "23H2")],
            antivirus=SecurityTool("Defender", ToolStatus.AKTIV),
            browsers=[BrowserEntry("Chrome", "124")],
            encryption=["BitLocker"],
            vpn="Mullvad",
            remote_access=["TeamViewer"],
            server_infra="Azure",
            custom_software=["Slack"],
        )
        result = _tech_stack_from_json(_tech_stack_to_json(ts))
        assert result.operating_systems[0].name == "Windows 11"
        assert result.antivirus.name == "Defender"
        assert result.antivirus.status == ToolStatus.AKTIV
        assert result.browsers[0].name == "Chrome"
        assert result.encryption == ["BitLocker"]
        assert result.vpn == "Mullvad"

    def test_invalid_json_returns_empty(self) -> None:
        result = _tech_stack_from_json("not-json-{{{")
        assert isinstance(result, TechStack)
        assert result.operating_systems == []


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


class TestTechStackRepository:
    """Tests für TechStackRepository (tmppath-DB)."""

    def test_create_and_get_by_id(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            now = datetime.now(UTC).isoformat()
            p = SystemProfile(
                id=str(uuid.uuid4()),
                name="Test Kunde",
                system_type=SystemType.KUNDE,
                created_at=now,
                updated_at=now,
            )
            r.create(p)
            loaded = r.get_by_id(p.id)
            assert loaded is not None
            assert loaded.name == "Test Kunde"
            assert loaded.system_type == SystemType.KUNDE

    def test_get_all_sorted(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            now = datetime.now(UTC).isoformat()
            r.create(
                SystemProfile(
                    id=str(uuid.uuid4()),
                    name="Z Kunde",
                    system_type=SystemType.KUNDE,
                    created_at=now,
                    updated_at=now,
                )
            )
            r.create(
                SystemProfile(
                    id=str(uuid.uuid4()),
                    name="Mein System",
                    system_type=SystemType.EIGENES,
                    created_at=now,
                    updated_at=now,
                )
            )
            r.create(
                SystemProfile(
                    id=str(uuid.uuid4()),
                    name="A Kunde",
                    system_type=SystemType.KUNDE,
                    created_at=now,
                    updated_at=now,
                )
            )
            profiles = r.get_all()
            # Eigenes System zuerst
            assert profiles[0].system_type == SystemType.EIGENES
            # Kunden alphabetisch
            assert profiles[1].name == "A Kunde"
            assert profiles[2].name == "Z Kunde"

    def test_delete_kunde(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            now = datetime.now(UTC).isoformat()
            p = SystemProfile(
                id=str(uuid.uuid4()),
                name="Kunde",
                system_type=SystemType.KUNDE,
                created_at=now,
                updated_at=now,
            )
            r.create(p)
            assert r.count() == 1
            r.delete(p.id)
            assert r.count() == 0

    def test_delete_eigenes_raises(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            now = datetime.now(UTC).isoformat()
            p = SystemProfile(
                id=str(uuid.uuid4()),
                name="Mein System",
                system_type=SystemType.EIGENES,
                created_at=now,
                updated_at=now,
            )
            r.create(p)
            with pytest.raises(ValueError, match="eigene"):
                r.delete(p.id)


# ---------------------------------------------------------------------------
# Use Case
# ---------------------------------------------------------------------------


class TestManageProfilesUseCase:
    """Tests für ManageProfilesUseCase."""

    def test_ensure_own_system_creates_if_missing(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            uc = ManageProfilesUseCase(r)
            profile = uc.ensure_own_system()
            assert profile.system_type == SystemType.EIGENES
            assert profile.id

    def test_ensure_own_system_idempotent(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            uc = ManageProfilesUseCase(r)
            p1 = uc.ensure_own_system()
            p2 = uc.ensure_own_system()
            assert p1.id == p2.id
            assert r.count() == 1

    def test_create_customer_profile(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            uc = ManageProfilesUseCase(r)
            p = uc.create_customer_profile(
                "Muster GmbH", description="Test", contact="Max"
            )
            assert p.system_type == SystemType.KUNDE
            assert p.name == "Muster GmbH"
            assert p.contact == "Max"

    def test_create_customer_empty_name_raises(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            uc = ManageProfilesUseCase(r)
            with pytest.raises(ValueError):
                uc.create_customer_profile("  ")

    def test_delete_customer_profile(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            uc = ManageProfilesUseCase(r)
            p = uc.create_customer_profile("Kunde A")
            assert r.count() == 1
            uc.delete_customer_profile(p.id)
            assert r.count() == 0

    def test_migrate_existing_targets(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            uc = ManageProfilesUseCase(r)
            uc.ensure_own_system()
            count = uc.migrate_existing_targets(["Kunde Alpha", "Kunde Beta", ""])
            assert count == 2
            profiles = r.get_all()
            # 1 eigenes + 2 kunden
            assert len(profiles) == 3

    def test_migrate_idempotent(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            uc = ManageProfilesUseCase(r)
            uc.migrate_existing_targets(["Kunde X"])
            count2 = uc.migrate_existing_targets(["Kunde X"])
            assert count2 == 0
            assert r.count() == 1


# ---------------------------------------------------------------------------
# W1-Profil-Felder — additive Migration + P0-Synchronität
# ---------------------------------------------------------------------------

# Pre-W1-Schema (Stand): system_profiles nur bis ``rolle``, OHNE die 5
# W1-Spalten. Dient als Alt-DB-Fixture für den Migrationstest.
_PRE_W1_SCHEMA = """
CREATE TABLE system_profiles (
    profile_id  TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    system_type TEXT NOT NULL,
    description TEXT DEFAULT '',
    contact     TEXT DEFAULT '',
    tech_stack  TEXT DEFAULT '{}',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    branche     TEXT DEFAULT '',
    groesse     TEXT DEFAULT '',
    fte             INTEGER,
    umsatz_eur      INTEGER,
    bilanzsumme_eur INTEGER,
    sektor_key  TEXT DEFAULT '',
    nis2_anhang TEXT DEFAULT '',
    rolle       TEXT DEFAULT ''
);
"""

_W1_COLUMNS = (
    "segment",
    "hat_eigene_website",
    "hat_eigene_api",
    "ist_entwickler",
    "hat_server_infrastruktur",
)


def _own_profile(**overrides: object) -> SystemProfile:
    """Baut ein EIGENES-SystemProfile mit Pflicht-Timestamps für Repo-Tests."""
    now = datetime.now(UTC).isoformat()
    base = {
        "id": str(uuid.uuid4()),
        "name": "Mein System",
        "system_type": SystemType.EIGENES,
        "created_at": now,
        "updated_at": now,
    }
    base.update(overrides)
    return SystemProfile(**base)  # type: ignore[arg-type]


class TestW1ProfileFields:
    """: W1-Profil-Felder (segment + 4 Infrastruktur-Flags)."""

    def test_roundtrip_all_w1_fields(self, tmp_path: Path) -> None:
        # Fixture B: alle W1-Werte gesetzt → 1:1 zurück; 0 bleibt 0, None bleibt None.
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            p = _own_profile(
                segment="epu",
                hat_eigene_website=1,
                hat_eigene_api=0,
                ist_entwickler=1,
                hat_server_infrastruktur=None,
            )
            r.create(p)
            loaded = r.get_by_id(p.id)
            assert loaded is not None
            assert loaded.segment == "epu"
            assert loaded.hat_eigene_website == 1
            assert loaded.hat_eigene_api == 0  # 0 NICHT zu None koerziert
            assert loaded.ist_entwickler == 1
            assert loaded.hat_server_infrastruktur is None  # None bleibt None

    def test_defaults_are_empty_and_none(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            p = _own_profile()
            r.create(p)
            loaded = r.get_by_id(p.id)
            assert loaded is not None
            assert loaded.segment == ""
            assert loaded.hat_eigene_website is None
            assert loaded.hat_eigene_api is None
            assert loaded.ist_entwickler is None
            assert loaded.hat_server_infrastruktur is None

    def test_index_shift_detector(self, tmp_path: Path) -> None:
        # P0: charakteristischer Wert je Feld → kein Wert landet im
        # falschen Feld. Deckt die SELECT↔_row_to_profile-Index-Synchronität ab
        # (SELECT-Reihenfolge ≠ physische additive_columns-Reihenfolge).
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            p = _own_profile(
                description="DESC",
                contact="CONTACT",
                branche="BR",
                groesse="GR",
                fte=11,
                umsatz_eur=22,
                bilanzsumme_eur=33,
                sektor_key="energie",
                nis2_anhang="I",
                rolle="ROLE",
                segment="kmu_mittel",
                hat_eigene_website=1,
                hat_eigene_api=0,
                ist_entwickler=1,
                hat_server_infrastruktur=0,
            )
            r.create(p)
            loaded = r.get_by_id(p.id)
            assert loaded is not None
            #/-Block unverschoben
            assert loaded.description == "DESC"
            assert loaded.contact == "CONTACT"
            assert loaded.branche == "BR"
            assert loaded.groesse == "GR"
            assert loaded.fte == 11
            assert loaded.umsatz_eur == 22
            assert loaded.bilanzsumme_eur == 33
            assert loaded.sektor_key == "energie"
            assert loaded.nis2_anhang == "I"
            assert loaded.rolle == "ROLE"
            # W1-Block exakt zugeordnet (1/0/1/0 deckt Nachbar-Swaps auf)
            assert loaded.segment == "kmu_mittel"
            assert loaded.hat_eigene_website == 1
            assert loaded.hat_eigene_api == 0
            assert loaded.ist_entwickler == 1
            assert loaded.hat_server_infrastruktur == 0

    def test_update_sets_w1_without_clobbering(self, tmp_path: Path) -> None:
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            p = _own_profile(fte=5, sektor_key="energie", nis2_anhang="I")
            r.create(p)
            loaded = r.get_by_id(p.id)
            assert loaded is not None
            r.update(replace(loaded, segment="epu", hat_eigene_api=1))
            reread = r.get_by_id(p.id)
            assert reread is not None
            assert reread.segment == "epu"
            assert reread.hat_eigene_api == 1
            assert reread.fte == 5  # unbeteiligtes Feld nicht genullt
            assert reread.sektor_key == "energie"

    def test_migration_adds_w1_columns_to_old_db(self, tmp_path: Path) -> None:
        # Fixture A: Alt-DB (Pre-W1) → Migration ergänzt die 5 Spalten; Alt-Zeile
        # bleibt lesbar-Werte intakt, W1-Defaults korrekt.
        with patch.object(edb, "DB_DIR", tmp_path):
            db = edb.EncryptedDatabase("security_scoring")
            with db.connection() as conn:
                conn.executescript(_PRE_W1_SCHEMA)
                conn.execute(
                    "INSERT INTO system_profiles (profile_id, name, system_type,"
                    " created_at, updated_at, fte, sektor_key, nis2_anhang)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ("old-1", "Alt System", "eigenes", "t", "t", 42, "bankwesen", "I"),
                )
            # Repo-Instanziierung triggert _ensure_table → additive Migration.
            r = TechStackRepository()
            with r._db.connection() as conn:
                cols = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info(system_profiles)"
                    ).fetchall()
                }
            for col in _W1_COLUMNS:
                assert col in cols
            loaded = r.get_by_id("old-1")
            assert loaded is not None
            assert loaded.fte == 42  # intakt
            assert loaded.sektor_key == "bankwesen"
            assert loaded.segment == ""  # W1-Default
            assert loaded.hat_eigene_website is None
            assert loaded.hat_eigene_api is None
            assert loaded.ist_entwickler is None
            assert loaded.hat_server_infrastruktur is None

    def test_ensure_table_idempotent(self, tmp_path: Path) -> None:
        # ≥2 Läufe: jede W1-Spalte genau einmal, kein Fehler/Dup.
        with patch.object(edb, "DB_DIR", tmp_path):
            TechStackRepository()
            r2 = TechStackRepository()  # zweiter _ensure_table-Lauf = No-op
            with r2._db.connection() as conn:
                cols = [
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info(system_profiles)"
                    ).fetchall()
                ]
            for col in _W1_COLUMNS:
                assert cols.count(col) == 1

    def test_row_to_profile_short_tuple_uses_defaults(self) -> None:
        # Fixture C1: künstlich gekürztes Row-Tupel (nur bis updated_at, 8 Felder)
        # → Defaults via len(row)-Guard, kein IndexError.
        short = ("id", "n", "eigenes", "", "", "{}", "c", "u")
        p = _row_to_profile(short)
        assert p.rolle == ""  # Default
        assert p.fte is None
        assert p.segment == ""  # W1-Default
        assert p.hat_eigene_website is None
        assert p.hat_eigene_api is None
        assert p.ist_entwickler is None
        assert p.hat_server_infrastruktur is None

    def test_corrupt_tech_stack_keeps_w1_fields(self, tmp_path: Path) -> None:
        # Fixture C2: kaputter tech_stack-JSON + W1 gesetzt → leeres TechStack,
        # W1-Felder trotzdem korrekt (Block-Index-Unabhängigkeit).
        with patch.object(edb, "DB_DIR", tmp_path):
            r = TechStackRepository()
            p = _own_profile(segment="gamer", hat_eigene_api=1)
            r.create(p)
            with r._db.connection() as conn:
                conn.execute(
                    "UPDATE system_profiles SET tech_stack = ? WHERE profile_id = ?",
                    ("not-json-{{{", p.id),
                )
            loaded = r.get_by_id(p.id)
            assert loaded is not None
            assert loaded.tech_stack.operating_systems == []  # Fallback leer
            assert loaded.segment == "gamer"
            assert loaded.hat_eigene_api == 1
