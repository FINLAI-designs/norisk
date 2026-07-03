"""
test_system_tuner_snapshot_repo — Verschluesselte SQLCipher-Snapshot-Ablage (R5/T6/T9).

Deckt den ``ISnapshotRepo``-Vertrag (save/get/list_all) gegen eine echte
temp-SQLCipher-DB ab: ServiceStartMode-/Registry-Serialisierung, latest-wins
(append-only), Persistenz ueber Repo-Instanzen hinweg (prozessuebergreifend),
Verschluesselung-at-Rest und Schluessel-Bindung (anderer KeyManager/DEK → fail).

Der DB-Schluessel kommt aus dem zentralen ``KeyManager`` (T9). Die conftest-
autouse-Fixture stellt einen aktiven InMemory-KeyManager bereit; ``_repo`` nutzt
ihn, sodass mehrere Repo-Instanzen denselben DEK (und Schluessel) teilen.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.database.encrypted_db import DatabaseEncryptionError
from core.database.key_manager_context import get_active_key_manager
from tools.system_tuner.data.encrypted_snapshot_repo import EncryptedSnapshotRepository
from tools.system_tuner.domain.apply_entities import Snapshot
from tools.system_tuner.domain.enums import ServiceStartMode


def _repo(store_dir: Path, key_manager=None) -> EncryptedSnapshotRepository:
    """Repo gegen den aktiven (conftest) KeyManager — gemeinsamer DEK je Test."""
    return EncryptedSnapshotRepository(
        store_dir, key_manager or get_active_key_manager()
    )


def _service_snap(tweak_id: str = "TW-A") -> Snapshot:
    return Snapshot(
        tweak_id=tweak_id,
        target_key="service:DiagTrack",
        existed=True,
        prior_start_mode=ServiceStartMode.AUTOMATIC,
    )


# ---------------------------------------------------------------------------
# Vertrag: save / get / list_all
# ---------------------------------------------------------------------------


class TestRoundtrip:
    def test_service_start_mode_roundtrip(self, tmp_path: Path):
        repo = _repo(tmp_path)
        repo.save(_service_snap())
        got = repo.get("TW-A")
        assert got is not None
        assert got.tweak_id == "TW-A"
        assert got.target_key == "service:DiagTrack"
        assert got.existed is True
        assert got.prior_start_mode is ServiceStartMode.AUTOMATIC
        assert got.prior_registry_value is None

    def test_registry_snapshot_roundtrip(self, tmp_path: Path):
        repo = _repo(tmp_path)
        repo.save(
            Snapshot(
                tweak_id="TW-R",
                target_key="registry:HKLM\\Software\\X!Telemetry",
                existed=True,
                prior_registry_value="1",
                prior_registry_type="REG_DWORD",
            )
        )
        got = repo.get("TW-R")
        assert got is not None
        assert got.existed is True
        assert got.prior_registry_value == "1"
        assert got.prior_registry_type == "REG_DWORD"
        assert got.prior_start_mode is None

    def test_absent_value_snapshot(self, tmp_path: Path):
        """``existed=False`` (Ziel war nicht gesetzt → Revert = loeschen)."""
        repo = _repo(tmp_path)
        repo.save(
            Snapshot(
                tweak_id="TW-N",
                target_key="registry:HKCU\\X!New",
                existed=False,
                prior_registry_value=None,
            )
        )
        got = repo.get("TW-N")
        assert got is not None and got.existed is False
        assert got.prior_registry_value is None

    def test_get_unknown_returns_none(self, tmp_path: Path):
        assert _repo(tmp_path).get("missing") is None

    def test_empty_list_all(self, tmp_path: Path):
        assert _repo(tmp_path).list_all() == []

    def test_list_all_returns_latest_per_tweak(self, tmp_path: Path):
        repo = _repo(tmp_path)
        repo.save(_service_snap("TW-A"))
        repo.save(
            Snapshot(tweak_id="TW-B", target_key="service:Other", existed=False)
        )
        ids = sorted(s.tweak_id for s in repo.list_all())
        assert ids == ["TW-A", "TW-B"]


# ---------------------------------------------------------------------------
# Append-only / latest-wins
# ---------------------------------------------------------------------------


class TestLatestWins:
    def test_resave_same_tweak_latest_wins(self, tmp_path: Path):
        repo = _repo(tmp_path)
        repo.save(
            Snapshot(
                tweak_id="TW-A",
                target_key="service:DiagTrack",
                existed=True,
                prior_start_mode=ServiceStartMode.AUTOMATIC,
            )
        )
        repo.save(
            Snapshot(
                tweak_id="TW-A",
                target_key="service:DiagTrack",
                existed=True,
                prior_start_mode=ServiceStartMode.MANUAL,
            )
        )
        got = repo.get("TW-A")
        assert got is not None
        assert got.prior_start_mode is ServiceStartMode.MANUAL  # neuester gewinnt
        # list_all liefert genau einen Eintrag je tweak_id
        all_snaps = repo.list_all()
        assert len(all_snaps) == 1
        assert all_snaps[0].prior_start_mode is ServiceStartMode.MANUAL

    def test_many_resaves_same_second_pick_last(self, tmp_path: Path):
        """Mehrere Saves (gleiche Sekunde) → rowid trennt eindeutig (nicht uuid)."""
        repo = _repo(tmp_path)
        for mode in (
            ServiceStartMode.AUTOMATIC,
            ServiceStartMode.MANUAL,
            ServiceStartMode.DISABLED,
        ):
            repo.save(
                Snapshot(
                    tweak_id="TW-A",
                    target_key="service:DiagTrack",
                    existed=True,
                    prior_start_mode=mode,
                )
            )
        got = repo.get("TW-A")
        assert got is not None and got.prior_start_mode is ServiceStartMode.DISABLED


# ---------------------------------------------------------------------------
# Persistenz (prozessuebergreifend) + Schema
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_survives_new_repo_instance(self, tmp_path: Path):
        """Daten ueberleben das Schliessen/Neuoeffnen (elevated→Revert-Prozess)."""
        _repo(tmp_path).save(_service_snap("TW-A"))
        reopened = _repo(tmp_path)  # neue Instanz, gleicher store_dir + secret
        got = reopened.get("TW-A")
        assert got is not None
        assert got.prior_start_mode is ServiceStartMode.AUTOMATIC

    def test_schema_version_set(self, tmp_path: Path):
        assert _repo(tmp_path).get_schema_version() == 1


# ---------------------------------------------------------------------------
# Sicherheit: Verschluesselung-at-Rest + Schluessel-Bindung
# ---------------------------------------------------------------------------


class TestEncryption:
    def test_db_bytes_contain_no_plaintext(self, tmp_path: Path):
        marker_key = "DiagTrackZZSENTINEL"
        marker_val = "REGVALZZSENTINEL"
        repo = _repo(tmp_path)
        repo.save(
            Snapshot(tweak_id="TW-A", target_key=f"service:{marker_key}", existed=True)
        )
        repo.save(
            Snapshot(
                tweak_id="TW-R",
                target_key="registry:HKLM\\X",
                existed=True,
                prior_registry_value=marker_val,
                prior_registry_type="REG_SZ",
            )
        )
        # Haupt-DB (und, falls vorhanden, WAL/SHM) duerfen den Klartext nicht
        # tragen — weder target_key noch prior_registry_value. Die -wal-Frames
        # werden separat in test_wal_artifacts_contain_no_plaintext geprueft,
        # da sie nach save/Close i. d. R. schon gecheckpointet/entfernt sind.
        blob = b""
        for path in tmp_path.glob("snapshots.db*"):
            blob += path.read_bytes()
        assert blob, "Snapshot-DB wurde nicht angelegt"
        assert marker_key.encode("utf-8") not in blob
        assert marker_val.encode("utf-8") not in blob

    def test_wal_artifacts_contain_no_plaintext(self, tmp_path: Path):
        marker = "WALZZSENTINEL"
        repo = _repo(tmp_path)
        wal = tmp_path / "snapshots.db-wal"
        # Eine offen gehaltene Zweit-Verbindung verhindert, dass das WAL beim
        # save/Close gecheckpointet + entfernt wird — sonst waere die Pruefung
        # tautologisch (die -wal-Datei existierte zum Lesezeitpunkt gar nicht).
        with repo._db.connection() as keep:
            keep.execute("PRAGMA wal_autocheckpoint=0")
            repo.save(
                Snapshot(
                    tweak_id="TW-W",
                    target_key="registry:HKLM\\X",
                    existed=True,
                    prior_registry_value=marker,
                    prior_registry_type="REG_SZ",
                )
            )
            assert wal.exists(), "WAL nicht erzeugt — Test wuerde sonst nichts pruefen"
            assert marker.encode("utf-8") not in wal.read_bytes()

    def test_wrong_keymanager_rejected(self, tmp_path: Path, monkeypatch):
        """Anderer KeyManager (anderer DEK) → anderer DB-Schluessel → fail-closed."""
        from core.database import key_manager as km_mod
        from core.database.key_manager import KeyManager
        from core.database.key_manager_platform import InMemoryDPAPIBackend

        # Zwei isolierte KeyManager mit eigenem master.key + Backend -> 2 DEKs.
        # DEK je sofort cachen, damit spaetere _MASTER_KEY_FILE-Patches die
        # bereits geladenen Manager nicht beeinflussen.
        monkeypatch.setattr(km_mod, "_MASTER_KEY_FILE", tmp_path / "a.key")
        km_a = KeyManager(backend=InMemoryDPAPIBackend())
        km_a.initialize()
        km_a.load_master_key()
        monkeypatch.setattr(km_mod, "_MASTER_KEY_FILE", tmp_path / "b.key")
        km_b = KeyManager(backend=InMemoryDPAPIBackend())
        km_b.initialize()
        km_b.load_master_key()

        # Vorbedingung: verschiedene DEKs -> verschiedene Schluessel, sonst prueft
        # der raises-Block nichts (Isolation waere tautologisch). Erzwingt zugleich
        # das DEK-Caching beider KM vor dem Repo-Bau (gegen Reorder-Fragilitaet).
        assert km_a.derive_secondary_key("db:system_tuner_snapshots") != (
            km_b.derive_secondary_key("db:system_tuner_snapshots")
        )
        EncryptedSnapshotRepository(tmp_path, km_a).save(_service_snap("TW-A"))
        with pytest.raises(DatabaseEncryptionError):
            EncryptedSnapshotRepository(tmp_path, km_b)

    def test_db_key_purpose_pinned(self, tmp_path: Path):
        """Charakterisierung: die Snapshot-DB haengt am Purpose
        ``db:system_tuner_snapshots``. Ein Rename von _DB_NAME wuerde bestehende
        DBs still verwaisen -> Literal-Purpose hier festnageln (Regressionsschutz)."""
        from core.database.encrypted_db import EncryptedDatabase

        km = get_active_key_manager()
        _repo(tmp_path).save(_service_snap("TW-A"))
        db_file = tmp_path / "snapshots.db"
        # Oeffnet unter dem erwarteten db-name "system_tuner_snapshots".
        ok = EncryptedDatabase("system_tuner_snapshots", db_path=db_file, key_manager=km)
        with ok.connection() as conn:
            assert conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 1
        # Anderer db-name -> anderer abgeleiteter Key -> nicht entschluesselbar.
        renamed = EncryptedDatabase(
            "system_tuner_snapshots_RENAMED", db_path=db_file, key_manager=km
        )
        with pytest.raises(DatabaseEncryptionError), renamed.connection():
            pass


# ---------------------------------------------------------------------------
# End-to-End: TweakEngine x echtes Repo (ISnapshotRepo-Vertrag im Apply/Revert)
# ---------------------------------------------------------------------------


_REG_KEY = "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"


def _reg_tweak():
    from tools.system_tuner.domain.entities import (
        ChangeSpec,
        Provenance,
        RevertSpec,
        Tweak,
        VerifySpec,
    )
    from tools.system_tuner.domain.enums import (
        ChangeOp,
        Recommendation,
        RegistryValueType,
        RevertKind,
        RiskTier,
        TweakCategory,
    )

    return Tweak(
        id="TW-R",
        title_de="Telemetrie",
        category=TweakCategory.TELEMETRY,
        risk_tier=RiskTier.T1_SAFE,
        recommend=Recommendation.STANDARD,
        rationale_de="x",
        docs_url="https://learn.microsoft.com/x",
        change=ChangeSpec(
            op=ChangeOp.REGISTRY_SET,
            hive="HKLM",
            key=_REG_KEY,
            value_name="AllowTelemetry",
            value_type=RegistryValueType.REG_DWORD,
            desired=1,
        ),
        verify=VerifySpec(expect_value=1),
        revert=RevertSpec(kind=RevertKind.RESTORE_PRIOR),
        provenance=Provenance(source="MS"),
    )


def _svc_tweak():
    from tools.system_tuner.domain.entities import (
        ChangeSpec,
        Provenance,
        RevertSpec,
        Tweak,
        VerifySpec,
    )
    from tools.system_tuner.domain.enums import (
        ChangeOp,
        Recommendation,
        RevertKind,
        RiskTier,
        TweakCategory,
    )

    return Tweak(
        id="TW-S",
        title_de="Dienst",
        category=TweakCategory.SERVICES,
        risk_tier=RiskTier.T2_CAUTION,
        recommend=Recommendation.STANDARD,
        rationale_de="x",
        docs_url="https://learn.microsoft.com/x",
        change=ChangeSpec(
            op=ChangeOp.SERVICE_STARTMODE,
            service_name="DiagTrack",
            desired_start_mode=ServiceStartMode.MANUAL,
        ),
        verify=VerifySpec(expect_start_mode=ServiceStartMode.MANUAL),
        revert=RevertSpec(kind=RevertKind.RESTORE_PRIOR),
        provenance=Provenance(source="MS"),
    )


class TestEngineIntegration:
    """Beweist den ISnapshotRepo-Vertrag im Zusammenspiel mit TweakEngine gegen
    das ECHTE Repo (nicht InMemory): apply schreibt Snapshots, ein NEUER
    Repo+Engine (Prozesswechsel-Simulation) reverted aus der persistierten DB."""

    def test_apply_then_revert_through_fresh_repo(self, tmp_path: Path):
        from tools.system_tuner.application.tweak_engine import TweakEngine
        from tools.system_tuner.data.mock_tweak_probe import MockTweakProbe

        reg, svc = _reg_tweak(), _svc_tweak()
        probe = MockTweakProbe()
        # Vorzustand seeden (vor Apply): Telemetrie=0, DiagTrack=automatic.
        probe.set_registry_value("HKLM", _REG_KEY, "AllowTelemetry", "0")
        probe.set_service("DiagTrack", ServiceStartMode.AUTOMATIC)

        # Apply mit echtem SQLCipher-Repo -> Snapshots persistiert.
        TweakEngine(probe, _repo(tmp_path), allow_apply=True).apply([reg, svc])
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") == "1"
        assert probe.read_service_start_mode("DiagTrack") is ServiceStartMode.MANUAL

        # Prozesswechsel: frische Repo-Instanz (gleicher store_dir+secret) liest
        # die persistierten Snapshots und revertet den Vorzustand.
        TweakEngine(probe, _repo(tmp_path), allow_apply=True).revert_all([reg, svc])
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") == "0"
        assert probe.read_service_start_mode("DiagTrack") is ServiceStartMode.AUTOMATIC

    def test_reapply_then_revert_uses_latest_prior(self, tmp_path: Path):
        """Re-Apply (zweimal save desselben tweak_id) -> Revert ueber frische
        Repo-Instanz stellt den NEUESTEN Vorzustand wieder her (append-only)."""
        from tools.system_tuner.application.tweak_engine import TweakEngine
        from tools.system_tuner.data.mock_tweak_probe import MockTweakProbe

        reg = _reg_tweak()
        probe = MockTweakProbe()
        repo = _repo(tmp_path)

        probe.set_registry_value("HKLM", _REG_KEY, "AllowTelemetry", "0")
        TweakEngine(probe, repo, allow_apply=True).apply([reg])  # prior=0 gesnappt
        # Zwischenzeitliche Aenderung, dann erneuter Apply -> prior=5 gesnappt.
        probe.set_registry_value("HKLM", _REG_KEY, "AllowTelemetry", "5")
        TweakEngine(probe, repo, allow_apply=True).apply([reg])

        TweakEngine(probe, _repo(tmp_path), allow_apply=True).revert_all([reg])
        # NEUESTER Vorzustand (5) wird zurueckgeschrieben, nicht der erste (0).
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") == "5"
