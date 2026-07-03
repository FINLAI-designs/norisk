"""
test_system_tuner_windows_adapter — Windows-Apply-Adapter (R5/R6/T5).

Cross-platform testbare Logik der Adapter: Plan-/Result-Dateien (inkl. Single-
Use-Loeschung T5), KeyManager-abgeleitetes HMAC-Geheimnis (T9), restore_point
(fail-closed, via MockHardeningProbe). Der volle elevated-Entry-Round-Trip +
echte winreg-Writes sind im Live-Smoke gegen HKCU verifiziert. Snapshot-
Persistenz: siehe ``test_system_tuner_snapshot_repo``.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.finlai_paths import set_finlai_home
from core.probes.mock_hardening_probe import MockHardeningProbe
from tools.system_tuner.application.apply_plan import bind_plan
from tools.system_tuner.application.elevated_round_trip import (
    read_and_consume_plan,
    read_result,
    write_plan,
    write_result,
)
from tools.system_tuner.data.restore_point import _DESCRIPTION, create_restore_point
from tools.system_tuner.domain.apply_entities import BatchResult, TweakResult
from tools.system_tuner.domain.enums import TweakStatus


@pytest.fixture
def home(tmp_path: Path):
    set_finlai_home(str(tmp_path))
    yield tmp_path
    set_finlai_home(None)


def _km_secret() -> bytes:
    """Das KM-abgeleitete HMAC-Geheimnis (T9) — exakt wie Produktion es bildet."""
    from core.database.key_manager_context import get_active_key_manager
    from tools.system_tuner.application.elevated_round_trip import _apply_hmac_secret

    return _apply_hmac_secret(get_active_key_manager())


class TestPlanFiles:
    def test_write_then_consume_deletes_file(self, home: Path):
        payload = bind_plan("tok", ["TW-A"], "sig", secret=b"x" * 32).to_dict()
        path = write_plan(payload)
        assert path.exists()
        consumed = read_and_consume_plan(path)
        assert consumed is not None
        assert consumed["token"] == "tok"
        # Single-Use (T5): Datei ist nach dem Lesen weg
        assert not path.exists()

    def test_consume_missing_returns_none(self, home: Path):
        assert read_and_consume_plan(home / "nope.json") is None

    def test_result_roundtrip(self, tmp_path: Path):
        secret = b"k" * 32
        result = BatchResult((TweakResult("TW-A", TweakStatus.SUCCESS, "ok"),))
        write_result("tok", result, store_dir=tmp_path, secret=secret)
        loaded = read_result("tok", store_dir=tmp_path, secret=secret)
        assert loaded is not None
        assert loaded.results[0].status is TweakStatus.SUCCESS

    def test_result_missing_returns_none(self, tmp_path: Path):
        assert read_result("nope", store_dir=tmp_path, secret=b"k" * 32) is None

    def test_result_hmac_tamper_rejected(self, tmp_path: Path):
        import json

        secret = b"k" * 32
        write_result(
            "tok",
            BatchResult((TweakResult("TW-A", TweakStatus.SUCCESS, "ok"),)),
            store_dir=tmp_path,
            secret=secret,
        )
        path = tmp_path / "result_tok.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["results"][0]["status"] = "failed"  # Inhalt manipulieren, HMAC alt
        path.write_text(json.dumps(raw), encoding="utf-8")
        # A5c: manipulierter Inhalt -> HMAC mismatch -> verworfen
        assert read_result("tok", store_dir=tmp_path, secret=secret) is None
        # Falscher Secret -> ebenfalls verworfen
        assert read_result("tok", store_dir=tmp_path, secret=b"x" * 32) is None


class TestCoerceValue:
    def test_bad_dword_returns_none_type(self):
        # A8: nicht-numerisches desired -> (None, value), kein ValueError
        import types

        from tools.system_tuner.data.windows_tweak_probe import _coerce_value
        from tools.system_tuner.domain.enums import RegistryValueType

        fake_winreg = types.SimpleNamespace(REG_DWORD=4, REG_QWORD=11, REG_SZ=1)
        type_const, _value = _coerce_value(
            fake_winreg, RegistryValueType.REG_DWORD, "not-an-int"
        )
        assert type_const is None  # Caller liefert fail-ProbeResult, wirft nicht


class TestRestorePoint:
    def test_not_available_is_false(self):
        assert create_restore_point(MockHardeningProbe(available=False)) is False

    def test_powershell_failure_is_false(self):
        # Default: kein gesetztes PS-Ergebnis -> run_powershell meldet Fehler
        assert create_restore_point(MockHardeningProbe()) is False

    def test_success_returns_true(self):
        probe = MockHardeningProbe()
        script = (
            f"Checkpoint-Computer -Description '{_DESCRIPTION}' "
            "-RestorePointType 'MODIFY_SETTINGS'"
        )
        probe.set_powershell_result(script, success=True)
        assert create_restore_point(probe) is True


class TestTokenLedger:
    """A2-voll — persistenter Single-Use-Token-Ledger (Replay-Schutz)."""

    def test_mark_and_detect(self, tmp_path: Path):
        from tools.system_tuner.data.token_ledger import FileTokenLedger

        ledger = FileTokenLedger(tmp_path)
        assert "t1" not in ledger.load_used()
        assert ledger.mark_used("t1") is True
        assert "t1" in ledger.load_used()

    def test_empty_ledger(self, tmp_path: Path):
        from tools.system_tuner.data.token_ledger import FileTokenLedger

        assert FileTokenLedger(tmp_path).load_used() == frozenset()


class TestSecureStore:
    """A5 — admin-only Ablage (fail-closed ohne Admin)."""

    def test_secure_dir_under_programdata(self):
        from tools.system_tuner.data.secure_store import secure_dir

        assert "NoRisk" in str(secure_dir())

    def test_ensure_fail_closed_without_admin(self, tmp_path: Path):
        from core.elevation import is_admin
        from tools.system_tuner.data.secure_store import ensure_secure_dir

        result = ensure_secure_dir(tmp_path / "store")
        # Non-Admin kann keinen admin-only Owner/DACL setzen -> fail-closed.
        assert result == is_admin()


class TestEntryGates:
    """A3/A4/A2 im echten run_apply_entry (Dev-Fallback-Pfad; skip wenn Admin,
    weil dann die echte %ProgramData%-Ablage genutzt wuerde)."""

    def _write_plan(self, token: str) -> None:
        from tools.system_tuner.application.apply_plan import bind_plan
        from tools.system_tuner.application.catalog_loader import (
            default_signature_path,
        )
        from tools.system_tuner.application.elevated_round_trip import write_plan

        sig = default_signature_path().read_text(encoding="utf-8").strip()
        write_plan(
            bind_plan(
                token, ["TW-TEL-001"], sig, secret=_km_secret()
            ).to_dict()
        )

    def test_non_admin_fail_closed(self, home: Path):
        from core.elevation import is_admin
        from tools.system_tuner.application.elevated_round_trip import (
            _plan_path,
            run_apply_entry,
        )

        if is_admin():
            pytest.skip("Admin: nutzt echte ProgramData-Ablage")
        token = "tok-" + os.urandom(4).hex()
        self._write_plan(token)
        # ohne --allow-untrusted-path: secure_dir nicht herstellbar -> rc=2, kein Apply
        assert run_apply_entry(plan_path=_plan_path(token)) == 2

    def test_consent_gate_blocks(self, home: Path):
        from core.elevation import is_admin
        from tools.system_tuner.application.elevated_round_trip import (
            _plan_path,
            _st_dir,
            read_result,
            run_apply_entry,
        )

        if is_admin():
            pytest.skip("Admin: nutzt echte ProgramData-Ablage")
        token = "tok-" + os.urandom(4).hex()
        self._write_plan(token)
        rc = run_apply_entry(
            plan_path=_plan_path(token),
            allow_untrusted_path=True,
            skip_restore_point=True,
        )
        assert rc == 0
        res = read_result(
            token, store_dir=_st_dir(), secret=_km_secret()
        )
        assert res is not None
        assert res.results[0].status is TweakStatus.BLOCKED
        assert "A4" in res.results[0].detail

    def test_replay_blocked(self, home: Path):
        from core.elevation import is_admin
        from tools.system_tuner.application.consent_gate import ConsentGate
        from tools.system_tuner.application.elevated_round_trip import (
            _plan_path,
            _st_dir,
            consent_path,
            read_result,
            run_apply_entry,
        )

        if is_admin():
            pytest.skip("Admin: nutzt echte ProgramData-Ablage")
        ConsentGate(consent_path()).record_consent(recorded_at="2026-06-17T00:00:00")
        token = "tok-" + os.urandom(4).hex()
        self._write_plan(token)
        run_apply_entry(
            plan_path=_plan_path(token),
            allow_untrusted_path=True,
            skip_restore_point=True,
        )
        # Gleichen Token erneut einreichen -> A2 Replay-Reject
        self._write_plan(token)
        run_apply_entry(
            plan_path=_plan_path(token),
            allow_untrusted_path=True,
            skip_restore_point=True,
        )
        res = read_result(
            token, store_dir=_st_dir(), secret=_km_secret()
        )
        assert res is not None
        assert "A2" in res.results[0].detail


class TestEntryFailClosed:
    """run_apply_entry bleibt fail-closed (Reject-Marker statt Crash), wenn die
    Snapshot-DB-Init oder der Apply-Tail werfen — und verbrennt den Single-Use-
    Token NICHT bei einem reinen DB-Init-Fehler (sonst permanenter Apply-Ausfall)."""

    def _consent_and_plan(self, token: str) -> None:
        from tools.system_tuner.application.apply_plan import bind_plan
        from tools.system_tuner.application.catalog_loader import (
            default_signature_path,
        )
        from tools.system_tuner.application.consent_gate import ConsentGate
        from tools.system_tuner.application.elevated_round_trip import (
            consent_path,
            write_plan,
        )

        ConsentGate(consent_path()).record_consent(recorded_at="2026-06-17T00:00:00")
        sig = default_signature_path().read_text(encoding="utf-8").strip()
        write_plan(
            bind_plan(
                token, ["TW-TEL-001"], sig, secret=_km_secret()
            ).to_dict()
        )

    def test_snapshot_db_init_failure_is_fail_closed(self, home: Path, monkeypatch):
        from core.elevation import is_admin

        if is_admin():
            pytest.skip("Admin: nutzt echte ProgramData-Ablage")
        from tools.system_tuner.application import elevated_round_trip as ert
        from tools.system_tuner.data.token_ledger import FileTokenLedger

        def _boom(*_a, **_k):
            raise RuntimeError("DB-Init kaputt")

        monkeypatch.setattr(ert, "EncryptedSnapshotRepository", _boom)
        token = "tok-" + os.urandom(4).hex()
        self._consent_and_plan(token)

        rc = ert.run_apply_entry(
            plan_path=ert._plan_path(token),
            allow_untrusted_path=True,
            skip_restore_point=True,
        )
        assert rc == 0  # kein unbehandelter Crash
        res = ert.read_result(
            token, store_dir=ert._st_dir(), secret=_km_secret()
        )
        assert res is not None
        assert res.results[0].status is TweakStatus.BLOCKED
        assert "Snapshot" in res.results[0].detail
        # MED #3: Token NICHT verbrannt -> Retry desselben Plans bleibt moeglich.
        assert token not in FileTokenLedger(ert._st_dir()).load_used()

    def test_apply_tail_exception_is_fail_closed(self, home: Path, monkeypatch):
        from core.elevation import is_admin

        if is_admin():
            pytest.skip("Admin: nutzt echte ProgramData-Ablage")
        from tools.system_tuner.application import elevated_round_trip as ert

        def _boom(*_a, **_k):
            raise RuntimeError("Apply explodiert")

        monkeypatch.setattr(ert, "run_elevated_apply", _boom)
        token = "tok-" + os.urandom(4).hex()
        self._consent_and_plan(token)

        rc = ert.run_apply_entry(
            plan_path=ert._plan_path(token),
            allow_untrusted_path=True,
            skip_restore_point=True,
        )
        assert rc == 0
        res = ert.read_result(
            token, store_dir=ert._st_dir(), secret=_km_secret()
        )
        assert res is not None
        assert res.results[0].status is TweakStatus.BLOCKED
        assert "INTERNAL" in res.results[0].detail


class TestKeyManagerResolution:
    """T9: HMAC-Geheimnis + Snapshot-DB-Key aus dem envelope-DEK; der app-bootlose
    elevated Prozess bootet den KeyManager selbst, fail-closed wenn kein DEK."""

    def test_reuses_active_key_manager(self):
        from core.database.key_manager_context import get_active_key_manager
        from tools.system_tuner.application.elevated_round_trip import (
            _resolve_key_manager,
        )

        # Ist ein KM aktiv (GUI/Test), wird er wiederverwendet (kein Bootstrap)
        # -> GUI- und elevated-Seite teilen denselben DEK.
        assert _resolve_key_manager() is get_active_key_manager()

    def test_bootstraps_when_none_active(self, tmp_path: Path, monkeypatch):
        from core.database import key_manager as km_mod
        from core.database.key_manager import KeyManager
        from core.database.key_manager_context import (
            get_active_key_manager,
            set_active_key_manager,
        )
        from core.database.key_manager_platform import InMemoryDPAPIBackend
        from tools.system_tuner.application import elevated_round_trip as ert

        monkeypatch.setattr(km_mod, "_MASTER_KEY_FILE", tmp_path / "boot.key")
        built = KeyManager(backend=InMemoryDPAPIBackend())
        built.initialize()
        monkeypatch.setattr(ert, "KeyManager", lambda *a, **k: built)
        set_active_key_manager(None)  # app-bootloser Zustand simulieren

        resolved = ert._resolve_key_manager()
        assert resolved is built  # aus dem DPAPI-gewrappten DEK gebootet
        # Beweist, dass set_active_key_manager(built) lief (nicht nur das Lambda):
        assert get_active_key_manager() is built
        # Idempotent: jetzt aktiv -> zweiter Aufruf ueber den Reuse-Zweig.
        assert ert._resolve_key_manager() is built

    def test_keymanager_unavailable_is_fail_closed(self, home: Path, monkeypatch):
        from core.elevation import is_admin

        if is_admin():
            pytest.skip("Admin: nutzt echte ProgramData-Ablage")
        from tools.system_tuner.application import elevated_round_trip as ert

        def _no_dek() -> object:
            raise RuntimeError("kein DEK verfuegbar")

        # Resolver wirft (kein aktiver KM + kein master.key) -> run_apply_entry
        # liefert rc=2 (kein signierbarer Marker), kein unbehandelter Crash.
        monkeypatch.setattr(ert, "_resolve_key_manager", _no_dek)
        token = "tok-" + os.urandom(4).hex()
        rc = ert.run_apply_entry(
            plan_path=ert._plan_path(token),
            allow_untrusted_path=True,
            skip_restore_point=True,
        )
        assert rc == 2

    @pytest.mark.no_key_manager_bootstrap
    def test_cold_boot_missing_master_key_is_fail_closed(
        self, home: Path, monkeypatch
    ):
        from core.elevation import is_admin

        if is_admin():
            pytest.skip("Admin: nutzt echte ProgramData-Ablage")
        from core.database import key_manager as km_mod
        from core.database.key_manager_context import set_active_key_manager
        from tools.system_tuner.application import elevated_round_trip as ert

        # End-to-End cold-boot: kein aktiver KM + master.key fehlt -> der ECHTE
        # _resolve_key_manager (KeyManager.load_master_key) wirft
        # KeyManagerNotInitializedError -> run_apply_entry fail-closed rc=2.
        set_active_key_manager(None)
        monkeypatch.setattr(km_mod, "_MASTER_KEY_FILE", home / "absent.key")
        token = "tok-" + os.urandom(4).hex()
        rc = ert.run_apply_entry(
            plan_path=ert._plan_path(token),
            allow_untrusted_path=True,
            skip_restore_point=True,
        )
        assert rc == 2


class TestGuiRequestApply:
    """GUI-Seite request_elevated_apply (T9): bindet den Plan mit dem KM-Secret;
    fail-closed (return None), wenn kein KeyManager/DEK verfuegbar ist."""

    def test_binds_plan_with_km_secret(self, home: Path, monkeypatch):
        from tools.system_tuner.application import elevated_round_trip as ert
        from tools.system_tuner.application.apply_plan import verify_plan
        from tools.system_tuner.application.catalog_loader import (
            default_signature_path,
        )

        captured: dict = {}

        def _capture_write(payload: dict) -> Path:
            captured.update(payload)
            return home / "plan.json"

        monkeypatch.setattr(ert, "write_plan", _capture_write)
        monkeypatch.setattr(ert, "relaunch_elevated", lambda *a, **k: False)  # UAC ab

        assert ert.request_elevated_apply(["TW-TEL-001"]) is None  # UAC abgelehnt
        # Der gebundene Plan muss mit dem KM-Secret + Katalog-Sig verifizierbar
        # sein -> beweist: die GUI bindet mit demselben Secret
        # (_apply_hmac_secret(get_active_key_manager)), das die elevated-Seite
        # intern ableitet (cross-process-Konsistenz).
        sig = default_signature_path().read_text(encoding="utf-8").strip()
        verified = verify_plan(captured, secret=_km_secret(), expected_catalog_sig=sig)
        assert verified == ["TW-TEL-001"]

    def test_fail_closed_without_key_manager(self, home: Path, monkeypatch):
        from core.database.key_manager_context import set_active_key_manager
        from tools.system_tuner.application import elevated_round_trip as ert

        called = {"write": False, "relaunch": False}

        def _spy_write(payload: dict) -> Path:
            called["write"] = True
            return home / "plan.json"

        def _spy_relaunch(*a: object, **k: object) -> bool:
            called["relaunch"] = True
            return True

        monkeypatch.setattr(ert, "write_plan", _spy_write)
        monkeypatch.setattr(ert, "relaunch_elevated", _spy_relaunch)
        set_active_key_manager(None)  # kein DEK -> Secret-Ableitung wirft

        assert ert.request_elevated_apply(["TW-TEL-001"]) is None
        assert not called["write"]  # kein Plan geschrieben
        assert not called["relaunch"]  # keine UAC ausgeloest
