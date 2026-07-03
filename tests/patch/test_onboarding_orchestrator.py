"""
test_onboarding_orchestrator — Tests fuer
tools/patch_monitor/onboarding_orchestrator.py.

Bug-Fix-Sprint C-3 (Option D). Deckt:

1. should_show_onboarding-State-Machine (5 Pfade)
2. install_winget_module: success / install-failed / subprocess-error /
   non-windows-platform
3. install_winget_module liefert keine stderr-Excerpts in reason_class
   (Privacy-Filter-Direktive C-5)
4. refresh_module_status ruft get_winget_module_status mit
   force_refresh=True
5. INSTALL_REASON_CLASSES enthaelt alle reason_class-Werte
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from core.patch_collector import ModuleStatus, ModuleStatusDetail
from tools.patch_monitor import onboarding_orchestrator
from tools.patch_monitor.onboarding_marker import (
    OnboardingDecision,
    OnboardingMarker,
)
from tools.patch_monitor.onboarding_orchestrator import (
    INSTALL_REASON_CLASSES,
    InstallResult,
    create_scan_reminder_task,
    install_winget_module,
    refresh_module_status,
    should_show_onboarding,
)


def _marker(decision: OnboardingDecision) -> OnboardingMarker:
    return OnboardingMarker(
        schema_version=1,
        decided_at=datetime(2026, 5, 7, tzinfo=UTC),
        decision=decision,
    )


# ===========================================================================
# Akzeptanz 1 — should_show_onboarding-State-Machine
# ===========================================================================


class TestShouldShowOnboarding:
    def test_available_immer_kein_dialog(self) -> None:
        # Egal welcher Marker-State — wenn das Modul da ist, kein Dialog.
        assert should_show_onboarding(ModuleStatus.AVAILABLE, None) is False
        for decision in OnboardingDecision:
            assert (
                should_show_onboarding(ModuleStatus.AVAILABLE, _marker(decision))
                is False
            )

    def test_kein_marker_und_modul_fehlt_dialog(self) -> None:
        assert should_show_onboarding(ModuleStatus.NEEDS_INSTALL, None) is True
        assert should_show_onboarding(ModuleStatus.BLOCKED, None) is True

    def test_decision_never_kein_dialog(self) -> None:
        marker = _marker(OnboardingDecision.NEVER)
        assert should_show_onboarding(ModuleStatus.NEEDS_INSTALL, marker) is False
        assert should_show_onboarding(ModuleStatus.BLOCKED, marker) is False

    def test_decision_skip_session_kein_dialog_mehr(self) -> None:
        # "genau einmal fragen" — nach dem Ueberspringen erscheint das
        # Modal nicht erneut (Erinnerung laeuft ueber das Homescreen-Task).
        marker = _marker(OnboardingDecision.SKIP_SESSION)
        assert should_show_onboarding(ModuleStatus.NEEDS_INSTALL, marker) is False
        assert should_show_onboarding(ModuleStatus.BLOCKED, marker) is False

    def test_decision_installed_stale_kein_dialog(self) -> None:
        # Auch der Stale-INSTALLED-Fall (Marker sagt installiert, Modul
        # ist jetzt weg) zeigt das Modal NICHT erneut — der In-Tool-Banner
        # bietet den Re-Install-Weg an.
        marker = _marker(OnboardingDecision.INSTALLED)
        assert should_show_onboarding(ModuleStatus.NEEDS_INSTALL, marker) is False
        assert should_show_onboarding(ModuleStatus.BLOCKED, marker) is False


# ===========================================================================
# Akzeptanz 2-3 — install_winget_module
# ===========================================================================


class TestInstallWingetModule:
    def test_non_windows_platform(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(onboarding_orchestrator.sys, "platform", "linux")
        result = install_winget_module()
        assert result.success is False
        assert result.reason_class == "non-windows-platform"

    def test_subprocess_filenotfound(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(onboarding_orchestrator.sys, "platform", "win32")

        def _raise(*_args, **_kwargs):
            raise FileNotFoundError("powershell not on PATH")

        monkeypatch.setattr(
            onboarding_orchestrator.subprocess, "run", _raise
        )
        result = install_winget_module()
        assert result.success is False
        assert result.reason_class == "subprocess-error"

    def test_subprocess_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(onboarding_orchestrator.sys, "platform", "win32")

        def _raise(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(cmd="powershell", timeout=180)

        monkeypatch.setattr(
            onboarding_orchestrator.subprocess, "run", _raise
        )
        result = install_winget_module()
        assert result.success is False
        assert result.reason_class == "subprocess-error"

    def test_install_failed_returncode_nicht_null(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(onboarding_orchestrator.sys, "platform", "win32")
        fake_result = SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=(
                "Install-Module: User profile path C:\\Users\\patrick "
                "domain CONTOSO error 0xCAFEBABE"
            ),
        )
        monkeypatch.setattr(
            onboarding_orchestrator.subprocess,
            "run",
            lambda *_a, **_kw: fake_result,
        )
        result = install_winget_module()
        assert result.success is False
        assert result.reason_class == "install-failed"
        # Privacy-Filter: kein stderr-Inhalt im reason_class.
        assert "patrick" not in result.reason_class
        assert "CONTOSO" not in result.reason_class
        assert "0xCAFEBABE" not in result.reason_class

    def test_install_erfolgreich(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(onboarding_orchestrator.sys, "platform", "win32")
        fake_result = SimpleNamespace(returncode=0, stdout="", stderr="")
        monkeypatch.setattr(
            onboarding_orchestrator.subprocess,
            "run",
            lambda *_a, **_kw: fake_result,
        )
        result = install_winget_module()
        assert result.success is True
        assert result.reason_class == "ok"

    def test_install_kommando_ist_currentuser_und_force(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Sanity: die Kommando-Konstante darf nicht versehentlich auf
        # AllUsers oder ohne -Force gestellt werden — sonst UAC-Elevation
        # noetig (verfehlt den Onboarding-Sinn).
        cmd = onboarding_orchestrator._INSTALL_CMD
        assert "Microsoft.WinGet.Client" in cmd
        assert "-Scope CurrentUser" in cmd
        assert "-Force" in cmd


# ===========================================================================
# Akzeptanz 4 — refresh_module_status
# ===========================================================================


class TestRefreshModuleStatus:
    def test_ruft_get_winget_module_status_mit_force_refresh(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        def _fake(*, force_refresh: bool) -> ModuleStatusDetail:
            captured["force_refresh"] = force_refresh
            return ModuleStatusDetail(
                status=ModuleStatus.AVAILABLE,
                reason="probe-succeeded",
                can_attempt_install=False,
            )

        monkeypatch.setattr(
            onboarding_orchestrator,
            "get_winget_module_status",
            _fake,
        )
        status = refresh_module_status()
        assert status is ModuleStatus.AVAILABLE
        assert captured["force_refresh"] is True


# ===========================================================================
# Akzeptanz 5 — INSTALL_REASON_CLASSES enthaelt alle benutzten Werte
# ===========================================================================


class TestReasonClassesVokabular:
    def test_alle_reason_classes_im_vokabular(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Sammle alle moeglichen reason_class-Werte aus den vier Pfaden.
        observed: set[str] = set()

        # non-windows
        monkeypatch.setattr(onboarding_orchestrator.sys, "platform", "linux")
        observed.add(install_winget_module().reason_class)

        # subprocess-error
        monkeypatch.setattr(onboarding_orchestrator.sys, "platform", "win32")

        def _raise(*_args, **_kwargs):
            raise OSError("fake")

        monkeypatch.setattr(
            onboarding_orchestrator.subprocess, "run", _raise
        )
        observed.add(install_winget_module().reason_class)

        # install-failed
        fake_fail = SimpleNamespace(returncode=1, stdout="", stderr="x")
        monkeypatch.setattr(
            onboarding_orchestrator.subprocess,
            "run",
            lambda *_a, **_kw: fake_fail,
        )
        observed.add(install_winget_module().reason_class)

        # ok
        fake_ok = SimpleNamespace(returncode=0, stdout="", stderr="")
        monkeypatch.setattr(
            onboarding_orchestrator.subprocess,
            "run",
            lambda *_a, **_kw: fake_ok,
        )
        observed.add(install_winget_module().reason_class)

        assert observed <= INSTALL_REASON_CLASSES
        # Und alle vier Klassen sind tatsaechlich erreicht.
        assert observed == INSTALL_REASON_CLASSES


# ===========================================================================
# InstallResult — frozen dataclass
# ===========================================================================


class TestInstallResultDataclass:
    def test_install_result_ist_frozen(self) -> None:
        from dataclasses import FrozenInstanceError

        r = InstallResult(success=True, reason_class="ok")
        with pytest.raises(FrozenInstanceError):
            r.success = False  # type: ignore[misc]


# ===========================================================================
# create_scan_reminder_task (Homescreen-Reminder statt Dauerprompt)
# ===========================================================================


class _FakeTaskService:
    """Minimaler TaskService-Stub: faengt create_critical_task-Aufrufe ab."""

    def __init__(self, *, raise_on_create: bool = False) -> None:
        self.calls: list[dict] = []
        self._raise = raise_on_create

    def create_critical_task(self, **kwargs: object) -> object:
        if self._raise:
            raise RuntimeError("DB unreachable")
        self.calls.append(kwargs)
        return object()


class TestCreateScanReminderTask:
    def test_legt_kritisches_task_mit_dedup_key_an(self) -> None:
        svc = _FakeTaskService()
        result = create_scan_reminder_task(task_service=svc)  # type: ignore[arg-type]
        assert result is True
        assert len(svc.calls) == 1
        call = svc.calls[0]
        assert (
            call["dedup_key"]
            == onboarding_orchestrator._SCAN_REMINDER_DEDUP_KEY
        )
        assert call["source_tool"] == "patch_monitor"
        assert call["title"] == onboarding_orchestrator._SCAN_REMINDER_TITLE

    def test_fail_soft_bei_service_schreibfehler(self) -> None:
        # Wirft der Service, darf create_scan_reminder_task NICHT propagieren —
        # der Onboarding-Flow soll nie an einem Reminder scheitern.
        svc = _FakeTaskService(raise_on_create=True)
        assert create_scan_reminder_task(task_service=svc) is False  # type: ignore[arg-type]

    def test_fail_soft_wenn_kein_service_baubar(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Lazy-Bau scheitert (z. B. mainpage-DB gesperrt) → None → False,
        # kein Crash.
        monkeypatch.setattr(
            onboarding_orchestrator,
            "_build_default_task_service",
            lambda: None,
        )
        assert create_scan_reminder_task() is False
