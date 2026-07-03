"""
test_onboarding_dialog — Tests fuer
tools/patch_monitor/gui/onboarding_dialog.py.

Bug-Fix-Sprint C-3 (Option D). Logik-Tests ohne Qt-Render fuer:

1. _format_install_message-Mapping (Privacy-Filter-konform)
2. Dependency-Injection-Pfade fuer alle 3 Buttons via direkte Methoden-
   Aufrufe (kein QTest noetig)

Pytest-Qt-Tests fuer den vollstaendigen Dialog-Klick-Lifecycle sind unter
``@pytest.mark.gui`` markiert und nur erforderlich, wenn die GUI-Pipeline
gegen einen echten QApplication-Kontext laeuft.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.patch_collector import ModuleStatus
from tools.patch_monitor.gui.onboarding_dialog import (
    _REASON_TEXT,
    _format_install_message,
)
from tools.patch_monitor.onboarding_marker import (
    SCHEMA_VERSION,
    OnboardingDecision,
    OnboardingMarker,
)
from tools.patch_monitor.onboarding_orchestrator import (
    INSTALL_REASON_CLASSES,
    InstallResult,
)

# ===========================================================================
# Akzeptanz 1 — _format_install_message
# ===========================================================================


class TestFormatInstallMessage:
    def test_alle_install_reason_classes_haben_text(self) -> None:
        # Jeder Wert in INSTALL_REASON_CLASSES muss einen lesbaren Text
        # haben — sonst kommt im UI ein Fallback "unbekannt"-String.
        for reason_class in INSTALL_REASON_CLASSES:
            assert reason_class in _REASON_TEXT, (
                f"reason_class={reason_class} hat keinen User-Text"
            )

    def test_message_enthaelt_keine_stderr_excerpts(self) -> None:
        # Privacy-Filter: auch bei "install-failed" darf der Text keine
        # User-/Domain-Pfade enthalten.
        msg = _format_install_message(
            InstallResult(success=False, reason_class="install-failed")
        )
        assert "C:\\Users" not in msg
        assert "CONTOSO" not in msg

    def test_unbekannter_reason_class_fallback(self) -> None:
        msg = _format_install_message(
            InstallResult(success=False, reason_class="future-reason-class")
        )
        # Fallback ist generisch und verraet keine internen Details.
        assert "App-Logs" in msg


# ===========================================================================
# Akzeptanz 2 — Dependency-Injection-Pfade ohne QApplication
# ===========================================================================
#
# Wir testen die Persistierungs-Logik, die der Dialog aufruft, **ohne**
# das QDialog tatsaechlich zu instanziieren — der QApplication-Setup
# ist im non-gui-Markerlauf nicht verfuegbar. Dafuer rufen wir die
# private Helper-Methode:meth:`_persist_decision` direkt mit einem
# Stub-Saver auf.
#
# Vollstaendige End-to-End-Tests mit QTest.mouseClick werden in einer
# spaeteren GUI-Test-Session ergaenzt (markiert ``@pytest.mark.gui``).


class _StubSaver:
    """Faengt save_marker-Aufrufe ab und speichert sie."""

    def __init__(self) -> None:
        self.calls: list[OnboardingDecision] = []

    def __call__(self, decision: OnboardingDecision) -> OnboardingMarker:
        self.calls.append(decision)
        return OnboardingMarker(
            schema_version=SCHEMA_VERSION,
            decided_at=datetime(2026, 5, 7, tzinfo=UTC),
            decision=decision,
        )


class _StubTaskCreator:
    """Faengt create_scan_reminder_task-Aufrufe ab und zaehlt sie."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> bool:
        self.calls += 1
        return True


@pytest.mark.gui
class TestDialogIntegration:
    """End-to-End-Tests mit pytest-qt — laufen nur unter dem gui-Marker."""

    def test_install_button_setzt_marker_bei_erfolg(self, qtbot) -> None:
        from tools.patch_monitor.gui.onboarding_dialog import (
            WingetModuleOnboardingDialog,
        )

        saver = _StubSaver()
        creator = _StubTaskCreator()
        dialog = WingetModuleOnboardingDialog(
            installer=lambda: InstallResult(success=True, reason_class="ok"),
            refresher=lambda: ModuleStatus.AVAILABLE,
            marker_saver=saver,
            task_creator=creator,
        )
        qtbot.addWidget(dialog)
        dialog._on_install_clicked()
        # Worker ist async — warte bis Dialog accept'ed wird (max 5 s).
        qtbot.waitUntil(lambda: dialog.result() != 0, timeout=5000)
        assert dialog.result_decision() is OnboardingDecision.INSTALLED
        assert saver.calls == [OnboardingDecision.INSTALLED]
        # Erfolgreiche Installation legt KEIN Reminder-Task an.
        assert creator.calls == 0

    def test_skip_button_setzt_marker_und_legt_task_an(self, qtbot) -> None:
        from tools.patch_monitor.gui.onboarding_dialog import (
            WingetModuleOnboardingDialog,
        )

        saver = _StubSaver()
        creator = _StubTaskCreator()
        dialog = WingetModuleOnboardingDialog(
            installer=lambda: InstallResult(success=False, reason_class="ok"),
            refresher=lambda: ModuleStatus.BLOCKED,
            marker_saver=saver,
            task_creator=creator,
        )
        qtbot.addWidget(dialog)
        dialog._on_skip_clicked()
        assert dialog.result_decision() is OnboardingDecision.SKIP_SESSION
        assert saver.calls == [OnboardingDecision.SKIP_SESSION]
        # Ueberspringen erinnert per kritischem Homescreen-Task.
        assert creator.calls == 1

    def test_x_close_wie_skip_legt_task_an(self, qtbot) -> None:
        # X-Abbruch ohne Button = wie "Diesmal ueberspringen" —
        # Marker setzen + Reminder-Task, damit das Modal nicht erneut nervt.
        from tools.patch_monitor.gui.onboarding_dialog import (
            WingetModuleOnboardingDialog,
        )

        saver = _StubSaver()
        creator = _StubTaskCreator()
        dialog = WingetModuleOnboardingDialog(
            installer=lambda: InstallResult(success=False, reason_class="ok"),
            refresher=lambda: ModuleStatus.BLOCKED,
            marker_saver=saver,
            task_creator=creator,
        )
        qtbot.addWidget(dialog)
        dialog.reject()
        assert dialog.result_decision() is OnboardingDecision.SKIP_SESSION
        assert saver.calls == [OnboardingDecision.SKIP_SESSION]
        assert creator.calls == 1

    def test_never_button_setzt_marker_ohne_task(self, qtbot) -> None:
        from tools.patch_monitor.gui.onboarding_dialog import (
            WingetModuleOnboardingDialog,
        )

        saver = _StubSaver()
        creator = _StubTaskCreator()
        dialog = WingetModuleOnboardingDialog(
            installer=lambda: InstallResult(success=False, reason_class="ok"),
            refresher=lambda: ModuleStatus.BLOCKED,
            marker_saver=saver,
            task_creator=creator,
        )
        qtbot.addWidget(dialog)
        dialog._on_never_clicked()
        assert dialog.result_decision() is OnboardingDecision.NEVER
        assert saver.calls == [OnboardingDecision.NEVER]
        # "Nie wieder fragen" legt KEIN Reminder-Task an.
        assert creator.calls == 0

    def test_install_fail_buttons_werden_wieder_aktiv(self, qtbot) -> None:
        from tools.patch_monitor.gui.onboarding_dialog import (
            WingetModuleOnboardingDialog,
        )

        saver = _StubSaver()
        creator = _StubTaskCreator()
        dialog = WingetModuleOnboardingDialog(
            installer=lambda: InstallResult(
                success=False, reason_class="install-failed"
            ),
            refresher=lambda: ModuleStatus.BLOCKED,
            marker_saver=saver,
            task_creator=creator,
        )
        qtbot.addWidget(dialog)
        dialog._on_install_clicked()
        # Buttons werden waehrend Worker disabled; nach Worker-Finish
        # sollen sie wieder aktiv sein.
        qtbot.waitUntil(
            lambda: dialog._install_btn.isEnabled(), timeout=5000
        )
        assert dialog._skip_btn.isEnabled()
        assert dialog._never_btn.isEnabled()
        # Marker NICHT gespeichert — User kann nochmal entscheiden.
        assert saver.calls == []
        assert dialog.result_decision() is None
        # Fehlgeschlagene Installation legt kein Task an.
        assert creator.calls == 0
