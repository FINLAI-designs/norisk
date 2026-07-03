"""GUI-Tests fuer NetworkCollectorSetupTab Phase C).

Mockt Task-Status, Elevation und Dialoge — kein echter Task-Scheduler-Zugriff,
kein UAC-Prompt, keine modal blockierenden Dialoge.
"""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QDialog

import tools.einstellungen.gui.network_collector_setup_tab as mod
from tools.einstellungen.gui.network_collector_setup_tab import (
    NetworkCollectorSetupTab,
)
from tools.network_monitor.domain.collector_status import CollectorStatus


@pytest.fixture(autouse=True)
def _no_blocking_dialogs(monkeypatch):
    """Dialoge nicht modal blockieren — Default: Bestaetigt."""
    monkeypatch.setattr(
        mod.FinlaiConfirmDialog,
        "exec",
        lambda self: QDialog.DialogCode.Accepted,
        raising=False,
    )
    monkeypatch.setattr(
        mod.FinlaiInfoDialog, "exec", lambda self: 0, raising=False
    )


def _make_tab(
    qtbot,
    monkeypatch,
    *,
    status: CollectorStatus,
    needs_migration: bool = False,
    action_path: str = "C:/Program Files/NoRisk/norisk-collector.exe",
    reject_reason: str | None = None,
) -> NetworkCollectorSetupTab:
    monkeypatch.setattr(mod, "get_collector_status", lambda: status)
    monkeypatch.setattr(mod, "collector_needs_migration", lambda: needs_migration)
    monkeypatch.setattr(mod, "get_collector_action_path", lambda: action_path)
    monkeypatch.setattr(mod, "take_install_reject", lambda: reject_reason)
    tab = NetworkCollectorSetupTab()
    qtbot.addWidget(tab)
    return tab


def test_status_aktiv(qtbot, monkeypatch) -> None:
    tab = _make_tab(qtbot, monkeypatch, status=CollectorStatus.ACTIVE)
    assert "aktiv" in tab._status_text.text().lower()
    assert tab._activate_btn.isEnabled() is False
    assert tab._deactivate_btn.isEnabled() is True


def test_status_inaktiv(qtbot, monkeypatch) -> None:
    tab = _make_tab(qtbot, monkeypatch, status=CollectorStatus.NOT_INSTALLED)
    assert "nicht aktiv" in tab._status_text.text().lower()
    assert tab._activate_btn.isEnabled() is True
    assert tab._deactivate_btn.isEnabled() is False


def test_status_broken_meldet_reparatur(qtbot, monkeypatch) -> None:
    tab = _make_tab(qtbot, monkeypatch, status=CollectorStatus.BROKEN)
    assert "läuft aber nicht" in tab._status_text.text().lower()
    # BROKEN: beides erlaubt — erneut aktivieren (repariert Pfad) oder entfernen.
    assert tab._activate_btn.isEnabled() is True
    assert tab._deactivate_btn.isEnabled() is True
    assert "reparieren" in tab._activate_btn.text().lower()


def test_zeigt_installationspfad(qtbot, monkeypatch) -> None:
    # F-C-5: Action.Path-Bezug — der Tab zeigt, wohin die Aufgabe startet.
    tab = _make_tab(
        qtbot,
        monkeypatch,
        status=CollectorStatus.NOT_INSTALLED,
        action_path="C:/Program Files/NoRisk/norisk-collector.exe",
    )
    assert "norisk-collector.exe" in tab._path_label.text()


def test_status_aktiv_mit_migration_bietet_aktualisieren(qtbot, monkeypatch) -> None:
    # F-C-5: Aufgabe aktiv, zeigt aber auf veralteten Build-Pfad -> Aktualisieren.
    tab = _make_tab(
        qtbot, monkeypatch, status=CollectorStatus.ACTIVE, needs_migration=True
    )
    assert "aktualisieren" in tab._activate_btn.text().lower()
    assert tab._activate_btn.isEnabled() is True
    assert tab._deactivate_btn.isEnabled() is True
    assert "veralteten" in tab._status_text.text().lower()


def test_refresh_after_install_zeigt_security_reject(qtbot, monkeypatch) -> None:
    # F-C-5: der elevated Reject (Gate F-C-3) wird per Marker zurückgemeldet
    # und als Status + Hinweis-Dialog angezeigt.
    shown: dict[str, str] = {}

    class _FakeInfo:
        def __init__(self, *, title, message, parent=None) -> None:
            shown.update(title=title, message=message)

        def exec(self) -> int:
            return 0

    monkeypatch.setattr(mod, "FinlaiInfoDialog", _FakeInfo)
    tab = _make_tab(
        qtbot,
        monkeypatch,
        status=CollectorStatus.NOT_INSTALLED,
        reject_reason="Der Zielpfad ist beschreibbar.",
    )
    tab._refresh_after_install()
    assert "abgelehnt" in tab._status_text.text().lower()
    assert "abgelehnt" in shown["title"].lower()
    assert shown["message"] == "Der Zielpfad ist beschreibbar."


def test_refresh_after_install_ohne_reject_normaler_status(qtbot, monkeypatch) -> None:
    shown = {"v": False}

    class _FakeInfo:
        def __init__(self, **_kw) -> None:
            shown["v"] = True

        def exec(self) -> int:
            return 0

    monkeypatch.setattr(mod, "FinlaiInfoDialog", _FakeInfo)
    tab = _make_tab(
        qtbot, monkeypatch, status=CollectorStatus.NOT_INSTALLED, reject_reason=None
    )
    tab._refresh_after_install()
    assert "nicht aktiv" in tab._status_text.text().lower()
    assert shown["v"] is False  # kein Reject -> kein Dialog


def test_aktivieren_bestaetigt_ruft_relaunch_mit_install_flag(
    qtbot, monkeypatch
) -> None:
    tab = _make_tab(qtbot, monkeypatch, status=CollectorStatus.NOT_INSTALLED)
    captured: dict[str, str] = {}
    monkeypatch.setattr(
        mod, "relaunch_elevated", lambda flag: captured.update(flag=flag) or True
    )
    tab._on_activate_clicked()
    assert captured["flag"] == mod._INSTALL_FLAG


def test_aktivieren_abgebrochen_kein_relaunch(qtbot, monkeypatch) -> None:
    tab = _make_tab(qtbot, monkeypatch, status=CollectorStatus.NOT_INSTALLED)
    monkeypatch.setattr(
        mod.FinlaiConfirmDialog,
        "exec",
        lambda self: QDialog.DialogCode.Rejected,
        raising=False,
    )
    called = {"v": False}
    monkeypatch.setattr(
        mod, "relaunch_elevated", lambda flag: called.update(v=True)
    )
    tab._on_activate_clicked()
    assert called["v"] is False


def test_deaktivieren_bestaetigt_ruft_uninstall(qtbot, monkeypatch) -> None:
    tab = _make_tab(qtbot, monkeypatch, status=CollectorStatus.ACTIVE)
    called = {"v": False}
    monkeypatch.setattr(
        mod, "deactivate_collector", lambda: called.update(v=True) or True
    )
    tab._on_deactivate_clicked()
    assert called["v"] is True


def test_deaktivieren_permissionerror_geht_elevated(qtbot, monkeypatch) -> None:
    # unelevierter DeleteTask einer HIGHEST-Aufgabe -> PermissionError ->
    # ruhiger elevierter Fallback mit dem Uninstall-Flag (kein ERROR-Traceback).
    tab = _make_tab(qtbot, monkeypatch, status=CollectorStatus.ACTIVE)

    def _raise() -> bool:
        raise PermissionError("admin noetig")

    monkeypatch.setattr(mod, "deactivate_collector", _raise)
    captured: dict[str, str] = {}
    monkeypatch.setattr(
        mod, "relaunch_elevated", lambda flag: captured.update(flag=flag) or True
    )
    tab._on_deactivate_clicked()
    assert captured["flag"] == mod._UNINSTALL_FLAG  # noqa: SLF001
