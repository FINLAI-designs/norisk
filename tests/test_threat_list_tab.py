"""Tests für den Bedrohungslisten-Tab F-D-GUI).

Prüft die GUI-Logik isoliert: Whitelist anzeigen/hinzufügen/entfernen (mit
Inline-Validierung + Bestätigungsdialog) und den manuellen Refresh (One-Shot-
Worker → ``entries_refreshed``). WhitelistService arbeitet auf ``tmp_path``, die
Refresh-Factory ist gefälscht — keine DB, kein Netz (Regel 9).
"""

from __future__ import annotations

import ipaddress
import threading
from pathlib import Path

import pytest

from tools.network_monitor.application.whitelist_service import WhitelistService
from tools.network_monitor.domain.models import FeedRefreshSnapshot
from tools.network_monitor.gui.threat_list_tab import ThreatListTab


class _BlockingService:
    """ThreatFeedService-Ersatz, dessen refresh_snapshot bis zur Freigabe blockiert.

    ``entered`` wird beim Eintritt gesetzt, damit der Test sicher den Zustand „Worker
    steckt im (nicht abbrechbaren) Download" treffen kann (statt nur ``isRunning``,
    das schon direkt nach ``start`` True ist).
    """

    def __init__(self, gate: threading.Event, entered: threading.Event) -> None:
        self._gate = gate
        self._entered = entered

    def refresh_snapshot(self, *, force: bool = False) -> FeedRefreshSnapshot:
        self._entered.set()
        self._gate.wait(5)  # Safety-Timeout, damit der Test nie hängt
        return FeedRefreshSnapshot()


class _FakeService:
    """ThreatFeedService-Ersatz für den Refresh-Worker (keine DB/Netz)."""

    def refresh_snapshot(self, *, force: bool = False) -> FeedRefreshSnapshot:
        return FeedRefreshSnapshot(
            entries=[(ipaddress.ip_network("9.9.9.9"), "feed")],
            whitelist=[ipaddress.ip_network("10.0.0.0/8")],
            updated_count=1,
            error_count=0,
        )


class _AcceptDialog:
    """Stub für FinlaiConfirmDialog, der immer „Accepted" zurückgibt."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    def exec(self):
        from PySide6.QtWidgets import QDialog

        return QDialog.DialogCode.Accepted


class _RejectDialog(_AcceptDialog):
    def exec(self):
        from PySide6.QtWidgets import QDialog

        return QDialog.DialogCode.Rejected


@pytest.fixture
def tab(qtbot, tmp_path: Path):
    svc = WhitelistService(whitelist_path=tmp_path / "wl.txt")
    w = ThreatListTab(
        whitelist_service=svc,
        refresh_service_factory=lambda: _FakeService(),
    )
    qtbot.addWidget(w)
    return w


class TestWhitelistEditor:
    def test_frisch_zeigt_empty_state(self, tab) -> None:
        assert tab._empty_state.isHidden() is False
        assert tab._list.isHidden() is True
        assert tab._remove_btn.isEnabled() is False

    def test_add_fuegt_hinzu_und_emittiert(self, tab, qtbot) -> None:
        received: list = []
        tab.whitelist_changed.connect(received.append)
        tab._entry_input.setText("203.0.113.10")
        tab._add_btn.click()

        assert tab._list.count() == 1
        assert tab._list.item(0).text() == "203.0.113.10/32"
        assert tab._empty_state.isHidden() is True
        assert tab._list.isHidden() is False
        assert tab._entry_input.text() == ""  # Feld geleert
        assert tab._input_error.isHidden() is True
        assert len(received) == 1
        assert [str(n) for n in received[0]] == ["203.0.113.10/32"]
        # persistiert
        assert {str(n) for n in tab._whitelist_service.load()} == {"203.0.113.10/32"}

    def test_add_muell_zeigt_inline_fehler(self, tab) -> None:
        received: list = []
        tab.whitelist_changed.connect(received.append)
        tab._entry_input.setText("kein-netz")
        tab._add_btn.click()
        assert tab._input_error.isHidden() is False
        assert tab._list.count() == 0
        assert received == []

    def test_add_duplikat_zeigt_inline_fehler(self, tab) -> None:
        tab._entry_input.setText("10.0.0.0/8")
        tab._add_btn.click()
        tab._entry_input.setText("10.0.0.0/8")
        tab._add_btn.click()
        assert tab._input_error.isHidden() is False
        assert tab._list.count() == 1

    def test_add_leer_macht_nichts(self, tab) -> None:
        tab._entry_input.setText("   ")
        tab._add_btn.click()
        assert tab._list.count() == 0
        assert tab._input_error.isHidden() is True

    def test_remove_mit_bestaetigung(self, tab, qtbot, monkeypatch) -> None:
        tab._entry_input.setText("9.9.9.9")
        tab._add_btn.click()
        assert tab._list.count() == 1

        monkeypatch.setattr("core.dialogs.FinlaiConfirmDialog", _AcceptDialog)
        received: list = []
        tab.whitelist_changed.connect(received.append)
        tab._list.setCurrentRow(0)
        tab._remove_btn.click()

        assert tab._list.count() == 0
        assert tab._empty_state.isHidden() is False
        assert received and received[-1] == []
        assert tab._whitelist_service.load() == []

    def test_remove_abgebrochen_behaelt_eintrag(self, tab, monkeypatch) -> None:
        tab._entry_input.setText("9.9.9.9")
        tab._add_btn.click()
        monkeypatch.setattr("core.dialogs.FinlaiConfirmDialog", _RejectDialog)
        received: list = []
        tab.whitelist_changed.connect(received.append)
        tab._list.setCurrentRow(0)
        tab._remove_btn.click()
        assert tab._list.count() == 1
        assert received == []

    def test_remove_button_folgt_auswahl(self, tab) -> None:
        tab._entry_input.setText("9.9.9.9")
        tab._add_btn.click()
        tab._list.setCurrentRow(-1)
        tab._update_remove_state()
        assert tab._remove_btn.isEnabled() is False
        tab._list.setCurrentRow(0)
        assert tab._remove_btn.isEnabled() is True


class TestManualRefresh:
    def test_refresh_emittiert_entries(self, tab, qtbot) -> None:
        # Whitelist-Eintrag, der NICHT vom Worker-Fake (10.0.0.0/8) stammt → beweist,
        # dass der Refresh die frische, autoritative Whitelist aus dem Service
        # emittiert (P2-Fix gegen Lost-Update), nicht den Worker-Snapshot.
        tab._entry_input.setText("203.0.113.5")
        tab._add_btn.click()
        with qtbot.waitSignal(tab.entries_refreshed, timeout=3000) as blocker:
            tab._refresh_btn.click()
        entries, whitelist = blocker.args
        assert [str(n) for n, _ in entries] == ["9.9.9.9/32"]
        assert [str(n) for n in whitelist] == ["203.0.113.5/32"]
        # Button wieder aktiv, Status gesetzt
        qtbot.waitUntil(lambda: tab._refresh_btn.isEnabled(), timeout=2000)
        assert "aktiv" in tab._refresh_status.text()
        tab.shutdown()

    def test_shutdown_haelt_laufenden_worker(self, qtbot, tmp_path: Path) -> None:
        # P1-Regression: shutdown während eines noch laufenden (blockierten)
        # Refresh darf die QThread-Referenz NICHT verwerfen — sonst Teardown-Crash.
        gate = threading.Event()
        entered = threading.Event()
        svc = WhitelistService(whitelist_path=tmp_path / "wl.txt")
        tab = ThreatListTab(
            whitelist_service=svc,
            refresh_service_factory=lambda: _BlockingService(gate, entered),
        )
        qtbot.addWidget(tab)
        try:
            tab._refresh_btn.click()
            # Erst wenn der Worker WIRKLICH im (blockierten) update steckt, ist der
            # Teardown-Vektor reproduziert (isRunning allein ist schon nach start True).
            qtbot.waitUntil(entered.is_set, timeout=2000)
            tab.shutdown()  # wait(2000) läuft ins Timeout (Worker blockiert)
            assert tab._refresh_worker is not None  # Referenz GEHALTEN, nicht None
        finally:
            gate.set()  # Worker freigeben → finished → _clear_refresh_worker
        qtbot.waitUntil(lambda: tab._refresh_worker is None, timeout=4000)
