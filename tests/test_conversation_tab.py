"""Tests für den Konversationen-Tab Phase 5).

Prüft die GUI-Logik isoliert mit injiziertem Fake-Service (kein DB/Netz):
Befüllung, Schnellfilter-Chips, Volltext-Suche, Experten-Filter inkl. Inline-
Parse-Fehler (Tabelle bleibt bedienbar) und Empty-State. Sichtbarkeit wird über
``isHidden`` geprüft (``isVisible`` ist ohne gezeigtes Top-Level immer False).
"""

from __future__ import annotations

import pytest

from tools.network_monitor.domain.models import Conversation
from tools.network_monitor.gui.conversation_tab import ConversationTab


class _FakeService:
    def __init__(self, conversations: list[Conversation]) -> None:
        self._conversations = conversations

    def aggregate(self, hours: int = 24) -> list[Conversation]:
        return self._conversations


class _RaisingService:
    def aggregate(self, hours: int = 24) -> list[Conversation]:
        raise RuntimeError("DB nicht lesbar")


def _boom_factory():
    raise RuntimeError("kein KeyManager")


def _conv(**kwargs) -> Conversation:
    base = {
        "process_name": "chrome.exe",
        "remote_ip": "8.8.8.8",
        "connection_count": 10,
        "ports": (443, 80),
        "statuses": ("ESTABLISHED",),
        "suspicious": False,
    }
    base.update(kwargs)
    return Conversation(**base)


_SAMPLE = [
    _conv(),
    _conv(process_name="evil.exe", remote_ip="9.9.9.9", suspicious=True, ports=(4444,)),
    _conv(process_name="svc.exe", remote_ip="10.0.0.5", ports=(22,), statuses=("LISTEN",)),
]


@pytest.fixture
def tab(qtbot):
    w = ConversationTab(service=_FakeService(list(_SAMPLE)))
    qtbot.addWidget(w)
    w.stop()  # 30s-Timer im Test stilllegen
    return w


class TestPopulate:
    def test_zeigt_alle_zeilen(self, tab) -> None:
        assert tab._table.rowCount() == 3
        assert tab._table.isHidden() is False
        assert tab._empty_state.isHidden() is True


class TestByteColumns:
    def test_byte_spalten_formatiert_und_numerisch_sortierbar(self, qtbot) -> None:
        from PySide6.QtCore import Qt

        conv = _conv(process_name="dl.exe", bytes_sent=1_500_000, bytes_recv=2000)
        w = ConversationTab(service=_FakeService([conv]))
        qtbot.addWidget(w)
        w.stop()
        gesendet = w._table.item(0, 3)  # Spalte 3 = Gesendet
        assert "MB" in gesendet.text()  # laienlesbar formatiert (format_bytes)
        assert gesendet.data(Qt.ItemDataRole.UserRole) == 1_500_000  # numerischer Sort-Key


class TestChips:
    def test_nur_verdaechtige(self, tab) -> None:
        tab._chip_suspicious.setChecked(True)
        assert tab._table.rowCount() == 1
        assert tab._table.item(0, 0).text() == "evil.exe"

    def test_nur_extern(self, tab) -> None:
        tab._chip_external.setChecked(True)
        # 10.0.0.5 (privat) fällt raus → 2 externe bleiben
        assert tab._table.rowCount() == 2

    def test_suche(self, tab) -> None:
        tab._search.setText("svc")
        assert tab._table.rowCount() == 1
        assert tab._table.item(0, 0).text() == "svc.exe"


class TestExpertFilter:
    def test_gueltiger_ausdruck_filtert(self, tab) -> None:
        tab._expert.setText("verdaechtig = ja")
        assert tab._table.rowCount() == 1
        assert tab._table.item(0, 0).text() == "evil.exe"
        assert tab._filter_error.isHidden() is True

    def test_ungueltiger_ausdruck_zeigt_inline_fehler(self, tab) -> None:
        tab._expert.setText("unbekannt = x")
        # Fehler sichtbar, Tabelle bleibt befüllt (Schnellfilter-Ergebnis = alle)
        assert tab._filter_error.isHidden() is False
        assert tab._table.rowCount() == 3

    def test_fehler_verschwindet_nach_korrektur(self, tab) -> None:
        tab._expert.setText("unbekannt = x")
        assert tab._filter_error.isHidden() is False
        tab._expert.setText("prozess ~ chrome")
        assert tab._filter_error.isHidden() is True
        assert tab._table.rowCount() == 1

    def test_chip_und_experten_filter_kombiniert(self, tab) -> None:
        tab._chip_external.setChecked(True)  # chrome + evil
        tab._expert.setText("verdaechtig = ja")  # davon nur evil
        assert tab._table.rowCount() == 1
        assert tab._table.item(0, 0).text() == "evil.exe"


class TestEmptyAndFailSoft:
    def test_leerer_service_zeigt_empty_state(self, qtbot) -> None:
        w = ConversationTab(service=_FakeService([]))
        qtbot.addWidget(w)
        w.stop()
        assert w._table.isHidden() is True
        assert w._empty_state.isHidden() is False

    def test_aggregate_fehler_failt_soft(self, qtbot) -> None:
        # Lesefehler im Service darf nie crashen → leere Tabelle + Empty-State.
        w = ConversationTab(service=_RaisingService())
        qtbot.addWidget(w)
        w.stop()
        assert w._table.rowCount() == 0
        assert w._empty_state.isHidden() is False

    def test_service_factory_failt_soft(self, qtbot, monkeypatch) -> None:
        # Ohne KeyManager scheitert die Factory → Tab baut fail-soft ohne Service.
        import tools.network_monitor.application.monitor_service as ms

        monkeypatch.setattr(
            ms.MonitorService,
            "create_conversation_service",
            staticmethod(_boom_factory),
        )
        w = ConversationTab(service=None)
        qtbot.addWidget(w)
        w.stop()
        assert w._service is None
        assert w._table.rowCount() == 0
        assert w._empty_state.isHidden() is False
