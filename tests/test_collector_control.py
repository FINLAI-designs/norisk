"""Tests für die Application-Fassade collector_control F-C-5).

Plattformunabhängig — die data-Schicht (COM/Marker-IO) wird gemockt.
"""

from __future__ import annotations

import tools.network_monitor.application.collector_control as cc

_MOD = "tools.network_monitor.application.collector_control"


class TestActionPath:
    def test_liefert_default_action_exe(self, monkeypatch) -> None:
        monkeypatch.setattr(
            f"{_MOD}.default_collector_action",
            lambda: ("C:/x/norisk-collector.exe", "", "C:/x"),
        )
        assert cc.get_collector_action_path() == "C:/x/norisk-collector.exe"


class TestNeedsMigration:
    def test_delegiert_an_data(self, monkeypatch) -> None:
        monkeypatch.setattr(f"{_MOD}.collector_task_needs_migration", lambda: True)
        assert cc.collector_needs_migration() is True


class TestTakeInstallReject:
    def test_kein_marker_gibt_none(self, monkeypatch) -> None:
        monkeypatch.setattr(f"{_MOD}.read_install_marker", lambda: None)
        # clear darf gar nicht erst aufgerufen werden
        monkeypatch.setattr(
            f"{_MOD}.clear_install_marker",
            lambda: (_ for _ in ()).throw(AssertionError("clear ohne Marker")),
        )
        assert cc.take_install_reject() is None

    def test_reject_marker_gibt_reason_und_verbraucht(self, monkeypatch) -> None:
        cleared = {"v": False}
        monkeypatch.setattr(
            f"{_MOD}.read_install_marker",
            lambda: {"result": cc.INSTALL_RESULT_REJECTED, "reason": "X"},
        )
        monkeypatch.setattr(
            f"{_MOD}.clear_install_marker", lambda: cleared.__setitem__("v", True)
        )
        assert cc.take_install_reject() == "X"
        assert cleared["v"] is True  # Marker einmalig -> verbraucht

    def test_reject_ohne_reason_hat_fallback(self, monkeypatch) -> None:
        monkeypatch.setattr(
            f"{_MOD}.read_install_marker",
            lambda: {"result": cc.INSTALL_RESULT_REJECTED},
        )
        monkeypatch.setattr(f"{_MOD}.clear_install_marker", lambda: None)
        reason = cc.take_install_reject()
        assert reason and "beschreibbar" in reason.lower()

    def test_nicht_string_reason_gibt_str_fallback(self, monkeypatch) -> None:
        # Korrupter/manipulierter Marker mit truthy Nicht-String (Liste/Zahl) ->
        # str-Fallback, damit kein Nicht-String an QLabel gerät (TypeError im Slot).
        monkeypatch.setattr(
            f"{_MOD}.read_install_marker",
            lambda: {"result": cc.INSTALL_RESULT_REJECTED, "reason": [1, 2, 3]},
        )
        monkeypatch.setattr(f"{_MOD}.clear_install_marker", lambda: None)
        reason = cc.take_install_reject()
        assert isinstance(reason, str)
        assert "beschreibbar" in reason.lower()

    def test_anderes_ergebnis_gibt_none_aber_verbraucht(self, monkeypatch) -> None:
        cleared = {"v": False}
        monkeypatch.setattr(
            f"{_MOD}.read_install_marker", lambda: {"result": "irgendwas"}
        )
        monkeypatch.setattr(
            f"{_MOD}.clear_install_marker", lambda: cleared.__setitem__("v", True)
        )
        assert cc.take_install_reject() is None
        assert cleared["v"] is True
