"""test_patch_quick_check — On-Demand-Quick-Check des Patch-Monitors.

Deckt den leichten "Schnell nach Updates suchen"-Pfad ab:
    * Widget: Button feuert ``request_quick_check`` (nur mit Inventar),
      Guards (kein Inventar / laufender Scan), Button-Lifecycle,
      ``reload_after_refresh`` / ``quick_check_failed``.
    * MainWindow-Routing: ``_on_patch_quick_check_requested`` ruft den
      leichten ``run_daily_refresh`` (NICHT ``full_scan``) und respektiert
      den ``is_busy``-Guard; ``_on_daily_refresh_finished`` macht den
      Hintergrund-Check sichtbar (Reload + Toast nur bei Updates).
    * InfoToast: konstruierbar, leere Nachricht crasht nicht.

Die Widget-Tests instanziieren echte Qt-Widgets → ``@pytest.mark.gui``.
Die Routing-Tests umgehen die schwere MainWindow-Konstruktion via
``__new__`` und testen nur die Methodenlogik mit Fakes.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.patch_result import PatchScanResult


def _result(
    name: str = "App",
    recommendation: str = "update",
    winget_id: str | None = "Vendor.App",
    available_version: str | None = "2.0",
    installed_version: str = "1.0",
) -> PatchScanResult:
    return PatchScanResult(
        name=name,
        normalized_name=name.lower(),
        vendor=None,
        winget_id=winget_id,
        source="winget",
        installed_version=installed_version,
        available_version=available_version,
        channel="latest",
        policy_source="policy",
        cve_ids=(),
        cvss_max=None,
        exploit_available=False,
        eol=False,
        confidence_score=0.9,
        recommendation=recommendation,
    )


class _FakeService:
    """Minimaler Service-Stub fuer reload_after_refresh ohne echte DB."""

    def __init__(self, results: list[PatchScanResult]) -> None:
        self._results = results

    def load_from_db(self) -> list[PatchScanResult]:
        return list(self._results)

    def get_last_full_scan_at(self):  # noqa: ANN201 — Stub
        return None

    def get_last_daily_refresh_at(self):  # noqa: ANN201 — Stub
        return None


# ===========================================================================
# Widget — Button + Signal + Guards
# ===========================================================================


@pytest.mark.gui
class TestQuickCheckButton:
    def _widget(self):  # noqa: ANN202
        from tools.patch_monitor.gui.patch_console_widget import (
            PatchConsoleWidget,
        )

        return PatchConsoleWidget()

    def test_button_existiert_und_aktiv(self, qapp) -> None:
        w = self._widget()
        assert w._quick_check_btn is not None
        assert w._quick_check_btn.isEnabled()

    def test_klick_mit_inventar_feuert_signal(self, qapp) -> None:
        w = self._widget()
        w._results = [_result()]
        emitted: list[bool] = []
        w.request_quick_check.connect(lambda: emitted.append(True))

        w._on_quick_check_clicked()

        assert emitted == [True]
        # Button waehrend des Checks gesperrt (Doppelklick-Schutz).
        assert not w._quick_check_btn.isEnabled()
        assert "Suche nach neuen Updates" in w._status_label.text()

    def test_klick_ohne_inventar_feuert_nicht(self, qapp) -> None:
        w = self._widget()
        w._results = []
        emitted: list[bool] = []
        w.request_quick_check.connect(lambda: emitted.append(True))

        w._on_quick_check_clicked()

        assert emitted == []
        assert w._quick_check_btn.isEnabled()
        assert "Inventar" in w._status_label.text()

    def test_klick_waehrend_scan_feuert_nicht(self, qapp) -> None:
        w = self._widget()
        w._results = [_result()]
        w._scan_thread = object()  # laufenden Scan simulieren
        emitted: list[bool] = []
        w.request_quick_check.connect(lambda: emitted.append(True))

        w._on_quick_check_clicked()

        assert emitted == []
        assert "bereits ein Scan" in w._status_label.text()

    def test_button_waehrend_scan_gesperrt(self, qapp) -> None:
        w = self._widget()
        w.on_scan_started()
        assert not w._quick_check_btn.isEnabled()
        # Scan-Fehler gibt den Button wieder frei (kein DB-Persist noetig).
        w.on_scan_failed("NVD offline")
        assert w._quick_check_btn.isEnabled()

    def test_reload_after_refresh_reaktiviert_und_laedt(self, qapp) -> None:
        w = self._widget()
        w._quick_check_btn.setEnabled(False)
        w._inventory_service = _FakeService([_result(name="Firefox")])

        w.reload_after_refresh()

        assert w._quick_check_btn.isEnabled()
        assert w._table.rowCount() == 1

    def test_quick_check_failed_reaktiviert_und_meldet(self, qapp) -> None:
        w = self._widget()
        w._quick_check_btn.setEnabled(False)

        w.quick_check_failed("Es laeuft bereits eine Pruefung.")

        assert w._quick_check_btn.isEnabled()
        assert "bereits eine Pruefung" in w._status_label.text()


# ===========================================================================
# MainWindow-Routing — leichter Pfad statt Vollscan, is_busy-Guard
# ===========================================================================


class _FakeWorker:
    def __init__(self, busy: bool = False) -> None:
        self._busy = busy
        self.daily_calls = 0
        self.full_calls = 0

    def is_busy(self) -> bool:
        return self._busy

    def run_daily_refresh(self) -> None:
        self.daily_calls += 1

    def run_full_scan(self, scan_type: str = "manual") -> None:
        self.full_calls += 1


def _bare_main_window():  # noqa: ANN202
    """MainWindow-Instanz ohne __init__ (umgeht die Qt-Window-Konstruktion)."""
    from core.main_window import MainWindow

    return MainWindow.__new__(MainWindow)


class TestMainWindowQuickCheckRouting:
    def test_loest_daily_refresh_aus_nicht_vollscan(self) -> None:
        mw = _bare_main_window()
        worker = _FakeWorker(busy=False)
        mw._inv_worker = worker
        calls: list[tuple] = []
        triggered: list[object] = []
        mw._call_patch_console = lambda *a: calls.append(a) or True
        # _trigger_daily_refresh marshallt real via QMetaObject in den
        # Worker-Thread (nicht GUI-Thread) — hier stubben wir nur den
        # Routing-Entscheid.
        mw._trigger_daily_refresh = lambda w: triggered.append(w)

        mw._on_patch_quick_check_requested()

        assert triggered == [worker]  # leichter Pfad angestossen
        assert worker.full_calls == 0  # NIE der Vollscan
        assert calls == []  # kein Fehler-/Busy-Callback

    def test_busy_worker_wird_freundlich_abgewiesen(self) -> None:
        mw = _bare_main_window()
        worker = _FakeWorker(busy=True)
        mw._inv_worker = worker
        calls: list[tuple] = []
        triggered: list[object] = []
        mw._call_patch_console = lambda *a: calls.append(a) or True
        mw._trigger_daily_refresh = lambda w: triggered.append(w)

        mw._on_patch_quick_check_requested()

        assert triggered == []  # kein Doppellauf
        assert len(calls) == 1
        assert calls[0][0] == "quick_check_failed"

    def test_ohne_worker_meldet_inaktiv(self) -> None:
        mw = _bare_main_window()
        mw._inv_worker = None
        calls: list[tuple] = []
        triggered: list[object] = []
        mw._call_patch_console = lambda *a: calls.append(a) or True
        mw._trigger_daily_refresh = lambda w: triggered.append(w)

        mw._on_patch_quick_check_requested()

        assert triggered == []
        assert len(calls) == 1
        assert calls[0][0] == "quick_check_failed"

    def test_finished_mit_updates_zeigt_toast_und_reloadt(self) -> None:
        mw = _bare_main_window()
        calls: list[tuple] = []
        toasts: list[int] = []
        mw._call_patch_console = lambda *a: calls.append(a) or True
        mw._show_patch_update_toast = lambda n: toasts.append(n)

        mw._on_daily_refresh_finished(
            SimpleNamespace(items_total=5, items_with_updates=3, cves_refreshed=0)
        )

        assert ("reload_after_refresh",) in calls
        assert toasts == [3]

    def test_finished_ohne_updates_kein_toast(self) -> None:
        mw = _bare_main_window()
        calls: list[tuple] = []
        toasts: list[int] = []
        mw._call_patch_console = lambda *a: calls.append(a) or True
        mw._show_patch_update_toast = lambda n: toasts.append(n)

        mw._on_daily_refresh_finished(
            SimpleNamespace(items_total=5, items_with_updates=0, cves_refreshed=2)
        )

        assert ("reload_after_refresh",) in calls
        assert toasts == []

    def test_failed_meldet_an_widget(self) -> None:
        mw = _bare_main_window()
        calls: list[tuple] = []
        mw._call_patch_console = lambda *a: calls.append(a) or True

        mw._on_daily_refresh_failed("Bumms")

        assert len(calls) == 1
        assert calls[0][0] == "quick_check_failed"


# ===========================================================================
# InfoToast — Smoke
# ===========================================================================


@pytest.mark.gui
class TestInfoToast:
    def test_konstruktion_ohne_crash(self, qapp) -> None:
        from core.widgets.info_toast import InfoToast

        toast = InfoToast("Patch-Monitor: 2 Updates verfuegbar.")
        assert toast is not None

    def test_leere_nachricht_zeigt_nichts(self, qapp) -> None:
        from core.widgets.info_toast import InfoToast

        toast = InfoToast("   ")
        # show_toast raeumt sich bei leerer Nachricht selbst auf (kein Crash).
        toast.show_toast()
        assert not toast.isVisible()
