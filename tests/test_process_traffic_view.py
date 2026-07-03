"""Tests fuer die Per-Prozess-Live-View Stop-Step C).

format_bytes ist pure (kein Qt); die View-Tests nutzen qtbot + ein Fake-Repo
(kein ETW/DB).
"""

from __future__ import annotations

from tools.network_monitor.domain.models import ProcessTrafficAggregate
from tools.network_monitor.gui.labels import format_bytes
from tools.network_monitor.gui.process_traffic_view import ProcessTrafficView


class _FakeRepo:
    def __init__(self, aggregates: list[ProcessTrafficAggregate]) -> None:
        self._aggregates = aggregates

    def aggregate_last_24h(self) -> list[ProcessTrafficAggregate]:
        return self._aggregates


def _agg(
    pid: int = 1, name: str = "x.exe", sent: int = 0, recv: int = 0
) -> ProcessTrafficAggregate:
    return ProcessTrafficAggregate(
        pid=pid, process_name=name, total_bytes_sent=sent, total_bytes_recv=recv
    )


class TestFormatBytes:
    def test_bytes(self) -> None:
        assert format_bytes(0) == "0 B"
        assert format_bytes(512) == "512 B"

    def test_kb(self) -> None:
        assert format_bytes(1500) == "1,50 KB"

    def test_mb(self) -> None:
        assert format_bytes(12_000_000) == "12,00 MB"

    def test_gb_komma(self) -> None:
        assert format_bytes(10_500_000_000) == "10,50 GB"


class TestProcessTrafficView:
    def test_pro_fuellt_tabelle_groesste_zuerst(self, qtbot) -> None:
        # msedge zuerst geliefert, ist aber kleiner → muss nach claude kommen.
        repo = _FakeRepo(
            [
                _agg(pid=20, name="msedge.exe", sent=50_000, recv=80_000),
                _agg(pid=10, name="claude.exe", sent=12_000_000, recv=100_000),
            ]
        )
        view = ProcessTrafficView(repository=repo)
        qtbot.addWidget(view)
        # refresh laedt jetzt asynchron-Residual) — auf Worker warten.
        qtbot.waitUntil(lambda: view._worker is None, timeout=5000)
        assert view._table is not None
        assert view._table.rowCount() == 2
        # Default-Sortierung: groesster Gesamt-Verbrauch zuerst.
        assert view._table.item(0, 0).text() == "claude.exe"
        assert view._table.item(0, 2).text() == format_bytes(12_000_000)

    def test_numerische_sortierung_nicht_lexikalisch(self, qtbot) -> None:
        # 27 MB > 900 KB numerisch, aber "27,00 MB" < "900,00 KB" lexikalisch.
        repo = _FakeRepo(
            [
                _agg(pid=1, name="klein.exe", sent=900_000, recv=0),
                _agg(pid=2, name="gross.exe", sent=27_000_000, recv=0),
            ]
        )
        view = ProcessTrafficView(repository=repo)
        qtbot.addWidget(view)
        qtbot.waitUntil(lambda: view._worker is None, timeout=5000)
        # Numerisch absteigend → gross.exe (27 MB) vor klein.exe (900 KB).
        assert view._table.item(0, 0).text() == "gross.exe"
        assert view._table.item(1, 0).text() == "klein.exe"

    def test_pro_leer_zeigt_hinweis(self, qtbot) -> None:
        view = ProcessTrafficView(repository=_FakeRepo([]))
        qtbot.addWidget(view)
        qtbot.waitUntil(lambda: view._worker is None, timeout=5000)
        assert view._table is not None
        assert view._table.rowCount() == 0
        assert "Noch keine Daten" in view._status_label.text()
