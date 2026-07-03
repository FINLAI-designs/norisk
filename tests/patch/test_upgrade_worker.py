"""
test_upgrade_worker — Tests fuer Stop-Step C UpgradeWorker.

Strategie analog ``test_scan_worker.py``: kein QApplication noetig —
Same-Thread Signal-Connections laufen synchron via DirectConnection.
Wir injizieren einen Mock-BatchUpgradeService und sammeln alle
Signal-Emissionen in einem Recorder.

Deckt:
* batch_started wird mit ``total`` emittiert
* item_started / item_finished werden via Service-Callbacks gebridged
* batch_done erhaelt die Summary aus dem Service
* Cancel: Service bekommt should_cancel-Callback, der das Flag liest
* batch_failed bei unerwarteter Service-Exception (Safety-Net)
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from core.patch_upgrade import (
    UpgradeRequest,
    UpgradeResult,
    UpgradeStatus,
)
from tools.patch_monitor.application.batch_upgrade_service import BatchSummary
from tools.patch_monitor.gui.upgrade_worker import UpgradeWorker

# ===========================================================================
# Helfer
# ===========================================================================


def _req(winget_id: str = "Mozilla.Firefox") -> UpgradeRequest:
    return UpgradeRequest(
        winget_id=winget_id,
        version_from="1.0",
        version_to="2.0",
        display_name=winget_id,
    )


def _result(
    *,
    winget_id: str = "Mozilla.Firefox",
    status: UpgradeStatus = UpgradeStatus.SUCCESS,
) -> UpgradeResult:
    return UpgradeResult(
        winget_id=winget_id,
        status=status,
        exit_code=0,
        duration_ms=10,
        stdout="",
        stderr="",
        error=None,
    )


def _summary(*, total: int = 0, results: list | None = None) -> BatchSummary:
    return BatchSummary(
        total=total,
        succeeded=total,
        failed=0,
        timed_out=0,
        skipped=0,
        results=results or [],
    )


class _SignalRecorder:
    """Sammelt alle UpgradeWorker-Signals in der Reihenfolge der Emits."""

    def __init__(self) -> None:
        self.events: list[tuple[str, Any, ...]] = []

    def batch_started(self, total: int) -> None:
        self.events.append(("batch_started", total))

    def item_started(self, idx: int, total: int, req: object) -> None:
        self.events.append(("item_started", idx, total, req))

    def item_finished(self, idx: int, total: int, req: object, res: object) -> None:
        self.events.append(("item_finished", idx, total, req, res))

    def batch_done(self, summary: object) -> None:
        self.events.append(("batch_done", summary))

    def batch_failed(self, msg: str) -> None:
        self.events.append(("batch_failed", msg))


def _connect(worker: UpgradeWorker, rec: _SignalRecorder) -> None:
    worker.batch_started.connect(rec.batch_started)
    worker.item_started.connect(rec.item_started)
    worker.item_finished.connect(rec.item_finished)
    worker.batch_done.connect(rec.batch_done)
    worker.batch_failed.connect(rec.batch_failed)


# ===========================================================================
# batch_started
# ===========================================================================


class TestBatchStarted:
    def test_emit_mit_total_3(self) -> None:
        service = MagicMock()
        service.upgrade_batch.return_value = _summary(total=3)
        worker = UpgradeWorker(
            requests=[_req("A.A"), _req("B.B"), _req("C.C")],
            service=service,
        )
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run()

        assert ("batch_started", 3) in rec.events
        # batch_started ist das ERSTE Event
        assert rec.events[0] == ("batch_started", 3)

    def test_emit_mit_total_0_bei_leerer_liste(self) -> None:
        service = MagicMock()
        service.upgrade_batch.return_value = _summary(total=0)
        worker = UpgradeWorker(requests=[], service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run()

        assert rec.events[0] == ("batch_started", 0)


# ===========================================================================
# item_started / item_finished — durch Service-Callbacks gebridged
# ===========================================================================


class TestItemSignals:
    def test_item_started_und_finished_werden_gebridged(self) -> None:
        captured = {}

        def fake_upgrade_batch(requests, *, on_start, on_finish, should_cancel):
            # Simuliert was BatchUpgradeService macht: feuert Callbacks
            captured["start_cb"] = on_start
            captured["finish_cb"] = on_finish
            on_start(1, 2, requests[0])
            on_finish(1, 2, requests[0], _result(winget_id="A.A"))
            on_start(2, 2, requests[1])
            on_finish(2, 2, requests[1], _result(winget_id="B.B"))
            return _summary(total=2)

        service = MagicMock()
        service.upgrade_batch.side_effect = fake_upgrade_batch
        worker = UpgradeWorker(requests=[_req("A.A"), _req("B.B")], service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run()

        kinds = [e[0] for e in rec.events]
        assert kinds == [
            "batch_started",
            "item_started",
            "item_finished",
            "item_started",
            "item_finished",
            "batch_done",
        ]
        # item_started 1: (1, 2, request)
        first_start = next(e for e in rec.events if e[0] == "item_started")
        assert first_start[1] == 1
        assert first_start[2] == 2

    def test_item_finished_traegt_result(self) -> None:
        result = _result(winget_id="X.Y", status=UpgradeStatus.FAILED)

        def fake_upgrade_batch(requests, *, on_start, on_finish, should_cancel):
            on_finish(1, 1, requests[0], result)
            return _summary(total=1)

        service = MagicMock()
        service.upgrade_batch.side_effect = fake_upgrade_batch
        worker = UpgradeWorker(requests=[_req("X.Y")], service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run()

        finish_event = next(e for e in rec.events if e[0] == "item_finished")
        # (event_name, idx, total, request, result)
        assert finish_event[4] is result


# ===========================================================================
# batch_done
# ===========================================================================


class TestBatchDone:
    def test_emit_mit_summary(self) -> None:
        summary = _summary(total=2)
        service = MagicMock()
        service.upgrade_batch.return_value = summary
        worker = UpgradeWorker(requests=[_req("A.A"), _req("B.B")], service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run()

        done_event = next(e for e in rec.events if e[0] == "batch_done")
        assert done_event[1] is summary
        # batch_done ist das LETZTE Event
        assert rec.events[-1][0] == "batch_done"


# ===========================================================================
# Cancel
# ===========================================================================


class TestCancel:
    def test_cancel_setzt_flag_und_should_cancel_callback_liest_es(self) -> None:
        captured_cancel = {}

        def fake_upgrade_batch(requests, *, on_start, on_finish, should_cancel):
            captured_cancel["before"] = should_cancel()
            return _summary(total=0)

        service = MagicMock()
        service.upgrade_batch.side_effect = fake_upgrade_batch
        worker = UpgradeWorker(requests=[_req("A.A")], service=service)
        worker.cancel()  # Flag setzen
        worker.run()

        assert captured_cancel["before"] is True

    def test_kein_cancel_callback_liefert_false(self) -> None:
        captured_cancel = {}

        def fake_upgrade_batch(requests, *, on_start, on_finish, should_cancel):
            captured_cancel["value"] = should_cancel()
            return _summary(total=0)

        service = MagicMock()
        service.upgrade_batch.side_effect = fake_upgrade_batch
        worker = UpgradeWorker(requests=[_req("A.A")], service=service)
        worker.run()

        assert captured_cancel["value"] is False


# ===========================================================================
# batch_failed — Safety-Net bei Service-Crash
# ===========================================================================


class TestBatchFailed:
    def test_service_exception_emittiert_batch_failed(self) -> None:
        service = MagicMock()
        service.upgrade_batch.side_effect = RuntimeError("kaputt")
        worker = UpgradeWorker(requests=[_req("A.A")], service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run()

        kinds = [e[0] for e in rec.events]
        assert "batch_failed" in kinds
        # batch_done WIRD bei Exception nicht emittiert
        assert "batch_done" not in kinds

    def test_batch_started_kommt_trotzdem_vor_dem_fail(self) -> None:
        service = MagicMock()
        service.upgrade_batch.side_effect = RuntimeError("kaputt")
        worker = UpgradeWorker(requests=[_req("A.A"), _req("B.B")], service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run()

        assert rec.events[0] == ("batch_started", 2)


# ===========================================================================
# Konstruktion
# ===========================================================================


class TestConstruction:
    def test_worker_ohne_qapplication_instanziierbar(self) -> None:
        UpgradeWorker(requests=[_req("A.A")], service=MagicMock())

    def test_worker_kopiert_request_liste(self) -> None:
        """Original-Liste darf nach Konstruktion mutiert werden,
        ohne den Worker zu beeinflussen."""
        requests = [_req("A.A"), _req("B.B")]
        service = MagicMock()
        service.upgrade_batch.return_value = _summary(total=2)
        worker = UpgradeWorker(requests=requests, service=service)
        requests.clear()  # Caller modifiziert seine Kopie

        rec = _SignalRecorder()
        _connect(worker, rec)
        worker.run()

        assert rec.events[0] == ("batch_started", 2)
