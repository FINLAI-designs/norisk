"""
test_batch_upgrade_service — Tests fuer Stop-Step B BatchService.

Deckt:
* Leerer Batch → leere Summary
* Reihenfolge wird beibehalten
* Pro-Item-Executor-Aufruf + Repository-Record
* on_start / on_finish-Callbacks werden aufgerufen
* should_cancel pausiert Restliste mit SKIPPED
* Executor-Exception → FAILED-Result mit error-Text, Batch laeuft weiter
* Repository-Exception crasht den Batch nicht
* Summary-Zaehler stimmen
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.patch_upgrade import (
    UpgradeRequest,
    UpgradeResult,
    UpgradeStatus,
)
from tools.patch_monitor.application.batch_upgrade_service import (
    BatchSummary,
    BatchUpgradeService,
)


def _req(winget_id: str = "Mozilla.Firefox") -> UpgradeRequest:
    """Test-Helper: baut einen UpgradeRequest mit Defaults."""
    return UpgradeRequest(
        winget_id=winget_id,
        version_from="1.0",
        version_to="2.0",
        display_name=winget_id,
    )


def _result(
    *,
    status: UpgradeStatus = UpgradeStatus.SUCCESS,
    winget_id: str = "Mozilla.Firefox",
    exit_code: int | None = 0,
    error: str | None = None,
) -> UpgradeResult:
    return UpgradeResult(
        winget_id=winget_id,
        status=status,
        exit_code=exit_code,
        duration_ms=10,
        stdout="",
        stderr="",
        error=error,
    )


# ---------------------------------------------------------------------------
# Leerer Batch
# ---------------------------------------------------------------------------


class TestEmptyBatch:
    def test_leere_liste_gibt_summary_total_0(self) -> None:
        executor = MagicMock()
        repo = MagicMock()
        service = BatchUpgradeService(executor=executor, repository=repo)

        summary = service.upgrade_batch([])

        assert summary.total == 0
        assert summary.succeeded == 0
        assert summary.failed == 0
        assert summary.results == []
        executor.upgrade.assert_not_called()
        repo.record.assert_not_called()


# ---------------------------------------------------------------------------
# Happy Path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_drei_requests_drei_executor_aufrufe(self) -> None:
        executor = MagicMock()
        executor.upgrade.side_effect = [
            _result(winget_id="A.A"),
            _result(winget_id="B.B"),
            _result(winget_id="C.C"),
        ]
        repo = MagicMock()
        service = BatchUpgradeService(executor=executor, repository=repo)

        summary = service.upgrade_batch([_req("A.A"), _req("B.B"), _req("C.C")])

        assert executor.upgrade.call_count == 3
        assert repo.record.call_count == 3
        assert summary.total == 3
        assert summary.succeeded == 3

    def test_reihenfolge_wird_beibehalten(self) -> None:
        executor = MagicMock()
        executor.upgrade.side_effect = [
            _result(winget_id="A.A"),
            _result(winget_id="B.B"),
            _result(winget_id="C.C"),
        ]
        service = BatchUpgradeService(executor=executor, repository=MagicMock())

        summary = service.upgrade_batch([_req("A.A"), _req("B.B"), _req("C.C")])

        ids = [r.winget_id for r in summary.results]
        assert ids == ["A.A", "B.B", "C.C"]

    def test_executor_bekommt_winget_id(self) -> None:
        executor = MagicMock()
        executor.upgrade.return_value = _result(winget_id="Mozilla.Firefox")
        service = BatchUpgradeService(executor=executor, repository=MagicMock())

        service.upgrade_batch([_req("Mozilla.Firefox")])

        executor.upgrade.assert_called_once_with("Mozilla.Firefox")

    def test_repo_bekommt_audit_felder(self) -> None:
        executor = MagicMock()
        result = _result()
        executor.upgrade.return_value = result
        repo = MagicMock()
        service = BatchUpgradeService(executor=executor, repository=repo)

        service.upgrade_batch(
            [
                UpgradeRequest(
                    winget_id="X.Y",
                    version_from="1.0",
                    version_to="2.0",
                    display_name="X-Y Display",
                )
            ]
        )

        repo.record.assert_called_once()
        _, kwargs = repo.record.call_args
        assert kwargs["winget_id"] == "X.Y"
        assert kwargs["display_name"] == "X-Y Display"
        assert kwargs["version_from"] == "1.0"
        assert kwargs["version_to"] == "2.0"
        assert kwargs["result"] is result


# ---------------------------------------------------------------------------
# Synthetische Ids (Registry-/MSIX-Apps) — nie an den Executor
# ---------------------------------------------------------------------------


class TestSyntheticId:
    @pytest.mark.parametrize("synthetic_id", ["regid:7-zip", "msix:Microsoft.Photos"])
    def test_synthetische_id_wird_skipped_ohne_executor(
        self, synthetic_id: str
    ) -> None:
        """Eine synthetische Id im Batch wird SKIPPED — der Executor wird
        nie aufgerufen (Sicherheits-Invariante: nie an winget)."""
        executor = MagicMock()
        service = BatchUpgradeService(executor=executor, repository=MagicMock())

        summary = service.upgrade_batch([_req(synthetic_id)])

        executor.upgrade.assert_not_called()
        executor.upgrade_msstore.assert_not_called()
        assert summary.skipped == 1
        assert summary.results[0].status is UpgradeStatus.SKIPPED

    def test_echte_id_neben_synthetischer_laeuft_weiter(self) -> None:
        """Eine echte Id im selben Batch wird normal ausgefuehrt, die
        synthetische daneben SKIPPED — Batch bleibt vollstaendig."""
        executor = MagicMock()
        executor.upgrade.return_value = _result(winget_id="Mozilla.Firefox")
        service = BatchUpgradeService(executor=executor, repository=MagicMock())

        summary = service.upgrade_batch(
            [_req("regid:7-zip"), _req("Mozilla.Firefox")]
        )

        executor.upgrade.assert_called_once_with("Mozilla.Firefox")
        assert summary.skipped == 1
        assert summary.succeeded == 1


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------


class TestCallbacks:
    def test_on_start_pro_item_aufgerufen(self) -> None:
        executor = MagicMock()
        executor.upgrade.return_value = _result()
        service = BatchUpgradeService(executor=executor, repository=MagicMock())
        on_start = MagicMock()

        service.upgrade_batch([_req("A.A"), _req("B.B")], on_start=on_start)

        assert on_start.call_count == 2
        # Pruefen: (index, total, request)
        first_call_args = on_start.call_args_list[0][0]
        assert first_call_args[0] == 1  # 1-basierter Index
        assert first_call_args[1] == 2  # total

    def test_on_finish_pro_item_mit_result(self) -> None:
        executor = MagicMock()
        r1 = _result(winget_id="A.A")
        r2 = _result(winget_id="B.B")
        executor.upgrade.side_effect = [r1, r2]
        service = BatchUpgradeService(executor=executor, repository=MagicMock())
        on_finish = MagicMock()

        service.upgrade_batch([_req("A.A"), _req("B.B")], on_finish=on_finish)

        assert on_finish.call_count == 2
        # Letztes Argument im jeweiligen Call ist das Result
        first_result = on_finish.call_args_list[0][0][3]
        second_result = on_finish.call_args_list[1][0][3]
        assert first_result.winget_id == "A.A"
        assert second_result.winget_id == "B.B"

    def test_kein_callback_kein_problem(self) -> None:
        executor = MagicMock()
        executor.upgrade.return_value = _result()
        service = BatchUpgradeService(executor=executor, repository=MagicMock())

        # Kein on_start / on_finish → kein AttributeError
        summary = service.upgrade_batch([_req("A.A")])
        assert summary.succeeded == 1


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


class TestCancellation:
    def test_should_cancel_vor_erstem_item_skipped(self) -> None:
        executor = MagicMock()
        repo = MagicMock()
        service = BatchUpgradeService(executor=executor, repository=repo)

        summary = service.upgrade_batch(
            [_req("A.A"), _req("B.B")],
            should_cancel=lambda: True,
        )

        # Kein Executor-Aufruf, beide als SKIPPED
        executor.upgrade.assert_not_called()
        # SKIPPED-Eintraege werden NICHT persistiert (kein Audit fuer
        # nicht-ausgefuehrte Aktionen)
        repo.record.assert_not_called()
        assert summary.skipped == 2
        assert summary.total == 2

    def test_cancel_nach_erstem_item(self) -> None:
        executor = MagicMock()
        executor.upgrade.return_value = _result()
        repo = MagicMock()

        call_count = {"n": 0}

        def cancel_after_first() -> bool:
            call_count["n"] += 1
            return call_count["n"] > 1  # erstmals False, dann True

        service = BatchUpgradeService(executor=executor, repository=repo)
        summary = service.upgrade_batch(
            [_req("A.A"), _req("B.B"), _req("C.C")],
            should_cancel=cancel_after_first,
        )

        assert executor.upgrade.call_count == 1
        assert summary.succeeded == 1
        assert summary.skipped == 2

    def test_skipped_results_haben_richtigen_status(self) -> None:
        service = BatchUpgradeService(executor=MagicMock(), repository=MagicMock())
        summary = service.upgrade_batch([_req("A.A")], should_cancel=lambda: True)
        assert summary.results[0].status is UpgradeStatus.SKIPPED


# ---------------------------------------------------------------------------
# Fehler-Toleranz
# ---------------------------------------------------------------------------


class TestErrorTolerance:
    def test_executor_exception_wird_failed_result(self) -> None:
        executor = MagicMock()
        executor.upgrade.side_effect = RuntimeError("boom")
        repo = MagicMock()
        service = BatchUpgradeService(executor=executor, repository=repo)

        summary = service.upgrade_batch([_req("A.A")])

        assert summary.failed == 1
        assert summary.results[0].status is UpgradeStatus.FAILED
        assert "RuntimeError" in (summary.results[0].error or "")
        # Audit-Record trotzdem geschrieben
        repo.record.assert_called_once()

    def test_executor_exception_bricht_batch_nicht(self) -> None:
        executor = MagicMock()
        executor.upgrade.side_effect = [
            RuntimeError("first"),
            _result(winget_id="B.B"),
        ]
        service = BatchUpgradeService(executor=executor, repository=MagicMock())

        summary = service.upgrade_batch([_req("A.A"), _req("B.B")])

        assert summary.failed == 1
        assert summary.succeeded == 1

    def test_repo_exception_crasht_batch_nicht(self) -> None:
        executor = MagicMock()
        executor.upgrade.return_value = _result()
        repo = MagicMock()
        repo.record.side_effect = RuntimeError("DB kaputt")

        service = BatchUpgradeService(executor=executor, repository=repo)
        summary = service.upgrade_batch([_req("A.A")])

        # Result ist trotzdem im Summary
        assert summary.succeeded == 1


# ---------------------------------------------------------------------------
# Summary-Zaehler
# ---------------------------------------------------------------------------


class TestSummary:
    def test_summary_zaehlt_alle_4_status(self) -> None:
        executor = MagicMock()
        executor.upgrade.side_effect = [
            _result(status=UpgradeStatus.SUCCESS),
            _result(status=UpgradeStatus.FAILED, exit_code=1, error="x"),
            _result(status=UpgradeStatus.TIMEOUT, exit_code=None, error="t"),
        ]
        service = BatchUpgradeService(executor=executor, repository=MagicMock())

        summary = service.upgrade_batch([_req("A.A"), _req("B.B"), _req("C.C")])

        assert summary.total == 3
        assert summary.succeeded == 1
        assert summary.failed == 1
        assert summary.timed_out == 1
        assert summary.skipped == 0

    def test_summary_ist_frozen(self) -> None:
        service = BatchUpgradeService(executor=MagicMock(), repository=MagicMock())
        summary = service.upgrade_batch([])
        with pytest.raises(Exception):  # FrozenInstanceError oder AttributeError
            summary.total = 99  # type: ignore[misc]

    def test_summary_ist_eine_BatchSummary(self) -> None:
        service = BatchUpgradeService(executor=MagicMock(), repository=MagicMock())
        summary = service.upgrade_batch([])
        assert isinstance(summary, BatchSummary)


# ---------------------------------------------------------------------------
# Dispatch zwischen Catalog (winget_id) und Store (store_id)
# ---------------------------------------------------------------------------


class TestMsstoreDispatch:
    """`_run_single` waehlt anhand des nicht-None-Felds (winget_id vs.
    store_id) den richtigen Executor-Mode."""

    def test_store_id_request_calls_upgrade_msstore(self) -> None:
        executor = MagicMock()
        executor.upgrade_msstore.return_value = _result(
            winget_id="XP8K2L36VP0QMB"
        )
        service = BatchUpgradeService(executor=executor, repository=MagicMock())

        msstore_req = UpgradeRequest(
            winget_id=None,
            store_id="XP8K2L36VP0QMB",
            version_from="1.0",
            version_to="2.0",
            display_name="KeePassXC",
        )
        service.upgrade_batch([msstore_req])

        executor.upgrade_msstore.assert_called_once_with("XP8K2L36VP0QMB")
        executor.upgrade.assert_not_called()

    def test_winget_id_request_calls_upgrade(self) -> None:
        executor = MagicMock()
        executor.upgrade.return_value = _result()
        service = BatchUpgradeService(executor=executor, repository=MagicMock())

        service.upgrade_batch([_req("Mozilla.Firefox")])

        executor.upgrade.assert_called_once_with("Mozilla.Firefox")
        executor.upgrade_msstore.assert_not_called()

    def test_both_none_returns_failed_result(self) -> None:
        """Programmierfehler vom Caller: weder winget_id noch store_id
        gesetzt. Service crashed nicht, gibt FAILED-Result zurueck."""
        executor = MagicMock()
        service = BatchUpgradeService(executor=executor, repository=MagicMock())

        empty_req = UpgradeRequest(
            winget_id=None,
            store_id=None,
            version_from=None,
            version_to=None,
            display_name="(broken)",
        )
        summary = service.upgrade_batch([empty_req])

        assert summary.failed == 1
        executor.upgrade.assert_not_called()
        executor.upgrade_msstore.assert_not_called()


class TestUpgradeRequestPackageId:
    """`UpgradeRequest.package_id` ist die kanonische Identifier-
    Auflösung fuer Audit + Log."""

    def test_package_id_returns_winget_id_when_set(self) -> None:
        r = UpgradeRequest(
            winget_id="Mozilla.Firefox",
            version_from=None,
            version_to=None,
            display_name="Firefox",
        )
        assert r.package_id == "Mozilla.Firefox"

    def test_package_id_returns_store_id_when_only_store_set(self) -> None:
        r = UpgradeRequest(
            winget_id=None,
            store_id="XP8K2L36VP0QMB",
            version_from=None,
            version_to=None,
            display_name="KeePassXC",
        )
        assert r.package_id == "XP8K2L36VP0QMB"

    def test_package_id_fallback_unknown_when_both_none(self) -> None:
        r = UpgradeRequest(
            winget_id=None,
            store_id=None,
            version_from=None,
            version_to=None,
            display_name="(broken)",
        )
        assert r.package_id == "<unknown>"
