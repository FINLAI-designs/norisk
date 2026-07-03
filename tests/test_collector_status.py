"""Tests fuer das Collector-Status-Verdikt — reine Domain-Logik.

Deckt die Ableitung von:class:`CollectorStatus` aus den Roh-Fakten ab; ohne
Windows/COM, plattformunabhaengig.
"""

from __future__ import annotations

from tools.network_monitor.domain.collector_status import (
    CollectorStatus,
    CollectorTaskHealth,
)

#: SCHED_S_*-Codes, die KEINEN Fehlschlag bedeuten (vgl. domain-Konstanten).
_HAS_NOT_RUN = 0x00041303
_RUNNING = 0x00041301
#: Win32 ERROR_FILE_NOT_FOUND — die-Konstellation (toter Worktree-Pfad).
_FILE_NOT_FOUND = 2


class TestCollectorTaskHealthVerdict:
    def test_nicht_installiert(self) -> None:
        assert (
            CollectorTaskHealth(installed=False).status
            is CollectorStatus.NOT_INSTALLED
        )

    def test_installiert_ziel_fehlt_ist_broken(self) -> None:
        health = CollectorTaskHealth(installed=True, target_exists=False)
        assert health.status is CollectorStatus.BROKEN

    def test_installiert_ziel_da_letzter_lauf_ok_ist_aktiv(self) -> None:
        health = CollectorTaskHealth(
            installed=True, target_exists=True, last_task_result=0
        )
        assert health.status is CollectorStatus.ACTIVE

    def test_installiert_ziel_da_noch_nie_gelaufen_ist_aktiv(self) -> None:
        health = CollectorTaskHealth(
            installed=True, target_exists=True, last_task_result=_HAS_NOT_RUN
        )
        assert health.status is CollectorStatus.ACTIVE

    def test_installiert_ziel_da_laeuft_gerade_ist_aktiv(self) -> None:
        health = CollectorTaskHealth(
            installed=True, target_exists=True, last_task_result=_RUNNING
        )
        assert health.status is CollectorStatus.ACTIVE

    def test_start_fehler_file_not_found_ist_broken(self) -> None:
        # ERROR_FILE_NOT_FOUND = Action konnte nicht starten -> BROKEN.
        health = CollectorTaskHealth(
            installed=True, target_exists=True, last_task_result=_FILE_NOT_FOUND
        )
        assert health.status is CollectorStatus.BROKEN

    def test_start_fehler_path_not_found_ist_broken(self) -> None:
        health = CollectorTaskHealth(
            installed=True, target_exists=True, last_task_result=0x3
        )
        assert health.status is CollectorStatus.BROKEN

    def test_generischer_exit_code_kein_false_broken(self) -> None:
        # Regulaer beendeter/terminierter Dauer-Collector: non-zero Exit- bzw.
        # Termination-Code, aber Ziel existiert -> KEIN False-Broken-Verify).
        for code in (1, 0x40010004, 0xC000013A):
            health = CollectorTaskHealth(
                installed=True, target_exists=True, last_task_result=code
            )
            assert health.status is CollectorStatus.ACTIVE, code

    def test_ziel_fehlt_schlaegt_durch_trotz_ok_result(self) -> None:
        health = CollectorTaskHealth(
            installed=True, target_exists=False, last_task_result=0
        )
        assert health.status is CollectorStatus.BROKEN

    def test_result_none_wird_ignoriert(self) -> None:
        health = CollectorTaskHealth(
            installed=True, target_exists=True, last_task_result=None
        )
        assert health.status is CollectorStatus.ACTIVE
