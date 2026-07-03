"""
test_inventory_setup — Tests fuer Stop-Step E Setup-Factory.

Verifiziert die Verdrahtung zwischen Scheduler-Signals und Worker-Slots,
ohne MainWindow oder QApplication zu starten (Setup-Factory-Pattern).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from PySide6.QtCore import QObject

from tools.patch_monitor.gui.inventory_setup import (
    setup_patch_inventory,
    teardown_patch_inventory,
)

# pytest-Marker: alle Setup-Tests brauchen QApplication weil
# QThread / QTimer / Signal-Connection-Resolution einen Event-Loop
# erwarten.
pytestmark = pytest.mark.gui


class TestSetupPatchInventory:
    """Verdrahtung Scheduler → Worker."""

    def test_returns_thread_worker_scheduler_service(self, qapp) -> None:
        service = MagicMock()
        service.is_inventory_empty.return_value = False
        service.get_last_full_scan_at.return_value = None
        service.get_last_daily_refresh_at.return_value = None

        parent = QObject()
        thread, worker, scheduler, returned_service = setup_patch_inventory(
            parent,
            service=service,
            auto_start_scheduler=False,
        )

        assert thread is not None
        assert worker is not None
        assert scheduler is not None
        assert returned_service is service

        teardown_patch_inventory(thread, scheduler)

    def test_scheduler_monthly_due_triggers_worker(self, qapp) -> None:
        """monthly_full_due muss worker.run_monthly_full (kein Lambda!) treffen.

        Regressionsschutz: ein frueher Setup nutzte
        ``lambda: worker.run_full_scan('monthly_full')`` — Lambdas haben
        keinen QObject-Owner, Qt loest die Verbindung als DirectConnection
        auf und fuehrt den 20-min-Vollscan auf dem Emitter-Thread aus.
        Ergebnis: GUI-Freeze. Wenn der Test rot wird, dann ist die
        Lambda-Verdrahtung zurueckgekommen.
        """
        service = MagicMock()
        service.is_inventory_empty.return_value = False
        from datetime import UTC, datetime, timedelta

        # Monthly faellig — last_full liegt >31 Tage zurueck
        service.get_last_full_scan_at.return_value = datetime.now(UTC) - timedelta(
            days=40
        )
        service.get_last_daily_refresh_at.return_value = datetime.now(UTC)
        service.full_scan.return_value = MagicMock(
            scan_id="m",
            scan_type="monthly_full",
            items_total=1,
            items_with_updates=0,
            items_with_cves=0,
        )

        parent = QObject()
        thread, worker, scheduler, _ = setup_patch_inventory(
            parent,
            service=service,
            auto_start_scheduler=False,
        )

        scheduler.tick_now()
        qapp.processEvents()
        thread.wait(500)
        qapp.processEvents()

        # Service.full_scan muss MIT scan_type='monthly_full' aufgerufen
        # worden sein — kein Lambda-Direct-Call auf Main-Thread
        service.full_scan.assert_called_with(scan_type="monthly_full")

        teardown_patch_inventory(thread, scheduler)

    def test_scheduler_daily_due_triggers_worker(self, qapp) -> None:
        """daily_refresh_due → worker.run_daily_refresh."""
        service = MagicMock()
        service.is_inventory_empty.return_value = False
        from datetime import UTC, datetime, timedelta

        service.get_last_full_scan_at.return_value = datetime.now(UTC) - timedelta(
            days=5
        )
        service.get_last_daily_refresh_at.return_value = datetime.now(UTC) - timedelta(
            hours=48
        )

        parent = QObject()
        thread, worker, scheduler, _ = setup_patch_inventory(
            parent,
            service=service,
            auto_start_scheduler=False,
        )

        # Spy auf Worker-Slot durch direktes Tracking (run_daily_refresh
        # ruft service.daily_refresh — wir koennen das via Mock pruefen)
        service.daily_refresh.return_value = MagicMock(
            scan_id="x",
            items_total=1,
            items_with_updates=0,
            cves_refreshed=0,
        )

        # Tick manuell — sollte daily_refresh_due emittieren und Worker triggern
        scheduler.tick_now()

        # Worker laeuft in eigenem Thread, also Event-Loop kurz pumpen
        qapp.processEvents()
        # Ggf. mehrmals (Queued-Connection Cross-Thread)
        thread.wait(500)
        qapp.processEvents()

        # Service.daily_refresh sollte mindestens einmal gerufen worden sein
        assert service.daily_refresh.called

        teardown_patch_inventory(thread, scheduler)
