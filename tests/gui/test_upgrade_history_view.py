"""test_upgrade_history_view — View der bisherigen Patch-Upgrade-Versuche.

Verifiziert die Reader-Seite des reaktivierten Lost-Features ``upgrade_history``:
die View liest per injiziertem Repository und rendert Zeit/App/Version/Status/
Dauer/Fehler — fail-safe ohne Repository.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from core.patch_upgrade import UpgradeStatus
from tools.patch_monitor.data.upgrade_history_repository import UpgradeHistoryEntry
from tools.patch_monitor.gui.upgrade_history_view import UpgradeHistoryView

pytestmark = pytest.mark.gui


def _entry(
    status: UpgradeStatus = UpgradeStatus.SUCCESS, error: str | None = None
) -> UpgradeHistoryEntry:
    return UpgradeHistoryEntry(
        id="x",
        created_at=datetime(2026, 7, 1, 10, 30, tzinfo=UTC),
        winget_id="Mozilla.Firefox",
        display_name="Mozilla Firefox",
        version_from="123.0",
        version_to="124.0",
        status=status,
        exit_code=0,
        duration_ms=4200,
        error=error,
    )


def test_view_populates_from_repo(app) -> None:
    repo = MagicMock()
    repo.list_recent.return_value = [
        _entry(),
        _entry(UpgradeStatus.FAILED, "winget 0x8"),
    ]
    view = UpgradeHistoryView(repository=repo)
    assert view._table.rowCount() == 2
    assert view._table.item(0, 1).text() == "Mozilla Firefox"
    assert "123.0" in view._table.item(0, 2).text()
    assert view._table.item(0, 3).text() == "Erfolg"
    assert view._table.item(1, 3).text() == "Fehlgeschlagen"
    assert view._table.item(1, 5).text() == "winget 0x8"
    assert view._empty_hint.isHidden() is True


def test_view_empty_state(app) -> None:
    repo = MagicMock()
    repo.list_recent.return_value = []
    view = UpgradeHistoryView(repository=repo)
    assert view._table.rowCount() == 0
    assert view._empty_hint.isHidden() is False


def test_view_fail_safe_without_repo(app) -> None:
    view = UpgradeHistoryView(repository=None)
    assert view._table.rowCount() == 0


def test_view_fail_safe_repo_raises(app) -> None:
    repo = MagicMock()
    repo.list_recent.side_effect = RuntimeError("DB weg")
    view = UpgradeHistoryView(repository=repo)  # darf NICHT werfen
    assert view._table.rowCount() == 0
