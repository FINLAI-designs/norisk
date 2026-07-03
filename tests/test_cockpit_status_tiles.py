"""Tests für Cockpit Increment-2 — Status-Kacheln + Daten-Accessoren.

Deckt ab:
  - status_tile_metrics: fail-soft Defaults (kein DB/Tool -> 0/None).
  - PatchInventoryService.offene_und_eol_counts: recommendation-Klassifikation.
  - PasswordService persistiert den Prüf-Zeitpunkt (best-effort).
  - LastCheckRepository: markiere_geprueft <-> letzter_check Roundtrip + Upsert.
  - deeplink_registry: focus-Mappings für die Kachel-Ziele.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.database.db_context import clear_db_app_id
from tools.norisk_dashboard.application import status_tile_metrics as metrics


@pytest.fixture(autouse=True)
def reset_db_context():
    clear_db_app_id()
    yield
    clear_db_app_id()


@pytest.fixture
def isolated_db_dir(tmp_path: Path):
    with patch("core.database.encrypted_db.DB_DIR", tmp_path):
        yield tmp_path


def _result(recommendation: str) -> MagicMock:
    return MagicMock(recommendation=recommendation)


# ---------------------------------------------------------------------------
# status_tile_metrics — fail-soft Defaults
# ---------------------------------------------------------------------------


def test_patch_metric_fail_soft(isolated_db_dir):
    # Keine Patch-DB im isolierten Verzeichnis -> (0, 0), kein Crash.
    assert metrics.patch_offene_und_eol() == (0, 0)


def test_supply_metric_fail_soft(isolated_db_dir):
    assert metrics.supply_offene_punkte() == 0


def test_password_metric_fail_soft(isolated_db_dir):
    assert metrics.passwort_letzter_check() is None


# ---------------------------------------------------------------------------
# Patch-Count-Klassifikation (recommendation -> offen/EOL)
# ---------------------------------------------------------------------------


def test_patch_offene_und_eol_klassifikation():
    from tools.patch_monitor.application.patch_inventory_service import (
        PatchInventoryService,
    )

    svc = PatchInventoryService.__new__(PatchInventoryService)  # ohne __init__
    svc.load_from_db = MagicMock(  # type: ignore[method-assign]
        return_value=[
            _result("update_urgent"),
            _result("update"),
            _result("update_available"),
            _result("eol_no_patch"),
            _result("eol_no_patch"),
            _result("up_to_date"),
        ]
    )
    assert svc.offene_und_eol_counts() == (3, 2)


def test_patch_offene_und_eol_fail_soft():
    from tools.patch_monitor.application.patch_inventory_service import (
        PatchInventoryService,
    )

    svc = PatchInventoryService.__new__(PatchInventoryService)
    svc.load_from_db = MagicMock(side_effect=RuntimeError("db"))  # type: ignore[method-assign]
    assert svc.offene_und_eol_counts() == (0, 0)


# ---------------------------------------------------------------------------
# Password-Persistenz
# ---------------------------------------------------------------------------


def test_password_service_persistiert_zeitpunkt():
    from tools.password_checker.application.password_service import PasswordService

    repo = MagicMock()
    svc = PasswordService(hibp_client=None, last_check_repo=repo)
    svc.pruefen("Sommer2026!#xQ", mit_breach_check=False)
    repo.markiere_geprueft.assert_called_once()


def test_lastcheck_repo_roundtrip(isolated_db_dir):
    from tools.password_checker.data.last_check_repository import LastCheckRepository

    repo = LastCheckRepository()
    assert repo.letzter_check() is None  # noch nie geprüft

    ts = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
    repo.markiere_geprueft(ts)
    assert repo.letzter_check() == ts

    # Upsert: Single-Row, der zweite Aufruf überschreibt.
    ts2 = datetime(2026, 6, 2, 9, 0, tzinfo=UTC)
    repo.markiere_geprueft(ts2)
    assert repo.letzter_check() == ts2


# ---------------------------------------------------------------------------
# deeplink_registry — focus-Mappings der Kachel-Ziele
# ---------------------------------------------------------------------------


def test_deeplink_focus_mappings():
    from core.deeplink_registry import DEEPLINK_TARGETS

    for key in ("patch_monitor", "supply_chain_monitor", "password_checker"):
        assert DEEPLINK_TARGETS[key] == {"focus": str}


# ---------------------------------------------------------------------------
# Perf Stage 1a — StatusTilesSection lädt Metriken erst post-paint
# ---------------------------------------------------------------------------


@pytest.mark.gui
def test_status_tiles_metriken_deferred(qtbot):  # noqa: ANN001
    """Der ctor öffnet KEINE Metrik-DBs (Freeze-Vermeidung vor dem ersten Paint);
    die 4–5 DB-Reads laufen erst in ``_load_metrics`` (post-paint via Kind-QTimer)."""
    import tools.norisk_dashboard.gui.status_tiles_section as sts

    with (
        patch.object(sts, "patch_offene_und_eol", return_value=(3, 1)) as m_patch,
        patch.object(sts, "supply_offene_punkte", return_value=2) as m_supply,
        patch.object(sts, "netzwerk_letzter_scan", return_value=None) as m_netz,
        patch.object(sts, "passwort_letzter_check", return_value=None) as m_pw,
    ):
        widget = sts.StatusTilesSection()
        qtbot.addWidget(widget)

        # ctor darf die Metriken NICHT synchron ziehen (sonst Freeze vor Paint).
        m_patch.assert_not_called()
        m_supply.assert_not_called()
        m_netz.assert_not_called()
        m_pw.assert_not_called()

        # post-paint: _load_metrics zieht die Werte (einmal je Metrik).
        widget._load_metrics()
        m_patch.assert_called_once()
        m_supply.assert_called_once()
        m_netz.assert_called_once()
        m_pw.assert_called_once()
