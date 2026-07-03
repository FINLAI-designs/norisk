"""
test_pdf_export_button — GUI-Tests für den PDF-Export-Button (Phase 3).

Abdeckung:
- Export-Button existiert im Dashboard-Header mit erwartetem Text + ToolTip
- Klick ohne geladene Daten → Info-Dialog, kein Export
- Klick mit abgebrochenem Dialog → kein Export
- Klick mit Zielpfad → Export-Service wird aufgerufen, Erfolgs-Dialog
- Export-Service-Fehler → Fehler-Dialog, kein Crash
- Suffix ``.pdf`` wird ergänzt, wenn der User ihn weglässt

Author: Patrick Riederich
Version: 0.3 (Phase 3)
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tools.norisk_dashboard.domain.models import (
    DashboardData,
    ScoreSnapshot,
    TimeRange,
)

pytestmark = pytest.mark.gui


def _empty_data() -> DashboardData:
    return DashboardData(
        time_range=TimeRange.WEEK,
        score=ScoreSnapshot(target="ACME GmbH"),
        generated=datetime(2026, 4, 21, 12, 0, 0),
    )


@pytest.fixture
def stub_aggregator():
    """Liefert einen Aggregator-Mock, der leere Daten zurückgibt."""
    agg = MagicMock()
    agg.aggregate.return_value = _empty_data()
    return agg


@pytest.fixture
def dashboard(qtbot, app, stub_aggregator, tmp_path):
    """Erstellt ein NoRiskDashboardWidget mit injiziertem Aggregator + Export-Stub."""
    from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget

    export_service = MagicMock()
    export_service.export.return_value = tmp_path / "fake-report.pdf"
    w = NoRiskDashboardWidget(
        aggregator=stub_aggregator,
        export_service=export_service,
    )
    qtbot.addWidget(w)
    # Der Initial-Refresh laeuft jetzt async im Worker -> abwarten, damit
    # _last_data gesetzt ist, bevor der Export-Klick darauf zugreift.
    with qtbot.waitSignal(w.refreshed, timeout=3000):
        pass
    return w


class TestExportButtonExistiert:
    def test_button_vorhanden(self, dashboard) -> None:
        assert dashboard._export_btn is not None

    def test_button_text(self, dashboard) -> None:
        assert dashboard._export_btn.text() == "Als PDF exportieren"

    def test_button_tooltip(self, dashboard) -> None:
        tip = dashboard._export_btn.toolTip()
        assert "PDF" in tip
        assert "rüfer" in tip or "rüfung" in tip or "ompliance" in tip

    def test_button_ist_aktiv(self, dashboard) -> None:
        assert dashboard._export_btn.isEnabled()


class TestExportButtonKlick:
    def test_klick_ohne_daten_zeigt_info(self, qtbot, app, stub_aggregator) -> None:
        """Wenn _last_data None ist, wird eine Info angezeigt, kein Export."""
        from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget

        stub_aggregator.aggregate.side_effect = RuntimeError("kein Datensatz")
        export_service = MagicMock()
        w = NoRiskDashboardWidget(
            aggregator=stub_aggregator, export_service=export_service
        )
        qtbot.addWidget(w)
        assert w._last_data is None

        with patch(
            "tools.norisk_dashboard.gui.dashboard_widget.FinlaiInfoDialog"
        ) as info_dialog:
            w._on_export_clicked()

        # Migration QMessageBox.information → FinlaiInfoDialog: Hinweis erscheint,
        # wenn der Dialog instanziiert UND angezeigt (.exec) wurde.
        info_dialog.assert_called_once()
        info_dialog.return_value.exec.assert_called_once()
        export_service.export.assert_not_called()

    def test_abgebrochener_dialog_exportiert_nicht(self, dashboard) -> None:
        with patch(
            "tools.norisk_dashboard.gui.dashboard_widget.QFileDialog.getSaveFileName",
            return_value=("", ""),
        ):
            dashboard._on_export_clicked()
        dashboard._export_service.export.assert_not_called()

    def test_erfolgreicher_export_ruft_service(self, dashboard, tmp_path) -> None:
        target = tmp_path / "report.pdf"
        with (
            patch(
                "tools.norisk_dashboard.gui.dashboard_widget.QFileDialog.getSaveFileName",
                return_value=(str(target), "PDF-Dokumente (*.pdf)"),
            ),
            patch(
                "tools.norisk_dashboard.gui.dashboard_widget.FinlaiSuccessDialog"
            ) as success_dialog,
        ):
            dashboard._on_export_clicked()

        dashboard._export_service.export.assert_called_once()
        call = dashboard._export_service.export.call_args
        assert call.kwargs["output_path"] == target
        assert call.kwargs["target_name"] == "ACME GmbH"
        # Migration QMessageBox.information → FinlaiSuccessDialog: der
        # Erfolgs-Dialog wird instanziiert UND angezeigt (.exec).
        success_dialog.assert_called_once()
        success_dialog.return_value.exec.assert_called_once()

    def test_pdf_suffix_wird_ergaenzt(self, dashboard, tmp_path) -> None:
        """User gibt Pfad ohne.pdf-Suffix ein — der Export legt ihn trotzdem als.pdf an."""
        target_ohne_suffix = tmp_path / "report"
        with (
            patch(
                "tools.norisk_dashboard.gui.dashboard_widget.QFileDialog.getSaveFileName",
                return_value=(str(target_ohne_suffix), ""),
            ),
            patch(
                "tools.norisk_dashboard.gui.dashboard_widget.FinlaiSuccessDialog"
            ),
        ):
            dashboard._on_export_clicked()

        call = dashboard._export_service.export.call_args
        assert call.kwargs["output_path"].suffix == ".pdf"

    def test_service_fehler_zeigt_messagebox(self, dashboard, tmp_path) -> None:
        """Wenn der Export-Service crasht, sieht der User eine Fehlermeldung."""
        dashboard._export_service.export.side_effect = OSError("disk full")
        target = tmp_path / "report.pdf"
        with (
            patch(
                "tools.norisk_dashboard.gui.dashboard_widget.QFileDialog.getSaveFileName",
                return_value=(str(target), ""),
            ),
            patch(
                "tools.norisk_dashboard.gui.dashboard_widget.FinlaiInfoDialog"
            ) as error_dialog,
            patch(
                "tools.norisk_dashboard.gui.dashboard_widget.FinlaiSuccessDialog"
            ) as success_dialog,
        ):
            dashboard._on_export_clicked()

        # Migration: Fehlerfall → FinlaiInfoDialog (icon_name=Icons.ERROR) statt
        # QMessageBox.critical; der Erfolgs-Dialog darf NICHT erscheinen.
        error_dialog.assert_called_once()
        error_dialog.return_value.exec.assert_called_once()
        success_dialog.assert_not_called()


class TestDefaultPathHelpers:
    def test_default_output_dir_erzeugt_verzeichnis(self) -> None:
        from tools.norisk_dashboard.application.pdf_export_service import (
            default_output_dir,
        )

        p: Path = default_output_dir()
        assert p.exists()
        assert p.is_dir()

    def test_default_filename_pattern(self) -> None:
        from tools.norisk_dashboard.application.pdf_export_service import (
            default_filename,
        )

        name = default_filename(datetime(2026, 12, 31, 23, 59))
        assert name.startswith("NoRisk-Dashboard-Report_")
        assert name.endswith(".pdf")
        assert "2026-12-31" in name
        assert "2359" in name
