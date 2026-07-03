"""GUI-Tests fuer den-AP6-Empty-State im api_security Neuer-Scan-Tab.

Deckt ab:
  - Der Stack startet auf dem Empty-State (Index 0) mit 1-2-3-Anleitung.
  - Erfolgreicher Scan (auch mit 0 Findings) schaltet auf die Ergebnis-Seite.
  - Die KPI-Zeile zaehlt kritisch/hoch/mittel korrekt;
    bei 0 Findings erscheint die positive Bestaetigung.
  - Scan-Fehler (result.error bzw. scan_error-Signalpfad) bleibt im Empty-State.
  - Export-Buttons sind vor dem Scan disabled und werden erst nach
    erfolgreichem Scan aktiviert (Enable-Logik unveraendert).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tools.api_security.application.scanner_service import ScannerService
from tools.api_security.domain.models import (
    Finding,
    OWASPCategory,
    ScanResult,
    ScanTarget,
    Severity,
)
from tools.api_security.gui.api_security_widget import (
    _STACK_EMPTY,
    _STACK_RESULTS,
    ApiSecurityWidget,
)

pytestmark = pytest.mark.gui


# ---------------------------------------------------------------------------
# Hilfsfunktionen + Fixtures
# ---------------------------------------------------------------------------


def _make_service() -> MagicMock:
    """Erstellt einen ScannerService-Mock mit leerem Verlauf."""
    service = MagicMock(spec=ScannerService)
    service.lade_verlauf.return_value = []
    service.lade_alle_gescannten_urls.return_value = []
    return service


def _finding(severity: Severity, code: str = "TEST_CODE") -> Finding:
    """Baut ein minimales Finding mit gegebenem Schweregrad."""
    return Finding(
        code=code,
        title="Testbefund",
        description="Beschreibung des Testbefunds",
        severity=severity,
        owasp=OWASPCategory.API8,
        remediation="Empfehlung",
    )


def _result(findings: list[Finding], error: str = "") -> ScanResult:
    """Baut ein minimales ScanResult fuer den Slot-Direktaufruf."""
    return ScanResult(
        target=ScanTarget(url="https://api.example.com/v1"),
        findings=findings,
        scan_time="2026-06-11T10:00:00+00:00",
        duration_ms=42,
        error=error,
    )


@pytest.fixture
def widget(qtbot, app):  # noqa: ARG001
    """ApiSecurityWidget mit gemocktem ScannerService."""
    w = ApiSecurityWidget(service=_make_service())
    qtbot.addWidget(w)
    return w


# ---------------------------------------------------------------------------
# (a) Startzustand: Empty-State
# ---------------------------------------------------------------------------


def test_stack_startet_auf_empty_state(widget):
    """Vor dem ersten Scan zeigt der Stack den Empty-State (Index 0)."""
    assert widget._scan_stack.currentIndex() == _STACK_EMPTY  # noqa: SLF001


def test_export_buttons_vor_dem_scan_disabled(widget):
    """Die Export-Buttons sind vor dem ersten Scan deaktiviert."""
    assert not widget._json_btn.isEnabled()  # noqa: SLF001
    assert not widget._xlsx_btn.isEnabled()  # noqa: SLF001
    assert not widget._pdf_btn.isEnabled()  # noqa: SLF001


# ---------------------------------------------------------------------------
# (b) Erfolgreicher Scan schaltet auf die Ergebnis-Seite
# ---------------------------------------------------------------------------


def test_scan_ergebnis_schaltet_auf_ergebnis_seite(widget):
    """Nach Empfang eines ScanResults steht der Stack auf der Ergebnis-Seite."""
    widget._on_scan_finished(_result([_finding(Severity.HIGH)]))  # noqa: SLF001

    assert widget._scan_stack.currentIndex() == _STACK_RESULTS  # noqa: SLF001
    assert widget._json_btn.isEnabled()  # noqa: SLF001
    assert widget._xlsx_btn.isEnabled()  # noqa: SLF001
    assert widget._pdf_btn.isEnabled()  # noqa: SLF001


def test_null_findings_schaltet_auf_ergebnis_seite(widget):
    """Auch 0 Findings nach erfolgreichem Scan zeigen die Ergebnis-Seite."""
    widget._on_scan_finished(_result([]))  # noqa: SLF001

    assert widget._scan_stack.currentIndex() == _STACK_RESULTS  # noqa: SLF001
    assert "Keine Befunde" in widget._kpi_label.text()  # noqa: SLF001


# ---------------------------------------------------------------------------
# (c) KPI-Zeile zaehlt korrekt
# ---------------------------------------------------------------------------


def test_kpi_zeile_zaehlt_korrekt(widget):
    """Die KPI-Zeile zaehlt kritisch/hoch/mittel aus den Findings."""
    findings = [
        _finding(Severity.CRITICAL, "C1"),
        _finding(Severity.CRITICAL, "C2"),
        _finding(Severity.HIGH, "H1"),
        _finding(Severity.MEDIUM, "M1"),
        _finding(Severity.MEDIUM, "M2"),
        _finding(Severity.MEDIUM, "M3"),
        _finding(Severity.LOW, "L1"),
        _finding(Severity.INFO, "I1"),
    ]
    widget._on_scan_finished(_result(findings))  # noqa: SLF001

    text = widget._kpi_label.text()  # noqa: SLF001
    assert "2 kritisch" in text
    assert "1 hoch" in text
    assert "3 mittel" in text


# ---------------------------------------------------------------------------
# (d) Scan-Fehler: Empty-State bleibt
# ---------------------------------------------------------------------------


def test_scan_fehler_im_result_bleibt_im_empty_state(widget):
    """Ein ScanResult mit error-Feld schaltet NICHT auf die Ergebnis-Seite."""
    widget._on_scan_finished(  # noqa: SLF001
        _result([], error="Timeout beim Verbinden")
    )

    assert widget._scan_stack.currentIndex() == _STACK_EMPTY  # noqa: SLF001
    assert not widget._json_btn.isEnabled()  # noqa: SLF001


def test_scan_error_signal_bleibt_im_empty_state(widget):
    """Der scan_error-Pfad (Thread-Exception) bleibt im Empty-State."""
    widget._on_scan_error("DNS-Aufloesung fehlgeschlagen")  # noqa: SLF001

    assert widget._scan_stack.currentIndex() == _STACK_EMPTY  # noqa: SLF001
    assert not widget._pdf_btn.isEnabled()  # noqa: SLF001


def test_folge_scan_fehler_zeigt_keine_alte_kpi(widget, monkeypatch):
    """Scan-Start leert die KPI des Vorgaengers — ein fehlschlagender
    Folge-Scan darf keine Geister-Befunde behaupten (Review-P2)."""
    import tools.api_security.gui.api_security_widget as mod

    widget._on_scan_finished(_result([_finding(Severity.CRITICAL)]))  # noqa: SLF001
    assert "1 kritisch" in widget._kpi_label.text()  # noqa: SLF001

    class _DummyThread:
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            self.scan_finished = MagicMock()
            self.scan_error = MagicMock()

        def start(self) -> None:
            pass

    monkeypatch.setattr(mod, "_ScanThread", _DummyThread)
    widget._url_input.setText("https://api.example.com/v1")  # noqa: SLF001
    widget._on_scan_clicked()  # noqa: SLF001

    assert widget._kpi_label.text() == ""  # noqa: SLF001

    widget._on_scan_error("Timeout")  # noqa: SLF001
    assert widget._kpi_label.text() == ""  # noqa: SLF001
