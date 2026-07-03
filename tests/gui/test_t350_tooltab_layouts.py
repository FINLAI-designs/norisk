"""GUI-Tests für die Tool-Tab-Raumnutzung AP5a/b/c).

Lockt das Muster „eine Primärfläche pro Seite" ein:

* techstack: Stack-Tabelle ohne Höhendeckel, CVE-Bereich mit Empty-State
  statt leerem Raster (AP5a).
* password_checker: 2-Spalten-Split — Ergebnis-Stack startet im
  Empty-State und schaltet nach der Prüfung auf das Ergebnis um (AP5b).
* cert_monitor: Detail-Panel startet eingeklappt, öffnet bei Selektion
  und klappt bei leerer Selektion wieder zu (AP5c).

Headless via pytest-qt (offscreen); Services gemockt, kein Netzwerk.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from tools.cert_monitor.application.cert_monitor_service import CertMonitorService
from tools.cert_monitor.domain.models import CertInfo
from tools.cert_monitor.gui.cert_monitor_widget import CertMonitorWidget
from tools.cyber_dashboard.application.dashboard_service import DashboardService
from tools.cyber_dashboard.domain.models import CveEintrag
from tools.password_checker.application.password_service import PasswordService
from tools.password_checker.domain.models import (
    PasswordCheckResult,
    PasswordStaerke,
)
from tools.password_checker.gui.password_checker_widget import PasswordCheckerWidget
from tools.techstack.gui.techstack_widget import TechStackWidget

pytestmark = pytest.mark.gui


# ---------------------------------------------------------------------------
# AP5a — techstack
# ---------------------------------------------------------------------------


@pytest.fixture
def techstack_widget(qtbot, app):  # noqa: ARG001
    """TechStack-Widget mit gemocktem Service (leerer Stack)."""
    service = MagicMock(spec=DashboardService)
    service.lade_techstack.return_value = []
    w = TechStackWidget(service)
    qtbot.add_widget(w)
    return w


def test_techstack_stack_tabelle_ohne_hoehendeckel(techstack_widget):
    """Die Primärtabelle hat keinen 180px-Deckel mehr (Muster R2)."""
    assert techstack_widget._stack_tabelle.maximumHeight() > 10_000  # noqa: SLF001


def test_techstack_cve_bereich_startet_im_empty_state(techstack_widget):
    """Vor dem ersten Laden zeigt der CVE-Bereich den Hinweis, kein Raster."""
    stack = techstack_widget._cve_stack  # noqa: SLF001
    assert stack.currentWidget() is techstack_widget._cve_empty_lbl  # noqa: SLF001


def test_techstack_cve_tabelle_erscheint_bei_daten(techstack_widget):
    """Mit Treffern schaltet der CVE-Bereich auf die Tabelle um."""
    cve = CveEintrag(
        cve_id="CVE-2026-0001",
        beschreibung="Test",
        schweregrad="HIGH",
        cvss_score=8.1,
        veroeffentlicht=datetime.now(UTC),
        geaendert=datetime.now(UTC),
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
    )
    techstack_widget._cve_tabelle_befuellen([cve])  # noqa: SLF001
    stack = techstack_widget._cve_stack  # noqa: SLF001
    assert stack.currentWidget() is techstack_widget._cve_tabelle  # noqa: SLF001

    # Leeres Ergebnis fällt zurück auf den Empty-State (positiver Befund).
    techstack_widget._cve_tabelle_befuellen([])  # noqa: SLF001
    assert stack.currentWidget() is techstack_widget._cve_empty_lbl  # noqa: SLF001
    assert "gefunden" in techstack_widget._cve_empty_lbl.text()  # noqa: SLF001


def test_techstack_fehlschlag_zeigt_keine_entwarnung(techstack_widget):
    """Eine fehlgeschlagene Suche darf NICHT 'Keine CVEs gefunden' sagen
    (Review-P2: falscher Positiv-Befund in einem Security-Tool)."""
    techstack_widget._cves_fehlgeschlagen("ConnectionError")  # noqa: SLF001
    text = techstack_widget._cve_empty_lbl.text()  # noqa: SLF001
    assert "fehlgeschlagen" in text
    assert "Keine CVEs für" not in text
    assert techstack_widget._btn_cve_suchen.isEnabled()  # noqa: SLF001


def test_techstack_offline_ohne_cache_keine_entwarnung(techstack_widget):
    """Leeres Ergebnis bei NVD-offline-ohne-Cache ist keine Entwarnung."""
    techstack_widget._cve_tabelle_befuellen(  # noqa: SLF001
        [], befund_moeglich=False
    )
    text = techstack_widget._cve_empty_lbl.text()  # noqa: SLF001
    assert "keine Aussage" in text


# ---------------------------------------------------------------------------
# AP5b — password_checker
# ---------------------------------------------------------------------------


@pytest.fixture
def pw_widget(qtbot, app):  # noqa: ARG001
    """Passwort-Checker mit gemocktem Service."""
    service = MagicMock(spec=PasswordService)
    w = PasswordCheckerWidget(service)
    qtbot.add_widget(w)
    return w


def test_password_checker_startet_im_empty_state(pw_widget):
    """Rechte Spalte zeigt vor der ersten Prüfung den Hinweis-Text."""
    assert pw_widget._ergebnis_stack.currentIndex() == 0  # noqa: SLF001


def test_password_checker_ergebnis_expandiert_rechts(pw_widget):
    """Nach der Prüfung schaltet die rechte Spalte aufs Ergebnis um."""
    result = PasswordCheckResult(
        staerke=PasswordStaerke.MITTEL,
        score=55,
        entropie_bits=42.0,
        laenge=12,
    )
    pw_widget._zeige_ergebnis(result)  # noqa: SLF001
    assert pw_widget._ergebnis_stack.currentIndex() == 1  # noqa: SLF001


# ---------------------------------------------------------------------------
# AP5c — cert_monitor
# ---------------------------------------------------------------------------


@pytest.fixture
def cert_widget(qtbot, app):  # noqa: ARG001
    """Cert-Monitor mit gemocktem Service (keine Domains)."""
    service = MagicMock(spec=CertMonitorService)
    service.lade_letzte_ergebnisse.return_value = []
    service.lade_domains.return_value = []
    w = CertMonitorWidget(service)
    qtbot.add_widget(w)
    return w


def test_cert_monitor_detail_startet_eingeklappt(cert_widget):
    """Ohne Selektion reserviert das Detail-Panel keine Fläche (Muster R4)."""
    assert cert_widget._splitter.sizes()[1] == 0  # noqa: SLF001


def test_cert_monitor_empty_state_ohne_domains(cert_widget):
    """0 Domains → Hinweis statt leerem 5-Spalten-Raster (Muster R3)."""
    stack = cert_widget._tabelle_stack  # noqa: SLF001
    assert stack.currentWidget() is cert_widget._tabelle_empty_lbl  # noqa: SLF001


def test_cert_monitor_selektion_oeffnet_detail(cert_widget, qtbot):
    """Eine Zeilen-Selektion öffnet das Detail-Panel, Deselektion schließt."""
    service = cert_widget._service  # noqa: SLF001
    cert = CertInfo(domain="example.at", port=443)
    service.lade_letzte_ergebnisse.return_value = [cert]
    service.lade_domains.return_value = [("example.at", 443)]
    cert_widget._lade_gespeicherte_ergebnisse()  # noqa: SLF001

    assert (
        cert_widget._tabelle_stack.currentWidget()  # noqa: SLF001
        is cert_widget._tabelle  # noqa: SLF001
    )

    cert_widget._tabelle.selectRow(0)  # noqa: SLF001
    assert cert_widget._splitter.sizes()[1] > 0  # noqa: SLF001

    cert_widget._tabelle.clearSelection()  # noqa: SLF001
    assert cert_widget._splitter.sizes()[1] == 0  # noqa: SLF001
