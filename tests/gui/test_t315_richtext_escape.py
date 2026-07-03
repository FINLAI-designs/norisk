"""GUI-Tests: RichText-Injektionshärtung im Sovereignty-Step.

Scan-Daten (DetectedProvider.name/via/evidence, scan_errors) sind untrusted
(DNS/SPF/Software-Scan) und werden in RichText-Labels gerendert — sie MÜSSEN
escaped ankommen. Lockt die-Test-Pflicht 4 ein.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QLabel

from tools.customer_audit.domain.entities import DetectedProvider
from tools.customer_audit.gui.step_widgets.sovereignty_step import SovereigntyStep

pytestmark = pytest.mark.gui


def _alle_label_texte(widget) -> str:
    return "\n".join(lbl.text() for lbl in widget.findChildren(QLabel))


@pytest.fixture
def step(qtbot, app):  # noqa: ARG001
    s = SovereigntyStep()
    qtbot.add_widget(s)
    # Ohne aktive Detection early-returnt _refresh_provider_list
    s._chk_detection.setChecked(True)  # noqa: SLF001
    return s


def test_provider_markup_wird_escaped(step):
    """Markup in Scan-Evidence erscheint als Entity, nie als Roh-Tag."""
    step._detected = [  # noqa: SLF001
        DetectedProvider(
            name="<img src=x onerror=alert(1)>",
            status="cloud_act",
            category="Mail",
            via="<b>dns_mx</b>",
            evidence="<script>alert(1)</script>",
        )
    ]
    step._refresh_provider_list(scan_errors=[])  # noqa: SLF001

    texte = _alle_label_texte(step)
    assert "&lt;img src=x" in texte
    assert "&lt;script&gt;" in texte
    assert "&lt;b&gt;dns_mx&lt;/b&gt;" in texte
    assert "<script>" not in texte
    assert "<img src=x" not in texte


def test_scan_fehler_werden_escaped(step):
    """Scan-Fehlertexte (Netz-Antworten) werden escaped gerendert."""
    step._detected = []  # noqa: SLF001
    step._refresh_provider_list(  # noqa: SLF001
        scan_errors=['DNS: <i>timeout</i> bei "example.at"']
    )

    texte = _alle_label_texte(step)
    assert "&lt;i&gt;timeout&lt;/i&gt;" in texte
    assert "<i>timeout</i>" not in texte


def test_backup_step_detected_label_ist_plaintext(qtbot, app):  # noqa: ARG001
    """-Pflicht 4 (DetectedTool): Scan-Namen nie als Auto-RichText."""
    from PySide6.QtCore import Qt

    from tools.customer_audit.gui.step_widgets.backup_step import BackupStep

    s = BackupStep()
    qtbot.add_widget(s)
    assert s._lbl_detected.textFormat() == Qt.TextFormat.PlainText  # noqa: SLF001


def test_summary_step_firmenname_und_empfehlungen_plaintext(qtbot, app):  # noqa: ARG001
    """Review-P1: Summary rendert Klartext-Freitexte nie als Auto-RichText."""
    from PySide6.QtCore import Qt

    from tools.customer_audit.domain.entities import (
        CustomerAuditResult,
        CustomerData,
        InfrastructureData,
        NetworkData,
        OrganizationalData,
    )
    from tools.customer_audit.gui.step_widgets.summary_step import SummaryStep

    s = SummaryStep()
    qtbot.add_widget(s)
    result = CustomerAuditResult(
        audit_id="sum-1",
        customer_data=CustomerData(firmenname="Acme <img src=x> & Co."),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
        created_at="2026-06-11T10:00:00+00:00",
        recommendations=["[Kritisch] Virenschutz '<b>Defender</b>' prüfen"],
    )
    s.set_result(result)

    betroffene = [
        lbl
        for lbl in s.findChildren(QLabel)
        if "Acme" in lbl.text() or "Defender" in lbl.text()
    ]
    assert betroffene, "Erwartete Labels nicht gefunden"
    for lbl in betroffene:
        assert lbl.textFormat() == Qt.TextFormat.PlainText


def test_audit_listenzeile_firmenname_plaintext(qtbot, app):  # noqa: ARG001
    """Review-P1: die Audit-Liste rendert firmenname nie als Auto-RichText."""
    from unittest.mock import MagicMock

    from PySide6.QtCore import Qt

    from tools.customer_audit.gui.customer_list_widget import CustomerListWidget

    services = MagicMock()
    services.load.get_all_summaries.return_value = [
        {
            "audit_id": "a1",
            "firmenname": "Acme <img src=x> & Co.",
            "created_at": "2026-06-11T10:00:00+00:00",
            "overall_score": 70.0,
            "risk_level": "Mittel",
            "version": 1,
        }
    ]
    w = CustomerListWidget(services)
    qtbot.add_widget(w)

    betroffene = [
        lbl for lbl in w.findChildren(QLabel) if "Acme" in lbl.text()
    ]
    assert betroffene, "Firmenname-Label nicht gefunden"
    for lbl in betroffene:
        assert lbl.textFormat() == Qt.TextFormat.PlainText


def test_customer_data_step_roundtrip_sonderzeichen(qtbot, app):  # noqa: ARG001
    """-Pflicht 3: get_data→set_data ist byte-identisch für
    'Müller & Co. <GmbH>' (kein Escape-Artefakt mehr im Roundtrip)."""
    from tools.customer_audit.gui.step_widgets.customer_data_step import (
        CustomerDataStep,
    )

    raw = 'Müller & Co. <GmbH> "Wien"'
    s = CustomerDataStep()
    qtbot.add_widget(s)
    s._input_firma.setText(raw)  # noqa: SLF001
    data = s.get_data()
    assert data.firmenname == raw

    s2 = CustomerDataStep()
    qtbot.add_widget(s2)
    s2.set_data(data)
    assert s2._input_firma.text() == raw  # noqa: SLF001
