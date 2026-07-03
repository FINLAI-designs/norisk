"""
test_audit_step_widgets — Headless-GUI-Tests fuer die Wizard-Step-Widgets.

Review-Followup: die Step-Widgets von Iter 1a..1c
hatten zwei latente Bugs, die kein bestehender Test gefangen hat:

1. ``ModeSelectStep`` / ``BackupStep`` / ``SovereigntyStep`` /
   ``IncidentResponseStep`` hatten ``validate`` statt der vom
   Wizard erwarteten ``is_valid``-Methode → ``AttributeError`` beim
   ersten Klick auf "Weiter".
2. ``SovereigntyStep.get_data`` baute das Result via
   ``SovereigntyAuditResult(**audit.to_dict)`` — dadurch landeten
   serialisierte ``dict``-Provider im ``detected``-Feld und das
   anschliessende ``CustomerAuditResult.to_dict`` crashte mit
   ``AttributeError: 'dict' object has no attribute 'to_dict'``.

Diese Test-Suite deckt beide Faelle ab, indem sie die Step-Widgets
direkt instanziiert und einen Roundtrip
(get_data → CustomerAuditResult.to_dict → from_dict → equal) prueft.

Schichtzugehoerigkeit: tests/ — darf alle Schichten anfassen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

from tools.customer_audit.domain.entities import (
    AuditMode,
    BackupAuditResult,
    CustomerAuditResult,
    CustomerData,
    DetectedProvider,
    IncidentResponsePlan,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
    SovereigntyAuditResult,
)


@pytest.fixture(scope="module")
def qapp():
    """Stellt eine ``QApplication`` fuer alle Tests im Modul bereit."""
    from PySide6.QtWidgets import QApplication  # noqa: PLC0415

    app = QApplication.instance() or QApplication([])
    yield app


# ---------------------------------------------------------------------------
# is_valid-Vertrag fuer alle Step-Widgets
# ---------------------------------------------------------------------------


def test_mode_select_step_hat_is_valid(qapp) -> None:
    """Regression: ModeSelectStep muss ``is_valid`` haben (nicht ``validate``).
    Sonst crasht der Wizard beim ersten Klick auf "Weiter".
    """
    from tools.customer_audit.gui.step_widgets.mode_select_step import (  # noqa: PLC0415
        ModeSelectStep,
    )

    step = ModeSelectStep()
    assert callable(getattr(step, "is_valid", None))
    assert step.is_valid() is True


def test_backup_step_hat_is_valid(qapp) -> None:
    from tools.customer_audit.gui.step_widgets.backup_step import (  # noqa: PLC0415
        BackupStep,
    )

    step = BackupStep()
    assert callable(getattr(step, "is_valid", None))
    assert step.is_valid() is True


def test_sovereignty_step_hat_is_valid(qapp) -> None:
    from tools.customer_audit.gui.step_widgets.sovereignty_step import (  # noqa: PLC0415
        SovereigntyStep,
    )

    step = SovereigntyStep()
    assert callable(getattr(step, "is_valid", None))
    assert step.is_valid() is True


def test_incident_response_step_hat_is_valid(qapp) -> None:
    from tools.customer_audit.gui.step_widgets.incident_response_step import (  # noqa: PLC0415
        IncidentResponseStep,
    )

    step = IncidentResponseStep()
    assert callable(getattr(step, "is_valid", None))
    assert step.is_valid() is True


# ---------------------------------------------------------------------------
# Roundtrip-Tests: get_data -> CustomerAuditResult.to_dict darf nicht crashen
# ---------------------------------------------------------------------------


def test_backup_step_roundtrip(qapp) -> None:
    """BackupStep: get_data liefert ein well-formed Dataclass, das via
    ``CustomerAuditResult.to_dict / from_dict`` rundtrippen kann."""
    from tools.customer_audit.gui.step_widgets.backup_step import (  # noqa: PLC0415
        BackupStep,
    )

    step = BackupStep()
    audit = step.get_data()
    assert isinstance(audit, BackupAuditResult)

    # Ueber das Aggregat-Result in JSON serialisieren
    result = CustomerAuditResult(
        audit_id="test",
        customer_data=CustomerData(firmenname="Test"),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
        backup_audit=audit,
        category_scores=[],
        overall_score=0.0,
        risk_level="niedrig",
        recommendations=[],
    )
    payload = result.to_dict()
    reloaded = CustomerAuditResult.from_dict(payload)
    assert isinstance(reloaded.backup_audit, BackupAuditResult)


def test_sovereignty_step_roundtrip_keine_dict_in_detected(qapp) -> None:
    """SovereigntyStep: ``detected`` und ``declared`` muessen
    ``DetectedProvider``-Instanzen enthalten, NICHT dicts.

    Vor-Review-Followup baute ``get_data`` das Result via
    ``**audit.to_dict`` und uebergab damit serialisierte dicts an den
    Konstruktor — der naechste ``to_dict``-Call crashte mit
    ``AttributeError: 'dict' object has no attribute 'to_dict'``.
    """
    from tools.customer_audit.gui.step_widgets.sovereignty_step import (  # noqa: PLC0415
        SovereigntyStep,
    )

    step = SovereigntyStep()
    # Manuelle Detection-Befund injizieren
    step._detected = [
        DetectedProvider(
            name="Hetzner",
            status="eu_sovereign",
            category="saas_other",
            via="dns_mx",
            evidence="mx.hetzner.com",
        )
    ]
    audit = step.get_data()
    assert isinstance(audit, SovereigntyAuditResult)
    # Kernregression: detected enthaelt Dataclasses, keine dicts.
    assert all(isinstance(p, DetectedProvider) for p in audit.detected)

    # Aggregat-Roundtrip darf nicht crashen
    result = CustomerAuditResult(
        audit_id="test",
        customer_data=CustomerData(firmenname="Test"),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
        sovereignty_audit=audit,
        category_scores=[],
        overall_score=0.0,
        risk_level="niedrig",
        recommendations=[],
    )
    payload = result.to_dict()
    reloaded = CustomerAuditResult.from_dict(payload)
    assert isinstance(reloaded.sovereignty_audit, SovereigntyAuditResult)
    assert all(
        isinstance(p, DetectedProvider) for p in reloaded.sovereignty_audit.detected
    )


def test_sovereignty_step_teams_ueberlebt_reload(qapp) -> None:
    """: 'Microsoft Teams' geht beim Wiederoeffnen nicht mehr verloren.

    ``find_by_keyword('Microsoft Teams')`` kollabiert im Catalog auf
    'Microsoft 365'; vor dem Fix matchte ``set_data`` per ``name`` und das
    Teams-Haeckchen ging verloren. Jetzt traegt ``_collect_declared`` das
    Original-Label mit und ``set_data`` matcht label-treu (Regression).
    """
    from tools.customer_audit.gui.step_widgets.sovereignty_step import (  # noqa: PLC0415
        SovereigntyStep,
    )

    step = SovereigntyStep()
    step._declaration_combos["Microsoft Teams"].setChecked(True)

    audit = step.get_data()
    # Persistenz-Roundtrip nachbilden (Widget -> dict -> dict -> Widget).
    reloaded_audit = SovereigntyAuditResult.from_dict(audit.to_dict())

    fresh = SovereigntyStep()
    fresh.set_data(reloaded_audit)
    assert fresh._declaration_combos["Microsoft Teams"].isChecked()
    # 'Microsoft 365' war nicht angehakt -> bleibt aus (keine Falsch-Positiven).
    assert not fresh._declaration_combos["Microsoft 365"].isChecked()


def test_incident_response_step_roundtrip(qapp) -> None:
    """IncidentResponseStep: get_data rundtrippt ohne Crash."""
    from tools.customer_audit.gui.step_widgets.incident_response_step import (  # noqa: PLC0415
        IncidentResponseStep,
    )

    step = IncidentResponseStep()
    plan = step.get_data()
    assert isinstance(plan, IncidentResponsePlan)

    result = CustomerAuditResult(
        audit_id="test",
        customer_data=CustomerData(firmenname="Test"),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
        incident_response_plan=plan,
        category_scores=[],
        overall_score=0.0,
        risk_level="niedrig",
        recommendations=[],
    )
    payload = result.to_dict()
    reloaded = CustomerAuditResult.from_dict(payload)
    assert isinstance(reloaded.incident_response_plan, IncidentResponsePlan)


def test_mode_select_step_roundtrip(qapp) -> None:
    from tools.customer_audit.gui.step_widgets.mode_select_step import (  # noqa: PLC0415
        ModeSelectStep,
    )

    step = ModeSelectStep()
    assert step.get_mode() == AuditMode.SELF
    step.set_mode(AuditMode.CUSTOMER)
    assert step.get_mode() == AuditMode.CUSTOMER


# ---------------------------------------------------------------------------
# Phase 1: Detektions-Sperre im Kunden-Audit (GUI-Guard)
# ---------------------------------------------------------------------------


def test_backup_step_set_detection_unavailable_clears_and_disables(qapp) -> None:
    from tools.customer_audit.gui.step_widgets.backup_step import (  # noqa: PLC0415
        BackupStep,
    )

    step = BackupStep()
    # Detektion-an-mit-Treffer-Zustand deterministisch herstellen (ohne echten
    # Registry-Scan): Signal blocken, Flag setzen, Treffer manuell eintragen.
    step._chk_detection.blockSignals(True)
    step._chk_detection.setChecked(True)
    step._chk_detection.blockSignals(False)
    step._detected_tools = ["Veeam Agent"]

    step.set_detection_available(False)

    assert step._chk_detection.isChecked() is False
    assert step._chk_detection.isEnabled() is False
    assert step._detected_tools == []
    data = step.get_data()
    assert data.detection_enabled is False
    assert data.detected_tools == []

    # Zurueck auf SELF: Schalter wieder bedienbar.
    step.set_detection_available(True)
    assert step._chk_detection.isEnabled() is True


def test_sovereignty_step_set_detection_unavailable_clears_and_disables(qapp) -> None:
    from tools.customer_audit.gui.step_widgets.sovereignty_step import (  # noqa: PLC0415
        SovereigntyStep,
    )

    step = SovereigntyStep()
    step._chk_detection.blockSignals(True)
    step._chk_detection.setChecked(True)
    step._chk_detection.blockSignals(False)
    step._detected = [
        DetectedProvider(
            name="Microsoft 365",
            status="eu_boundary",
            category="saas_other",
            via="dns_mx",
            evidence="mx: outlook.com",
        )
    ]

    step.set_detection_available(False)

    assert step._chk_detection.isChecked() is False
    assert step._chk_detection.isEnabled() is False
    assert step._detected == []
    data = step.get_data()
    assert data.detection_enabled is False
    assert data.detected == []

    step.set_detection_available(True)
    assert step._chk_detection.isEnabled() is True


def test_sovereignty_step_customer_keeps_declared(qapp) -> None:
    # Die Sperre leert NUR den Scan-Bestand — selbst-deklarierte Dienste
    # (Fragebogen) bleiben erhalten.
    from tools.customer_audit.gui.step_widgets.sovereignty_step import (  # noqa: PLC0415
        SovereigntyStep,
    )

    step = SovereigntyStep()
    step._declaration_combos["DATEV"].setChecked(True)
    step.set_detection_available(False)

    data = step.get_data()
    assert data.detection_enabled is False
    assert any(p.name == "DATEV" or p.original_label == "DATEV" for p in data.declared)


def test_sovereignty_custom_service_add_und_reload(qapp) -> None:
    """: eigener Dienst -> Checkbox + collect + Reload-Roundtrip bleibt erhalten."""
    from tools.customer_audit.gui.step_widgets.sovereignty_step import (  # noqa: PLC0415
        SovereigntyStep,
    )

    step = SovereigntyStep()
    step._edt_custom_service.setText("Mein Spezial-CRM")
    step._on_add_custom_service()
    assert "Mein Spezial-CRM" in step._declaration_combos
    assert step._declaration_combos["Mein Spezial-CRM"].isChecked()
    assert step._edt_custom_service.text() == ""  # Eingabefeld geleert
    assert "Mein Spezial-CRM" in {p.name for p in step._collect_declared()}

    # Reload-Roundtrip in frischer Instanz: eigener Dienst wird wieder angelegt
    # UND angehakt (sonst gingen Custom-Dienste beim Laden verloren).
    audit = step.get_data()
    step2 = SovereigntyStep()
    step2.set_data(audit)
    assert "Mein Spezial-CRM" in step2._declaration_combos
    assert step2._declaration_combos["Mein Spezial-CRM"].isChecked()
