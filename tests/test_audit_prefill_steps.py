"""Tests fuer die SELF-Audit-Vorbefuellung im Wizard Phase 3).

Deckt ab:
* Infra-/Network-Step: ``apply_prefill`` mappt gemessene Werte korrekt
  (Roundtrip via ``get_data``), Override (Haken entfernen) gibt Felder frei und
  behaelt den Wert, ``set_prefill_available(False)`` (CUSTOMER) sperrt + leert.
* Leeres/nicht-messbares Prefill aendert nichts + hakt ab.
* Wizard-Orchestrierung: Cache (kein Doppel-Scan), Verteilung an wartende Steps,
  fail-soft ohne Provider — alles ohne echten Hintergrund-Scan getestet.

Nicht ``@pytest.mark.gui`` (laeuft im Push-Gate) — nutzt nur das pytest-qt
``qapp``-Fixture, keine Event-Loop/qtbot-Interaktion.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from core.scan_prefill.models import AuditPrefill, MeasuredField
from tools.customer_audit.domain.entities import AuditMode
from tools.customer_audit.gui.step_widgets.infrastructure_step import (
    InfrastructureStep,
)
from tools.customer_audit.gui.step_widgets.network_step import NetworkStep

_TS = "2026-06-27T10:00:00+00:00"


def _mf(value: bool | str, check_id: str = "SH-001") -> MeasuredField:
    return MeasuredField(
        value=value,
        check_id=check_id,
        source_tool="system_scanner",
        measured_at=_TS,
    )


def _full_infra_prefill() -> AuditPrefill:
    return AuditPrefill(
        firewall_active=_mf(True, "SH-001"),
        remote_access_rdp=_mf(True, "SH-003"),
        disk_encryption_active=_mf(True, "SH-010"),
        patch_ok=_mf(True, "SH-004"),
        os_name=_mf("Windows 11", "os_info"),
        open_ports_scanned=_mf(True, "network_scanner"),
        generated_at=_TS,
    )


# ---------------------------------------------------------------------------
# InfrastructureStep
# ---------------------------------------------------------------------------


class TestInfrastructureStepPrefill:
    def test_apply_prefill_maps_all_fields(self, qapp) -> None:  # noqa: ARG002
        step = InfrastructureStep()
        step.apply_prefill(_full_infra_prefill())
        data = step.get_data()
        assert data.firewall_status == "aktiv"
        assert "Windows 11" in data.betriebssysteme
        assert "BitLocker" in data.verschluesselung
        assert "RDP" in data.remote_access_tools
        assert data.os_patch_stand  # nicht leer (SH-004-Text)

    def test_measured_fields_are_readonly_until_override(self, qapp) -> None:  # noqa: ARG002
        step = InfrastructureStep()
        step._chk_prefill.setChecked(True)  # noqa: SLF001 — Opt-in simulieren
        step.apply_prefill(_full_infra_prefill())
        assert not step._combo_fw_status.isEnabled()  # noqa: SLF001
        # Override: Haken entfernen -> Felder editierbar, Wert bleibt erhalten.
        step._chk_prefill.setChecked(False)  # noqa: SLF001
        assert step._combo_fw_status.isEnabled()  # noqa: SLF001
        assert step.get_data().firewall_status == "aktiv"

    def test_firewall_inactive_maps_to_inaktiv(self, qapp) -> None:  # noqa: ARG002
        step = InfrastructureStep()
        step.apply_prefill(AuditPrefill(firewall_active=_mf(False), generated_at=_TS))
        assert step.get_data().firewall_status == "inaktiv"

    def test_rdp_not_in_use_does_not_add_rdp(self, qapp) -> None:  # noqa: ARG002
        step = InfrastructureStep()
        step.apply_prefill(
            AuditPrefill(remote_access_rdp=_mf(False, "SH-003"), generated_at=_TS)
        )
        assert "RDP" not in step.get_data().remote_access_tools

    def test_customer_gate_clears_resets_and_disables(self, qapp) -> None:  # noqa: ARG002
        step = InfrastructureStep()
        step._chk_prefill.setChecked(True)  # noqa: SLF001
        step.apply_prefill(_full_infra_prefill())
        step.set_prefill_available(False)  # CUSTOMER
        assert not step._chk_prefill.isEnabled()  # noqa: SLF001
        assert not step._chk_prefill.isChecked()  # noqa: SLF001
        assert step._combo_fw_status.isEnabled()  # noqa: SLF001 — entsperrt
        assert step._measured_widgets == []  # noqa: SLF001
        # CUSTOMER-Gate setzt gemessene Eigenscan-Werte HART zurueck (kein Leak).
        data = step.get_data()
        assert data.firewall_status == "unbekannt"
        assert data.betriebssysteme == []
        assert data.verschluesselung == []
        assert data.remote_access_tools == []
        assert data.os_patch_stand == ""

    def test_apply_prefill_noop_when_unavailable(self, qapp) -> None:  # noqa: ARG002
        step = InfrastructureStep()
        step.set_prefill_available(False)  # CUSTOMER -> gesperrt
        step.apply_prefill(_full_infra_prefill())  # darf NICHTS tun (fail-closed)
        data = step.get_data()
        assert "Windows 11" not in data.betriebssysteme
        assert "BitLocker" not in data.verschluesselung
        assert "RDP" not in data.remote_access_tools
        assert step._measured_widgets == []  # noqa: SLF001

    def test_bitlocker_inactive_not_added(self, qapp) -> None:  # noqa: ARG002
        step = InfrastructureStep()
        step.apply_prefill(
            AuditPrefill(disk_encryption_active=_mf(False, "SH-010"), generated_at=_TS)
        )
        assert "BitLocker" not in step.get_data().verschluesselung

    def test_empty_prefill_changes_nothing(self, qapp) -> None:  # noqa: ARG002
        step = InfrastructureStep()
        step._chk_prefill.setChecked(True)  # noqa: SLF001
        step.apply_prefill(AuditPrefill(generated_at=_TS))
        assert step._measured_widgets == []  # noqa: SLF001
        assert not step._chk_prefill.isChecked()  # noqa: SLF001 — wieder abgehakt

    def test_toggle_on_emits_request(self, qapp) -> None:  # noqa: ARG002
        step = InfrastructureStep()
        received: list = []
        step.prefill_requested.connect(received.append)
        step._chk_prefill.setChecked(True)  # noqa: SLF001
        assert received == [step]


# ---------------------------------------------------------------------------
# NetworkStep
# ---------------------------------------------------------------------------


class TestNetworkStepPrefill:
    def test_apply_prefill_sets_ports_known(self, qapp) -> None:  # noqa: ARG002
        step = NetworkStep()
        step.apply_prefill(
            AuditPrefill(
                open_ports_scanned=_mf(True, "network_scanner"), generated_at=_TS
            )
        )
        assert step.get_data().offene_ports_bekannt == "Ja"
        assert not step._combo_ports.isEnabled()  # noqa: SLF001

    def test_no_scan_leaves_default(self, qapp) -> None:  # noqa: ARG002
        step = NetworkStep()
        step._chk_prefill.setChecked(True)  # noqa: SLF001
        step.apply_prefill(AuditPrefill(generated_at=_TS))
        assert step.get_data().offene_ports_bekannt == "Nein"
        assert not step._chk_prefill.isChecked()  # noqa: SLF001

    def test_customer_gate_clears_and_disables(self, qapp) -> None:  # noqa: ARG002
        step = NetworkStep()
        step.apply_prefill(
            AuditPrefill(
                open_ports_scanned=_mf(True, "network_scanner"), generated_at=_TS
            )
        )
        step.set_prefill_available(False)
        assert not step._chk_prefill.isEnabled()  # noqa: SLF001
        assert step._combo_ports.isEnabled()  # noqa: SLF001
        assert step._measured_widgets == []  # noqa: SLF001
        # CUSTOMER-Gate setzt den gemessenen Wert HART zurueck (kein Leak).
        assert step.get_data().offene_ports_bekannt == "Nein"

    def test_apply_prefill_noop_when_unavailable(self, qapp) -> None:  # noqa: ARG002
        step = NetworkStep()
        step.set_prefill_available(False)
        step.apply_prefill(
            AuditPrefill(
                open_ports_scanned=_mf(True, "network_scanner"), generated_at=_TS
            )
        )
        assert step.get_data().offene_ports_bekannt == "Nein"
        assert step._measured_widgets == []  # noqa: SLF001


# ---------------------------------------------------------------------------
# Wizard-Orchestrierung (ohne echten Hintergrund-Scan)
# ---------------------------------------------------------------------------


def _make_wizard(scan_prefill=None):  # noqa: ANN001, ANN202
    from tools.customer_audit.gui.customer_wizard import CustomerWizard

    services = MagicMock()
    services.scan_prefill = scan_prefill
    return CustomerWizard(services, risk_service=MagicMock())


class TestWizardPrefillOrchestration:
    def test_no_provider_notifies_failed(self, qapp) -> None:  # noqa: ARG002
        wizard = _make_wizard(scan_prefill=None)
        step = MagicMock()
        wizard._on_prefill_requested(step)  # noqa: SLF001
        step.notify_prefill_failed.assert_called_once()
        step.apply_prefill.assert_not_called()

    def test_cached_prefill_applied_without_worker(self, qapp) -> None:  # noqa: ARG002
        wizard = _make_wizard(scan_prefill=MagicMock())
        prefill = AuditPrefill(generated_at=_TS)
        wizard._audit_prefill = prefill  # noqa: SLF001 — Cache simulieren
        step = MagicMock()
        wizard._on_prefill_requested(step)  # noqa: SLF001
        step.apply_prefill.assert_called_once_with(prefill)
        assert wizard._prefill_running is False  # noqa: SLF001 — kein Worker

    def test_done_caches_and_distributes_to_pending(self, qapp) -> None:  # noqa: ARG002
        wizard = _make_wizard(scan_prefill=MagicMock())
        s1, s2 = MagicMock(), MagicMock()
        wizard._prefill_pending = [s1, s2]  # noqa: SLF001
        wizard._prefill_running = True  # noqa: SLF001
        prefill = AuditPrefill(generated_at=_TS)
        wizard._on_prefill_done(prefill)  # noqa: SLF001
        assert wizard._audit_prefill is prefill  # noqa: SLF001
        assert wizard._prefill_running is False  # noqa: SLF001
        s1.apply_prefill.assert_called_once_with(prefill)
        s2.apply_prefill.assert_called_once_with(prefill)

    def test_customer_mode_disables_prefill_on_steps(self, qapp) -> None:  # noqa: ARG002
        wizard = _make_wizard(scan_prefill=MagicMock())
        wizard._apply_mode_to_scanner_steps(AuditMode.CUSTOMER)  # noqa: SLF001
        assert not wizard._step_infra._chk_prefill.isEnabled()  # noqa: SLF001
        assert not wizard._step_network._chk_prefill.isEnabled()  # noqa: SLF001
        wizard._apply_mode_to_scanner_steps(AuditMode.SELF)  # noqa: SLF001
        assert wizard._step_infra._chk_prefill.isEnabled()  # noqa: SLF001
        assert wizard._step_network._chk_prefill.isEnabled()  # noqa: SLF001

    def test_failed_distributes_to_pending(self, qapp) -> None:  # noqa: ARG002
        wizard = _make_wizard(scan_prefill=MagicMock())
        s1, s2 = MagicMock(), MagicMock()
        wizard._prefill_pending = [s1, s2]  # noqa: SLF001
        wizard._prefill_running = True  # noqa: SLF001
        wizard._on_prefill_failed("TestError")  # noqa: SLF001
        assert wizard._prefill_running is False  # noqa: SLF001
        s1.notify_prefill_failed.assert_called_once_with("TestError")
        s2.notify_prefill_failed.assert_called_once_with("TestError")

    def test_customer_mode_invalidates_cache_and_pending(self, qapp) -> None:  # noqa: ARG002
        """Mid-Scan-Race: CUSTOMER verwirft Cache + Warteschlange (kein Leak)."""
        wizard = _make_wizard(scan_prefill=MagicMock())
        wizard._audit_prefill = AuditPrefill(generated_at=_TS)  # noqa: SLF001
        wizard._prefill_pending = [MagicMock()]  # noqa: SLF001
        wizard._prefill_running = True  # noqa: SLF001
        wizard._apply_mode_to_scanner_steps(AuditMode.CUSTOMER)  # noqa: SLF001
        assert wizard._audit_prefill is None  # noqa: SLF001
        assert wizard._prefill_pending == []  # noqa: SLF001
        assert wizard._prefill_running is False  # noqa: SLF001
