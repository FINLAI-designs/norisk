"""
test_customer_wizard_edit: Ansichts-Modus (view-only) für bestehende Audits.

Fehlersuche-Befund: Ein bestehendes Audit wurde im Wizard editierbar geöffnet,
Änderungen aber beim "Speichern & Schließen" still verworfen (Datenverlust).
Entscheidung (sauberste/sicherste Lösung): ein bestehendes Audit ist ein
unveränderlicher Record → schreibgeschützter Ansichts-Modus (kein Speichern;
Re-Assessment nach Remediation = neues Audit über den Neu-Flow).

Diese Tests sichern, dass im Ansichts-Modus NICHTS gespeichert/emittiert wird,
der Neu-Modus aber unverändert das berechnete Ergebnis emittiert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tools.customer_audit.gui.customer_wizard import CustomerWizard


class _SaveStub:
    """Minimal-Stub für den unbound-Aufruf von ``_save_and_close``."""

    def __init__(self, *, view_only, result=None):
        self._view_only = view_only
        self._result = result
        self.audit_saved = MagicMock()
        self.accept = MagicMock()


def test_view_only_close_does_not_emit():
    # Ansichts-Modus: bestehendes Audit wird NICHT gespeichert/emittiert.
    stub = _SaveStub(view_only=True, result=MagicMock())
    CustomerWizard._save_and_close(stub)
    stub.audit_saved.emit.assert_not_called()
    stub.accept.assert_called_once()


def test_new_mode_emits_and_closes():
    # Neu-Modus: das berechnete Ergebnis wird emittiert + Dialog geschlossen.
    existing = MagicMock()
    stub = _SaveStub(view_only=False, result=existing)
    CustomerWizard._save_and_close(stub)
    stub.audit_saved.emit.assert_called_once_with(existing)
    stub.accept.assert_called_once()


def test_new_mode_without_result_just_closes():
    # Neu-Modus ohne berechnetes Ergebnis: nur schliessen, kein Emit.
    stub = _SaveStub(view_only=False, result=None)
    CustomerWizard._save_and_close(stub)
    stub.audit_saved.emit.assert_not_called()
    stub.accept.assert_called_once()


@pytest.mark.gui
def test_customer_mode_gates_detection_steps(qtbot):  # noqa: ANN001
    # Phase 1: Wechsel auf Kunden-Audit sperrt die Auto-
    # Detektion in Backup- und Souveränitäts-Step; SELF gibt sie wieder frei.
    from tools.customer_audit.domain.entities import AuditMode

    wiz = CustomerWizard(MagicMock(), risk_service=MagicMock())
    qtbot.addWidget(wiz)

    # Default ist SELF → Detektion verfügbar.
    assert wiz._step_backup._chk_detection.isEnabled() is True
    assert wiz._step_sovereignty._chk_detection.isEnabled() is True

    # Über das ECHTE Signal gehen — verifiziert die mode_changed-Verdrahtung
    # im Wizard (nicht nur die Handler-Methode direkt). Bricht, wenn der
    # connect in __init__ entfernt wird.
    wiz._step_mode.mode_changed.emit(AuditMode.CUSTOMER)
    assert wiz._step_backup._chk_detection.isEnabled() is False
    assert wiz._step_backup._chk_detection.isChecked() is False
    assert wiz._step_sovereignty._chk_detection.isEnabled() is False

    wiz._step_mode.mode_changed.emit(AuditMode.SELF)
    assert wiz._step_backup._chk_detection.isEnabled() is True
    assert wiz._step_sovereignty._chk_detection.isEnabled() is True


@pytest.mark.gui
def test_view_only_button_state_on_summary(qtbot):  # noqa: ANN001
    # Default ist Neu-Modus; im Ansichts-Modus zeigt der Summary-Step nur
    # "Schließen" (kein Berechnen, kein Speichern) — Regressions-Guard gegen
    # versehentliches Wiederherstellen eines Schreib-Buttons.
    from tools.customer_audit.gui.customer_wizard import _SUMMARY_STEP

    wiz = CustomerWizard(MagicMock(), risk_service=MagicMock())
    qtbot.addWidget(wiz)
    assert wiz._view_only is False  # Default: Neu-Modus

    wiz._view_only = True
    wiz._stack.setCurrentIndex(_SUMMARY_STEP)
    wiz._update_navigation()
    assert wiz._btn_save.text() == "Schließen"
    assert not wiz._btn_calculate.isVisibleTo(wiz)


@pytest.mark.gui
def test_load_for_edit_routes_to_version_literal_bleibt(qtbot):  # noqa: ANN001
    # Routing +/-Semantik: Öffnen lädt editierbar
    # (load_for_edit, OHNE Unescape — DB ist Klartext); Berechnen/Speichern
    # routet zum CreateVersionUseCase. Ein LITERAL eingetipptes '&amp;' muss
    # den Edit-Roundtrip byte-identisch überleben (früher hätte der
    # Unescape es zu '&' zerstört) — End-to-End durch die Widgets.
    from tools.customer_audit.domain.entities import (  # noqa: PLC0415
        CustomerAuditResult,
        CustomerData,
        InfrastructureData,
        NetworkData,
        OrganizationalData,
    )

    base = CustomerAuditResult(
        audit_id="base-1",
        customer_data=CustomerData(firmenname="Acme &amp; Co"),  # Literal-Eingabe
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
    )
    services = MagicMock()
    services.create_version.execute.return_value = base
    risk = MagicMock()
    risk.load.return_value = []

    wiz = CustomerWizard(services, risk_service=risk)
    qtbot.addWidget(wiz)

    wiz.load_for_edit(base)
    assert wiz._base_audit_id == "base-1"
    assert wiz._view_only is False

    wiz._calculate()

    services.create_version.execute.assert_called_once()
    args, _kwargs = services.create_version.execute.call_args
    assert args[0] == "base-1"  # base_audit_id (positional)
    # Klartext-Roundtrip: das Literal bleibt byte-identisch erhalten.
    assert args[1].firmenname == "Acme &amp; Co"
    assert "&amp;amp;" not in args[1].firmenname


# ---------------------------------------------------------------------------
# Risikomatrix-Refresh — Re-Seed beim Betreten des Risk-Steps,
# unabhaengig von der Navigationsrichtung (_stack.currentChanged statt _go_next).
# ---------------------------------------------------------------------------


def test_betreten_des_risk_steps_reseedet(qtbot):  # noqa: ANN001
    """currentChanged auf den Risk-Step loest das Re-Seeding aus (jede Richtung)."""
    wiz = CustomerWizard(MagicMock(), risk_service=MagicMock())
    qtbot.addWidget(wiz)

    calls: list[bool] = []
    wiz._maybe_seed_risk = lambda: calls.append(True)  # noqa: SLF001 — Spy

    risk_idx = wiz._steps.index(wiz._step_risk)  # noqa: SLF001
    wiz._stack.setCurrentIndex(risk_idx)  # noqa: SLF001 — feuert currentChanged
    assert calls, "Betreten des Risk-Steps muss _maybe_seed_risk ausloesen"

    # Ein anderer Step loest KEIN Seeding aus.
    calls.clear()
    wiz._stack.setCurrentIndex(0)  # noqa: SLF001
    assert not calls


def test_cockpit_risk_matrix_empty_state_ohne_audit(qtbot):  # noqa: ANN001
    """Cockpit-Risikomatrix-Factory liefert ohne SELF-Audit einen Empty-State (kein Crash)."""
    from datetime import datetime

    from tools.norisk_dashboard.domain.models import (
        DashboardData,
        ScoreSnapshot,
        TimeRange,
    )
    from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget

    # Echte (leere) DashboardData, damit der deferred Initial-Refresh-Worker beim
    # Teardown sauber _apply durchlaeuft (statt an MagicMock-Attributen zu crashen).
    agg = MagicMock()
    agg.aggregate.return_value = DashboardData(
        time_range=TimeRange.WEEK,
        score=ScoreSnapshot(target="X"),
        generated=datetime(2026, 6, 28, 12, 0, 0),  # noqa: DTZ001
    )
    agg.subjects.return_value = []
    w = NoRiskDashboardWidget(aggregator=agg)
    qtbot.addWidget(w)
    w._last_data = None  # noqa: SLF001 — kein Audit-Stand
    widget = w._build_risk_matrix_content()  # noqa: SLF001
    assert widget is not None  # Empty-State-Widget, kein Crash
