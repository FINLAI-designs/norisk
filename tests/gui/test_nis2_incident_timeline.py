"""Tests fuer Nis2IncidentTimeline + die Pure-Function-Helper."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from core.widgets.charts import StepStatus
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    Nis2Incident,
    PhaseEvent,
    PhaseStatus,
)
from tools.customer_audit.gui.widgets.nis2_incident_timeline import (
    Nis2IncidentTimeline,
    incident_to_steps,
    map_phase_status_to_step,
)

pytestmark = pytest.mark.gui


class TestMapPhaseStatusToStep:
    def test_open_to_pending(self):
        assert map_phase_status_to_step(PhaseStatus.OPEN) is StepStatus.PENDING

    def test_in_progress_to_in_progress(self):
        assert (
            map_phase_status_to_step(PhaseStatus.IN_PROGRESS)
            is StepStatus.IN_PROGRESS
        )

    def test_done_to_done(self):
        assert map_phase_status_to_step(PhaseStatus.DONE) is StepStatus.DONE

    def test_skipped_to_skipped(self):
        assert (
            map_phase_status_to_step(PhaseStatus.SKIPPED) is StepStatus.SKIPPED
        )


def _incident(**overrides) -> Nis2Incident:
    defaults = {
        "incident_id": str(uuid.uuid4()),
        "audit_id": "audit-1",
        "title": "Test-Vorfall",
        "description": "Beschreibung",
        "severity": IncidentSeverity.HIGH,
        "detected_at": datetime(2026, 5, 27, 8, 0, tzinfo=UTC),
        "current_phase": IncidentPhase.DETECT,
    }
    defaults.update(overrides)
    return Nis2Incident(**defaults)


class TestIncidentToSteps:
    def test_six_steps_in_order(self):
        steps = incident_to_steps(_incident())
        labels = [step.label for step in steps]
        assert labels == [
            "Detect",
            "Triage",
            "24h Early-Warning",
            "72h Notification",
            "30d Final-Report",
            "Post-Incident",
        ]

    def test_current_phase_is_in_progress(self):
        incident = _incident(current_phase=IncidentPhase.EARLY_WARNING)
        steps = incident_to_steps(incident)
        ew_step = steps[2]
        assert ew_step.status is StepStatus.IN_PROGRESS

    def test_phase_before_current_is_done(self):
        incident = _incident(current_phase=IncidentPhase.NOTIFICATION)
        steps = incident_to_steps(incident)
        # DETECT, TRIAGE und EARLY_WARNING liegen vor NOTIFICATION
        assert steps[0].status is StepStatus.DONE
        assert steps[1].status is StepStatus.DONE
        assert steps[2].status is StepStatus.DONE

    def test_phase_after_current_is_pending(self):
        incident = _incident(current_phase=IncidentPhase.TRIAGE)
        steps = incident_to_steps(incident)
        assert steps[3].status is StepStatus.PENDING

    def test_skipped_event_propagates_to_step(self):
        incident = _incident(
            current_phase=IncidentPhase.EARLY_WARNING,
            events=(
                PhaseEvent(
                    event_id=1,
                    incident_id="x",
                    phase=IncidentPhase.TRIAGE,
                    status=PhaseStatus.SKIPPED,
                    actor="patrick",
                    note="kein erheblicher Vorfall",
                    occurred_at=datetime.now(UTC),
                ),
            ),
        )
        steps = incident_to_steps(incident)
        assert steps[1].status is StepStatus.SKIPPED

    def test_early_warning_deadline_is_24h(self):
        incident = _incident()
        steps = incident_to_steps(incident)
        ew_step = steps[2]
        assert ew_step.deadline == incident.detected_at + timedelta(hours=24)

    def test_detect_has_no_deadline(self):
        incident = _incident()
        steps = incident_to_steps(incident)
        assert steps[0].deadline is None


def test_widget_initial_state(app, qtbot):
    widget = Nis2IncidentTimeline()
    qtbot.addWidget(widget)
    assert widget.current_incident() is None
    # Im Empty-State sind die Action-Buttons disabled
    assert widget._advance_btn.isEnabled() is False
    assert widget._close_btn.isEnabled() is False


def test_widget_renders_incident(app, qtbot):
    widget = Nis2IncidentTimeline()
    qtbot.addWidget(widget)
    incident = _incident(current_phase=IncidentPhase.EARLY_WARNING)
    widget.set_incident(incident)
    assert widget.current_incident() is incident
    assert widget._advance_btn.isEnabled() is True
    assert widget._close_btn.isEnabled() is True


def test_widget_draft_ready_reflects_in_pill_and_button(app, qtbot):
    """D5b: draft_ready=True spiegelt sich im Status-Pill UND als Button-Nudge."""
    widget = Nis2IncidentTimeline()
    qtbot.addWidget(widget)
    incident = _incident(current_phase=IncidentPhase.EARLY_WARNING)
    widget.set_incident(incident, draft_ready=True)
    assert "bereit zum Einreichen" in widget._status_pill.text()  # noqa: SLF001
    assert widget._advance_btn.text() == "Phase einreichen →"  # noqa: SLF001
    assert widget._advance_btn.styleSheet() != ""  # noqa: SLF001 — Akzent gesetzt


def test_widget_draft_ready_default_false_keeps_neutral(app, qtbot):
    widget = Nis2IncidentTimeline()
    qtbot.addWidget(widget)
    incident = _incident(current_phase=IncidentPhase.EARLY_WARNING)
    widget.set_incident(incident)  # draft_ready default False
    assert widget._status_pill.text().strip() == "offen"  # noqa: SLF001
    assert (  # noqa: SLF001
        widget._advance_btn.text() == "Phase bearbeiten / einreichen"
    )
    assert widget._advance_btn.styleSheet() == ""  # noqa: SLF001


def test_widget_draft_ready_nudge_resets_on_next_incident(app, qtbot):
    """Der Akzent-Nudge darf nicht an der naechsten (nicht-bereiten) Auswahl kleben."""
    widget = Nis2IncidentTimeline()
    qtbot.addWidget(widget)
    widget.set_incident(_incident(), draft_ready=True)
    assert widget._advance_btn.styleSheet() != ""  # noqa: SLF001
    widget.set_incident(_incident(), draft_ready=False)
    assert widget._advance_btn.styleSheet() == ""  # noqa: SLF001
    assert (  # noqa: SLF001
        widget._advance_btn.text() == "Phase bearbeiten / einreichen"
    )


def test_widget_closed_incident_disables_actions(app, qtbot):
    widget = Nis2IncidentTimeline()
    qtbot.addWidget(widget)
    incident = _incident(
        current_phase=IncidentPhase.POST_INCIDENT,
        closed_at=datetime.now(UTC),
    )
    widget.set_incident(incident)
    assert widget._advance_btn.isEnabled() is False
    assert widget._close_btn.isEnabled() is False


def test_widget_set_none_returns_to_empty(app, qtbot):
    widget = Nis2IncidentTimeline()
    qtbot.addWidget(widget)
    widget.set_incident(_incident())
    widget.set_incident(None)
    assert widget.current_incident() is None
    assert widget._advance_btn.isEnabled() is False


def test_complete_phase_signal_emits_on_click(app, qtbot):
    widget = Nis2IncidentTimeline()
    qtbot.addWidget(widget)
    widget.set_incident(_incident())
    with qtbot.waitSignal(
        widget.complete_current_phase_requested, timeout=500
    ):
        widget._advance_btn.click()


def test_close_signal_emits_on_click(app, qtbot):
    widget = Nis2IncidentTimeline()
    qtbot.addWidget(widget)
    widget.set_incident(_incident())
    with qtbot.waitSignal(widget.close_incident_requested, timeout=500):
        widget._close_btn.click()


def test_start_and_stop_live_updates(app, qtbot):
    widget = Nis2IncidentTimeline()
    qtbot.addWidget(widget)
    widget.start_live_updates()
    assert widget._timeline._timer.isActive()
    widget.stop_live_updates()
    assert not widget._timeline._timer.isActive()
