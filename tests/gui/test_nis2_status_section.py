"""Tests fuer Nis2StatusSection (Dashboard-Card) und die Pure-Function-Helper."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from core import theme
from tools.customer_audit.application.nis2_incident_service import (
    Nis2IncidentService,
)
from tools.customer_audit.data.nis2_incident_repository import (
    DbNis2IncidentRepository,
)
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    Nis2Incident,
)
from tools.norisk_dashboard.gui.nis2_status_section import (
    Nis2StatusSection,
    color_for_deadline,
    compute_critical_deadline,
    format_remaining_compact,
)

pytestmark = pytest.mark.gui


class _FakeConn:
    def __init__(self, c):
        self._c = c

    def __enter__(self):
        return self._c

    def __exit__(self, *_a):
        return None


class _InMemoryDB:
    def __init__(self):
        self._c = sqlite3.connect(":memory:")

    def connection(self):
        return _FakeConn(self._c)


def _incident(detected_at: datetime, phase: IncidentPhase) -> Nis2Incident:
    return Nis2Incident(
        incident_id=str(uuid.uuid4()),
        audit_id="aud",
        title="x",
        description="",
        severity=IncidentSeverity.HIGH,
        detected_at=detected_at,
        current_phase=phase,
    )


class TestComputeCriticalDeadline:
    NOW = datetime(2026, 5, 27, 12, 0, tzinfo=UTC)

    def test_empty_returns_none(self):
        seconds, phase = compute_critical_deadline([], now=self.NOW)
        assert seconds is None
        assert phase is None

    def test_picks_shortest_deadline(self):
        urgent = _incident(
            self.NOW - timedelta(hours=23), IncidentPhase.EARLY_WARNING
        )
        relaxed = _incident(
            self.NOW - timedelta(hours=10), IncidentPhase.EARLY_WARNING
        )
        seconds, phase = compute_critical_deadline(
            [urgent, relaxed], now=self.NOW
        )
        assert phase is IncidentPhase.EARLY_WARNING
        # urgent hat 1h Restzeit (24h - 23h), relaxed 14h
        assert 0 <= seconds <= 3700  # zwischen 0 und ~1h

    def test_no_deadline_phase_walks_forward(self):
        # DETECT hat keine Frist → next_phase mit Frist ist EARLY_WARNING
        inc = _incident(
            self.NOW - timedelta(hours=12), IncidentPhase.DETECT
        )
        seconds, phase = compute_critical_deadline([inc], now=self.NOW)
        assert phase is IncidentPhase.EARLY_WARNING
        # 24h - 12h = 12h Restzeit
        assert seconds is not None
        assert 11 * 3600 < seconds < 13 * 3600


class TestColorForDeadline:
    def test_none_returns_secure_green(self):
        assert color_for_deadline(None) == theme.SCORE_STAGE_SECURE

    def test_critical_under_one_hour(self):
        assert color_for_deadline(3599) == theme.DARK_DANGER

    def test_expired_is_critical(self):
        assert color_for_deadline(-1) == theme.DARK_DANGER

    def test_warning_under_six_hours(self):
        assert color_for_deadline(3 * 3600) == theme.WARNING_ORANGE

    def test_accent_above_six_hours(self):
        assert color_for_deadline(20 * 3600) == theme.DARK_ACCENT


class TestFormatRemainingCompact:
    def test_none_is_no_deadline(self):
        assert format_remaining_compact(None) == "keine Frist anstehend"

    def test_negative_is_expired(self):
        assert format_remaining_compact(-100) == "Frist ABGELAUFEN"

    def test_minutes_only(self):
        assert format_remaining_compact(125).startswith("in ")
        assert "m" in format_remaining_compact(125)

    def test_hours_format(self):
        assert format_remaining_compact(3 * 3600 + 27 * 60) == "in 03h 27m"

    def test_days_format(self):
        # 2T 04h
        assert format_remaining_compact(2 * 86400 + 4 * 3600) == "in 2T 04h"


def test_section_initial_state_zero_count(app, qtbot):
    service = Nis2IncidentService(
        repository=DbNis2IncidentRepository(db=_InMemoryDB())
    )
    section = Nis2StatusSection(service=service)
    qtbot.addWidget(section)
    assert section._open_count == 0
    assert "Keine offenen" in section._deadline_text.text()


def test_section_refresh_shows_count_and_deadline(app, qtbot):
    service = Nis2IncidentService(
        repository=DbNis2IncidentRepository(db=_InMemoryDB())
    )
    service.open_incident("aud", "x", IncidentSeverity.HIGH)
    service.open_incident("aud", "y", IncidentSeverity.LOW)
    section = Nis2StatusSection(service=service)
    qtbot.addWidget(section)
    section.refresh()
    assert section._open_count == 2
    # Es muss eine Frist anstehen (Early-Warning der gerade angelegten
    # Vorfaelle in ca. 24h)
    assert section._critical_seconds is not None


def test_section_tool_requested_signal_emits(app, qtbot):
    service = Nis2IncidentService(
        repository=DbNis2IncidentRepository(db=_InMemoryDB())
    )
    section = Nis2StatusSection(service=service)
    qtbot.addWidget(section)
    with qtbot.waitSignal(section.tool_requested, timeout=500):
        section._tool_btn.click()
