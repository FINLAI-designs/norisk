"""Tests fuer das eigenstaendige NIS2-Incident-Tool.

Pure-Function-Tests fuer ``format_next_deadline``,
``_deadline_sort_key``, ``_is_critical_deadline`` plus Widget-Tests
fuer Nis2IncidentsWidget (refresh, signals, table-population) und
IncidentFormDialog (collected data).
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from PySide6.QtCore import QDate, QDateTime, QTime, QTimeZone

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
from tools.nis2_incidents.gui.incident_form_dialog import (
    IncidentFormData,
    IncidentFormDialog,
)
from tools.nis2_incidents.gui.nis2_incidents_widget import (
    Nis2IncidentsWidget,
    _deadline_sort_key,
    _is_critical_deadline,
    format_next_deadline,
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


def _incident(**overrides) -> Nis2Incident:
    defaults = {
        "incident_id": str(uuid.uuid4()),
        "audit_id": "audit-1",
        "title": "Test-Vorfall",
        "description": "",
        "severity": IncidentSeverity.HIGH,
        "detected_at": datetime(2026, 5, 27, 8, 0, tzinfo=UTC),
        "current_phase": IncidentPhase.DETECT,
    }
    defaults.update(overrides)
    return Nis2Incident(**defaults)


@pytest.fixture
def service():
    return Nis2IncidentService(
        repository=DbNis2IncidentRepository(db=_InMemoryDB())
    )


class TestFormatNextDeadline:
    NOW = datetime(2026, 5, 27, 12, 0, tzinfo=UTC)

    def test_detect_phase_uses_24h_deadline(self):
        # DETECT hat keine Frist; aber das Pure-Function sucht next_phase
        # mit Frist → EARLY_WARNING (24h ab detected_at)
        inc = _incident(
            detected_at=self.NOW - timedelta(hours=12),
            current_phase=IncidentPhase.DETECT,
        )
        result = format_next_deadline(inc, now=self.NOW)
        assert "Early-Warning" in result
        # 24h - 12h Vorlauf = 12h Restzeit
        assert "12h" in result

    def test_expired_deadline_marked(self):
        inc = _incident(
            detected_at=self.NOW - timedelta(hours=30),
            current_phase=IncidentPhase.EARLY_WARNING,
        )
        result = format_next_deadline(inc, now=self.NOW)
        assert "abgelaufen" in result

    def test_post_incident_has_no_deadline(self):
        inc = _incident(current_phase=IncidentPhase.POST_INCIDENT)
        result = format_next_deadline(inc, now=self.NOW)
        assert result == "—"

    def test_multi_day_formats_with_T(self):
        inc = _incident(
            detected_at=self.NOW - timedelta(hours=1),
            current_phase=IncidentPhase.FINAL_REPORT,
        )
        result = format_next_deadline(inc, now=self.NOW)
        # 30d - 1h ≈ 29 Tage 23h
        assert "T" in result


class TestDeadlineSortKey:
    NOW = datetime(2026, 5, 27, 12, 0, tzinfo=UTC)

    def test_shorter_deadline_smaller_key(self):
        urgent = _incident(
            detected_at=self.NOW - timedelta(hours=23),
            current_phase=IncidentPhase.EARLY_WARNING,
        )
        relaxed = _incident(
            detected_at=self.NOW - timedelta(hours=1),
            current_phase=IncidentPhase.EARLY_WARNING,
        )
        assert _deadline_sort_key(urgent, now=self.NOW) < _deadline_sort_key(
            relaxed, now=self.NOW
        )

    def test_no_deadline_returns_infinity(self):
        inc = _incident(current_phase=IncidentPhase.POST_INCIDENT)
        assert _deadline_sort_key(inc, now=self.NOW) == float("inf")


class TestIsCriticalDeadline:
    NOW = datetime(2026, 5, 27, 12, 0, tzinfo=UTC)

    def test_under_six_hours_is_critical(self):
        inc = _incident(
            detected_at=self.NOW - timedelta(hours=20),
            current_phase=IncidentPhase.EARLY_WARNING,
        )
        # 24h - 20h = 4h Restzeit → kritisch
        assert _is_critical_deadline(inc, now=self.NOW) is True

    def test_more_than_six_hours_not_critical(self):
        inc = _incident(
            detected_at=self.NOW - timedelta(hours=10),
            current_phase=IncidentPhase.EARLY_WARNING,
        )
        # 24h - 10h = 14h Restzeit → nicht kritisch
        assert _is_critical_deadline(inc, now=self.NOW) is False

    def test_expired_not_critical(self):
        # Bewusste Konvention: abgelaufen wird separat behandelt
        # (eigene Farbe rot), is_critical liefert hier False weil
        # remaining < 0.
        inc = _incident(
            detected_at=self.NOW - timedelta(hours=30),
            current_phase=IncidentPhase.EARLY_WARNING,
        )
        assert _is_critical_deadline(inc, now=self.NOW) is False


def test_widget_initial_renders(app, qtbot, service):
    widget = Nis2IncidentsWidget(service=service)
    qtbot.addWidget(widget)
    assert widget._open_table.rowCount() == 0
    assert widget._archive_table.rowCount() == 0


def test_widget_refresh_populates_open_table(app, qtbot, service):
    service.open_incident(
        "audit-1", "Test-A", IncidentSeverity.HIGH
    )
    service.open_incident(
        "audit-1", "Test-B", IncidentSeverity.MEDIUM
    )
    widget = Nis2IncidentsWidget(service=service)
    qtbot.addWidget(widget)
    widget.refresh()
    assert widget._open_table.rowCount() == 2


def test_widget_closed_incidents_in_archive_tab(app, qtbot, service):
    incident_a = service.open_incident(
        "audit-1", "Open-A", IncidentSeverity.HIGH
    )
    incident_b = service.open_incident(
        "audit-1", "Closed-B", IncidentSeverity.LOW
    )
    service.close_incident(incident_b.incident_id)
    widget = Nis2IncidentsWidget(service=service)
    qtbot.addWidget(widget)
    widget.refresh()
    assert widget._open_table.rowCount() == 1
    assert widget._archive_table.rowCount() == 1
    # Header-Reihe in Tab 0 = Offen-Liste enthaelt nur Open-A
    open_title = widget._open_table.item(0, 0)
    assert open_title is not None
    assert open_title.text() == "Open-A"
    # Inzident b im Archiv
    archive_title = widget._archive_table.item(0, 0)
    assert archive_title is not None
    assert archive_title.text() == "Closed-B"
    # Sicherstellen dass das verwendete Beispiel-Incident_a noch offen ist
    assert incident_a.is_open()


def test_widget_complete_phase_action_opens_dialog(
    app, qtbot, service, monkeypatch
):
    """ §1/§2: "Phase bearbeiten / einreichen" oeffnet das Pro-Phase-

    Formular fuer die aktuelle Phase (statt des fruehen 1-Klick-advance_phase).
    Der Dialog wird hier statt ``exec`` ueber einen monkeypatch ausgefuehrt,
    der ein vollstaendiges DETECT-Formular einreicht; danach steht der Vorfall
    in TRIAGE (DETECT-Event DONE → next_phase).
    """
    from tools.customer_audit.domain.nis2_incident import (  # noqa: PLC0415
        PhaseStatus,
    )
    from tools.nis2_incidents.gui import (  # noqa: PLC0415
        nis2_incidents_widget as widget_mod,
    )

    incident = service.open_incident(
        "audit-1", "Test", IncidentSeverity.HIGH
    )
    widget = Nis2IncidentsWidget(service=service)
    qtbot.addWidget(widget)
    widget.refresh()
    widget._open_table.selectRow(0)

    captured: dict = {}

    def _fake_exec(self) -> int:
        # Simuliert das Einreichen der DETECT-Phase mit dem Pflichtfeld.
        captured["incident_id"] = self._incident_id
        captured["phase"] = self._phase
        self._service.save_draft(
            self._incident_id,
            self._phase,
            {"kenntnisnahme_zeitpunkt": "2026-06-22T08:00:00+00:00"},
        )
        self._service.submit_draft(
            self._incident_id, self._phase, status=PhaseStatus.DONE
        )
        self._service.advance_header_after_submit(
            self._incident_id, self._phase
        )
        self._action = self.ACTION_SUBMIT
        return 1

    monkeypatch.setattr(
        widget_mod.PhaseFormDialog, "exec", _fake_exec, raising=True
    )
    widget._on_complete_current_phase()

    assert captured["phase"] is IncidentPhase.DETECT
    reloaded = service.load_incident(incident.incident_id)
    assert reloaded is not None
    # DETECT → DONE → next_phase = TRIAGE
    assert reloaded.current_phase is IncidentPhase.TRIAGE


def test_tab_roundtrip_open_archive_open_keeps_selection(app, qtbot, service):
    """Roundtrip offen -> Archiv -> offen erhaelt Auswahl + Timeline (Bugfix).

    Regression: ein gemeinsames ``_selected_id`` fuer beide Tabs wurde beim
    Wechsel auf 'Archiv' geleert (offener Vorfall nicht in der closed-Liste),
    sodass der Rueckwechsel eine leere Timeline zeigte. Jetzt fuehren
    ``_selected_open``/``_selected_closed`` getrennte Selektionen.
    """
    open_inc = service.open_incident(
        "audit-1", "Offen-A", IncidentSeverity.HIGH
    )
    closed_inc = service.open_incident(
        "audit-1", "Geschlossen-B", IncidentSeverity.LOW
    )
    service.close_incident(closed_inc.incident_id)

    widget = Nis2IncidentsWidget(service=service)
    qtbot.addWidget(widget)
    widget.refresh()

    # 1) Offenen Vorfall im Offen-Tab auswaehlen.
    widget._tabs.setCurrentIndex(0)
    widget._open_table.selectRow(0)
    assert widget._selected_open == open_inc.incident_id
    assert widget._open_detail.current_incident() is not None
    assert (
        widget._open_detail.current_incident().incident_id
        == open_inc.incident_id
    )

    # 2) Auf Archiv wechseln — die offene Selektion DARF NICHT verloren gehen.
    widget._tabs.setCurrentIndex(1)
    assert widget._selected_open == open_inc.incident_id

    # 3) Zurueck zu Offen — gewaehlter Vorfall + Timeline wieder da.
    widget._tabs.setCurrentIndex(0)
    assert widget._selected_open == open_inc.incident_id
    restored = widget._open_detail.current_incident()
    assert restored is not None
    assert restored.incident_id == open_inc.incident_id


def test_tabs_keep_independent_selection(app, qtbot, service):
    """Offen- und Archiv-Tab merken sich jeweils ihre eigene Auswahl."""
    open_inc = service.open_incident(
        "audit-1", "Offen-A", IncidentSeverity.HIGH
    )
    closed_inc = service.open_incident(
        "audit-1", "Geschlossen-B", IncidentSeverity.LOW
    )
    service.close_incident(closed_inc.incident_id)

    widget = Nis2IncidentsWidget(service=service)
    qtbot.addWidget(widget)
    widget.refresh()

    widget._tabs.setCurrentIndex(0)
    widget._open_table.selectRow(0)
    widget._tabs.setCurrentIndex(1)
    widget._archive_table.selectRow(0)

    assert widget._selected_open == open_inc.incident_id
    assert widget._selected_closed == closed_inc.incident_id
    # Der Archiv-Detail zeigt den geschlossenen, der Offen-Detail den offenen.
    assert (
        widget._archive_detail.current_incident().incident_id
        == closed_inc.incident_id
    )
    widget._tabs.setCurrentIndex(0)
    assert (
        widget._open_detail.current_incident().incident_id
        == open_inc.incident_id
    )


def test_close_incident_moves_selection_to_archive(app, qtbot, service):
    """Schliessen leert die Offen-Selektion und merkt sie im Archiv vor."""
    inc = service.open_incident("audit-1", "Offen-A", IncidentSeverity.HIGH)
    widget = Nis2IncidentsWidget(service=service)
    qtbot.addWidget(widget)
    widget.refresh()
    widget._open_table.selectRow(0)
    assert widget._selected_open == inc.incident_id

    # close_incident bestaetigt sonst per QMessageBox -> Service direkt nutzen
    # und den internen Bookkeeping-Pfad spiegeln.
    service.close_incident(inc.incident_id)
    widget._selected_open = None
    widget._selected_closed = inc.incident_id
    widget.refresh()

    assert widget._selected_open is None
    widget._tabs.setCurrentIndex(1)
    archived = widget._archive_detail.current_incident()
    assert archived is not None
    assert archived.incident_id == inc.incident_id


def test_incident_form_data_dataclass_immutable():
    data = IncidentFormData(
        audit_id="aud-1",
        title="Test",
        description="x",
        severity=IncidentSeverity.LOW,
        detected_at=datetime.now(UTC),
        actor="patrick",
    )
    with pytest.raises(Exception):  # noqa: B017 — frozen dataclass
        data.title = "anders"  # type: ignore[misc]


def test_incident_form_dialog_disabled_without_audits(app, qtbot):
    dialog = IncidentFormDialog(audit_choices=[])
    qtbot.addWidget(dialog)
    # Ohne Customer-Audit ist der Combo deaktiviert
    assert dialog._audit_combo.isEnabled() is False


def test_incident_form_dialog_pre_select_default(app, qtbot):
    dialog = IncidentFormDialog(
        audit_choices=[("aud-1", "Kunde 1"), ("aud-2", "Kunde 2")],
        default_audit_id="aud-2",
    )
    qtbot.addWidget(dialog)
    assert dialog._audit_combo.currentData() == "aud-2"


@pytest.mark.parametrize(
    "index, expected",
    [
        (0, IncidentSeverity.LOW),
        (1, IncidentSeverity.MEDIUM),
        (2, IncidentSeverity.HIGH),
        (3, IncidentSeverity.CRITICAL),
    ],
)
def test_incident_form_dialog_severity_roundtrip(app, qtbot, index, expected):
    """: jede gewaehlte Severity wird korrekt eingesammelt.

    Regression: StrEnum-userData kam ueber Qt/QVariant als plain str zurueck,
    der isinstance-Check schlug fehl und die Severity fiel immer auf MEDIUM.
    """
    dialog = IncidentFormDialog(audit_choices=[("aud-1", "Kunde 1")])
    qtbot.addWidget(dialog)
    dialog._severity_combo.setCurrentIndex(index)
    dialog.accept()
    data = dialog.collected()
    assert data is not None
    assert data.severity is expected
    assert isinstance(data.severity, IncidentSeverity)


def test_incident_form_dialog_detected_at_utc_anchor(app, qtbot):
    """: das Erkennungs-Widget fuehrt UTC und liefert einen aware-Anker.

    Regression: das Widget lief in Lokalzeit, naive Werte wurden als UTC
    gestempelt statt konvertiert -> NIS2-Fristen um den lokalen Offset
    verschoben (Frist-Skew, der nur auf Nicht-UTC-Rechnern auftrat).
    """
    dialog = IncidentFormDialog(audit_choices=[("aud-1", "Kunde 1")])
    qtbot.addWidget(dialog)
    # Das Widget MUSS in UTC laufen, sonst entsteht der Frist-Skew.
    assert bytes(dialog._detected_edit.timeZone().id()) == b"UTC"
    # Bekannter UTC-Instant -> exakt so als aware UTC eingesammelt.
    known = QDateTime(QDate(2026, 5, 27), QTime(8, 0), QTimeZone(QTimeZone.UTC))
    dialog._detected_edit.setDateTime(known)
    dialog.accept()
    data = dialog.collected()
    assert data is not None
    assert data.detected_at == datetime(2026, 5, 27, 8, 0, tzinfo=UTC)
    assert data.detected_at.utcoffset() == timedelta(0)
