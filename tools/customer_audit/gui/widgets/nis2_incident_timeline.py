"""nis2_incident_timeline — Widget fuer den NIS2-Reporting-Workflow.

Reuse-Proof des generischen:class:`TimelineSteps` aus
``core.widgets.charts`` mit Customer-Audit-Domain-Adapter. Zeigt die
sechs NIS2-Reporting-Phasen mit Live-Countdown bis zur naechsten Frist.

Layout:
- Header: Vorfall-Titel + Severity-Pille + Open/Closed-Status
- Mitte: TimelineSteps mit den 6 Stationen
- Unten: Aktionen (Phase abschliessen / Vorfall schliessen) +
  externe Hinweise (BSI-Portal-Link wird vom Wizard-Step eingebettet).

ADR-Bezug: docs/adr/-nis2-incident-tracker.md.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.widgets.charts import (
    StepStatus,
    TimelineStep,
    TimelineSteps,
)
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    Nis2Incident,
    PhaseStatus,
    phase_order,
)

_PHASE_LABELS: dict[IncidentPhase, str] = {
    IncidentPhase.DETECT: "Detect",
    IncidentPhase.TRIAGE: "Triage",
    IncidentPhase.EARLY_WARNING: "24h Early-Warning",
    IncidentPhase.NOTIFICATION: "72h Notification",
    IncidentPhase.FINAL_REPORT: "30d Final-Report",
    IncidentPhase.POST_INCIDENT: "Post-Incident",
}

_PHASE_DETAIL: dict[IncidentPhase, str] = {
    IncidentPhase.DETECT: (
        "Awareness des erheblichen Vorfalls. Zeitpunkt der Kenntnisnahme "
        "festhalten — er verankert alle NIS2-Fristen (24h/72h/30d)."
    ),
    IncidentPhase.TRIAGE: (
        "Erst-Klassifikation und Eskalations-Entscheidung. Liegt ein "
        "erheblicher Vorfall im NIS2-Sinn vor? Davon haengt die Meldepflicht ab."
    ),
    IncidentPhase.EARLY_WARNING: (
        "24h-Fruehwarnung an das CSIRT (AT: nis.govcert.gv.at) gemaess NIS2 "
        "Art. 23 Abs. 4 (a): Verdacht auf rechtswidrige Handlung? "
        "Grenzueberschreitende Auswirkungen?"
    ),
    IncidentPhase.NOTIFICATION: (
        "72h-Meldung an das CSIRT mit Erstbewertung des Schadensausmasses "
        "(Schweregrad, Auswirkungen, erste Ursache, IoCs). Bei Personenbezug "
        "laeuft parallel die DSGVO-Art.33-72h-Frist an die Datenschutzbehoerde."
    ),
    IncidentPhase.FINAL_REPORT: (
        "30-Tage-Abschlussbericht an das CSIRT: vollstaendiger Hergang, "
        "endgueltige Ursache (Root Cause) und ergriffene/geplante Massnahmen."
    ),
    IncidentPhase.POST_INCIDENT: (
        "Lessons Learned und Follow-ups. Keine externe Meldepflicht mehr."
    ),
}

_STATUS_MAPPING: dict[PhaseStatus, StepStatus] = {
    PhaseStatus.OPEN: StepStatus.PENDING,
    PhaseStatus.IN_PROGRESS: StepStatus.IN_PROGRESS,
    PhaseStatus.DONE: StepStatus.DONE,
    PhaseStatus.SKIPPED: StepStatus.SKIPPED,
}


def map_phase_status_to_step(status: PhaseStatus) -> StepStatus:
    """Pure: PhaseStatus (Domain) → StepStatus (Generic-Chart)."""
    return _STATUS_MAPPING[status]


def incident_to_steps(
    incident: Nis2Incident,
) -> list[TimelineStep]:
    """Pure: bildet die 6 NIS2-Phasen auf TimelineStep-Liste ab.

    - ``label`` aus ``_PHASE_LABELS``
    - ``status`` aus ``incident.status_for_phase(phase)`` mappen
    - ``deadline`` aus ``deadline_for_phase`` (None bei Phasen ohne Frist)
    - ``detail`` aus ``_PHASE_DETAIL``
    """
    steps: list[TimelineStep] = []
    for phase in phase_order():
        domain_status = incident.status_for_phase(phase)
        steps.append(
            TimelineStep(
                label=_PHASE_LABELS[phase],
                status=map_phase_status_to_step(domain_status),
                deadline=incident.deadline_for(phase),
                detail=_PHASE_DETAIL[phase],
            )
        )
    return steps


_SEVERITY_COLOR: dict[IncidentSeverity, str] = {
    IncidentSeverity.LOW: theme.SEVERITY_SIGNAL_LOW,
    IncidentSeverity.MEDIUM: theme.SEVERITY_SIGNAL_MEDIUM,
    IncidentSeverity.HIGH: theme.SEVERITY_SIGNAL_HIGH,
    IncidentSeverity.CRITICAL: theme.SEVERITY_SIGNAL_CRITICAL,
}


class Nis2IncidentTimeline(QWidget):
    """Card-Widget mit Header + TimelineSteps + Aktions-Buttons.

    Signals:
        complete_current_phase_requested: User klickt "Phase bearbeiten / einreichen".
        close_incident_requested: User klickt "Vorfall schliessen".
        export_meldevorlage_requested: User klickt "Meldevorlage exportieren".
    """

    complete_current_phase_requested = Signal()
    close_incident_requested = Signal()
    export_meldevorlage_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._incident: Nis2Incident | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # Header-Zeile
        header_row = QHBoxLayout()
        header_row.setSpacing(8)
        self._title_label = QLabel("Kein Vorfall geladen")
        # Incident-Titel ist User-Freitext — nie als Auto-RichText, R22)
        self._title_label.setTextFormat(Qt.TextFormat.PlainText)
        self._title_label.setStyleSheet(
            f"color: {theme.DARK_TEXT_PRIMARY}; "
            f"font-size: {theme.FONT_SIZE_H2}px; font-weight: bold;"
        )
        header_row.addWidget(self._title_label)
        header_row.addStretch(1)
        self._severity_pill = QLabel("")
        self._severity_pill.setVisible(False)
        self._severity_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_row.addWidget(self._severity_pill)
        self._status_pill = QLabel("")
        self._status_pill.setVisible(False)
        self._status_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_row.addWidget(self._status_pill)
        root.addLayout(header_row)

        # Timeline
        self._timeline = TimelineSteps()
        self._timeline.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        root.addWidget(self._timeline)

        # Sichtbare Anleitung zur AKTUELLEN Phase (frueher nur Hover-Tooltip,
        # Schritt 4): was muss in dieser Phase ans CSIRT, welche Frist.
        self._guidance_label = QLabel("")
        self._guidance_label.setObjectName("lbl_current_phase_guidance")
        self._guidance_label.setWordWrap(True)
        self._guidance_label.setTextFormat(Qt.TextFormat.PlainText)
        self._guidance_label.setVisible(False)
        self._guidance_label.setStyleSheet(
            f"color: {theme.DARK_TEXT_PRIMARY}; "
            f"background-color: {theme.DARK_BG_SECONDARY}; "
            f"border-left: 3px solid {theme.DARK_ACCENT}; "
            f"padding: 8px 10px; font-size: {theme.FONT_SIZE_BODY}px;"
        )
        root.addWidget(self._guidance_label)

        # Aktionen
        actions_row = QHBoxLayout()
        actions_row.setSpacing(8)
        self._advance_btn = QPushButton("Phase bearbeiten / einreichen")
        self._advance_btn.setObjectName("btn_edit_phase")
        self._advance_btn.setEnabled(False)
        self._advance_btn.clicked.connect(
            self.complete_current_phase_requested.emit
        )
        actions_row.addWidget(self._advance_btn)
        self._export_btn = QPushButton("Meldevorlage exportieren")
        self._export_btn.setObjectName("btn_export_meldevorlage")
        self._export_btn.setEnabled(False)
        self._export_btn.clicked.connect(
            self.export_meldevorlage_requested.emit
        )
        actions_row.addWidget(self._export_btn)
        self._close_btn = QPushButton("Vorfall schliessen")
        self._close_btn.setObjectName("btn_close_incident")
        self._close_btn.setEnabled(False)
        self._close_btn.clicked.connect(self.close_incident_requested.emit)
        actions_row.addWidget(self._close_btn)
        actions_row.addStretch(1)
        self._description_label = QLabel("")
        # Beschreibung ist User-Freitext — nie als Auto-RichText, R22)
        self._description_label.setTextFormat(Qt.TextFormat.PlainText)
        self._description_label.setWordWrap(True)
        self._description_label.setStyleSheet(
            f"color: {theme.DARK_TEXT_SECONDARY}; font-style: italic;"
        )
        actions_row.addWidget(self._description_label, stretch=1)
        root.addLayout(actions_row)

    def set_incident(
        self, incident: Nis2Incident | None, draft_ready: bool = False
    ) -> None:
        """Aktualisiert Header, Timeline und Action-Buttons.

        Args:
            incident: Aktueller Vorfall, oder None fuer Empty-State.
            draft_ready: ``True`` wenn der Entwurf der aktuellen Phase alle
                Pflichtfelder erfuellt, aber noch nicht eingereicht ist (D5b,
                aus ``Nis2IncidentService.is_phase_draft_ready``). Spiegelt sich
                im Status-Pill ("bereit zum Einreichen") UND als Button-Nudge,
                damit der fehlende Submit-Schritt sichtbar wird. Reines
                Anzeige-Flag — aendert nichts an der Hashkette.
        """
        self._incident = incident
        if incident is None:
            self._title_label.setText("Kein Vorfall geladen")
            self._severity_pill.setVisible(False)
            self._status_pill.setVisible(False)
            self._description_label.setText("")
            self._guidance_label.setVisible(False)
            self._timeline.set_steps([])
            self._advance_btn.setEnabled(False)
            self._advance_btn.setText("Phase bearbeiten / einreichen")
            self._advance_btn.setStyleSheet("")
            self._export_btn.setEnabled(False)
            self._close_btn.setEnabled(False)
            return

        self._title_label.setText(incident.title)
        self._severity_pill.setText(
            f"  {incident.severity.value.upper()}  "
        )
        sev_color = _SEVERITY_COLOR[incident.severity]
        self._severity_pill.setStyleSheet(
            f"color: {theme.DARK_BG_PRIMARY}; background-color: {sev_color}; "
            "padding: 2px 6px; border-radius: 8px; font-weight: 700;"
        )
        self._severity_pill.setVisible(True)

        is_open = incident.is_open()
        # Status-Pill spiegelt den "bereit zum Einreichen"-Zustand (D5b):
        # geschlossen | bereit (Entwurf vollstaendig) | offen.
        ready = is_open and draft_ready
        if not is_open:
            pill_text = "  geschlossen  "
            status_bg = theme.SCORE_STAGE_SECURE
        elif ready:
            pill_text = "  Entwurf vollständig — bereit zum Einreichen  "
            status_bg = theme.DARK_ACCENT
        else:
            pill_text = "  offen  "
            status_bg = theme.SCORE_STAGE_AT_RISK
        self._status_pill.setText(pill_text)
        self._status_pill.setStyleSheet(
            f"color: {theme.DARK_BG_PRIMARY}; background-color: {status_bg}; "
            "padding: 2px 6px; border-radius: 8px; font-weight: 700;"
        )
        self._status_pill.setVisible(True)
        self._description_label.setText(incident.description)

        steps = incident_to_steps(incident)
        self._timeline.set_steps(steps)

        guidance = _PHASE_DETAIL.get(incident.current_phase, "")
        self._guidance_label.setText(
            f"Aktuelle Phase — {_PHASE_LABELS[incident.current_phase]}: "
            f"{guidance}"
        )
        self._guidance_label.setVisible(bool(guidance))

        self._advance_btn.setEnabled(is_open)
        # Button-Nudge (D5b): ist der Entwurf vollstaendig, ruft der Button
        # zum Einreichen auf (Akzent + "→ Einreichen") statt nur neutral zum
        # Bearbeiten. Beim Wechsel auf einen nicht-bereiten Vorfall den Akzent
        # wieder zuruecksetzen (sonst klebt er an der naechsten Auswahl).
        if ready:
            self._advance_btn.setText("Phase einreichen →")
            self._advance_btn.setStyleSheet(
                f"background-color: {theme.DARK_ACCENT}; "
                f"color: {theme.DARK_BG_PRIMARY}; font-weight: 700; "
                "padding: 4px 10px; border-radius: 4px;"
            )
        else:
            self._advance_btn.setText("Phase bearbeiten / einreichen")
            self._advance_btn.setStyleSheet("")
        # Meldevorlage darf auch im Archiv (read-only) exportiert werden —
        # der Auditor braucht den Nachweis auch nach Abschluss.
        self._export_btn.setEnabled(True)
        self._close_btn.setEnabled(is_open)

    def start_live_updates(self) -> None:
        """Aktiviert den 1-Sekunden-Countdown-Tick im TimelineSteps."""
        self._timeline.start_countdown_updates()

    def stop_live_updates(self) -> None:
        """Stoppt den Countdown-Tick (z.B. wenn Widget unsichtbar)."""
        self._timeline.stop_countdown_updates()

    def current_incident(self) -> Nis2Incident | None:
        """Liefert den zuletzt gesetzten Vorfall (oder None)."""
        return self._incident


def _build_demo() -> Nis2IncidentTimeline:
    """Demo: Vorfall in der EARLY_WARNING-Phase mit aktiver Frist."""
    from datetime import timedelta

    from tools.customer_audit.domain.nis2_incident import (
        Nis2Incident,
        PhaseEvent,
    )

    now = datetime.now(UTC)
    detected = now - timedelta(hours=5, minutes=18)
    events = (
        PhaseEvent(
            event_id=1,
            incident_id="demo-1",
            phase=IncidentPhase.DETECT,
            status=PhaseStatus.DONE,
            actor="patrick",
            note="Verdacht gemeldet",
            occurred_at=detected,
        ),
        PhaseEvent(
            event_id=2,
            incident_id="demo-1",
            phase=IncidentPhase.TRIAGE,
            status=PhaseStatus.DONE,
            actor="patrick",
            note="Klassifiziert als erheblich",
            occurred_at=detected + timedelta(minutes=30),
        ),
        PhaseEvent(
            event_id=3,
            incident_id="demo-1",
            phase=IncidentPhase.EARLY_WARNING,
            status=PhaseStatus.IN_PROGRESS,
            actor="patrick",
            note="Meldung an BSI-Portal vorbereitet",
            occurred_at=detected + timedelta(hours=1),
        ),
    )
    incident = Nis2Incident(
        incident_id="demo-1",
        audit_id="audit-1",
        title="Ransomware-Verdacht in der Buchhaltung",
        description=(
            "Ein Mitarbeiter berichtet ueber verschluesselte Dateien auf einem "
            "Netzlaufwerk. Reichweite unklar, Triage laeuft."
        ),
        severity=IncidentSeverity.HIGH,
        detected_at=detected,
        current_phase=IncidentPhase.EARLY_WARNING,
        events=events,
    )
    widget = Nis2IncidentTimeline()
    widget.set_incident(incident)
    widget.resize(960, 260)
    return widget


if __name__ == "__main__":  # pragma: no cover - Demo-Snippet
    import sys

    from PySide6.QtWidgets import QApplication

    qapp = QApplication(sys.argv)
    theme.apply(qapp)
    demo = _build_demo()
    demo.setWindowTitle("NIS2-Incident-Timeline Demo")
    demo.start_live_updates()
    demo.show()
    sys.exit(qapp.exec())
