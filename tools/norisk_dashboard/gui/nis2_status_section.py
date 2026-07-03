"""nis2_status_section — Dashboard-Card fuer den NIS2-Incident-Tracker.

Zeigt die Anzahl offener Vorfaelle plus die kritischste anstehende Frist.
Klick auf den Tool-Button oeffnet das eigenstaendige NIS2-Tool.

Schichtzugehoerigkeit: gui/ — darf application + core importieren.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from core.widgets.button_styles import link_button_qss
from tools.customer_audit.application.nis2_incident_service import (
    Nis2IncidentService,
)
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    Nis2Incident,
    next_phase,
)

_log = get_logger(__name__)

_PHASE_LABELS: dict[IncidentPhase, str] = {
    IncidentPhase.DETECT: "Detect",
    IncidentPhase.TRIAGE: "Triage",
    IncidentPhase.EARLY_WARNING: "24h Early-Warning",
    IncidentPhase.NOTIFICATION: "72h Notification",
    IncidentPhase.FINAL_REPORT: "30d Final-Report",
    IncidentPhase.POST_INCIDENT: "Post-Incident",
}


def compute_critical_deadline(
    incidents: Sequence[Nis2Incident],
    now: datetime | None = None,
) -> tuple[int | None, IncidentPhase | None]:
    """Pure: liefert ``(seconds_remaining, phase)`` der kuerzesten Frist.

    Sucht ueber alle offenen Vorfaelle die naechste anstehende Phase mit
    Frist und gibt das kuerzeste Delta zurueck. ``(None, None)`` wenn
    keine Frist mehr ansteht.
    """
    reference = now or datetime.now(UTC)
    best_seconds: float | None = None
    best_phase: IncidentPhase | None = None
    for incident in incidents:
        phase: IncidentPhase | None = incident.current_phase
        while phase is not None:
            deadline = incident.deadline_for(phase)
            if deadline is not None:
                remaining = (deadline - reference).total_seconds()
                if best_seconds is None or remaining < best_seconds:
                    best_seconds = remaining
                    best_phase = phase
                break
            phase = next_phase(phase)
    if best_seconds is None:
        return None, None
    return int(best_seconds), best_phase


def color_for_deadline(seconds: int | None) -> str:
    """Pure: Theme-Hex-Token fuer eine Restzeit in Sekunden.

    - keine Vorfaelle / keine Frist → SCORE_STAGE_SECURE (gruen)
    - abgelaufen oder < 1h → DARK_DANGER (rot)
    - < 6h → WARNING_ORANGE
    - sonst → DARK_ACCENT
    """
    if seconds is None:
        return theme.SCORE_STAGE_SECURE
    if seconds < 3600:
        return theme.DARK_DANGER
    if seconds < 6 * 3600:
        return theme.WARNING_ORANGE
    return theme.DARK_ACCENT


def format_remaining_compact(seconds: int | None) -> str:
    """Pure: kompakte Restzeit-Darstellung (z.B. 'in 23h 12m')."""
    if seconds is None:
        return "keine Frist anstehend"
    if seconds < 0:
        return "Frist ABGELAUFEN"
    if seconds < 3600:
        minutes = seconds // 60
        return f"in {minutes:02d}m {seconds % 60:02d}s"
    if seconds < 48 * 3600:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"in {hours:02d}h {minutes:02d}m"
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    return f"in {days}T {hours:02d}h"


class Nis2StatusSection(QWidget):
    """Kompakte Dashboard-Card zur NIS2-Incident-Lage.

    Signals:
        tool_requested: User klickt den "Tool oeffnen"-Button.
    """

    tool_requested = Signal()

    def __init__(
        self,
        service: Nis2IncidentService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service or Nis2IncidentService()
        self._open_count: int = 0
        self._critical_seconds: int | None = None
        self._critical_phase: IncidentPhase | None = None
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        c = theme.get()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(12)

        self._badge = QFrame()
        self._badge.setObjectName("Nis2StatusBadge")
        badge_layout = QVBoxLayout(self._badge)
        badge_layout.setContentsMargins(10, 6, 10, 6)
        badge_layout.setSpacing(2)
        self._badge_count = QLabel("0")
        self._badge_count.setStyleSheet(
            f"color: {theme.DARK_BG_PRIMARY}; "
            f"font-size: {theme.FONT_SIZE_HERO}px; font-weight: 700;"
        )
        self._badge_label = QLabel("offen")
        self._badge_label.setStyleSheet(
            f"color: {theme.DARK_BG_PRIMARY}; "
            f"font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: 600;"
        )
        badge_layout.addWidget(self._badge_count)
        badge_layout.addWidget(self._badge_label)
        layout.addWidget(self._badge)

        info_box = QVBoxLayout()
        info_box.setSpacing(2)
        self._title = QLabel("NIS2-Incident-Tracker")
        self._title.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-weight: 600; "
            f"font-size: {theme.FONT_SIZE_BODY_LG}px;"
        )
        self._deadline_text = QLabel("Keine offenen Vorfaelle")
        self._deadline_text.setStyleSheet(
            f"color: {c.TEXT_DIM}; "
            f"font-size: {theme.FONT_SIZE_BODY}px;"
        )
        info_box.addWidget(self._title)
        info_box.addWidget(self._deadline_text)
        layout.addLayout(info_box, stretch=1)

        self._tool_btn = QPushButton("Tool oeffnen →")
        self._tool_btn.setStyleSheet(link_button_qss())
        self._tool_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._tool_btn.clicked.connect(self.tool_requested.emit)
        self._tool_btn.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred
        )
        layout.addWidget(self._tool_btn)

    def refresh(self) -> None:
        """Laedt offene Vorfaelle und aktualisiert die Anzeige."""
        try:
            incidents = self._service.list_open_incidents()
        except (RuntimeError, OSError):
            _log.exception("nis2_status_section_refresh_failed")
            incidents = []
        self._open_count = len(incidents)
        seconds, phase = compute_critical_deadline(incidents)
        self._critical_seconds = seconds
        self._critical_phase = phase
        self._apply_state()

    def _apply_state(self) -> None:
        color = color_for_deadline(self._critical_seconds)
        # Badge-Farbe je nach Severity der kuerzesten Frist
        self._badge.setStyleSheet(
            f"#Nis2StatusBadge {{ background-color: {color}; "
            "border-radius: 8px; }}"
        )
        self._badge_count.setText(str(self._open_count))
        self._badge_label.setText(
            "offen" if self._open_count != 1 else "offen"
        )
        if self._open_count == 0:
            self._deadline_text.setText("Keine offenen NIS2-Vorfaelle.")
            self._deadline_text.setStyleSheet(
                f"color: {theme.SCORE_STAGE_SECURE}; font-weight: 600;"
            )
            return
        if self._critical_phase is None:
            self._deadline_text.setText(
                "Vorfall offen — keine harten Fristen mehr anstehend."
            )
            self._deadline_text.setStyleSheet(
                f"color: {theme.DARK_TEXT_PRIMARY};"
            )
            return
        phase_label = _PHASE_LABELS[self._critical_phase]
        remaining = format_remaining_compact(self._critical_seconds)
        self._deadline_text.setText(
            f"Kuerzeste Frist: {phase_label} — {remaining}"
        )
        text_color = (
            theme.DARK_DANGER
            if (self._critical_seconds or 0) < 3600
            else theme.DARK_TEXT_PRIMARY
        )
        self._deadline_text.setStyleSheet(
            f"color: {text_color}; font-weight: 500;"
        )
