"""nis2_incidents_widget — Haupt-Widget des NIS2-Incident-Trackers.

Layout:
- Header mit Info-Text + "Neuer Vorfall"-Button
- QTabWidget mit zwei Tabs:
  * "Offene Vorfaelle" — Splitter: Liste links + Detail (Timeline) rechts
  * "Archiv" — gleiche Struktur, nur geschlossene Vorfaelle (read-only)

Reuse-Pattern: ``Nis2IncidentTimeline`` aus
``tools.customer_audit.gui.widgets`` wird als Detail-Widget eingebettet.

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

ADR-Bezug: docs/adr/-nis2-incident-tracker.md.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import (
    FinlaiConfirmDialog,
    FinlaiInfoDialog,
    FinlaiSuccessDialog,
)
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import Icons
from core.logger import get_logger
from tools.customer_audit.application.nis2_incident_service import (
    Nis2IncidentService,
)
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    Nis2Incident,
    next_phase,
    phase_order,
)
from tools.customer_audit.gui.widgets.nis2_incident_timeline import (
    Nis2IncidentTimeline,
)
from tools.nis2_incidents.gui.export_meldevorlage import (
    MeldeFrist,
    build_meldevorlage,
    build_meldevorlage_pdf,
)
from tools.nis2_incidents.gui.incident_form_dialog import (
    IncidentFormDialog,
)
from tools.nis2_incidents.gui.phase_form_dialog import PhaseFormDialog

_log = get_logger(__name__)

_LIST_HEADERS: tuple[str, ...] = (
    "Vorfall",
    "Severity",
    "Phase",
    "Naechste Frist",
    "Erkannt am (UTC)",
)

_SEVERITY_COLOR: dict[IncidentSeverity, str] = {
    IncidentSeverity.LOW: theme.SEVERITY_SIGNAL_LOW,
    IncidentSeverity.MEDIUM: theme.SEVERITY_SIGNAL_MEDIUM,
    IncidentSeverity.HIGH: theme.SEVERITY_SIGNAL_HIGH,
    IncidentSeverity.CRITICAL: theme.SEVERITY_SIGNAL_CRITICAL,
}

_PHASE_LABELS: dict[IncidentPhase, str] = {
    IncidentPhase.DETECT: "Detect",
    IncidentPhase.TRIAGE: "Triage",
    IncidentPhase.EARLY_WARNING: "24h Early-Warning",
    IncidentPhase.NOTIFICATION: "72h Notification",
    IncidentPhase.FINAL_REPORT: "30d Final-Report",
    IncidentPhase.POST_INCIDENT: "Post-Incident",
}

#: Provider-Callback fuer Customer-Audit-Auswahl im Anlage-Dialog. Liste
#: von ``(audit_id, display_label)``-Tupeln. Wenn None, wird ein Stub
#: verwendet (nur fuer Tests/Standalone-Demo).
AuditChoicesProvider = Callable[[], Sequence[tuple[str, str]]]


def format_next_deadline(
    incident: Nis2Incident, now: datetime | None = None
) -> str:
    """Pure: liefert die naechste anstehende NIS2-Frist als Text.

    Sucht die naechste Phase nach ``current_phase`` mit einer Frist
    (Early-Warning/Notification/Final-Report) und gibt die Restzeit
    formatiert zurueck. Wenn keine Frist mehr ansteht: leer.
    """
    reference = now or datetime.now(UTC)
    phase: IncidentPhase | None = incident.current_phase
    while phase is not None:
        deadline = incident.deadline_for(phase)
        if deadline is not None:
            delta = deadline - reference
            if delta.total_seconds() < 0:
                return f"{_PHASE_LABELS[phase]}: abgelaufen"
            hours = int(delta.total_seconds() // 3600)
            mins = int((delta.total_seconds() % 3600) // 60)
            if hours >= 48:
                days = hours // 24
                rem_h = hours % 24
                return f"{_PHASE_LABELS[phase]}: {days}T {rem_h:02d}h"
            return f"{_PHASE_LABELS[phase]}: {hours:02d}h {mins:02d}m"
        phase = next_phase(phase)
    return "—"


class Nis2IncidentsWidget(QWidget):
    """Eigenstaendiger Tool-Tab fuer NIS2-Incident-Tracking."""

    def __init__(
        self,
        service: Nis2IncidentService | None = None,
        audit_choices_provider: AuditChoicesProvider | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service or Nis2IncidentService()
        self._audit_choices_provider = (
            audit_choices_provider or _default_audit_choices_provider
        )
        self._incidents_open: list[Nis2Incident] = []
        self._incidents_closed: list[Nis2Incident] = []
        # Getrennte Selektion je Tab: ein gemeinsames _selected_id wurde beim
        # Tab-Wechsel auf 'Archiv' geloescht (offener Vorfall nicht in der
        # closed-Liste), sodass der Rueckwechsel eine leere Timeline zeigte.
        self._selected_open: str | None = None
        self._selected_closed: str | None = None
        self._build_ui()
        self.refresh()

    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("nis2_incidents")
        return hc.tooltips.get(key, "") if hc else ""

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)

        header_row = QHBoxLayout()
        header = QLabel("NIS2 Art. 23 — Incident-Tracker")
        header.setStyleSheet(
            f"color: {theme.DARK_TEXT_PRIMARY}; "
            f"font-size: {theme.FONT_SIZE_H2}px; font-weight: bold;"
        )
        header_row.addWidget(header)
        header_row.addStretch(1)
        self._new_btn = QPushButton("Neuer Vorfall …")
        self._new_btn.setObjectName("btn_new_incident")
        self._new_btn.setProperty("class", "primary")
        self._new_btn.clicked.connect(self._on_new_incident)
        header_row.addWidget(self._new_btn)
        _tip_new = self._help_tip("btn_new_incident")
        if _tip_new:
            header_row.addWidget(HelpButton(_tip_new, title="Neuer NIS2-Vorfall"))
        self._refresh_btn = QPushButton("Aktualisieren")
        self._refresh_btn.setObjectName("btn_refresh")
        self._refresh_btn.clicked.connect(self.refresh)
        header_row.addWidget(self._refresh_btn)
        root.addLayout(header_row)

        info = QLabel(
            "Erheblicher Sicherheitsvorfall? Hier werden die NIS2-Reporting-"
            "Phasen (24h Early-Warning / 72h Notification / 30d Final-Report) "
            "mit Live-Countdown und unveraenderbarem Audit-Trail gefuehrt. "
            "Append-only — kein Phase-Event laesst sich nachtraeglich aendern."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {theme.DARK_TEXT_SECONDARY};")
        root.addWidget(info)

        _hc = HelpRegistry.get("nis2_incidents")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            root.addWidget(self._help_panel)

        self._tabs = QTabWidget()
        self._open_tab, self._open_table, self._open_detail = (
            self._build_tab_with_split(is_archive=False)
        )
        self._archive_tab, self._archive_table, self._archive_detail = (
            self._build_tab_with_split(is_archive=True)
        )
        self._tabs.addTab(self._open_tab, "Offene Vorfaelle")
        self._tabs.addTab(self._archive_tab, "Archiv")
        self._tabs.currentChanged.connect(self._on_tab_changed)
        root.addWidget(self._tabs, stretch=1)

    def _build_tab_with_split(
        self, is_archive: bool
    ) -> tuple[QWidget, QTableWidget, Nis2IncidentTimeline]:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(8)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        table = QTableWidget(0, len(_LIST_HEADERS))
        table.setHorizontalHeaderLabels(list(_LIST_HEADERS))
        table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        header = table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, len(_LIST_HEADERS)):
            header.setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        table.itemSelectionChanged.connect(
            lambda is_arch=is_archive: self._on_row_selected(is_arch)
        )
        splitter.addWidget(table)

        detail = Nis2IncidentTimeline()
        if is_archive:
            # Im Archiv darf nichts mehr veraendert werden — die Action-
            # Buttons werden in der Sub-Komponente bereits via is_open
            # gegated. Die Signals werden vom uebergeordneten Tool im
            # Archiv-Modus nicht angeschlossen.
            pass
        else:
            detail.complete_current_phase_requested.connect(
                self._on_complete_current_phase
            )
            detail.close_incident_requested.connect(self._on_close_incident)
        # Meldevorlage-Export ist auch im Archiv (read-only) erlaubt.
        detail.export_meldevorlage_requested.connect(
            lambda is_arch=is_archive: self._on_export_meldevorlage(is_arch)
        )
        detail.start_live_updates()
        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter)

        return container, table, detail

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        try:
            open_incidents = self._service.list_open_incidents()
        except (RuntimeError, OSError):
            _log.exception("nis2_incidents_open_load_failed")
            open_incidents = []
        try:
            closed_incidents = self._service.list_closed_incidents()
        except (RuntimeError, OSError):
            _log.exception("nis2_incidents_closed_load_failed")
            closed_incidents = []
        self._incidents_open = sorted(
            open_incidents,
            key=_deadline_sort_key,
        )
        self._incidents_closed = sorted(
            closed_incidents,
            key=lambda inc: inc.closed_at or inc.updated_at,
            reverse=True,
        )
        self._reload_table(self._open_table, self._incidents_open)
        self._reload_table(self._archive_table, self._incidents_closed)
        self._restore_selection()

    def _reload_table(
        self, table: QTableWidget, incidents: list[Nis2Incident]
    ) -> None:
        table.setRowCount(len(incidents))
        for row, incident in enumerate(incidents):
            self._fill_row(table, row, incident)

    def _fill_row(
        self, table: QTableWidget, row: int, incident: Nis2Incident
    ) -> None:
        title_item = QTableWidgetItem(incident.title)
        title_item.setData(Qt.ItemDataRole.UserRole, incident.incident_id)
        table.setItem(row, 0, title_item)

        sev_item = QTableWidgetItem(incident.severity.value.upper())
        sev_item.setForeground(_brush(_SEVERITY_COLOR[incident.severity]))
        sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        table.setItem(row, 1, sev_item)

        phase_item = QTableWidgetItem(_PHASE_LABELS[incident.current_phase])
        table.setItem(row, 2, phase_item)

        deadline_text = format_next_deadline(incident)
        deadline_item = QTableWidgetItem(deadline_text)
        if "abgelaufen" in deadline_text:
            deadline_item.setForeground(_brush(theme.DARK_DANGER))
        elif _is_critical_deadline(incident):
            deadline_item.setForeground(_brush(theme.WARNING_ORANGE))
        table.setItem(row, 3, deadline_item)

        detected_item = QTableWidgetItem(
            incident.detected_at.strftime("%Y-%m-%d %H:%M")
        )
        table.setItem(row, 4, detected_item)

    def _restore_selection(self) -> None:
        is_archive = self._tabs.currentIndex() == 1
        selected_id = self._current_selected_id()
        if selected_id is None:
            self._update_detail(self._current_detail(), None)
            return
        table = self._current_table()
        incidents = self._current_incidents()
        for row, incident in enumerate(incidents):
            if incident.incident_id == selected_id:
                table.selectRow(row)
                self._update_detail(self._current_detail(), incident)
                return
        # Selection im aktuellen Tab verloren (Vorfall geschlossen/entfernt).
        # Nur den Slot DES AKTUELLEN Tabs zuruecksetzen — die Selektion des
        # anderen Tabs bleibt fuer den Rueckwechsel erhalten.
        self._set_current_selected_id(None, is_archive=is_archive)
        self._update_detail(self._current_detail(), None)

    def _current_selected_id(self) -> str | None:
        return (
            self._selected_closed
            if self._tabs.currentIndex() == 1
            else self._selected_open
        )

    def _set_current_selected_id(
        self, incident_id: str | None, *, is_archive: bool
    ) -> None:
        if is_archive:
            self._selected_closed = incident_id
        else:
            self._selected_open = incident_id

    def _current_table(self) -> QTableWidget:
        return (
            self._archive_table
            if self._tabs.currentIndex() == 1
            else self._open_table
        )

    def _current_detail(self) -> Nis2IncidentTimeline:
        return (
            self._archive_detail
            if self._tabs.currentIndex() == 1
            else self._open_detail
        )

    def _current_incidents(self) -> list[Nis2Incident]:
        return (
            self._incidents_closed
            if self._tabs.currentIndex() == 1
            else self._incidents_open
        )

    def _on_tab_changed(self) -> None:
        self._restore_selection()

    def _on_row_selected(self, is_archive: bool) -> None:
        table = self._archive_table if is_archive else self._open_table
        rows = table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        incidents = (
            self._incidents_closed if is_archive else self._incidents_open
        )
        if not 0 <= idx < len(incidents):
            return
        incident = incidents[idx]
        self._set_current_selected_id(
            incident.incident_id, is_archive=is_archive
        )
        detail = self._archive_detail if is_archive else self._open_detail
        self._update_detail(detail, incident)

    def _update_detail(
        self,
        detail: Nis2IncidentTimeline,
        incident: Nis2Incident | None,
    ) -> None:
        # D5b: "Entwurf vollstaendig — bereit zum Einreichen" ableiten (reines
        # Anzeige-Derivat; Hashkette unberuehrt). Fail-soft: ein Draft-/DB-Fehler
        # darf die Detail-Anzeige nie brechen.
        draft_ready = False
        if incident is not None:
            try:
                draft_ready = self._service.is_phase_draft_ready(incident)
            except Exception:  # noqa: BLE001 — defensive UI-Schicht
                draft_ready = False
        detail.set_incident(incident, draft_ready=draft_ready)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _on_new_incident(self) -> None:
        choices = list(self._audit_choices_provider())
        dialog = IncidentFormDialog(audit_choices=choices, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        data = dialog.collected()
        if data is None:
            return
        try:
            incident = self._service.open_incident(
                audit_id=data.audit_id,
                title=data.title,
                severity=data.severity,
                description=data.description,
                detected_at=data.detected_at,
                actor=data.actor,
            )
        except (ValueError, RuntimeError, OSError) as exc:
            _log.exception("nis2_open_incident_failed")
            FinlaiInfoDialog(
                title="Vorfall anlegen fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()
            return
        self._selected_open = incident.incident_id
        self._tabs.setCurrentIndex(0)
        self.refresh()

    def _on_complete_current_phase(self) -> None:
        """Oeffnet das Pro-Phase-Formular fuer die aktuelle Phase §1/§2).

        Ersetzt den fruehen 1-Klick-``advance_phase``-Pfad: Der Bearbeiter
        fuellt das Pflichtformular aus, speichert es als Entwurf oder reicht
        es ein (Append-only-Event). Nach dem Einreichen wird die Liste neu
        geladen.
        """
        incident = self._open_detail.current_incident()
        if incident is None:
            return
        dialog = PhaseFormDialog(
            incident_id=incident.incident_id,
            phase=incident.current_phase,
            service=self._service,
            parent=self,
        )
        dialog.exec()
        # Nach Einreichen ODER Entwurf-Speichern neu laden, damit die
        # Timeline/Liste den neuen Stand (Phasenwechsel) widerspiegelt.
        if dialog.chosen_action() != PhaseFormDialog.ACTION_NONE:
            self.refresh()

    def _on_export_meldevorlage(self, is_archive: bool) -> None:
        """Baut die NIS2-Meldevorlage und speichert sie / kopiert sie.

        Der Bearbeiter waehlt die Ziel-Frist, dann wird die Vorlage aus den
        eingereichten Phasen-Payloads gebaut (``build_meldevorlage``). Speichern
        via QFileDialog; bei Abbruch des Datei-Dialogs landet die Vorlage in der
        Zwischenablage (Fallback).

        Args:
            is_archive: True, wenn der Export aus dem Archiv-Tab kommt.
        """
        detail = self._archive_detail if is_archive else self._open_detail
        incident = detail.current_incident()
        if incident is None:
            return
        frist = self._ask_meldefrist()
        if frist is None:
            return
        try:
            full = self._service.load_incident(incident.incident_id) or incident
            payloads = _collect_phase_payloads(full)
        except (RuntimeError, OSError) as exc:
            _log.exception("nis2_meldevorlage_build_failed")
            FinlaiInfoDialog(
                title="Meldevorlage fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()
            return
        self._save_or_copy_meldevorlage(full, frist, payloads, incident.title)

    def _ask_meldefrist(self) -> MeldeFrist | None:
        """Fragt die Ziel-Frist per Auswahl-Dialog ab (None = Abbruch)."""
        from PySide6.QtWidgets import QInputDialog  # noqa: PLC0415

        labels = {
            "24h-Fruehwarnung": MeldeFrist.FRUEHWARNUNG_24H,
            "72h-Meldung": MeldeFrist.MELDUNG_72H,
            "30d-Abschlussbericht": MeldeFrist.ABSCHLUSS_30D,
        }
        choice, ok = QInputDialog.getItem(
            self,
            "Meldevorlage exportieren",
            "Fuer welche NIS2-Frist?",
            list(labels.keys()),
            0,
            editable=False,
        )
        if not ok:
            return None
        return labels.get(choice)

    def _save_or_copy_meldevorlage(
        self,
        incident,  # noqa: ANN001 — Nis2Incident (voll geladen)
        frist: MeldeFrist,
        payloads: dict,
        title: str,
    ) -> None:
        """Speichert die Vorlage als PDF (Default) oder Markdown — sonst Clipboard.

        PDF ist die richtlinienkonforme Standardausgabe (FINLAI-gebrandet,
        mit Pflichtangaben-Status). Markdown bleibt fuer Copy-paste ins
        CSIRT-Portal waehlbar; bei Dialog-Abbruch landet die Markdown-Variante in
        der Zwischenablage.
        """
        from pathlib import Path  # noqa: PLC0415

        from PySide6.QtWidgets import (  # noqa: PLC0415
            QApplication,
            QFileDialog,
        )

        safe = "".join(c if c.isalnum() else "_" for c in title)[:40] or "nis2"
        path, selected = QFileDialog.getSaveFileName(
            self,
            "Meldevorlage speichern",
            f"{safe}_meldevorlage.pdf",
            "PDF-Dokument (*.pdf);;Markdown-Datei (*.md);;Text-Datei (*.txt)",
        )
        if not path:
            QApplication.clipboard().setText(
                build_meldevorlage(incident, frist, payloads)
            )
            FinlaiSuccessDialog(
                title="In Zwischenablage kopiert",
                message="Die Meldevorlage wurde in die Zwischenablage kopiert.",
                parent=self,
            ).exec()
            return

        as_pdf = path.lower().endswith(".pdf") or (
            "pdf" in selected.lower() and not path.lower().endswith((".md", ".txt"))
        )
        try:
            if as_pdf:
                target = path if path.lower().endswith(".pdf") else f"{path}.pdf"
                build_meldevorlage_pdf(incident, frist, payloads, Path(target))
            else:
                target = path
                with open(target, "w", encoding="utf-8") as fh:
                    fh.write(build_meldevorlage(incident, frist, payloads))
        except (OSError, RuntimeError) as exc:
            _log.exception("nis2_meldevorlage_write_failed")
            FinlaiInfoDialog(
                title="Speichern fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()
            return
        FinlaiSuccessDialog(
            title="Meldevorlage gespeichert",
            message="Die Vorlage wurde gespeichert.",
            file_path=str(target),
            parent=self,
        ).exec()

    def _on_close_incident(self) -> None:
        incident = self._open_detail.current_incident()
        if incident is None:
            return
        confirm = FinlaiConfirmDialog(
            title="Vorfall schliessen",
            message=(
                f"Vorfall '{incident.title}' abschliessen? Diese Aktion ist "
                "nicht reversibel, der Audit-Trail bleibt jedoch erhalten."
            ),
            confirm_text="Schliessen",
            parent=self,
        )
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._service.close_incident(
                incident_id=incident.incident_id,
                actor="",
                note="Vorfall per Tool geschlossen",
            )
        except (ValueError, RuntimeError, OSError) as exc:
            _log.exception("nis2_close_incident_failed")
            FinlaiInfoDialog(
                title="Schliessen fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()
            return
        # Vorfall wandert von 'offen' ins 'Archiv': offene Selektion leeren,
        # geschlossene auf den gerade geschlossenen Vorfall setzen.
        self._selected_open = None
        self._selected_closed = incident.incident_id
        self.refresh()


def _collect_phase_payloads(
    incident: Nis2Incident,
) -> dict[IncidentPhase, dict]:
    """Pure: sammelt je Phase den Payload des zuletzt eingereichten Events.

    Spaetere Events einer Phase ueberschreiben fruehere — die Vorlage zeigt
    den aktuellen (zuletzt eingereichten) Stand je Phase.

    Args:
        incident: Der Vorfall samt ``events``-Trail.

    Returns:
        Map ``IncidentPhase`` → Payload-Dict (nur Phasen mit Payload).
    """
    payloads: dict[IncidentPhase, dict] = {}
    for phase in phase_order():
        for event in incident.events:
            if event.phase is phase and event.payload:
                payloads[phase] = dict(event.payload)
    return payloads


def _deadline_sort_key(
    incident: Nis2Incident, now: datetime | None = None
) -> float:
    """Pure: sortier-Schluessel = Sekunden bis naechste Frist (kuerzeste zuerst)."""
    reference = now or datetime.now(UTC)
    phase: IncidentPhase | None = incident.current_phase
    while phase is not None:
        deadline = incident.deadline_for(phase)
        if deadline is not None:
            return (deadline - reference).total_seconds()
        phase = next_phase(phase)
    # Kein Phase mit Frist mehr — Vorfall ans Ende der Liste
    return float("inf")


def _is_critical_deadline(
    incident: Nis2Incident, now: datetime | None = None
) -> bool:
    """Pure: True wenn die naechste Frist in unter 6 Stunden ablaeuft."""
    reference = now or datetime.now(UTC)
    phase: IncidentPhase | None = incident.current_phase
    while phase is not None:
        deadline = incident.deadline_for(phase)
        if deadline is not None:
            remaining = (deadline - reference).total_seconds()
            return 0 <= remaining < 6 * 3600
        phase = next_phase(phase)
    return False


def _brush(color_token: str):  # noqa: ANN201
    from PySide6.QtGui import QBrush, QColor  # noqa: PLC0415

    return QBrush(QColor(color_token))


def _default_audit_choices_provider() -> list[tuple[str, str]]:
    """Standalone-/Fallback-Provider — laedt Customer-Audit-Summaries.

    Baut ein eigenes Service-Buendel (Composition-Root) und liest die Audit-
    Summaries. Spiegelt den Lese-/Feldzugriff von ``CustomerListWidget``
    (Summary-Dicts mit ``audit_id``/``firmenname``). Fail-safe: bei Import-/
    DB-Fehlern leere Liste, damit das Tool standalone (Tests, Demo) startet.
    """
    try:
        from tools.customer_audit.application.services import (  # noqa: PLC0415
            create_customer_audit_services,
        )

        services = create_customer_audit_services()
        summaries = services.load.get_all_summaries(limit=100)
    except Exception:  # noqa: BLE001 -- Standalone/Demo: Tool-Start nie crashen
        return []
    return [
        (
            s.get("audit_id", ""),
            f"{s.get('firmenname', 'Unbekannt')} ({s.get('audit_id', '')[:8]})",
        )
        for s in summaries
        if s.get("audit_id")
    ]


