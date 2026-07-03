"""
tuner_widget — "System optimieren" GUI (Scan + Apply-Verdrahtung).

Zeigt Edition-Ehrlichkeit, Verwaltungsstatus, Privacy-Score und eine Tabelle der
Empfehlungen (Ist→Soll). **Anwenden** laeuft fail-closed:
Consent (R7) → Confirm-Dialog → elevated Round-Trip im Worker-Thread. Solange
``elevated_apply.APPLY_ENABLED=False`` ist, liefert der elevated Pfad ``BLOCKED``
("noch nicht freigegeben") — die UX ist vollstaendig, mutiert aber nichts.

Status wird textuell signalisiert (kein hartkodiertes Farbschema). Score nutzt
das Theme-ACCENT-Token.

Schichtzugehoerigkeit: gui/ (PySide6-Adapter; nutzt application + domain + core).

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import Qt, QThread
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog, FinlaiSuccessDialog
from core.icons import Icons
from core.logger import get_logger
from core.widgets.tool_page import ToolPage
from tools.system_tuner.application.apply_terms import APPLY_TERMS_TEXT
from tools.system_tuner.application.consent_gate import (
    CURRENT_EULA_VERSION,
    ConsentGate,
)
from tools.system_tuner.application.elevated_round_trip import consent_path
from tools.system_tuner.application.evidence_service import (
    EvidenceExporter,
    build_evidence_report,
)
from tools.system_tuner.application.tuner_scan_use_case import TunerScanUseCase
from tools.system_tuner.domain.enums import TweakStatus
from tools.system_tuner.domain.scan_entities import ScanReport
from tools.system_tuner.gui.apply_confirm_dialog import ApplyConfirmDialog
from tools.system_tuner.gui.apply_worker import ApplyWorker
from tools.system_tuner.gui.consent_dialog import ConsentDialog

log = get_logger(__name__)

_STATUS_LABEL: dict[TweakStatus, str] = {
    TweakStatus.APPLIED: "Angewandt",
    TweakStatus.NOT_APPLIED: "Offen",
    TweakStatus.UNKNOWN: "Unbekannt",
}

_HEADERS: tuple[str, ...] = (
    "Empfehlung",
    "Kategorie",
    "Risiko",
    "Aktuell → Soll",
    "Status",
)

class SystemTunerWidget(ToolPage):
    """Datenschutz-/Telemetrie-Uebersicht + Anwenden: kein Pro-Gate mehr;
    Ed25519-Katalog-Signaturpruefung im Apply-Flow bleibt fail-closed der Trust-Root)."""

    def __init__(
        self,
        scan_use_case: TunerScanUseCase,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__("System optimieren", help_key="system_tuner", parent=parent)
        self._scan_use_case = scan_use_case
        self._report: ScanReport | None = None
        self._thread: QThread | None = None
        self._worker: ApplyWorker | None = None

        self._edition_lbl = self._wrapped_label()
        self._managed_lbl = self._wrapped_label()
        self._score_lbl = QLabel()
        self._score_lbl.setTextFormat(Qt.TextFormat.PlainText)

        controls = QHBoxLayout()
        controls.addWidget(self._score_lbl)
        controls.addStretch(1)
        self._apply_btn = QPushButton("Empfehlungen anwenden")
        self._apply_btn.clicked.connect(self._on_apply_clicked)
        self._configure_apply_button()
        controls.addWidget(self._apply_btn)
        self._refresh_btn = QPushButton("Aktualisieren")
        self._refresh_btn.clicked.connect(self._refresh)
        controls.addWidget(self._refresh_btn)
        self._export_btn = QPushButton("Nachweis exportieren")
        self._export_btn.setToolTip(
            "Erzeugt einen DSGVO/NIS2-Datenschutz-Nachweis (PDF) aus dem aktuellen Scan."
        )
        self._export_btn.clicked.connect(self._on_export_clicked)
        controls.addWidget(self._export_btn)

        self._table = QTableWidget(0, len(_HEADERS))
        self._table.setHorizontalHeaderLabels(list(_HEADERS))
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )

        self.body.addWidget(self._edition_lbl)
        self.body.addWidget(self._managed_lbl)
        self.body.addLayout(controls)
        self._hint_lbl = QLabel(
            "Haken Sie die Empfehlungen an, die angewandt werden sollen."
        )
        self._hint_lbl.setWordWrap(True)
        self._hint_lbl.setTextFormat(Qt.TextFormat.PlainText)
        self._hint_lbl.setStyleSheet(f"color: {theme.get().TEXT_DIM};")
        self.body.addWidget(self._hint_lbl)
        self.body.addWidget(self._table, stretch=1)

        self._refresh()

    @staticmethod
    def _wrapped_label() -> QLabel:
        lbl = QLabel()
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.TextFormat.PlainText)
        return lbl

    def _on_export_clicked(self) -> None:
        """Exportiert den aktuellen Scan als DSGVO/NIS2-Nachweis (PDF).

        Read-only: nutzt den bereits geladenen ``ScanReport`` (``self._report``)
        und den ``EvidenceExporter`` (Muster ``system_exporter``). Unabhaengig
        vom fail-closed Apply-Pfad — mutiert nichts am System.
        """
        if self._report is None:
            FinlaiInfoDialog(
                "Kein Scan vorhanden",
                "Bitte fuehren Sie zuerst einen Scan aus (Aktualisieren).",
                parent=self,
            ).exec()
            return
        default_name = (
            f"norisk-datenschutz-nachweis-{datetime.now(UTC).strftime('%Y%m%d')}.pdf"
        )
        path, _ = QFileDialog.getSaveFileName(
            self, "Nachweis speichern", default_name, "PDF-Dokument (*.pdf)"
        )
        if not path:
            return
        generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        report = build_evidence_report(self._report, generated_at=generated_at)
        try:
            EvidenceExporter().export_pdf(report, path)
        except Exception as exc:  # noqa: BLE001 — Export darf die App nie crashen
            log.exception("Nachweis-Export fehlgeschlagen: %s", exc)
            FinlaiInfoDialog(
                "Export fehlgeschlagen",
                f"Der Nachweis konnte nicht erstellt werden: {exc}",
                parent=self,
            ).exec()
            return
        FinlaiSuccessDialog(
            "Nachweis erstellt",
            "Der Datenschutz-/Telemetrie-Nachweis wurde als PDF gespeichert.",
            file_path=path,
            parent=self,
        ).exec()

    def _configure_apply_button(self) -> None:
        """Aktiviert den Anwenden-Button: kein Pro-Gate mehr; die
        Ed25519-Katalog-Signaturpruefung im Apply-Flow bleibt der Trust-Root)."""
        self._apply_btn.setEnabled(True)
        self._apply_btn.setToolTip("Empfohlene Datenschutz-Aenderungen anwenden")

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        """Fuehrt den read-only Scan aus und rendert das Ergebnis (fail-safe)."""
        try:
            report = self._scan_use_case.scan()
        except Exception as exc:  # noqa: BLE001 — GUI darf nie crashen
            log.warning("system_tuner-Scan fehlgeschlagen: %s", exc)
            self._edition_lbl.setText(
                "Scan konnte nicht ausgefuehrt werden. Bitte erneut versuchen."
            )
            self._table.setRowCount(0)
            self._report = None
            return
        self._render(report)

    def _render(self, report: ScanReport) -> None:
        """Befuellt Banner, Score und Tabelle aus dem Scan-Report."""
        self._report = report
        colors = theme.get()
        self._edition_lbl.setText(report.edition.banner_de)
        self._managed_lbl.setText(report.managed.detail_de)
        self._score_lbl.setText(
            f"Privacy-Score: {report.score.value}/100 "
            f"({report.score.label_de}) — {report.score.disclaimer_de}"
        )
        self._score_lbl.setStyleSheet(f"font-weight: bold; color: {colors.ACCENT};")

        by_id = {tweak.id: tweak for tweak in report.tweaks}
        self._table.setRowCount(len(report.states))
        for row, state in enumerate(report.states):
            tweak = by_id.get(state.tweak_id)
            title = tweak.title_de if tweak else state.tweak_id
            category = tweak.category.value if tweak else ""
            risk = tweak.risk_tier.value if tweak else ""
            transition = f"{state.current_value or '?'} → {state.desired_value or '?'}"
            status = _STATUS_LABEL.get(state.status, state.status.value)
            is_open = state.status is TweakStatus.NOT_APPLIED
            for col, text in enumerate((title, category, risk, transition, status)):
                item = QTableWidgetItem(text)
                if col == 0 and is_open:
                    # Offene Empfehlungen sind einzeln an-/abwaehlbar; nur die
                    # angehakten werden angewandt. Die tweak_id haengt als
                    # UserRole am Checkbox-Item — kein zweiter Index (Regel 2).
                    item.setFlags(
                        Qt.ItemFlag.ItemIsEnabled
                        | Qt.ItemFlag.ItemIsSelectable
                        | Qt.ItemFlag.ItemIsUserCheckable
                    )
                    item.setData(Qt.ItemDataRole.UserRole, state.tweak_id)
                    item.setCheckState(Qt.CheckState.Checked)
                else:
                    item.setFlags(
                        Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
                    )
                self._table.setItem(row, col, item)

    # ------------------------------------------------------------------
    # Apply (Pro, fail-closed)
    # ------------------------------------------------------------------

    def _open_recommendations(self) -> list[tuple[str, str, str]]:
        """``(tweak_id, titel, "Ist → Soll")`` aller offenen (NOT_APPLIED) Tweaks."""
        if self._report is None:
            return []
        by_id = {t.id: t for t in self._report.tweaks}
        rows: list[tuple[str, str, str]] = []
        for state in self._report.states:
            if state.status is not TweakStatus.NOT_APPLIED:
                continue
            tweak = by_id.get(state.tweak_id)
            title = tweak.title_de if tweak else state.tweak_id
            transition = f"{state.current_value or '?'} → {state.desired_value or '?'}"
            rows.append((state.tweak_id, title, transition))
        return rows

    def _selected_recommendations(self) -> list[tuple[str, str, str]]:
        """``(tweak_id, titel, "Ist → Soll")`` der ANGEHAKTEN offenen Tweaks.

        Liest die Auswahl direkt aus den Checkboxen der Empfehlungs-Tabelle
        (Spalte 0). Die ``tweak_id`` haengt als ``UserRole`` am Checkbox-Item —
        keine zweite Synchronstruktur (Coding-Rule 2).
        """
        if self._report is None:
            return []
        by_id = {t.id: t for t in self._report.tweaks}
        states_by_id = {s.tweak_id: s for s in self._report.states}
        rows: list[tuple[str, str, str]] = []
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item is None or item.checkState() is not Qt.CheckState.Checked:
                continue
            tweak_id = item.data(Qt.ItemDataRole.UserRole)
            state = states_by_id.get(tweak_id)
            if state is None:
                continue
            tweak = by_id.get(tweak_id)
            title = tweak.title_de if tweak else tweak_id
            transition = f"{state.current_value or '?'} → {state.desired_value or '?'}"
            rows.append((tweak_id, title, transition))
        return rows

    def _on_apply_clicked(self) -> None:
        """Apply-Flow: Auswahl → Consent → Confirm → elevated Worker
: kein Pro-Gate mehr; Katalog-Signatur bleibt Trust-Root).

        Es werden NUR die in der Tabelle angehakten Empfehlungen angewandt.
        """
        if not self._open_recommendations():
            FinlaiInfoDialog(
                title="System optimieren",
                message="Es sind keine Empfehlungen offen.",
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        selected = self._selected_recommendations()
        if not selected:
            FinlaiInfoDialog(
                title="System optimieren",
                message="Keine Empfehlung ausgewaehlt. Haken Sie mindestens eine "
                "Empfehlung an, die angewandt werden soll.",
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        if not self._ensure_consent():
            return
        dialog = ApplyConfirmDialog(
            [(title, transition) for _id, title, transition in selected],
            parent=self,
        )
        if dialog.exec() != ApplyConfirmDialog.DialogCode.Accepted:
            return
        self._start_apply([tid for tid, _t, _tr in selected])

    def _ensure_consent(self) -> bool:
        """Stellt das einmalige Pro-Apply-Consent sicher (R7); Dialog bei Bedarf.

        Zeigt den vollstaendigen Nutzungshinweis (:data:`APPLY_TERMS_TEXT`) im
:class:`ConsentDialog`; bei Zustimmung wird sie versioniert + protokolliert.
        """
        gate = ConsentGate(consent_path())
        if gate.has_consent(CURRENT_EULA_VERSION):
            return True
        dialog = ConsentDialog(APPLY_TERMS_TEXT, parent=self)
        if dialog.exec() != ConsentDialog.DialogCode.Accepted:
            return False
        gate.record_consent(recorded_at=datetime.now(UTC).isoformat())
        return True

    def _start_apply(self, tweak_ids: list[str]) -> None:
        """Startet den elevated Apply im Worker-Thread (UI bleibt responsiv)."""
        self._apply_btn.setEnabled(False)
        self._apply_btn.setText("Wird angewandt …")
        self._thread = QThread()
        self._worker = ApplyWorker(tweak_ids)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.done.connect(self._on_apply_done)
        self._worker.failed.connect(self._on_apply_failed)
        self._worker.done.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.start(QThread.Priority.LowPriority)

    def _restore_apply_button(self) -> None:
        self._apply_btn.setText("Empfehlungen anwenden")
        self._configure_apply_button()

    def _on_apply_done(self, result: object) -> None:
        """Zeigt das Ergebnis des elevated Apply + frischt den Scan auf.

        Macht den Elevation-Ausgang sichtbar (D6): bei abgelehnten oder
        fehlgeschlagenen Tweaks werden die Detail-Gruende mit angezeigt — vor
        allem globale Reject-Marker wie ``"A3: Laufzeit-Image nicht
        vertrauenswuerdig"``, die im unsignierten Build den Apply blocken.
        """
        self._restore_apply_button()
        if result is None or not getattr(result, "results", ()):
            FinlaiInfoDialog(
                title="System optimieren",
                message="Das Anwenden wurde abgebrochen, abgelehnt oder ist noch "
                "nicht freigegeben. Es wurde nichts geaendert.",
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            self._refresh()
            return
        applied = getattr(result, "applied", 0)
        blocked = getattr(result, "blocked", 0)
        failed = getattr(result, "failed", 0)
        message = (
            f"Angewandt: {applied} · Abgelehnt/gesperrt: {blocked} · "
            f"Fehlgeschlagen: {failed}."
        )
        reasons = self._apply_reason_lines(result)
        if reasons:
            message += "\n\nGruende:\n" + "\n".join(f"• {line}" for line in reasons)
        FinlaiInfoDialog(
            title="System optimieren",
            message=message,
            icon_name=Icons.INFO,
            parent=self,
        ).exec()
        self._refresh()

    def _apply_reason_lines(self, result: object) -> list[str]:
        """Sammelt die Detail-Gruende abgelehnter oder fehlgeschlagener Tweaks.

        Args:
            result: Das ``BatchResult`` des elevated Apply-Round-Trips.

        Returns:
            Lesbare ``"<Titel>: <Grund>"``-Zeilen. Globale Reject-Marker ohne
            Tweak-Bezug (``tweak_id`` nicht im Scan-Report) erscheinen nur mit
            ihrem Grund. Leer, wenn nichts abgelehnt/fehlgeschlagen ist.
        """
        titles = (
            {t.id: t.title_de for t in self._report.tweaks}
            if self._report is not None
            else {}
        )
        failed_states = (
            TweakStatus.BLOCKED,
            TweakStatus.FAILED,
            TweakStatus.FAILED_ROLLED_BACK,
        )
        lines: list[str] = []
        for r in getattr(result, "results", ()):
            if r.status not in failed_states:
                continue
            detail = (r.detail or "").strip()
            if not detail:
                continue
            label = titles.get(r.tweak_id)
            lines.append(f"{label}: {detail}" if label else detail)
        return lines

    def _on_apply_failed(self, message: str) -> None:
        self._restore_apply_button()
        log.warning("system_tuner Apply fehlgeschlagen: %s", message)
        FinlaiInfoDialog(
            title="System optimieren",
            message="Das Anwenden ist unerwartet fehlgeschlagen.",
            icon_name=Icons.WARNING,
            parent=self,
        ).exec()
