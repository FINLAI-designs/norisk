"""
customer_wizard — 9-Schritt-Wizard fuer das Kunden-Audit.

Koordiniert die Schritte, fuehrt die Berechnung durch und speichert das Ergebnis.

Schichtzugehoerigkeit: gui/ — nur UI-Logik + Use-Case-Aufruf.

Author: Patrick Riederich
Version: 1.1-Review-Followup: Step-Count im
Docstring + Signal ``audit_saved`` (alter Name ``assessment_saved``
als Backwards-Compat-Alias).
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from tools.customer_audit.application.risk_assessment_service import (
    RiskAssessmentService,
)
from tools.customer_audit.application.services import (
    CustomerAuditServices,
)
from tools.customer_audit.domain.entities import (
    AuditMode,
    CustomerAuditResult,
    compute_backup_score,
)
from tools.customer_audit.domain.risk_derivation import derive_risk_seeds
from tools.customer_audit.gui.step_widgets.backup_step import BackupStep
from tools.customer_audit.gui.step_widgets.customer_data_step import (
    CustomerDataStep,
)
from tools.customer_audit.gui.step_widgets.incident_response_step import (
    IncidentResponseStep,
)
from tools.customer_audit.gui.step_widgets.infrastructure_step import (
    InfrastructureStep,
)
from tools.customer_audit.gui.step_widgets.mode_select_step import ModeSelectStep
from tools.customer_audit.gui.step_widgets.network_step import NetworkStep
from tools.customer_audit.gui.step_widgets.organizational_step import (
    OrganizationalStep,
)
from tools.customer_audit.gui.step_widgets.phishing_step import PhishingStep
from tools.customer_audit.gui.step_widgets.risk_matrix_step import RiskMatrixStep
from tools.customer_audit.gui.step_widgets.sovereignty_step import SovereigntyStep
from tools.customer_audit.gui.step_widgets.summary_step import SummaryStep

log = get_logger(__name__)

# Wizard erweitert um Mode-Switch + Backup-Audit.
# + Datensouveraenitaets-Audit.
# + Incident-Response-Plan vor Summary.
# + Risiko-Bewertung (BSI 200-3) vor Summary.
_STEP_TITLES = [
    "1 · Audit-Modus",
    "2 · Kundenstammdaten",
    "3 · IT-Infrastruktur",
    "4 · Organisatorische Sicherheit",
    "5 · Netzwerksicherheit",
    "6 · Backup-Audit",
    "7 · Datensouveraenitaet",
    "8 · Incident-Response-Plan",
    "9 · Phishing- / E-Mail-Sicherheit",
    "10 · Risiko-Bewertung (BSI 200-3)",
    "11 · Ergebnis",
]

_SUMMARY_STEP = 10  # 0-basierter Index des Ergebnis-Slots (Phishing-Step: +1)


class CustomerWizard(QDialog):
    """9-Schritt-Wizard zum Erstellen eines Kunden-Audits.

    Signals:
        audit_saved: Emittiert mit dem Ergebnis nach erfolgreichem
            Speichern. ``assessment_saved`` ist ein Backwards-Compat-
            Alias fuer Code, der vor entstanden ist.

    Attributes:
        _steps: Liste der Schritt-Widgets.
        _stack: Gestapeltes Widget fuer die Schritte.
        _use_case: CreateAuditUseCase-Instanz.
        _result: Berechnetes Ergebnis (None bis zum Summary-Step).
    """

    audit_saved = Signal(object)  # CustomerAuditResult
    assessment_saved = audit_saved  # Backwards-Compat-Alias

    def __init__(
        self,
        services: CustomerAuditServices,
        parent: QWidget | None = None,
        *,
        risk_service: RiskAssessmentService | None = None,
    ) -> None:
        """Initialisiert den Wizard.

        Args:
            services: Use-Case-Buendel: GUI nutzt application-
                Services statt direkter Repository-Anbindung).
            parent: Optionales Eltern-Widget.
            risk_service: Optionaler RiskAssessmentService — Default:
                neue Instanz. Injizierbar fuer Tests.
        """
        super().__init__(parent)
        self._use_case = services.create
        self._version_use_case = services.create_version
        self._result: CustomerAuditResult | None = None
        # Phase 3: gemessene SELF-Vorbefuellung. Der core
        # ScanDataPort wird im Hintergrund-Worker EINMAL erhoben + gecacht und
        # dann an Infra- UND Netzwerk-Step verteilt (kein Doppel-Scan).
        self._scan_prefill = services.scan_prefill
        self._audit_prefill: object | None = None
        self._prefill_pending: list = []
        self._prefill_running = False
        self._prefill_signals: object | None = None
        # Ansichts-Modus: von load_for_view gesetzt — bestehende Audits
        # werden nur angezeigt, nicht ueberschrieben (immutable Record).
        self._view_only = False
        # Edit-Modus: von load_for_edit gesetzt — Speichern erzeugt eine
        # neue Version des Audits ``_base_audit_id`` (statt eines neuen Audits).
        self._base_audit_id: str | None = None
        self._risk_service = risk_service or RiskAssessmentService()
        self._build_ui()
        self._update_navigation()
        # /: Initial-Resize NACH dem Build, damit der Wizard
        # mit einer vernuenftigen Groesse oeffnet (720x720) und nicht der
        # max-sizeHint folgt. Auf kleinen Screens (< 800px) wird die
        # Hoehe auf available - 60 gekappt.
        _screen = QApplication.primaryScreen()
        if _screen is not None:
            _avail = _screen.availableGeometry()
            self.resize(720, min(720, _avail.height() - 60))

    def _build_ui(self) -> None:
        """Baut das Dialog-Layout auf."""
        c = theme.get()
        self.setWindowTitle("Security-Audit")
        self.setMinimumSize(600, 560)
        # / (2026-05-27/28): Dialog war ohne Cap > 1100px hoch
        # (Footer-Buttons unter dem Bildschirmrand) auf 1080p-Screens.
        # Ursache: ``QStackedWidget.sizeHint`` aggregiert die max-Hoehe
        # aller Step-Pages (Risk-Matrix-Heatmap, Summary). Qt's Layout-
        # Engine ignoriert setMaximumHeight/setFixedHeight/sizeHint-
        # Overrides zuverlaessig nicht (Live-Smoke 2026-05-28 bewies das).
        # Robuste Loesung: ``QScrollArea`` um den ``QStackedWidget`` --
        # einzelne Step-Pages koennen beliebig hoch sein, der Wizard
        # selbst bleibt im Cap und scrollt intern fuer ueberlange Steps.
        # Dazu ein initialer ``resize(720, min(720, screen-cap))`` damit
        # der Dialog beim ersten Open vernuenftig dimensioniert ist.
        self.setStyleSheet(f"background: {c.BG_MAIN}; color: {c.TEXT_MAIN};")

        root = QVBoxLayout(self)
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)

        # --- Schritt-Anzeige (Breadcrumb) ---
        self._lbl_step = QLabel()
        self._lbl_step.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_step.setStyleSheet(
            f"background: {c.CARD_BG}; color: {c.ACCENT};"
            " font-family: Raleway; font-weight: 700; font-size: 13px;"
            f" padding: 10px; border-bottom: 1px solid {c.BORDER};"
        )
        root.addWidget(self._lbl_step)

        # --- Inhaltsbereich ---
        content_wrapper = QWidget()
        content_wrapper.setStyleSheet(f"background: {c.BG_MAIN};")
        content_layout = QVBoxLayout(content_wrapper)
        content_layout.setContentsMargins(24, 16, 24, 16)
        content_layout.setSpacing(0)

        self._stack = QStackedWidget()

        self._step_mode = ModeSelectStep()
        self._step_customer = CustomerDataStep()
        self._step_infra = InfrastructureStep()
        self._step_org = OrganizationalStep()
        self._step_network = NetworkStep()
        self._step_backup = BackupStep()
        self._step_sovereignty = SovereigntyStep()
        self._step_incident = IncidentResponseStep()
        self._step_phishing = PhishingStep()
        self._step_risk = RiskMatrixStep()
        self._step_summary = SummaryStep()

        self._steps = [
            self._step_mode,
            self._step_customer,
            self._step_infra,
            self._step_org,
            self._step_network,
            self._step_backup,
            self._step_sovereignty,
            self._step_incident,
            self._step_phishing,
            self._step_risk,
            self._step_summary,
        ]
        for step in self._steps:
            self._stack.addWidget(step)

        # Risikomatrix-Refresh: die Ableitung an das Betreten des
        # Risk-Steps haengen — egal aus welcher Richtung. Vorher hing das Seeding
        # an _go_next (nur Vorwaerts-Sprung Phishing->Risk), wodurch geaenderte
        # Antworten im Edit-Modus/Rueckwaerts-Pfad die Matrix stale liessen.
        # currentChanged feuert hier noch NICHT (Index 0 ist bereits aktiv).
        self._stack.currentChanged.connect(self._on_stack_changed)

        # Phase 1: im Kunden-Audit die Auto-Detektion (Backup-/
        # Souveränitäts-Scan) sperren — kein Eigenscan im Fremd-Audit. Die
        # autoritative Sperre sitzt in der Use-Case-Assertion; dies hält die
        # GUI synchron, damit der Nutzer gar nicht erst einen Scan auslöst.
        self._step_mode.mode_changed.connect(self._apply_mode_to_scanner_steps)
        self._apply_mode_to_scanner_steps(self._step_mode.get_mode())

        # Phase 3: Infra-/Netzwerk-Step fordern die gemessene
        # Vorbefuellung an → Wizard erhebt den Snapshot im Worker und verteilt ihn.
        self._step_infra.prefill_requested.connect(self._on_prefill_requested)
        self._step_network.prefill_requested.connect(self._on_prefill_requested)

        # /: QScrollArea um QStackedWidget -- siehe Kommentar
        # in _build_ui. Damit kann der Wizard im Screen-Cap bleiben, auch
        # wenn ein Step-Widget (Risk-Matrix-Heatmap, Summary) viel
        # vertikalen Raum braucht.
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._scroll.setStyleSheet(f"background: {c.BG_MAIN};")
        self._scroll.setWidget(self._stack)
        content_layout.addWidget(self._scroll)
        root.addWidget(content_wrapper, stretch=1)

        # --- Fehlermeldung ---
        self._lbl_error = QLabel("")
        self._lbl_error.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_error.setStyleSheet(
            f"color: {c.DANGER}; font-size: 13px; padding: 4px 24px;"
        )
        self._lbl_error.hide()
        root.addWidget(self._lbl_error)

        # --- Navigation ---
        nav = QWidget()
        nav.setStyleSheet(f"background: {c.CARD_BG}; border-top: 1px solid {c.BORDER};")
        nav_layout = QHBoxLayout(nav)
        nav_layout.setContentsMargins(16, 10, 16, 10)

        self._btn_back = QPushButton("Zurück")
        self._btn_back.clicked.connect(self._go_back)
        self._btn_back.setStyleSheet(self._secondary_btn_style(c))

        self._btn_next = QPushButton("Weiter")
        self._btn_next.clicked.connect(self._go_next)
        self._btn_next.setStyleSheet(self._primary_btn_style(c))

        self._btn_calculate = QPushButton("Berechnen")
        self._btn_calculate.clicked.connect(self._calculate)
        self._btn_calculate.setStyleSheet(self._primary_btn_style(c))
        self._btn_calculate.hide()

        self._btn_save = QPushButton("Speichern & Schließen")
        self._btn_save.clicked.connect(self._save_and_close)
        self._btn_save.setStyleSheet(self._primary_btn_style(c))
        self._btn_save.hide()

        self._btn_cancel = QPushButton("Abbrechen")
        self._btn_cancel.clicked.connect(self.reject)
        self._btn_cancel.setStyleSheet(self._secondary_btn_style(c))

        nav_layout.addWidget(self._btn_cancel)
        nav_layout.addStretch()
        nav_layout.addWidget(self._btn_back)
        nav_layout.addWidget(self._btn_next)
        nav_layout.addWidget(self._btn_calculate)
        nav_layout.addWidget(self._btn_save)

        root.addWidget(nav)

    @staticmethod
    def _primary_btn_style(c) -> str:
        return (
            f"QPushButton {{ background: {c.ACCENT}; color: {theme.TEXT_ON_ACCENT_DEEP};"
            f" border: none; border-radius: 4px; padding: 8px 18px;"
            f" font-family: Raleway; font-weight: 700; font-size: 13px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}cc; }}"
            f"QPushButton:disabled {{ background: {c.BORDER}; color: {c.TEXT_DIM}; }}"
        )

    @staticmethod
    def _secondary_btn_style(c) -> str:
        return (
            f"QPushButton {{ background: transparent; color: {c.TEXT_DIM};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 8px 18px;"
            f" font-family: Raleway; font-weight: 600; font-size: 13px; }}"
            f"QPushButton:hover {{ color: {c.TEXT_MAIN}; border-color: {c.TEXT_MAIN}; }}"
        )

    def _current_index(self) -> int:
        return self._stack.currentIndex()

    def _update_navigation(self) -> None:
        """Aktualisiert Schritt-Label und Button-Sichtbarkeit."""
        idx = self._current_index()
        self._lbl_step.setText(_STEP_TITLES[idx])
        self._lbl_error.hide()

        is_last = idx == _SUMMARY_STEP
        self._btn_back.setVisible(idx > 0)
        self._btn_next.setVisible(not is_last)
        if self._view_only:
            # Ansichts-Modus: kein Berechnen/Speichern — nur Schliessen
            # auf dem Summary. Ein bestehendes Audit ist unveraenderlich.
            self._btn_calculate.setVisible(False)
            self._btn_save.setVisible(is_last)
            self._btn_save.setText("Schließen")
        else:
            self._btn_calculate.setVisible(is_last and self._result is None)
            self._btn_save.setVisible(is_last and self._result is not None)
            # Edit-Modus: Speichern erzeugt eine neue Version.
            self._btn_calculate.setText(
                "Neu berechnen" if self._base_audit_id else "Berechnen"
            )
            self._btn_save.setText(
                "Als neue Version speichern"
                if self._base_audit_id
                else "Speichern & Schließen"
            )

    def _go_next(self) -> None:
        """Wechselt zum nächsten Schritt, wenn der aktuelle gültig ist."""
        idx = self._current_index()
        step = self._steps[idx]
        if not step.is_valid():
            self._show_error("Bitte fülle alle Pflichtfelder aus.")
            return
        if idx < _SUMMARY_STEP:
            self._stack.setCurrentIndex(idx + 1)
            self._update_navigation()
            # Seeding der Risikomatrix laeuft jetzt ueber _on_stack_changed
            # (currentChanged), unabhaengig von der Navigationsrichtung.

    def _on_stack_changed(self, idx: int) -> None:
        """Leitet die Risikomatrix neu ab, sobald der Risk-Step betreten wird.

        Richtungs-unabhaengiger Trigger: feuert bei Vorwaerts-,
        Rueckwaerts- und jedem kuenftigen Direkt-Sprung auf den Risk-Step. Andere
        Steps sind no-op.
        """
        if 0 <= idx < len(self._steps) and self._steps[idx] is self._step_risk:
            self._maybe_seed_risk()

    def _maybe_seed_risk(self) -> None:
        """Leitet die Risiko-Matrix bei JEDEM Betreten aus den Audit-Antworten ab.

 (Patrick-Entscheid 2026-06-27): nicht mehr einmalig — geaenderte
        Antworten (z. B. Phishing auf „Ja") aktualisieren die Matrix, auch im
        Edit-Modus. Leitet die Start-P/S der Katalog-Risiken aus Backup-Audit,
        organisatorischer Sicherheit und Phishing-/E-Mail-Sicherheit ab; der Step
        (:meth:`RiskMatrixStep.seed_from_audit`) schont dabei manuell angepasste
        Eintraege. Im View-Only-Modus (read-only Ansicht) wird nicht abgeleitet.
        Fail-soft — ein Fehler darf den Wizard nie blockieren.
        """
        if self._view_only:
            return
        try:
            seeds = derive_risk_seeds(
                organizational=self._step_org.get_data(),
                # Ungedeckelt: fuer die Risiko-Ableitung zaehlt die deklarierte
                # Backup-Qualitaet (sonst bleibt ein perfektes Selbst-Auskunft-
                # Backup wegen des 50%-Detection-Caps "schwach" -> Risiko hoch).
                backup_score=compute_backup_score(
                    self._step_backup.get_data(), apply_detection_cap=False
                ),
                phishing=self._step_phishing.get_data(),
            )
            if seeds:
                self._step_risk.seed_from_audit(seeds)
        except Exception:  # noqa: BLE001 — Seeding darf den Wizard nicht crashen
            log.exception("Risiko-Seeding aus Audit-Antworten fehlgeschlagen")

    def _apply_mode_to_scanner_steps(self, mode: AuditMode) -> None:
        """Gibt Auto-Detektion + Mess-Vorbefuellung nur im Selbst-Audit frei.

        Ein Kunden-Audit (CUSTOMER) darf keine Scan-Daten des eigenen Berater-
        rechners enthalten. Im CUSTOMER-Modus werden die Detektions-Schalter
        (Backup-/Souveränitäts-Step) UND die gemessene Infra-/Netzwerk-
        Vorbefuellung deaktiviert und geleert; im SELF-Modus wieder
        freigegeben. Die autoritative Sperre sitzt in der Use-Case-Assertion;
        dies hält die GUI synchron, damit gar nicht erst ein Scan ausgeloest wird.

        Args:
            mode: Der gewählte Audit-Modus.
        """
        allow = mode is AuditMode.SELF
        if not allow:
            # CUSTOMER: laufende/gecachte Mess-Vorbefuellung verwerfen, damit ein
            # verspaeteter Worker-Callback (Mode-Wechsel mitten im Scan) keine
            # Eigenscan-Werte mehr in das Fremd-Audit schreibt,
            # fail-closed — der Step-Gate `_prefill_available` ist die 2. Schranke).
            self._audit_prefill = None
            self._prefill_pending = []
            self._prefill_running = False
        self._step_backup.set_detection_available(allow)
        self._step_sovereignty.set_detection_available(allow)
        self._step_infra.set_prefill_available(allow)
        self._step_network.set_prefill_available(allow)

    # ------------------------------------------------------------------
    # Phase 3 — gemessene SELF-Vorbefuellung (Hintergrund-Worker)
    # ------------------------------------------------------------------

    def _on_prefill_requested(self, step) -> None:  # noqa: ANN001
        """Erhebt den Mess-Snapshot (einmal, gecacht) und verteilt ihn an den Step.

        Kein Provider → fail-soft Hinweis. Bereits gecacht → sofort anwenden
        (kein erneuter Scan). Sonst: Step in die Warteschlange + Worker starten
        (maximal einer gleichzeitig).
        """
        if self._scan_prefill is None:
            step.notify_prefill_failed("nicht verfuegbar")
            return
        if self._audit_prefill is not None:
            step.apply_prefill(self._audit_prefill)
            return
        if step not in self._prefill_pending:
            self._prefill_pending.append(step)
        step.set_prefill_loading(True)
        if self._prefill_running:
            return
        self._prefill_running = True
        self._start_prefill_worker()

    def _start_prefill_worker(self) -> None:
        """Startet den ScanDataPort-Snapshot im QThreadPool (nicht-blockierend)."""
        from PySide6.QtCore import QThreadPool  # noqa: PLC0415

        from tools.customer_audit.gui.prefill_worker import (  # noqa: PLC0415
            PrefillSignals,
            PrefillTask,
        )

        signals = PrefillSignals()
        # Teardown-Sicherheit: PrefillSignals hat KEIN Parent und wird vom
        # PrefillTask (QThreadPool haelt ihn bis Laufende) am Leben gehalten; der
        # Wizard selbst ueberlebt durch den Parent-Hold (parent=self + exec),
        # bis der Scan fertig ist. Diese Referenz verhindert vorzeitiges GC des
        # Traegers.
        self._prefill_signals = signals
        signals.done.connect(self._on_prefill_done)
        signals.failed.connect(self._on_prefill_failed)
        QThreadPool.globalInstance().start(PrefillTask(self._scan_prefill, signals))

    def _on_prefill_done(self, prefill) -> None:  # noqa: ANN001
        """Cacht den Snapshot und wendet ihn auf alle wartenden Steps an."""
        self._prefill_running = False
        self._audit_prefill = prefill
        pending = self._prefill_pending
        self._prefill_pending = []
        for step in pending:
            step.set_prefill_loading(False)
            step.apply_prefill(prefill)

    def _on_prefill_failed(self, reason: str) -> None:
        """Meldet allen wartenden Steps einen fehlgeschlagenen Scan (fail-soft)."""
        self._prefill_running = False
        pending = self._prefill_pending
        self._prefill_pending = []
        for step in pending:
            step.set_prefill_loading(False)
            step.notify_prefill_failed(reason)

    def _go_back(self) -> None:
        """Wechselt zum vorherigen Schritt."""
        idx = self._current_index()
        if idx > 0:
            self._stack.setCurrentIndex(idx - 1)
            self._update_navigation()

    def _show_error(self, msg: str) -> None:
        """Zeigt eine Fehlermeldung an.

        Args:
            msg: Anzuzeigende Meldung.
        """
        self._lbl_error.setText(msg)
        self._lbl_error.show()

    def _calculate(self) -> None:
        """Berechnet das Ergebnis und zeigt es im Summary.

        Neu-Audit (Default) → ``CreateAuditUseCase``. Edit-Modus,
        ``_base_audit_id`` gesetzt) → ``CreateVersionUseCase``: speichert eine
        neue Version des geladenen Audits, das Original bleibt erhalten.
        """
        customer_data = self._step_customer.get_data()
        infrastructure_data = self._step_infra.get_data()
        organizational_data = self._step_org.get_data()
        network_data = self._step_network.get_data()
        # Risikomatrix-Refresh: vor dem Einsammeln der Bewertungen
        # aus den AKTUELLEN Antworten neu ableiten — fuer den Pfad, in dem der
        # User (v.a. im Edit-Modus) Antworten aendert und direkt "Berechnen"
        # drueckt, ohne den Risk-Step erneut zu betreten. seed_from_audit schont
        # manuell angepasste Eintraege.
        self._maybe_seed_risk()
        # Iter 2e-ii: Risk-Bewertungen fliessen in die Empfehlungen ein.
        common = {
            "audit_mode": self._step_mode.get_mode(),
            "backup_audit": self._step_backup.get_data(),
            "sovereignty_audit": self._step_sovereignty.get_data(),
            "incident_response_plan": self._step_incident.get_data(),
            "phishing_data": self._step_phishing.get_data(),
            "risk_assessments": self._step_risk.collected_assessments(),
        }
        try:
            if self._base_audit_id:
                result = self._version_use_case.execute(
                    self._base_audit_id,
                    customer_data,
                    infrastructure_data,
                    organizational_data,
                    network_data,
                    **common,
                )
            else:
                result = self._use_case.execute(
                    customer_data=customer_data,
                    infrastructure_data=infrastructure_data,
                    organizational_data=organizational_data,
                    network_data=network_data,
                    **common,
                )
        except Exception as exc:
            log.warning("Audit-Berechnung fehlgeschlagen: %s", exc)
            self._show_error(f"Berechnung fehlgeschlagen: {exc}")
            return

        self._result = result
        # Risiko-Bewertungen mit der frischen audit_id persistieren.
        self._persist_risk_assessments(result.audit_id)
        self._step_summary.set_result(
            result, self._step_risk.collected_assessments()
        )
        self._update_navigation()

    def _persist_risk_assessments(self, audit_id: str) -> None:
        """Schreibt die im Risk-Step gesammelten Bewertungen mit der
        echten Audit-UUID in die DB.

        Tolerant: Fehler beim Schreiben blocken den Wizard-Flow NICHT —
        der User soll seinen Audit-Save nicht verlieren, nur weil die
        Risk-Persistenz hakt.
        """
        try:
            from dataclasses import replace as dc_replace  # noqa: PLC0415

            assessments = [
                dc_replace(a, audit_id=audit_id)
                for a in self._step_risk.collected_assessments()
            ]
            self._risk_service.replace(audit_id, assessments)
        except Exception:  # noqa: BLE001 — Persistenz-Hook darf den Wizard nicht crashen
            log.exception("Risk-Assessment-Persistenz fehlgeschlagen")

    def _save_and_close(self) -> None:
        """Schliesst den Dialog.

        Ansichts-Modus: ein bestehendes Audit wird NICHT gespeichert —
        es ist ein unveraenderlicher Record; Re-Assessment laeuft ueber ein
        neues Audit. Im Neu-Modus wird das berechnete Ergebnis emittiert.
        """
        if self._view_only:
            self.accept()
            return
        if self._result is not None:
            self.audit_saved.emit(self._result)
        self.accept()

    def _populate_steps(self, result: CustomerAuditResult) -> None:
        """Befüllt alle Step-Widgets mit einem Audit (Basis für Ansicht/Edit).

        Lädt auch die Risiko-Bewertungen aus der DB nach; fehlt die Liste (Audit
        vor 2e), werden die 10 Defaults initialisiert (idempotent).

        Args:
            result: Das anzuzeigende/zu editierende Audit.
        """
        self._step_mode.set_mode(result.audit_mode)
        self._step_customer.set_data(result.customer_data)
        self._step_infra.set_data(result.infrastructure_data)
        self._step_org.set_data(result.organizational_data)
        self._step_network.set_data(result.network_data)
        self._step_backup.set_data(result.backup_audit)
        self._step_sovereignty.set_data(result.sovereignty_audit)
        self._step_incident.set_data(result.incident_response_plan)
        self._step_phishing.set_data(result.phishing_data)
        # Phase 1: Mode-Gate nach dem Befüllen anwenden — set_mode
        # emittiert mode_changed nicht, daher hier explizit (sperrt/leert die
        # Detektion, falls ein Kunden-Audit geladen wird).
        self._apply_mode_to_scanner_steps(result.audit_mode)
        # Risiken kommen aus der DB. Beim Betreten des Risiko-Schritts
        # leitet ``_maybe_seed_risk`` aus den (geladenen) Antworten neu ab —
        # ``seed_from_audit`` schont dabei manuell angepasste Eintraege (current
        # weicht von der Ableitung ab → behalten), aktualisiert aber Risiken, die
        # noch der Ableitung entsprechen, wenn der Auditor Antworten aendert.
        try:
            self._risk_service.initialize_defaults(result.audit_id)
            self._step_risk.set_assessments(
                self._risk_service.load(result.audit_id)
            )
        except Exception:  # noqa: BLE001 — Risk-Load darf den Flow nicht crashen
            log.exception("Risk-Assessment-Load fehlgeschlagen")

    def load_for_view(self, result: CustomerAuditResult) -> None:
        """Befüllt alle Schritte schreibgeschützt (Ansichts-Modus).

        Aktiviert den read-only-Modus: das Audit wird beim Schliessen NICHT
        gespeichert. Wird seit nur noch für reine Vorschau genutzt — der
        normale „Öffnen"-Pfad lädt editierbar (:meth:`load_for_edit`).

        Args:
            result: Anzuzeigendes Audit-Ergebnis.
        """
        self._view_only = True
        self._populate_steps(result)

    def load_for_edit(self, result: CustomerAuditResult) -> None:
        """Befüllt alle Schritte zum Editieren.

        Speichern erzeugt über den ``CreateVersionUseCase`` eine **neue Version**
        (neue audit_id, supersedes-Kette); das Original bleibt unverändert.
        Seit/ enthält die DB Klartext — der frühere
        Unescape-beim-Laden ``unescaped_copy``) ist entfallen; er
        würde legitime Literal-Entities in User-Eingaben zerstören.

        Args:
            result: Das zu editierende (bestehende) Audit.
        """
        self._view_only = False
        self._base_audit_id = result.audit_id
        self._populate_steps(result)
        self._update_navigation()

    def show_summary(self, result: CustomerAuditResult) -> None:
        """Springt direkt zum Summary-Step und blendet das Ergebnis ein.

        Wird vom CustomerAuditWidget im View-Modus aufgerufen, wenn ein
        bestehendes Audit nur angesehen werden soll.

        Args:
            result: Bereits berechnetes Audit-Ergebnis.
        """
        self._result = result
        self._step_summary.set_result(
            result, self._step_risk.collected_assessments()
        )
        self._stack.setCurrentIndex(_SUMMARY_STEP)
        self._update_navigation()
