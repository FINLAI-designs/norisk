"""
scoring_dashboard_widget — PySide6 Widget für das Security-Scoring-Dashboard.

Zeigt:
  - Score-Ring (QPainter, farbkodiert)
  - Komponenten-Balken mit Finding-Details
  - Button zum PDF-Export (Teil 3)

Schichtzugehörigkeit: gui/ — keine Business-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.security_subject.models import SubjectKind
from core.widgets.section import Section
from tools.security_scoring.application.scoring_service import ScoringService
from tools.security_scoring.application.tech_stack.manage_profiles_use_case import (
    create_default_manage_profiles_use_case,
)
from tools.security_scoring.domain.hardening_score import (
    HardeningScoreResult,
    build_hardening_summary,
)
from tools.security_scoring.domain.models import SecurityScore
from tools.security_scoring.domain.tech_stack.entities import SystemProfile
from tools.security_scoring.gui.widgets.category_breakdown_widget import (
    CategoryBreakdownWidget,
)
from tools.security_scoring.gui.widgets.hardening_score_gauge import (
    HardeningScoreGauge,
)
from tools.security_scoring.gui.widgets.hardening_trend_indicator import (
    HardeningTrendIndicator,
)
from tools.security_scoring.gui.widgets.measurement_gate_banner import (
    GateBannerState,
    MeasurementGateBanner,
)
from tools.security_scoring.gui.widgets.regulatory_compliance_section import (
    RegulatoryComplianceSection,
)


def _recheck_reason_text(reason: object) -> str:
    """Deutscher, generischer Anzeigetext zu einem Recheck-Reject-Grund (D6).

    Bewusst generisch — keine Pfade/Exception-Texte (Info-Disclosure-Schutz).
    """
    from tools.system_scanner.domain.enums import RecheckReason  # noqa: PLC0415

    return {
        RecheckReason.PROBE_UNAVAILABLE: "Messung auf diesem System nicht verfügbar",
        RecheckReason.SCAN_FAILED: "die Messung ist fehlgeschlagen",
        RecheckReason.NOT_ADMIN: "der Vorgang lief ohne Administratorrechte",
        RecheckReason.PATH_UNTRUSTED: (
            "NoRisk läuft aus einem nicht vertrauenswürdigen Ordner"
        ),
        RecheckReason.INTERNAL: "ein interner Fehler ist aufgetreten",
    }.get(reason, "unbekannter Grund")


# ---------------------------------------------------------------------------
# Score-Ring Widget (QPainter)
# ---------------------------------------------------------------------------


# Phase 4.5: ``_ScoreRingWidget`` durch
# ``HardeningScoreGauge`` ersetzt (Pure-Replace) — der 4-Stufen-
# Gauge mit Stage-Label ist Lynis-Konvention und passt zum Brain-
# Hardening-Score-Modell (5 Kategorien).


# ---------------------------------------------------------------------------
# Hintergrund-Thread
# ---------------------------------------------------------------------------


class _ScoringThread(QThread):
    """Berechnet beide Scores im Hintergrund — Legacy ``SecurityScore``
    (fuer PDF-Export) und neuen ``HardeningScoreResult``
    (Phase 4.5 — fuer Gauge + Breakdown + TrendIndicator).

    Signals:
        ergebnis(SecurityScore, HardeningScoreResult): Beide Scores
            in einer einzigen Emission. So bleibt das UI-Update atomar.
        fehler(str): Fehler aufgetreten — eines der beiden Compute-Calls
            ist gescheitert.
    """

    ergebnis: Signal = Signal(object, object, object)
    fehler: Signal = Signal(str)

    def __init__(
        self,
        service: ScoringService,
        target_name: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._target_name = target_name

    def run(self) -> None:
        """Ruft beide Score-APIs auf und emittiert das kombinierte Ergebnis."""
        try:
            score = self._service.berechne_score(self._target_name)
            # Phase 4: frischen Hardening-Scan ausfuehren und durch den
            # Score reichen — aktiviert Kategorie E, Caps 3+4, den Coverage-Stage-
            # Guard UND die Mess-Disposition (Soft-Banner). Non-Windows / Probe
            # nicht verfuegbar -> None -> wie bisher ohne Kategorie E.
            from tools.system_scanner.application.windows_hardening_scanner import (  # noqa: PLC0415
                run_hardening_baseline_scan,
            )

            scan_result = run_hardening_baseline_scan()
            hardening = self._service.compute_hardening_score(
                scan_result=scan_result, target_name=self._target_name
            )
            self.ergebnis.emit(score, hardening, scan_result)
        except Exception as exc:  # noqa: BLE001 -- Worker-Thread Catch-All, fail-safe Error-Signal
            self.fehler.emit(str(exc))


# ---------------------------------------------------------------------------
# Haupt-Widget
# ---------------------------------------------------------------------------


class ScoringDashboardWidget(QWidget):
    """Haupt-Widget des Security-Scoring-Dashboards.

    Eigenes System (Live-Messung) ODER ein Kunde (manuell erfasste Werte), per
    Subjekt-Picker umschaltbar Phase A/8). Kundensysteme werden NIE
    gemessen — nur „erfasst" (Provenance ``erfasst``, E2).

    Attributes:
        _service: ScoringService-Instanz.
        _own_system: Eigenes SystemProfile (immer EIGENES).
        _current_score: Zuletzt berechneter Score.
        _thread: Aktiver Berechnungs-Thread oder None.

    Signals:
        navigate(str): Wird mit einem Tool-Sidebar-Key emittiert (z.B.
            ``"techstack"``) wenn der Nutzer aus einem No-Data-Hinweis in
            das Quell-Tool wechseln möchte. Wird vom MainWindow automatisch
            mit ``_on_sidebar_navigate`` verbunden.
    """

    navigate: Signal = Signal(str)

    def __init__(
        self,
        service: ScoringService,
        org_security_service=None,  # noqa: ANN001 — optionale Dependency
        subject_store=None,  # noqa: ANN001 — optionaler core SubjectStore
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Widget.

        Args:
            service: Vollständig konfigurierter ScoringService.
            org_security_service: Optionaler OrgSecurityService für den
                                  Assessment-Wizard-Button. Ohne Service wird
                                  kein Button angezeigt.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._service = service
        self._org_security_service = org_security_service
        self._current_score: SecurityScore | None = None
        self._current_hardening: HardeningScoreResult | None = None
        self._current_scan_result = None  # letzter Hardening-Scan (fuer Verzicht)
        self._thread: _ScoringThread | None = None
        # Use Case kommt aus der application-Schicht via Factory
        # (kapselt den Repository-Aufbau). Wenn das Repository nicht
        # initialisierbar ist, ist das hier ein Hard-Fehler — das
        # Scoring-Dashboard braucht das eigene System, dasselbe Verhalten
        # wie vor (TechStackRepository wuerde dann auch werfen).
        profiles_uc = create_default_manage_profiles_use_case()
        if profiles_uc is None:
            raise RuntimeError(
                "TechStackRepository nicht initialisierbar — "
                "Scoring-Dashboard kann nicht starten."
            )
        self._own_system: SystemProfile = profiles_uc.ensure_own_system()
        # D3 (GUI-Hülle): Verfügbarkeit der zwei Selbstbewertungs-Sektionen
        # einmalig auflösen. "Technische Bewertung" hängt am AUDIT_WIZARD-
        # Feature, "Organisatorische Sicherheit" am HARDENING_SCORE-Feature
        # UND am injizierten org_security_service. Die Gate-Prüfung bleibt
        # zusätzlich am Wizard-Start — Ausblenden ist keine Zugriffskontrolle.
        # kein Lizenz-Gate mehr — Technik-Bewertung immer verfuegbar;
        # Organisatorische Bewertung haengt nur noch an der Service-Injektion.
        self._tech_assessment_available = True
        self._org_assessment_available = self._org_security_service is not None
        # Phase A/8: geteilter SubjectStore (eigenes System + Kunden).
        # ``None``/leer -> SELF-only (Bestandsverhalten, kein Picker).
        self._subject_store = subject_store
        self._subjects = self._lade_subjects()
        self._current_subject = self._subjects[0] if self._subjects else None
        self._build_ui()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt das vollständige UI."""
        t = theme.get()
        self.setStyleSheet(f"background-color: {t.BG_MAIN}; color: {t.TEXT_MAIN};")

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)

        # Titel
        title = QLabel("Security-Scoring")
        title.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_H3}px; font-weight: bold; color: {t.ACCENT};"
        )
        root.addWidget(title)

        _hc = HelpRegistry.get("security_scoring")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            root.addWidget(self._help_panel)

        # Steuerleiste
        root.addLayout(self._build_control_bar())

        # Status
        self._lbl_status = QLabel("")
        self._lbl_status.setStyleSheet(
            f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
        )
        root.addWidget(self._lbl_status)

        # Phase 4: Soft-"N offen"-Mess-Banner (D4). Sichtbar nur wenn
        # nachmessbare Haertungs-Checks offen sind; zwei Aktionen (messen/verzichten).
        self._gate_banner = MeasurementGateBanner()
        self._gate_banner.measure_clicked.connect(self._on_gate_measure)
        self._gate_banner.decline_clicked.connect(self._on_gate_decline)
        root.addWidget(self._gate_banner)

        # Phase 4.5: 4-Stufen-Hardening-Gauge + TrendIndicator
        # ersetzen den Legacy _ScoreRingWidget. CategoryBreakdownWidget
        # ersetzt die per-Tool-Komponenten-Liste (zeigt die 5-
        # Kategorien + Hard-Cap-Hinweise statt 7-Tool-Bars).
        # kein Free/Pro-Gating mehr — Gauge/Trend/Breakdown
        # zeigen immer die volle Ansicht.

        main_row = QHBoxLayout()
        main_row.setSpacing(16)

        # Score-Gauge + TrendIndicator
        self._gauge = HardeningScoreGauge()
        self._trend = HardeningTrendIndicator()
        gauge_col = QVBoxLayout()
        gauge_col.addStretch()
        gauge_col.addWidget(self._gauge, alignment=Qt.AlignmentFlag.AlignCenter)
        gauge_col.addWidget(self._trend, alignment=Qt.AlignmentFlag.AlignCenter)
        _tip_score = self._help_tip("score_display")
        if _tip_score:
            gauge_col.addWidget(
                HelpButton(_tip_score), alignment=Qt.AlignmentFlag.AlignCenter
            )
        self._lbl_summary = QLabel("")
        self._lbl_summary.setWordWrap(True)
        self._lbl_summary.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_summary.setStyleSheet(
            f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; max-width: 220px;"
        )
        gauge_col.addWidget(self._lbl_summary, alignment=Qt.AlignmentFlag.AlignCenter)
        gauge_col.addStretch()
        main_row.addLayout(gauge_col)

        # Trennlinie
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet(f"color: {t.BORDER};")
        main_row.addWidget(sep)

        # CategoryBreakdownWidget — 5 Kategorien-Mini-Balken + Cap-Hinweise
        # in einem klappbaren Panel. Standard nicht gecollapsed damit
        # User die Aufschluesselung sofort sieht.
        self._breakdown = CategoryBreakdownWidget()
        breakdown_col = QVBoxLayout()
        breakdown_col.setSpacing(6)
        breakdown_col.setContentsMargins(0, 0, 0, 0)
        breakdown_scroll = QScrollArea()
        breakdown_scroll.setWidgetResizable(True)
        breakdown_scroll.setWidget(self._breakdown)
        breakdown_scroll.setStyleSheet("QScrollArea { border: none; }")
        breakdown_scroll.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        breakdown_col.addWidget(breakdown_scroll, stretch=1)
        main_row.addLayout(breakdown_col, stretch=1)

        root.addLayout(main_row)

        # Trennlinie
        reg_sep = QFrame()
        reg_sep.setFrameShape(QFrame.Shape.HLine)
        reg_sep.setStyleSheet(f"color: {t.BORDER};")
        root.addWidget(reg_sep)

        # W2: Regulatorik-/KMU-Massnahmen-Panel (indikativ, button-getriggert).
        self._regulatory = RegulatoryComplianceSection()
        root.addWidget(self._regulatory)

        # R6b: Mess-Transparenz — macht die NICHT-gemessene Flaeche
        # (Handlungsbedarf / bewusst verzichtet / nicht zutreffend) sichtbar,
        # komplementaer zu den "Was tun?"-Karten (nur messbare Verstoesse).
        self._mess_section = Section("Mess-Transparenz", expanded=False)
        self._mess_body = QLabel("")
        self._mess_body.setWordWrap(True)
        self._mess_body.setTextFormat(Qt.TextFormat.PlainText)
        self._mess_section.set_content(self._mess_body)
        self._mess_section.setVisible(False)
        root.addWidget(self._mess_section)

        # Export-Leiste
        root.addLayout(self._build_export_bar())

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("security_scoring")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "security_scoring", parent=self.window()
        )
        dlg.show()

    def _build_control_bar(self) -> QHBoxLayout:
        """Erstellt die Steuerleiste mit Subjekt-Auswahl und Aktionsbuttons."""
        t = theme.get()
        bar = QHBoxLayout()
        bar.setSpacing(8)

        lbl_prefix = QLabel("Subjekt:")
        lbl_prefix.setStyleSheet(
            f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_BODY}px;"
        )
        bar.addWidget(lbl_prefix)

        # Phase A/8: Subjekt-Picker (eigenes System + Kunden) aus dem
        # geteilten SubjectStore. Ohne Store/Subjekte fallback auf die statische
        # Eigen-System-Anzeige (SELF-only Bestandsverhalten).
        self._cmb_subject: QComboBox | None = None
        if self._subjects:
            cmb = QComboBox()
            for subj in self._subjects:
                cmb.addItem(self._subject_label(subj), subj)
            cmb.setStyleSheet(self._combo_qss())
            cmb.currentIndexChanged.connect(self._on_subject_changed)
            self._cmb_subject = cmb
            bar.addWidget(cmb)
        else:
            self._lbl_own_system = QLabel(self._own_system.name)
            self._lbl_own_system.setStyleSheet(
                f"color: {t.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY}px;"
                f" font-weight: bold;"
            )
            bar.addWidget(self._lbl_own_system)

        bar.addStretch()

        self._btn_calc = QPushButton("Neu berechnen")
        self._btn_calc.clicked.connect(self._on_berechnen)
        self._btn_calc.setStyleSheet(self._btn_style(accent=True))
        bar.addWidget(self._btn_calc)

        # D3 (GUI-Hülle): EIN Einstieg "Selbstbewertung". Nur im SELF-Modus
        # sichtbar (eigenes System).
        if self._tech_assessment_available or self._org_assessment_available:
            self._btn_self_assessment = QPushButton("Selbstbewertung starten")
            self._btn_self_assessment.setToolTip(
                "Technische und organisatorische Selbstbewertung Ihres eigenen Systems"
            )
            self._btn_self_assessment.clicked.connect(self._oeffne_selbstbewertung)
            self._btn_self_assessment.setStyleSheet(self._btn_style())
            bar.addWidget(self._btn_self_assessment)
            _tip_wizard = self._help_tip("btn_wizard")
            if _tip_wizard:
                bar.addWidget(HelpButton(_tip_wizard))
        else:
            self._btn_self_assessment = None

        # E2: Kunden-Hardening manuell erfassen (nur im Kunden-Modus
        # sichtbar — das eigene System wird gemessen, nicht erfasst).
        self._btn_erfassen = QPushButton("Hardening erfassen")
        self._btn_erfassen.setToolTip(
            "Hardening-Fakten des ausgewählten Kunden manuell erfassen"
        )
        self._btn_erfassen.clicked.connect(self._on_erfassen)
        self._btn_erfassen.setStyleSheet(self._btn_style(accent=True))
        self._btn_erfassen.setVisible(False)
        bar.addWidget(self._btn_erfassen)

        return bar

    # ------------------------------------------------------------------
    # Subjekt-Auswahl Phase A/8)
    # ------------------------------------------------------------------

    def _lade_subjects(self) -> list:
        """Lädt alle Subjekte (eigenes + Kunden) aus dem SubjectStore (fail-soft)."""
        if self._subject_store is None:
            return []
        try:
            return list(self._subject_store.list_all())
        except Exception as exc:  # noqa: BLE001 — fail-soft -> SELF-only
            from core.logger import get_logger  # noqa: PLC0415

            get_logger(__name__).debug(
                "Subjekt-Liste nicht ladbar (%s) — SELF-only.", type(exc).__name__
            )
            return []

    @staticmethod
    def _ist_eigenes(subj) -> bool:  # noqa: ANN001 — core Subject (duck)
        return getattr(subj, "kind", None) == SubjectKind.EIGENES

    @staticmethod
    def _subject_label(subj) -> str:  # noqa: ANN001 — core Subject (duck)
        name = getattr(subj, "name", "") or ""
        if ScoringDashboardWidget._ist_eigenes(subj):
            return f"Mein System ({name})" if name else "Mein System"
        return name or "(unbenannter Kunde)"

    @staticmethod
    def _combo_qss() -> str:
        t = theme.get()
        return (
            f"QComboBox {{ background: {t.BG_INPUT}; color: {t.TEXT_MAIN};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px; padding: 4px 8px;"
            f" min-width: 220px; font-size: {theme.FONT_SIZE_BODY}px; }}"
        )

    @Slot(int)
    def _on_subject_changed(self, index: int) -> None:
        """Schaltet zwischen SELF-Modus (Messung) und Kunden-Modus (erfasst)."""
        if self._cmb_subject is None:
            return
        subj = self._cmb_subject.itemData(index)
        if subj is None:
            return
        self._current_subject = subj
        if self._ist_eigenes(subj):
            self._set_self_mode()
        else:
            self._set_kunde_mode(subj)

    def _set_self_mode(self) -> None:
        """SELF-Modus: Live-Messung + Selbstbewertung aktiv, Erfassen aus."""
        self._btn_calc.setEnabled(True)
        self._btn_calc.setToolTip("")
        if self._btn_self_assessment is not None:
            self._btn_self_assessment.setVisible(True)
        self._btn_erfassen.setVisible(False)
        gemessen = self._service.lade_letztes_gemessenes_hardening_result()
        if gemessen is not None:
            self._zeige_hardening_readonly(
                gemessen,
                self._service.previous_hardening_score(self._own_system.name),
            )
        self._lbl_status.setText("Eigenes System — 'Neu berechnen' misst live.")

    def _set_kunde_mode(self, subj) -> None:  # noqa: ANN001 — core Subject (duck)
        """Kunden-Modus: Messung/Selbstbewertung aus, Erfassen an; lädt aus DB."""
        self._btn_calc.setEnabled(False)
        self._btn_calc.setToolTip(
            "Kundensysteme werden nicht gemessen — bitte 'Hardening erfassen'."
        )
        if self._btn_self_assessment is not None:
            self._btn_self_assessment.setVisible(False)
        self._btn_erfassen.setVisible(True)
        self._btn_pdf.setEnabled(False)
        sid = getattr(subj, "subject_id", "")
        result = self._service.lade_letztes_hardening_result_by_subject(sid)
        if result is not None:
            self._zeige_hardening_readonly(
                result,
                self._service.previous_hardening_score_by_subject(sid),
            )
            self._lbl_status.setText(
                f"Kunde — erfasste Bewertung: {result.overall_score:.0f}/100 "
                f"({result.stage.label})"
            )
        else:
            self._lbl_summary.setText("Noch keine Erfassung für diesen Kunden.")
            self._lbl_status.setText(
                "Für diesen Kunden liegt noch keine Erfassung vor — "
                "'Hardening erfassen' startet die Eingabe."
            )

    def _zeige_hardening_readonly(self, hardening, previous) -> None:  # noqa: ANN001
        """Zeigt einen persistierten HardeningScoreResult read-only an.

        Reuse von Gauge/Breakdown/Trend-Pfeil ohne Live-Compute/Legacy-Score/Banner.
        """
        self._current_hardening = hardening
        self._gauge.set_result(hardening)
        self._breakdown.set_result(hardening)
        self._trend.set_trend(previous, hardening.overall_score)
        self._lbl_summary.setText(build_hardening_summary(hardening))
        self._gate_banner.setVisible(False)
        self._mess_section.setVisible(False)

    def _render_mess_transparenz(self, scan_result: object) -> None:
        """Fuellt die Mess-Transparenz-Sektion aus dem Hardening-Scan R6b).

        ``None`` (kein Live-Scan, z.B. persistierter/Kunden-Pfad) blendet die
        Sektion aus — dann gibt es keine HardeningChecks zum Aufschluesseln.
        Reiner Presentation-Code; die Vier-Sektionen-Partition liefert
:func:`build_measurement_report`.
        """
        if scan_result is None:
            self._mess_section.setVisible(False)
            return
        from tools.system_scanner.application.measurement_report import (  # noqa: PLC0415
            build_measurement_report,
        )

        sections = build_measurement_report(scan_result.hardening_checks)
        lines: list[str] = [f"Gemessen: {len(sections.measured)}"]
        if sections.needs_action:
            lines.append(f"Handlungsbedarf: {len(sections.needs_action)}")
            lines += [f"  • {it.label}" for it in sections.needs_action]
        if sections.declined:
            lines.append(f"Bewusst verzichtet: {len(sections.declined)}")
            lines += [
                f"  • {it.label}" + (f" — {it.note}" if it.note else "")
                for it in sections.declined
            ]
        if sections.not_applicable:
            lines.append(f"Nicht zutreffend: {len(sections.not_applicable)}")
        self._mess_body.setText("\n".join(lines))
        self._mess_section.setVisible(True)

    @Slot()
    def _on_erfassen(self) -> None:
        """Öffnet den Kunden-Hardening-Erfassungs-Dialog und speichert (ERFASST)."""
        subj = self._current_subject
        if subj is None or self._ist_eigenes(subj):
            return
        from tools.security_scoring.application.kunden_hardening import (  # noqa: PLC0415
            KUNDEN_HARDENING_FACTS,
        )
        from tools.security_scoring.gui.dialogs.kunden_hardening_dialog import (  # noqa: PLC0415
            KundenHardeningDialog,
        )

        dialog = KundenHardeningDialog(
            KUNDEN_HARDENING_FACTS,
            kunde_name=getattr(subj, "name", ""),
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._service.erfasse_kunden_hardening(
                getattr(subj, "subject_id", ""), dialog.get_facts()
            )
        except Exception as exc:  # noqa: BLE001 — user-fehlertolerant
            FinlaiInfoDialog(
                title="Erfassung fehlgeschlagen",
                message=f"Die Werte konnten nicht gespeichert werden:\n{exc}",
                icon_name="error",
                icon_color=theme.get().DANGER,
                parent=self,
            ).exec()
            return
        self._set_kunde_mode(subj)  # neu laden

    def _build_export_bar(self) -> QHBoxLayout:
        """Erstellt die Export-Schaltflächenleiste."""
        bar = QHBoxLayout()
        self._btn_pdf = QPushButton("Security-Report PDF")
        self._btn_pdf.setEnabled(False)
        self._btn_pdf.setStyleSheet(self._btn_style())
        self._btn_pdf.clicked.connect(self._on_pdf_export)
        bar.addWidget(self._btn_pdf)
        bar.addStretch()
        return bar

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @Slot()
    def _on_berechnen(self) -> None:
        """Startet die Score-Berechnung für das eigene System."""
        if self._thread is not None and self._thread.isRunning():
            return
        # E2: Kundensysteme werden NIE live gemessen (der Scanner liefe
        # auf dem Beraterrechner). Der Button ist im Kunden-Modus deaktiviert;
        # diese Prüfung ist der defensive Backstop.
        if self._current_subject is not None and not self._ist_eigenes(
            self._current_subject
        ):
            return

        self._btn_calc.setEnabled(False)
        self._btn_pdf.setEnabled(False)
        self._lbl_status.setText("⏳ Berechne Score …")

        self._thread = _ScoringThread(self._service, self._own_system.name, self)
        self._thread.ergebnis.connect(self._score_empfangen)
        self._thread.fehler.connect(self._fehler_empfangen)
        self._thread.finished.connect(self._on_thread_finished)
        self._thread.start()

    @Slot(object, object, object)
    def _score_empfangen(
        self,
        score: SecurityScore,
        hardening: HardeningScoreResult,
        scan_result: object = None,
    ) -> None:
        """Zeigt beide berechneten Scores an.

        Legacy ``SecurityScore`` speist Trend-Chart + Summary-Text +
        PDF-Export. Neuer ``HardeningScoreResult`` speist Gauge +
        Breakdown + TrendIndicator (Phase 4.5).

        Args:
            score: Berechneter Legacy-SecurityScore.
            hardening: Berechneter 4-Stufen-HardeningScoreResult.
            scan_result: Der zugrunde liegende Hardening-Scan, oder
                ``None``. Wird fuer den Mess-Verzicht (Banner) gemerkt.
        """
        self._current_score = score
        self._current_hardening = hardening
        self._current_scan_result = scan_result
        self._render_mess_transparenz(scan_result)
        # "Neu berechnen" MUSS immer wieder bedienbar werden — auch wenn ein
        # nachgelagertes UI-Update (z.B. das Mess-Banner aus einer elevierten
        # Admin-Messung) wirft. Sonst bliebe der Button nach einem Recheck-
        # Fehler dauerhaft deaktiviert. Enable daher VOR allem anderen.
        self._btn_calc.setEnabled(True)
        self._gate_banner.update_from(
            hardening.disposition, open_labels=self._open_remeasurable_labels()
        )

        # 4-Stufen-Gauge + Breakdown aus HardeningScoreResult.
        self._gauge.set_result(hardening)
        self._breakdown.set_result(hardening)
        # TrendIndicator — letzten Hardening-Score-Vorgaenger aus dem
        # Repo holen. ``None`` falls erst-Scan (kein Vergleich).
        previous = self._load_previous_hardening_score(score.target_name)
        self._trend.set_trend(previous, hardening.overall_score)

        # Subtitle aus dem Hardening-Ergebnis (Single Source of
        # Truth) statt aus dem Legacy ``score.summary`` — damit Gauge,
        # Subtitle und Status dieselbe Zahl zeigen.
        self._lbl_summary.setText(build_hardening_summary(hardening))

        self._btn_pdf.setEnabled(True)
        self._lbl_status.setText(
            f"OK — Score berechnet: {hardening.overall_score:.0f}/100 "
            f"({hardening.stage.label})"
        )

    def _open_remeasurable_labels(self) -> list[str]:
        """Labels der offenen (NEEDS_ADMIN) Checks fuer die Banner-Transparenz (D6).

        Zeigt dem Nutzer, WAS "Mit Admin messen" misst und WAS geprueft wird,
        statt nur eine anonyme Zahl.
        """
        if self._current_scan_result is None:
            return []
        from tools.system_scanner.domain.enums import UnmeasuredReason  # noqa: PLC0415

        return [
            c.label
            for c in self._current_scan_result.hardening_checks
            if not c.measurable
            and c.unmeasured_reason == UnmeasuredReason.NEEDS_ADMIN
        ]

    @Slot()
    def _on_gate_measure(self) -> None:
        """Banner-Aktion "Mit Admin messen" — elevierter Single-Probe 4d).

        Startet via:func:`core.elevation.relaunch_elevated` EINEN UAC-Prozess
        (``--recheck-hardening``), der alle grauen Checks mit Adminrechten misst
        und das Ergebnis HMAC-signiert nach FINLAI_HOME schreibt. Diese
        (unelevierte) GUI pollt dann, verifiziert + merged (echte Messung gewinnt).
        """
        import sys  # noqa: PLC0415

        if sys.platform != "win32":
            FinlaiInfoDialog(
                title="Mit Admin messen",
                message="Die Admin-Messung ist nur unter Windows verfügbar.",
                parent=self,
            ).exec()
            return
        if self._current_scan_result is None:
            return
        if getattr(self, "_recheck_timer", None) is not None and self._recheck_timer.isActive():
            return  # Läuft bereits.

        # Path-Trust-Gate: keinen elevierten Neustart eines
        # manipulierbaren Binaries anbieten. Nur im gepackten Build relevant
        # (im Dev ist das Elevation-Ziel der Interpreter, kein Auslieferungs-Pfad).
        if getattr(sys, "frozen", False):
            from core.win_security import assess_install_path_trust  # noqa: PLC0415

            if not assess_install_path_trust(sys.executable).trusted:
                FinlaiInfoDialog(
                    title="Mit Admin messen",
                    message=(
                        "Die Admin-Messung wurde aus Sicherheitsgründen abgelehnt: "
                        "NoRisk läuft aus einem für normale Benutzer beschreibbaren "
                        "Pfad. Bitte NoRisk nach %ProgramFiles% installieren."
                    ),
                    parent=self,
                ).exec()
                return

        from core.elevation import relaunch_elevated  # noqa: PLC0415
        from core.finlai_paths import finlai_dir  # noqa: PLC0415
        from tools.system_scanner.application.hardening_recheck import (  # noqa: PLC0415
            recheck_file_path,
        )

        # Stale Marker entfernen — wir konsumieren nur ein FRISCHES Ergebnis.
        try:
            recheck_file_path().unlink(missing_ok=True)
        except OSError:
            pass

        # Einmal-Nonce bindet das erwartete Ergebnis an genau diesen Anstoss
        # (Replay-/Frische-Schutz, 4d-Review) — selbst wenn ein alter, korrekt
        # signierter Marker liegenbleibt, passt seine Nonce nicht.
        import secrets  # noqa: PLC0415

        self._recheck_nonce = secrets.token_hex(16)

        if not relaunch_elevated(
            "--recheck-hardening",
            "--finlai-home",
            str(finlai_dir()),
            "--recheck-nonce",
            self._recheck_nonce,
        ):
            FinlaiInfoDialog(
                title="Mit Admin messen",
                message="Die Messung wurde abgebrochen (keine Adminrechte erteilt).",
                parent=self,
            ).exec()
            return

        self._gate_banner.set_state(GateBannerState.RUNNING)
        self._lbl_status.setText("⏳ Messe offene Punkte mit Adminrechten …")
        self._recheck_elapsed_s = 0
        self._recheck_timer = QTimer(self)
        self._recheck_timer.setInterval(1000)
        self._recheck_timer.timeout.connect(self._poll_recheck)
        self._recheck_timer.start()

    @Slot()
    def _poll_recheck(self) -> None:
        """Pollt den elevierten Recheck-Marker (1 s-Takt, Timeout 90 s).

        Macht den Ausgang sichtbar (D6): Erfolg -> merge; signierter
        Reject -> Grund anzeigen (kein merge); kein Marker bis Timeout ->
        fail-closed Hinweis statt Stille.
        """
        from tools.system_scanner.application.hardening_recheck import (  # noqa: PLC0415
            read_and_consume_recheck_result,
        )

        self._recheck_elapsed_s += 1
        outcome = read_and_consume_recheck_result(
            expected_nonce=getattr(self, "_recheck_nonce", None)
        )
        if outcome is not None:
            self._recheck_timer.stop()
            if outcome.ok:
                self._apply_recheck_result(outcome.scan)
            else:
                self._show_recheck_reject(outcome.reason)
            return
        if self._recheck_elapsed_s >= 90:
            self._recheck_timer.stop()
            self._gate_banner.set_state(GateBannerState.TIMEOUT)
            self._lbl_status.setText(
                "Admin-Messung ohne Rückmeldung (kein Ergebnis in 90 s) — "
                "Score unverändert."
            )
            FinlaiInfoDialog(
                title="Admin-Messung ohne Rückmeldung",
                message=(
                    "Die Messung wurde gestartet, hat aber innerhalb von 90 "
                    "Sekunden kein Ergebnis geliefert. Ihr Score wurde nicht "
                    "verändert. Bitte versuchen Sie es erneut; tritt das wiederholt "
                    "auf, prüfen Sie das Protokoll unter ~/.finlai/logs/."
                ),
                parent=self,
            ).exec()

    def _show_recheck_reject(self, reason: object) -> None:
        """Macht einen signierten Recheck-Reject sichtbar (D6 Phase 2).

        Banner -> roter Zustand mit Grund + "Erneut messen"; bei terminalem
        ``PATH_UNTRUSTED`` zusaetzlich ein erklaerender Dialog.
        """
        from tools.system_scanner.domain.enums import RecheckReason  # noqa: PLC0415

        reason_text = _recheck_reason_text(reason)
        self._gate_banner.set_state(GateBannerState.REJECTED, reason_text=reason_text)
        self._lbl_status.setText(
            f"Admin-Messung fehlgeschlagen: {reason_text} — Score unverändert."
        )
        if reason is RecheckReason.PATH_UNTRUSTED:
            FinlaiInfoDialog(
                title="Messung aus Sicherheitsgründen abgelehnt",
                message=(
                    "Die Admin-Messung wurde abgelehnt: NoRisk läuft aus einem für "
                    "normale Benutzer beschreibbaren Ordner. Bitte installieren Sie "
                    "NoRisk nach %ProgramFiles% und starten Sie es erneut."
                ),
                parent=self,
            ).exec()

    def _apply_recheck_result(self, recheck_scan) -> None:  # noqa: ANN001
        """Merged das elevierte Ergebnis in den aktuellen Scan + berechnet neu.

        Echte (Admin-)Messung gewinnt fuer die zuvor grauen Checks; bewusste
        Verzichte + n/a bleiben unveraendert ``merge_recheck_checks``).
        """
        if self._current_scan_result is None or self._current_score is None:
            return
        from dataclasses import replace  # noqa: PLC0415

        from tools.system_scanner.application.hardening_recheck import (  # noqa: PLC0415
            merge_recheck_checks,
        )

        merged = merge_recheck_checks(
            self._current_scan_result.hardening_checks,
            recheck_scan.hardening_checks,
        )
        neuer_scan = replace(self._current_scan_result, hardening_checks=merged)
        # target_name=None: nur Anzeige/Session, kein persistierender Schreibpfad im
        # UI-Thread (4d-Review). Persistenz erfolgt beim naechsten "Neu berechnen".
        hardening = self._service.compute_hardening_score(scan_result=neuer_scan)
        self._score_empfangen(self._current_score, hardening, neuer_scan)

    @Slot()
    def _on_gate_decline(self) -> None:
        """Banner-Aktion "Nicht messen" — markiert offene Checks als Verzicht.

        Setzt die offenen (NEEDS_ADMIN) Checks auf USER_DECLINED und berechnet
        den Score neu (Session-Ebene, ohne History-Eintrag). Sie zaehlen damit
        als bewusster Verzicht: druecken die Coverage (Stage-Guard) und erscheinen
        im Report mit Begruendung — ohne als Verstoss zu gelten P5/P6).
        """
        if self._current_scan_result is None or self._current_score is None:
            return
        from dataclasses import replace  # noqa: PLC0415

        from tools.system_scanner.application.hardening_overrides import (  # noqa: PLC0415
            apply_user_decline,
        )

        neue_checks = apply_user_decline(self._current_scan_result.hardening_checks)
        neuer_scan = replace(self._current_scan_result, hardening_checks=neue_checks)
        hardening = self._service.compute_hardening_score(scan_result=neuer_scan)
        self._score_empfangen(self._current_score, hardening, neuer_scan)

    def _load_previous_hardening_score(self, target_name: str) -> float | None:
        """Holt den vorletzten Hardening-Score via ``ScoringService``.

        Returns:
            ``overall_score`` des vorletzten Snapshots oder ``None`` wenn
            keine History vorhanden ist (Erst-Scan eines Targets).
        """
        try:
            return self._service.previous_hardening_score(target_name)
        except Exception as exc:  # noqa: BLE001 — Trend-Lookup darf nie GUI crashen
            from core.logger import get_logger  # noqa: PLC0415

            get_logger(__name__).debug(
                "Hardening-Trend-Lookup fehlgeschlagen (%s) — kein Pfeil angezeigt.",
                type(exc).__name__,
            )
            return None

    @Slot(str)
    def _fehler_empfangen(self, message: str) -> None:
        """Zeigt eine Fehlermeldung an.

        Args:
            message: Fehlerbeschreibung.
        """
        self._btn_calc.setEnabled(True)
        self._lbl_status.setText(f"FEHLER: {message}")

    @Slot()
    def _on_thread_finished(self) -> None:
        """Thread-Referenz aufräumen."""
        self._thread = None

    @Slot()
    def _on_pdf_export(self) -> None:
        """Exportiert den aktuellen Score als PDF-Report."""
        if not self._current_score:
            FinlaiInfoDialog(
                title="Export nicht möglich",
                message="Kein Score vorhanden. Bitte zuerst einen Score berechnen.",
                parent=self,
            ).exec()
            return

        from datetime import date

        default_name = (
            f"Security_Report_{self._current_score.target_name}_{date.today()}.pdf"
        )
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Security-Report speichern",
            default_name,
            "PDF (*.pdf)",
        )
        if not path:
            return

        verlauf = self._service.lade_verlauf(self._current_score.target_name, limit=8)

        try:
            self._service.generate_pdf_report(
                self._current_score,
                path,
                verlauf=verlauf,
                hardening=self._current_hardening,
                # W3: bereits analysierte Regulatorik-Befunde (falls der
                # Nutzer im Panel "analysieren" geklickt hat) ohne zweiten Scan
                # in den Report uebernehmen.
                compliance_rows=self._regulatory.current_rows(),
            )
            from core.dialogs import FinlaiSuccessDialog  # noqa: PLC0415

            dlg = FinlaiSuccessDialog(
                title="PDF erfolgreich gespeichert",
                file_path=path,
                parent=self,
            )
            dlg.exec()
        except (OSError, RuntimeError, ImportError, ValueError) as exc:
            FinlaiInfoDialog(
                title="Export fehlgeschlagen",
                message=f"PDF konnte nicht erstellt werden:\n{exc}",
                icon_name="error",
                icon_color=theme.get().DANGER,
                parent=self,
            ).exec()

    @Slot()
    def _oeffne_selbstbewertung(self) -> None:
        """Öffnet den Auswahl-Dialog für die Selbstbewertung (D3 GUI-Hülle).

        Der Dialog zeigt zwei Sektionen — "Technische Bewertung" und
        "Organisatorische Sicherheit". Jede verfügbare Sektion startet
        ihren EIGENEN bestehenden Wizard (eigener State/Repo); eine nicht
        verfügbare/lizenzierte Sektion erscheint mit Lock-Hinweis statt zu
        verschwinden. Kein gemeinsamer Step-State, keine Facade.
        """
        from tools.security_scoring.gui.dialogs.selbstbewertung_dialog import (  # noqa: PLC0415
            SelbstbewertungDialog,
        )

        dialog = SelbstbewertungDialog(
            tech_available=self._tech_assessment_available,
            org_available=self._org_assessment_available,
            on_start_tech=self._starte_assessment,
            on_start_org=self._starte_org_assessment,
            parent=self,
        )
        dialog.exec()

    @Slot()
    def _starte_org_assessment(self) -> None:
        """Öffnet den Org-Security-Assessment-Wizard."""
        if self._org_security_service is None:
            return
        from tools.security_scoring.application.subject_store import (  # noqa: PLC0415
            eigenes_na_vorbelegung,
        )
        from tools.security_scoring.gui.dialogs.org_assessment_wizard import (  # noqa: PLC0415
            OrgAssessmentWizard,
        )

        # Ebene 2+3: profil- UND nutzungs-bedingte N/A-Vorbelegung —
        # Orchestrierung (Cross-Tool über core-Resolver, Konflikt-Regel gegen
        # das jüngste Assessment) liegt fail-soft in der application-Schicht.
        vorbelegung = eigenes_na_vorbelegung(self._org_security_service.lade_letztes())
        wizard = OrgAssessmentWizard(
            service=self._org_security_service,
            na_keys=vorbelegung.keys,
            na_nutzungs_keys=vorbelegung.nutzungs_keys,
            na_audit_datum=vorbelegung.audit_datum,
            parent=self,
        )
        wizard.assessment_gespeichert.connect(self._on_berechnen)
        wizard.exec()

    @Slot()
    def _starte_assessment(self) -> None:
        """Öffnet den geführten Assessment-Wizard für das eigene System."""
        from tools.security_scoring.gui.dialogs.assessment_wizard import (  # noqa: PLC0415
            AssessmentWizard,
        )

        services = {
            "api_security": self._service._api_sec,  # noqa: SLF001
            "network_scanner": self._service._network,  # noqa: SLF001
            "cert_monitor": self._service._cert_monitor,  # noqa: SLF001
            "dependency_auditor": None,
            "system_scanner": None,
        }
        wizard = AssessmentWizard(
            services=services,
            bekannte_targets=[self._own_system.name],
            score_repo=self._service._repo,  # noqa: SLF001
            parent=self,
        )
        wizard.exec()

    # ------------------------------------------------------------------
    # Hilfsmethoden
    # ------------------------------------------------------------------

    @staticmethod
    def _btn_style(accent: bool = False) -> str:
        t = theme.get()
        bg = t.ACCENT if accent else t.BG_BUTTON
        text = t.BG_MAIN if accent else t.TEXT_MAIN
        return (
            f"QPushButton {{ background-color: {bg}; color: {text};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px;"
            f" padding: 6px 14px; font-size: {theme.FONT_SIZE_BODY_SM}px; }}"
            f"QPushButton:hover {{ background-color: {t.ACCENT}; color: {t.BG_MAIN};"
            f" border-color: {t.ACCENT}; }}"
            f"QPushButton:pressed {{ background-color: {t.ACCENT_DARK}; color: {t.BG_MAIN};"
            f" border-color: {t.ACCENT_DARK}; padding-top: 7px; padding-bottom: 5px; }}"
            f"QPushButton:disabled {{ background-color: {t.BG_BUTTON_DISABLED};"
            f" color: {t.TEXT_BUTTON_DISABLED}; border-color: {t.BORDER_BUTTON_DISABLED}; }}"
        )
