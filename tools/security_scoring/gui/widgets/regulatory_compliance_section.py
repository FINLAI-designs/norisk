"""regulatory_compliance_section — GUI-Panel: indikative Regulatorik + KMU-Massnahmen W2).

Zeigt pro fehlgeschlagenem Windows-Haertungs-Check eine Karte mit indikativem
Norm-Bezug (NIS2/IT-SiG/DSGVO/TISAX), KMU-Prioritaet und Aufwands-Schaetzung.
Der (langsame) Haertungs-Scan laeuft button-getriggert im Hintergrund-Thread.

WICHTIG (UWG / R4): Das Panel traegt prominent den juristischen
Pflicht-Disclaimer (indikativ / keine Rechtsberatung / anwaltliche Pruefung
erforderlich). Alle Labels sind indikativ (nie "konform") — die Engine
(:mod:`core.compliance`) garantiert das.: "ENTWURF"-Kennzeichnung entfernt,
Patrick 2026-06-27 — der Disclaimer selbst bleibt.)

Schicht: gui/ — keine Business-Logik. Die Berechnung liegt in
:mod:`tools.system_scanner.application.compliance_report_service` (W1).
"""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal, Slot
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.compliance.regulatory_mapping import REGULATORY_DISCLAIMER
from core.security.severity import Severity
from tools.system_scanner.application.compliance_report_service import (
    ComplianceRow,
    severity_label,
)

# ---------------------------------------------------------------------------
# Pure Display-Helfer (ohne Qt, headless testbar)
# severity_label kommt geteilt aus dem application-Service (DRY) und ist hier
# re-exportiert, damit Tests + Karten denselben Mapper nutzen.
# ---------------------------------------------------------------------------


def format_compliance_row(row: ComplianceRow) -> dict[str, str]:
    """Wandelt eine:class:`ComplianceRow` in reine Anzeige-Strings (pure, testbar).

    Returns:
        Dict mit ``check``/``severity``/``norm``/``priority``/``capacity``.
        ``norm`` ist die Joined-Liste der indikativen Norm-Labels oder ein
        Platzhalter, wenn kein Bezug existiert (Lueckentoleranz).
    """
    norm = (
        " · ".join(row.view.reg_labels)
        if row.view.reg_labels
        else "(kein indikativer Norm-Bezug)"
    )
    return {
        "check": f"{row.label} ({row.check_id})",
        "severity": severity_label(row.severity),
        "norm": norm,
        "priority": f"Prioritaet {row.view.kmu_priority}/100",
        "capacity": row.view.capacity_hint,
    }


def _severity_color(severity: Severity) -> str:
    """Theme-Token-Farbe je Schweregrad (kein Hex).

    GRADE_* sind MODUL-Konstanten von ``core.theme`` (``theme.GRADE_F`` etc.),
    NICHT Attribute des ``theme.get``-Objekts — ``t.GRADE_*`` wuerde crashen.
    """
    t = theme.get()
    return {
        Severity.CRITICAL: theme.GRADE_F,
        Severity.HIGH: theme.GRADE_D,
        Severity.MEDIUM: theme.GRADE_C,
        Severity.LOW: theme.GRADE_B,
        Severity.INFO: t.TEXT_DIM,
    }.get(severity, t.TEXT_DIM)


# ---------------------------------------------------------------------------
# Hintergrund-Thread (Windows-Haertungs-Scan + Bruecke)
# ---------------------------------------------------------------------------


class _ComplianceThread(QThread):
    """Fuehrt den Haertungs-Scan + die Compliance-Bruecke im Hintergrund aus.

    Signals:
        ergebnis(object): ``list[ComplianceRow]`` (sortiert nach Prioritaet).
        fehler(str): Fehlertext (z.B. Nicht-Windows / Probe-Fehler).
    """

    ergebnis: Signal = Signal(object)
    fehler: Signal = Signal(str)

    def run(self) -> None:
        try:
            # Ueber die application-Schicht (kapselt die Windows-data-Probe) —
            # die gui importiert KEINEN data-Adapter (Hexagonal-Contract).
            from tools.system_scanner.application.compliance_report_service import (  # noqa: PLC0415
                collect_default_hardening_compliance,
            )

            rows = collect_default_hardening_compliance()
            self.ergebnis.emit(rows)
        except Exception as exc:  # noqa: BLE001 — Worker-Thread: fail-safe Error-Signal
            self.fehler.emit(str(exc))


# ---------------------------------------------------------------------------
# Panel
# ---------------------------------------------------------------------------


class RegulatoryComplianceSection(QWidget):
    """Klappbares Panel mit der indikativen Regulatorik-/KMU-Massnahmen-Sicht."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: _ComplianceThread | None = None
        self._rows: list[ComplianceRow] = []
        self._build_ui()

    def _build_ui(self) -> None:
        t = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        # Titelzeile + Analyse-Button
        head = QHBoxLayout()
        title = QLabel("Regulatorik & Massnahmen (indikativ)")
        title.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold; color: {t.TEXT_MAIN};"
        )
        head.addWidget(title)
        head.addStretch()
        self._btn = QPushButton("Regulatorik analysieren")
        self._btn.clicked.connect(self._on_analyze)
        self._btn.setStyleSheet(self._btn_style())
        head.addWidget(self._btn)
        root.addLayout(head)

        # Disclaimer-Banner (UWG, prominent). (Patrick 2026-06-27): die
        # "ENTWURF — anwaltliche Pruefung ausstehend"-Kennzeichnung entfernt;
        # der juristische Pflicht-Disclaimer (indikativ / keine Rechtsberatung /
        # anwaltliche Pruefung erforderlich) bleibt als UWG-Schutz erhalten.
        banner = QLabel(f"⚠ {REGULATORY_DISCLAIMER}")
        banner.setWordWrap(True)
        banner.setStyleSheet(
            f"background-color: {t.BG_BUTTON}; color: {t.TEXT_DIM};"
            f" border: 1px solid {theme.GRADE_D}; border-radius: 4px;"
            f" padding: 6px 8px; font-size: {theme.FONT_SIZE_CAPTION}px;"
        )
        root.addWidget(banner)

        # Status
        self._status = QLabel(
            "Noch nicht analysiert — Button starten fuer einen frischen Haertungs-Scan."
        )
        self._status.setStyleSheet(
            f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
        )
        root.addWidget(self._status)

        # Ergebnis-Container (scrollbar)
        self._results = QWidget()
        self._results_layout = QVBoxLayout(self._results)
        self._results_layout.setContentsMargins(0, 0, 0, 0)
        self._results_layout.setSpacing(6)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._results)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        scroll.setMinimumHeight(160)
        root.addWidget(scroll)

    # ------------------------------------------------------------------ Slots

    @Slot()
    def _on_analyze(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        self._btn.setEnabled(False)
        self._status.setText("⏳ Haertungs-Scan laeuft …")
        self._thread = _ComplianceThread(self)
        self._thread.ergebnis.connect(self._on_rows)
        self._thread.fehler.connect(self._on_error)
        self._thread.finished.connect(self._on_finished)
        self._thread.start()

    @Slot(object)
    def _on_rows(self, rows: list[ComplianceRow]) -> None:
        self._btn.setEnabled(True)
        self._rows = rows
        self._render_rows(rows)
        if rows:
            self._status.setText(
                f"{len(rows)} offene Haertungs-Befunde mit Norm-Bezug (indikativ)."
            )
        else:
            self._status.setText(
                "Keine fehlgeschlagenen Haertungs-Pruefungen gefunden."
            )

    @Slot(str)
    def _on_error(self, message: str) -> None:
        self._btn.setEnabled(True)
        self._status.setText(f"FEHLER beim Scan: {message}")

    @Slot()
    def _on_finished(self) -> None:
        self._thread = None

    def current_rows(self) -> list[ComplianceRow]:
        """Liefert die zuletzt analysierten Rows (leer, wenn noch nicht analysiert).

        Genutzt vom PDF-Export, um dieselben Befunde OHNE zweiten Scan in den
        Security-Report zu uebernehmen.
        """
        return self._rows

    # ------------------------------------------------------------------ Render

    def _render_rows(self, rows: list[ComplianceRow]) -> None:
        self._clear_results()
        if not rows:
            placeholder = QLabel(
                "Alle gepruefen Haertungs-Konfigurationen sind in Ordnung."
            )
            placeholder.setStyleSheet(f"color: {theme.get().TEXT_DIM};")
            self._results_layout.addWidget(placeholder)
            self._results_layout.addStretch()
            return
        for row in rows:
            self._results_layout.addWidget(self._make_card(row))
        self._results_layout.addStretch()

    def _make_card(self, row: ComplianceRow) -> QWidget:
        t = theme.get()
        data = format_compliance_row(row)
        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background-color: {t.BG_BUTTON}; border: 1px solid {t.BORDER};"
            f" border-radius: 4px; }}"
        )
        lay = QVBoxLayout(card)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(3)

        # Kopf: Check + Schweregrad-Badge + Prioritaet
        top = QHBoxLayout()
        check = QLabel(data["check"])
        check.setStyleSheet(
            f"color: {t.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold;"
        )
        top.addWidget(check)
        top.addStretch()
        sev = QLabel(data["severity"])
        sev.setStyleSheet(
            f"color: {_severity_color(row.severity)}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" font-weight: bold;"
        )
        top.addWidget(sev)
        prio = QLabel(data["priority"])
        prio.setStyleSheet(
            f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
        )
        top.addWidget(prio)
        lay.addLayout(top)

        # Norm-Bezug (indikativ)
        norm = QLabel(data["norm"])
        norm.setWordWrap(True)
        norm.setStyleSheet(
            f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
        )
        lay.addWidget(norm)

        # Aufwand
        cap = QLabel(data["capacity"])
        cap.setStyleSheet(f"color: {t.ACCENT}; font-size: {theme.FONT_SIZE_CAPTION}px;")
        lay.addWidget(cap)
        return card

    def _clear_results(self) -> None:
        while self._results_layout.count():
            item = self._results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    @staticmethod
    def _btn_style() -> str:
        t = theme.get()
        return (
            f"QPushButton {{ background-color: {t.BG_BUTTON}; color: {t.TEXT_MAIN};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px;"
            f" padding: 6px 14px; font-size: {theme.FONT_SIZE_BODY_SM}px; }}"
            f"QPushButton:hover {{ background-color: {t.ACCENT}; color: {t.BG_MAIN};"
            f" border-color: {t.ACCENT}; }}"
            f"QPushButton:pressed {{ background-color: {t.ACCENT_DARK}; color: {t.BG_MAIN}; }}"
            f"QPushButton:disabled {{ background-color: {t.BG_BUTTON_DISABLED};"
            f" color: {t.TEXT_BUTTON_DISABLED}; border-color: {t.BORDER_BUTTON_DISABLED}; }}"
        )
