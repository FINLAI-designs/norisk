"""
anomaly_section — Dashboard-Card fuer die Light-SIEM-Anomalie-Heuristik.

Iter 3e: Zeigt einen aggregierten Anomalie-Score
(0..100, gewichtet aus dem schwersten aktiven Finding) plus die
detaillierten Findings in einer kleinen Tabelle.

- Score-Pille mit Severity-Farbe.
- Status-Banner ("Stream stabil." / "X Anomaly-Findings im aktuellen
  Lookback.").
- Detail-Tabelle: Tag, Quelle, Severity, Beobachteter Score, Threshold,
  Begruendung.

Schichtzugehoerigkeit: gui/ — darf application + core importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from core.widgets.button_styles import link_button_qss
from tools.norisk_dashboard.application.anomaly_detector import (
    AnomalyDetector,
)
from tools.norisk_dashboard.application.light_siem_aggregator import (
    LightSiemAggregator,
)
from tools.norisk_dashboard.domain.anomaly_models import (
    MIN_BASELINE_DAYS,
    AnomalyFinding,
    AnomalyReport,
    AnomalySeverity,
)

_log = get_logger(__name__)

_SEVERITY_LABEL: dict[AnomalySeverity, str] = {
    AnomalySeverity.LOW: "LOW",
    AnomalySeverity.MEDIUM: "MEDIUM",
    AnomalySeverity.HIGH: "HIGH",
    AnomalySeverity.CRITICAL: "CRITICAL",
}

_TABLE_HEADERS: list[str] = [
    "Tag",
    "Quelle",
    "Severity",
    "Score",
    "Threshold",
    "Begruendung",
]
_MAX_ROWS: int = 12


class AnomalySection(QWidget):
    """Dashboard-Card mit Anomaly-Score + Findings-Tabelle."""

    def __init__(
        self,
        detector: AnomalyDetector | None = None,
        aggregator: LightSiemAggregator | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        # gemeinsamer Aggregator fuer Detector UND den On-Demand-Ingest,
        # damit "Neu berechnen" denselben Pool fuellt, den der Detector liest.
        self._aggregator = aggregator or LightSiemAggregator()
        self._detector = detector or AnomalyDetector(aggregator=self._aggregator)
        self._build_ui()
        self.reload()

    def _build_ui(self) -> None:
        c = theme.get()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        header_row = QHBoxLayout()
        header_row.setSpacing(12)

        self._score_pill = _ScorePill()
        header_row.addWidget(self._score_pill)

        status_box = QVBoxLayout()
        status_box.setSpacing(2)
        self._status_title = QLabel("Anomalie-Heuristik")
        self._status_title.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-weight: 600; font-size: 13px;"
        )
        status_box.addWidget(self._status_title)
        self._status_detail = QLabel("")
        self._status_detail.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 12px;"
        )
        self._status_detail.setWordWrap(True)
        status_box.addWidget(self._status_detail)
        header_row.addLayout(status_box, stretch=1)

        self._refresh_btn = QPushButton("Neu berechnen")
        self._refresh_btn.setObjectName("AnomalyRefreshButton")
        self._refresh_btn.setStyleSheet(link_button_qss())
        self._refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_btn.clicked.connect(self._on_refresh_clicked)
        header_row.addWidget(self._refresh_btn)

        layout.addLayout(header_row)

        # Sichtbare Erklaerung (D11, 2026-06-25): macht transparent, dass die
        # Heuristik passiv auf dem Light-SIEM-Ereignisstrom arbeitet und was
        # „Neu berechnen" tut — die konkreten Quell-Tools listet die Light-SIEM-
        # Card direkt darunter (hier bewusst nicht dupliziert).
        self._source_hint = QLabel(
            "Statistische Ausreißer-Erkennung über den Light-SIEM-"
            "Ereignisstrom deiner Scans. Der Knopf Neu berechnen wertet die "
            "aktuelle Baseline neu aus."
        )
        self._source_hint.setWordWrap(True)
        self._source_hint.setObjectName("AnomalySourceHint")
        self._source_hint.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px;"
        )
        layout.addWidget(self._source_hint)

        # konkreter Beleg, dass "Neu berechnen" tatsaechlich gelaufen ist
        # (sonst wirkt der Knopf "tot", wenn das Ergebnis unveraendert leer ist).
        self._last_calc_label = QLabel("")
        self._last_calc_label.setObjectName("AnomalyLastCalc")
        self._last_calc_label.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px;"
        )
        layout.addWidget(self._last_calc_label)

        self._table = QTableWidget(0, len(_TABLE_HEADERS))
        self._table.setHorizontalHeaderLabels(_TABLE_HEADERS)
        self._table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self._table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        for col in range(len(_TABLE_HEADERS) - 1):
            header.setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self._table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        layout.addWidget(self._table, stretch=1)

        self._empty_hint = QLabel("")
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_hint.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-style: italic; padding: 12px;"
        )
        self._empty_hint.setWordWrap(True)
        layout.addWidget(self._empty_hint)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_refresh_clicked(self) -> None:
        self._refresh_btn.setEnabled(False)
        try:
            # "Neu berechnen" zieht ZUERST frische Events aus den Tools in
            # den Pool (Ingest) und wertet DANN die Baseline aus — sonst blieb der
            # Pool leer, wenn der User die Light-SIEM-Card (mit dem Auto-Ingest)
            # gar nicht geoeffnet hatte. Synchron (Button-Klick, warme DBs ~10-20 ms,
            # idempotent via Dedup); der Cold-Start-Auto-Ingest bleibt off-thread
            # in der LightSiemSection.
            try:
                self._aggregator.run_ingest()
            except Exception:  # noqa: BLE001 -- Ingest fail-soft, Reload trotzdem
                _log.exception("anomaly_section_ingest_failed")
            self.reload()
        finally:
            self._refresh_btn.setEnabled(True)

    # ------------------------------------------------------------------
    # Render
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Loest eine Neu-Berechnung aus und rendert."""
        try:
            report = self._detector.compute_report()
        except Exception:  # noqa: BLE001 — defensive UI-Schicht
            _log.exception("anomaly_section_reload_failed")
            # nicht still scheitern -> der Knopf wirkt sonst "tot".
            self._status_detail.setText(
                "Neuberechnung fehlgeschlagen — Details im Log."
            )
            self._last_calc_label.setText(
                f"Letzter Versuch: {datetime.now():%H:%M:%S} (fehlgeschlagen)"
            )
            return
        self._render(report)
        # sichtbarer Beleg, dass die Heuristik gerade neu lief.
        self._last_calc_label.setText(
            f"Zuletzt berechnet: {datetime.now():%H:%M:%S}"
        )

    def _render(self, report: AnomalyReport) -> None:
        score = report.aggregate_score()
        self._score_pill.set_score(score, self._severity_for_score(report))
        self._status_detail.setText(self._status_text(report))

        self._table.setRowCount(len(report.findings))
        for row, finding in enumerate(report.findings):
            self._set_row(row, finding)
        if report.findings:
            self._empty_hint.setVisible(False)
            self._table.setVisible(True)
        else:
            self._table.setVisible(False)
            self._empty_hint.setVisible(True)
            self._empty_hint.setText(
                self._empty_hint_text(report)
            )

    def _set_row(self, row: int, finding: AnomalyFinding) -> None:
        day_item = QTableWidgetItem(finding.observed_at.isoformat())
        self._table.setItem(row, 0, day_item)
        self._table.setItem(
            row, 1, QTableWidgetItem(finding.source_label)
        )
        sev_item = QTableWidgetItem(
            _SEVERITY_LABEL.get(finding.severity, finding.severity.value)
        )
        sev_item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        sev_item.setForeground(_severity_brush(finding.severity))
        self._table.setItem(row, 2, sev_item)
        self._table.setItem(
            row, 3, QTableWidgetItem(f"{finding.observed_score:.0f}")
        )
        self._table.setItem(
            row, 4, QTableWidgetItem(f"{finding.threshold:.1f}")
        )
        self._table.setItem(row, 5, QTableWidgetItem(finding.reason))

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_for_score(report: AnomalyReport) -> AnomalySeverity | None:
        top = report.top_finding
        return top.severity if top is not None else None

    @staticmethod
    def _status_text(report: AnomalyReport) -> str:
        if not report.has_enough_data:
            # ehrlich unterscheiden — leerer Pool vs. Pool gefuellt aber
            # (noch) keine Mehrtages-Baseline. baseline_day_count zaehlt NUR die
            # Tage VOR dem juengsten, daher ist "0 Tage" bei frischen Daten normal.
            if report.total_events == 0:
                return (
                    "Noch keine Ereignisse im Pool — fuehre Scans aus "
                    "(Patch-Monitor / System-Scanner / Cert-Monitor / "
                    "Supply-Chain / Schulungen) und klicke 'Neu berechnen'."
                )
            return (
                f"{report.total_events} Ereignisse erfasst — Baseline "
                f"{report.baseline_day_count} von {MIN_BASELINE_DAYS} Tagen. "
                "Die Ausreisser-Erkennung aktiviert sich automatisch, sobald "
                f"{MIN_BASELINE_DAYS} Tage Event-Historie vorliegen."
            )
        if not report.findings:
            return (
                f"Stream stabil ueber die letzten {report.lookback_days} Tage."
            )
        n = len(report.findings)
        worst = report.top_finding
        if worst is None:
            return f"{n} Anomaly-Findings im Lookback."
        return (
            f"{n} {'Finding' if n == 1 else 'Findings'} im Lookback "
            f"(schwerstes: {worst.severity.display_label} bei "
            f"{worst.source_label})."
        )

    @staticmethod
    def _empty_hint_text(report: AnomalyReport) -> str:
        if not report.has_enough_data:
            # total_events trennt leeren Pool von "gefuellt, aber noch
            # keine Mehrtages-Baseline" — vorher stand faelschlich "0 Tage mit
            # Events", obwohl heutige Events vorhanden waren.
            if report.total_events == 0:
                return (
                    "Noch keine Ereignisse im Pool. Fuehre Scans aus und klicke "
                    "'Neu berechnen', um Ereignisse aus den Tools zu sammeln."
                )
            return (
                f"{report.total_events} Ereignisse erfasst — Baseline "
                f"{report.baseline_day_count} von {MIN_BASELINE_DAYS} Tagen. Die "
                f"Ausreisser-Erkennung aktiviert sich, sobald {MIN_BASELINE_DAYS} "
                "Tage Event-Historie vorliegen."
            )
        return (
            "Keine Anomalien — der Event-Stream liegt innerhalb des "
            f"Threshold-Bandes (Lookback {report.lookback_days} Tage)."
        )


# ---------------------------------------------------------------------------
# Internal — Score-Pille
# ---------------------------------------------------------------------------


class _ScorePill(QFrame):
    """Grosse Score-Pille mit Severity-Akzent."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("AnomalyScorePill")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(0)
        self._title = QLabel("Anomalie-Score")
        self._title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title.setStyleSheet("font-size: 10px; font-weight: 500;")
        layout.addWidget(self._title)
        self._value = QLabel("—")
        self._value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._value.setStyleSheet(
            "font-size: 22px; font-weight: 700;"
        )
        layout.addWidget(self._value)
        self.set_score(0, None)

    def set_score(self, score: int, severity: AnomalySeverity | None) -> None:
        self._value.setText(str(int(score)) if score > 0 else "—")
        c = theme.get()
        accent = _severity_color(severity, default=c.TEXT_DIM)
        self.setStyleSheet(
            f"#{self.objectName()} {{"
            f"  background-color: {c.CARD_BG};"
            f"  border: 1px solid {accent};"
            f"  border-radius: 8px;"
            f"  min-width: 110px;"
            f"}}"
        )
        # Title bleibt gedaempft, Value uebernimmt Severity-Farbe.
        self._title.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 10px; font-weight: 500;"
        )
        self._value.setStyleSheet(
            f"color: {accent}; font-size: 22px; font-weight: 700;"
        )


# ---------------------------------------------------------------------------
# Farb-Helper
# ---------------------------------------------------------------------------


def _severity_color(
    severity: AnomalySeverity | None,
    *,
    default: str,
) -> str:
    """Mappt eine Anomaly-Severity auf eine Theme-Farbe (Hex-String)."""
    c = theme.get()
    if severity is None:
        return default
    return {
        AnomalySeverity.LOW: c.INFO,
        AnomalySeverity.MEDIUM: c.WARNING,
        AnomalySeverity.HIGH: c.ERROR,
        AnomalySeverity.CRITICAL: c.DANGER,
    }[severity]


def _severity_brush(severity: AnomalySeverity):  # noqa: ANN201
    c = theme.get()
    color = _severity_color(severity, default=c.TEXT_MAIN)
    return QBrush(QColor(color))


__all__ = ["AnomalySection"]
