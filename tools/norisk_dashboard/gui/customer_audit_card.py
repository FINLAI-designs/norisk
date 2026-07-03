"""customer_audit_card — Kunden-Audit-Score-Karte-Folge).

Ersetzt im Dashboard den (für Kunden-Subjekte nicht aussagekräftigen,
self-only) Hardening-Hero, sobald im Header-Selektor ein Kunden-Subjekt
gewählt ist und für dieses Subjekt ein Security-Audit existiert. Zeigt den
jüngsten Audit-Score, die Risikostufe, das Datum und die Anzahl der Audits —
plus eine „Audit öffnen"-CTA, die zum Security-Audit-Tool navigiert.

Datenquelle::class:`CustomerAuditSummary` aus dem
:class:`DashboardAggregator` (Loader liest ``CustomerAuditRepository``,
adaptiert dict→DTO — kein tool→tool-Import in den unteren Schichten).

Sicherheitsdesign: ``firmenname`` ist Kunden-Eingabe → alle Labels rendern
als ``PlainText`` (kein QLabel-Rich-Text-Auto-Parsing, gegen Markup-Injektion
über einen präparierten Firmennamen — Lehre/).

Schichtzugehörigkeit: gui/ — keine Domain-Logik.

Author: Patrick Riederich
Version: 1.0-Folge)
"""

from __future__ import annotations

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
from tools.norisk_dashboard.domain.models import CustomerAuditSummary

# Risikostufe (customer_audit, deutsch) → Severity-Signal-Theme-Token.
# Effekt: färbt Score-Zahl + Badge in:meth:`CustomerAuditCard.set_data`.
# Bewusst lokales Mapping (kein customer_audit-Import → kein tool→tool); die
# Stufen-Strings stammen aus ``customer_audit/domain`` (Kritisch/Hoch/Mittel/
# Niedrig) — ändert sich deren Wortlaut, hier nachziehen.
_RISK_FARBE: dict[str, str] = {
    "kritisch": theme.SEVERITY_SIGNAL_CRITICAL,
    "hoch": theme.SEVERITY_SIGNAL_HIGH,
    "mittel": theme.SEVERITY_SIGNAL_MEDIUM,
    "niedrig": theme.SEVERITY_SIGNAL_OK,
}


class CustomerAuditCard(QFrame):
    """Karte mit dem jüngsten Kunden-Audit-Score eines Subjekts.

    Signals:
        open_audit: „Audit öffnen"-Klick — vom Dashboard zum
            Security-Audit-Tool geroutet (``navigate("customer_audit")``).
    """

    open_audit = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Baut die Karte (initial leer/unsichtbar)."""
        super().__init__(parent)
        self._data: CustomerAuditSummary | None = None
        self.setObjectName("customerAuditCard")
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

        outer = QHBoxLayout(self)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(20)

        c = theme.get()

        # Linke Spalte: große Score-Zahl + "von 100".
        score_col = QVBoxLayout()
        score_col.setSpacing(0)
        self._score = QLabel("—", self)
        self._score.setTextFormat(Qt.TextFormat.PlainText)
        self._score.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 44px; font-weight: bold; "
            f"background: transparent;"
        )
        score_col.addWidget(self._score)
        self._score_unit = QLabel("von 100", self)
        self._score_unit.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; background: transparent;"
        )
        score_col.addWidget(self._score_unit)
        outer.addLayout(score_col)

        # Mittlere Spalte: Überschrift, Firma, Risikostufe, Meta.
        info_col = QVBoxLayout()
        info_col.setSpacing(2)
        self._title = QLabel("LETZTES SECURITY-AUDIT", self)
        self._title.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 10px; font-weight: bold; "
            f"letter-spacing: 1px; background: transparent;"
        )
        info_col.addWidget(self._title)

        self._firma = QLabel("—", self)
        self._firma.setTextFormat(Qt.TextFormat.PlainText)
        self._firma.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 16px; font-weight: bold; "
            f"background: transparent;"
        )
        info_col.addWidget(self._firma)

        self._risk = QLabel("", self)
        self._risk.setTextFormat(Qt.TextFormat.PlainText)
        self._risk.setStyleSheet("background: transparent; font-size: 13px;")
        info_col.addWidget(self._risk)

        self._meta = QLabel("", self)
        self._meta.setTextFormat(Qt.TextFormat.PlainText)
        self._meta.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; background: transparent;"
        )
        info_col.addWidget(self._meta)
        outer.addLayout(info_col, stretch=1)

        # Rechte Spalte: CTA.
        self._open_btn = QPushButton("Audit öffnen", self)
        self._open_btn.setObjectName("customerAuditOpenBtn")
        self._open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._open_btn.clicked.connect(self.open_audit.emit)
        self._open_btn.setStyleSheet(
            f"QPushButton#customerAuditOpenBtn {{ color: {c.TEXT_MAIN}; "
            f"background: {c.BG_SIDEBAR}; border: 1px solid {c.BORDER}; "
            f"border-radius: 4px; padding: 6px 14px; }} "
            f"QPushButton#customerAuditOpenBtn:hover {{ "
            f"border-color: {theme.DARK_ACCENT}; }}"
        )
        outer.addWidget(self._open_btn, alignment=Qt.AlignmentFlag.AlignVCenter)

        self._apply_frame(theme.SEVERITY_SIGNAL_INFO)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_data(self, summary: CustomerAuditSummary | None) -> None:
        """Aktualisiert die Karte aus dem DTO (``None`` → neutraler Leerzustand).

        Die Sichtbarkeit steuert der Aufrufer (``dashboard_widget._apply``);
        ``set_data(None)`` setzt nur einen sauberen Ruhezustand, falls die Karte
        doch sichtbar bleibt.
        """
        self._data = summary
        if summary is None:
            c = theme.get()
            self._score.setText("—")
            # Farb-Styling zurücksetzen, damit der "—"-Platzhalter nicht in
            # einer Rest-Risikofarbe (z.B. Kritisch-Rot) eines vorigen
            # Zustands erscheint.
            self._score.setStyleSheet(
                f"color: {c.TEXT_MAIN}; font-size: 44px; font-weight: bold; "
                f"background: transparent;"
            )
            self._firma.setText("—")
            self._risk.setText("")
            self._risk.setStyleSheet(
                "background: transparent; font-size: 13px;"
            )
            self._meta.setText("")
            self._apply_frame(theme.SEVERITY_SIGNAL_INFO)
            self.setToolTip("")
            return

        farbe = _RISK_FARBE.get(
            summary.risk_level.casefold(), theme.SEVERITY_SIGNAL_INFO
        )
        c = theme.get()
        self._score.setText(f"{summary.overall_score:.0f}")
        self._score.setStyleSheet(
            f"color: {farbe}; font-size: 44px; font-weight: bold; "
            f"background: transparent;"
        )
        self._firma.setText(summary.firmenname or "Unbenanntes Subjekt")
        if summary.risk_level:
            self._risk.setText(f"Risikostufe: {summary.risk_level}")
            self._risk.setStyleSheet(
                f"color: {farbe}; font-size: 13px; font-weight: bold; "
                f"background: transparent;"
            )
        else:
            self._risk.setText("")
        self._meta.setText(self._meta_text(summary))
        self._meta.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; background: transparent;"
        )
        self._apply_frame(farbe)
        self.setToolTip(
            "Jüngstes Security-Audit dieses Kunden-Subjekts. Der technische "
            "Hardening-Score ist nur für das eigene System aussagekräftig "
            "und wird hier bewusst nicht gezeigt."
        )

    # ------------------------------------------------------------------
    # Interna
    # ------------------------------------------------------------------

    @staticmethod
    def _meta_text(summary: CustomerAuditSummary) -> str:
        """Baut die Meta-Zeile (Datum + Audit-Anzahl)."""
        parts: list[str] = []
        if summary.created_at is not None:
            parts.append(f"Stand {summary.created_at:%d.%m.%Y}")
        if summary.audit_count > 1:
            parts.append(f"{summary.audit_count} Audits")
        elif summary.audit_count == 1:
            parts.append("1 Audit")
        return " · ".join(parts)

    def _apply_frame(self, akzent: str) -> None:
        """Setzt Rahmen + Akzent-Linkskante der Karte."""
        c = theme.get()
        self.setStyleSheet(
            f"#customerAuditCard {{ background: {c.BG_MAIN}; "
            f"border: 1px solid {c.BORDER}; "
            f"border-left: 4px solid {akzent}; "
            f"border-radius: 6px; }}"
        )
