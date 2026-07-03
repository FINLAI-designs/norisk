"""
summary_step — Schritt 5: Ergebnis-Zusammenfassung.

Zeigt Score, Risikostufe, Kategorie-Scores und Empfehlungen.

Schichtzugehörigkeit: gui/ — nur UI-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.customer_audit.domain.entities import CustomerAuditResult
from tools.customer_audit.domain.risk_entities import RiskAssessment

# Reuse zentral definierter Risiko-Palette aus customer_list_widget — vermeidet
# Duplikat. Dies ist die domäne-spezifische Customer-Risiko-Achse, bewusst
# getrennt von theme.py-Severity-Farben.
from tools.customer_audit.gui.customer_list_widget import (  # noqa: E402
    RISK_COLORS as _RISK_COLORS,
)
from tools.customer_audit.gui.widgets.bsi_risk_matrix_widget import (
    BsiRiskMatrixWidget,
)


class SummaryStep(QWidget):
    """Wizard-Schritt 5: Ergebnis-Zusammenfassung.

    Zeigt den berechneten Score und die Empfehlungen an.
    Wird via set_result nach der Berechnung befüllt.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert den Schritt.

        Args:
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        """Baut das initiale Layout auf."""
        c = theme.get()

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        hdr = QLabel("Ergebnis-Zusammenfassung")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway;"
            " font-weight: 700; font-size: 14px;"
        )
        root.addWidget(hdr)

        # Scrollbarer Bereich für das Ergebnis
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self._scroll.setStyleSheet("background: transparent; border: none;")

        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(0, 8, 8, 0)
        self._content_layout.setSpacing(10)

        self._lbl_placeholder = QLabel(
            "Fülle alle Schritte aus und klicke auf 'Berechnen'."
        )
        self._lbl_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_placeholder.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
        self._lbl_placeholder.setWordWrap(True)
        self._content_layout.addWidget(self._lbl_placeholder)
        self._content_layout.addStretch()

        self._scroll.setWidget(self._content)
        root.addWidget(self._scroll)

    def _clear_content(self) -> None:
        """Entfernt alle dynamischen Widgets aus dem Content-Bereich."""
        while self._content_layout.count():
            item = self._content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def is_valid(self) -> bool:
        """Schritt ist immer gültig.

        Returns:
            True.
        """
        return True

    def set_result(
        self,
        result: CustomerAuditResult,
        risk_assessments: list[RiskAssessment] | None = None,
    ) -> None:
        """Befüllt die Zusammenfassung mit dem Berechnungsergebnis.

        Args:
            result: Vollständiges Assessment-Ergebnis.
            risk_assessments: Die Risiko-Bewertungen des Audits — werden als
                read-only Risikomatrix mit angezeigt (2026-06-28, Patrick: die
                Matrix soll auch im Audit-Bereich, wo sie erstellt wird,
                sichtbar sein). ``None``/leer -> keine Matrix-Sektion.
        """
        c = theme.get()
        self._clear_content()

        risk_color = _RISK_COLORS.get(result.risk_level, c.TEXT_MAIN)

        # --- Score-Karte ---
        score_frame = QFrame()
        score_frame.setStyleSheet(
            f"QFrame {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 6px; padding: 12px; }}"
        )
        score_layout = QVBoxLayout(score_frame)
        score_layout.setSpacing(4)

        lbl_score_val = QLabel(f"{result.overall_score:.1f} / 100")
        lbl_score_val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_score_val.setStyleSheet(
            f"color: {risk_color}; font-family: JetBrains Mono;"
            " font-weight: 700; font-size: 32px; border: none;"
        )
        score_layout.addWidget(lbl_score_val)

        lbl_risk = QLabel(f"Risikostufe: {result.risk_level}")
        lbl_risk.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_risk.setStyleSheet(
            f"color: {risk_color}; font-family: Raleway;"
            " font-weight: 700; font-size: 16px; border: none;"
        )
        score_layout.addWidget(lbl_risk)

        lbl_company = QLabel(result.customer_data.firmenname)
        # Freitext ist seit Klartext in der DB — nie als Auto-RichText
        # interpretieren, R22).
        lbl_company.setTextFormat(Qt.TextFormat.PlainText)
        lbl_company.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_company.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 13px; border: none;"
        )
        score_layout.addWidget(lbl_company)

        self._content_layout.addWidget(score_frame)

        # --- Kategorie-Scores ---
        if result.category_scores:
            lbl_cat_hdr = QLabel("Kategorie-Scores")
            lbl_cat_hdr.setStyleSheet(
                f"color: {c.TEXT_MAIN}; font-family: Raleway;"
                " font-weight: 700; font-size: 13px;"
            )
            self._content_layout.addWidget(lbl_cat_hdr)

            for cat in result.category_scores:
                cat_frame = QFrame()
                cat_frame.setStyleSheet(
                    f"QFrame {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
                    f" border-radius: 4px; padding: 6px 10px; }}"
                )
                cat_layout = QVBoxLayout(cat_frame)
                cat_layout.setSpacing(2)
                cat_layout.setContentsMargins(0, 0, 0, 0)

                cat_color = _RISK_COLORS.get(cat.label, c.TEXT_MAIN)
                lbl_cat = QLabel(f"{cat.name}  —  {cat.score:.0f}/100  ({cat.label})")
                lbl_cat.setStyleSheet(
                    f"color: {cat_color}; font-size: 13px; border: none;"
                )
                cat_layout.addWidget(lbl_cat)
                self._content_layout.addWidget(cat_frame)

        # --- Empfehlungen ---
        if result.recommendations:
            lbl_rec_hdr = QLabel("Handlungsempfehlungen")
            lbl_rec_hdr.setStyleSheet(
                f"color: {c.TEXT_MAIN}; font-family: Raleway;"
                " font-weight: 700; font-size: 13px;"
            )
            self._content_layout.addWidget(lbl_rec_hdr)

            for rec in result.recommendations:
                rec_lbl = QLabel(f"• {rec}")
                # Empfehlungen betten Freitexte ein (antivirus_name,
                # Scan-Tool-Namen) — nie als Auto-RichText, R22).
                rec_lbl.setTextFormat(Qt.TextFormat.PlainText)
                rec_lbl.setWordWrap(True)
                rec_lbl.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
                self._content_layout.addWidget(rec_lbl)

        # --- Risikomatrix (read-only, 2026-06-28) ---
        if risk_assessments:
            lbl_matrix_hdr = QLabel("Risikomatrix")
            lbl_matrix_hdr.setStyleSheet(
                f"color: {c.TEXT_MAIN}; font-family: Raleway;"
                " font-weight: 700; font-size: 13px;"
            )
            self._content_layout.addWidget(lbl_matrix_hdr)
            matrix = BsiRiskMatrixWidget()
            matrix.set_assessments(list(risk_assessments))
            self._content_layout.addWidget(matrix)

        self._content_layout.addStretch()
