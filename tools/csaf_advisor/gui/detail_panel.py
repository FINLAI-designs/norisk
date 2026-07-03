"""
detail_panel — Detail-Anzeige fuer ein ausgewaehltes CSAF-Advisory.

Sprint 6 Phase 2: Erstes Panel-Extract aus dem
``CsafAdvisorWidget``-God-Class-Refactor. Klare API:

* Input: ``show_advisory(advisory, match)``, ``clear``
* Output: ``status_message(str)``-Signal (statt Direktzugriff auf
           den Status-Label des Hauptwidgets).

Der vorherige Code lebte als ``_build_detail_panel``,
``_show_advisory_detail``, ``_clear_detail``, ``_on_open_source_url``
und ``_on_copy_cves`` in csaf_advisor_widget.py.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch
from tools.csaf_advisor.gui.severity_helpers import sev_color


class DetailPanel(QWidget):
    """Zeigt die Detail-Felder eines ausgewaehlten CSAF-Advisory.

    Felder: Titel, Herausgeber, CVEs, betroffene Produkte, CVSS-Score,
    Veroeffentlichungs-Datum, optionaler Match-Hinweis aus dem Software-
    Inventar, Zusammenfassung. Plus zwei Action-Buttons:

    * **Original oeffnen** -- ruft ``QDesktopServices.openUrl`` mit
      der ``source_url`` des Advisory.
    * **CVE-IDs kopieren** -- legt die CVE-Liste in die Zwischenablage,
      emittiert ``status_message`` zur Bestaetigung.

    Signals:
        status_message(str): Statusmeldung fuers Hauptwidget
            (Erfolgsanzeige z. B. nach "CVE-IDs kopiert").
    """

    status_message = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert das Detail-Panel.

        Args:
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._current_advisory: CsafAdvisory | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        """Erstellt alle Widgets und das Layout."""
        t = theme.get()
        self.setStyleSheet(
            f"background-color: {t.CARD_BG}; border-radius: 6px;"
            f" border: 1px solid {t.BORDER};"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        self._detail_title = QLabel("Kein Advisory ausgewählt")
        self._detail_title.setStyleSheet(
            f"color: {t.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY}px; font-weight: bold; border: none;"
        )
        self._detail_title.setWordWrap(True)
        layout.addWidget(self._detail_title)

        form = QFormLayout()
        form.setSpacing(4)

        label_style = f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_BODY_SM}px; border: none;"
        value_style = f"color: {t.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px; border: none;"

        def _make_label(style: str = value_style) -> QLabel:
            lbl = QLabel("")
            lbl.setStyleSheet(style)
            lbl.setWordWrap(True)
            return lbl

        self._detail_publisher = _make_label()
        self._detail_cves = _make_label()
        self._detail_products = _make_label()
        self._detail_cvss = _make_label()
        self._detail_date = _make_label()
        self._detail_match = _make_label(
            f"color: {t.WARNING}; font-size: {theme.FONT_SIZE_BODY_SM}px; border: none;"
        )
        self._detail_summary = _make_label()

        form.addRow(
            QLabel("Herausgeber:", styleSheet=label_style), self._detail_publisher
        )
        form.addRow(QLabel("CVEs:", styleSheet=label_style), self._detail_cves)
        form.addRow(QLabel("Produkte:", styleSheet=label_style), self._detail_products)
        form.addRow(QLabel("CVSS Score:", styleSheet=label_style), self._detail_cvss)
        form.addRow(
            QLabel("Veröffentlicht:", styleSheet=label_style), self._detail_date
        )
        form.addRow(QLabel("Treffer:", styleSheet=label_style), self._detail_match)
        form.addRow(
            QLabel("Zusammenfassung:", styleSheet=label_style), self._detail_summary
        )

        layout.addLayout(form)

        # Link-Buttons
        btn_row = QHBoxLayout()
        self._btn_open_url = QPushButton("Original öffnen")
        self._btn_open_url.setIcon(get_icon(Icons.LINK_WEB))
        self._btn_open_url.setEnabled(False)
        self._btn_open_url.clicked.connect(self._on_open_source_url)
        self._btn_open_url.setStyleSheet(self._btn_style())
        btn_row.addWidget(self._btn_open_url)

        self._btn_copy_cves = QPushButton("CVE-IDs kopieren")
        self._btn_copy_cves.setIcon(get_icon(Icons.COPY))
        self._btn_copy_cves.setEnabled(False)
        self._btn_copy_cves.clicked.connect(self._on_copy_cves)
        self._btn_copy_cves.setStyleSheet(self._btn_style())
        btn_row.addWidget(self._btn_copy_cves)

        btn_row.addStretch()
        layout.addLayout(btn_row)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def show_advisory(
        self, advisory: CsafAdvisory, match: AdvisoryMatch | None = None
    ) -> None:
        """Befuellt das Panel mit den Daten eines Advisory.

        Args:
            advisory: Anzuzeigendes Advisory.
            match: Optionaler AdvisoryMatch — wenn vorhanden, wird der
                      "Treffer im Software-Inventar"-Hinweis aktiviert.
        """
        self._current_advisory = advisory
        t = theme.get()

        self._detail_title.setText(advisory.title)
        self._detail_title.setStyleSheet(
            f"color: {sev_color(advisory.severity)}; font-size: {theme.FONT_SIZE_BODY}px;"
            f" font-weight: bold; border: none;"
        )

        self._detail_publisher.setText(advisory.publisher)
        self._detail_cves.setText(
            ", ".join(advisory.cve_ids) if advisory.cve_ids else "Keine CVE-IDs"
        )
        products_text = ", ".join(advisory.affected_products[:10])
        if len(advisory.affected_products) > 10:
            products_text += f" … (+{len(advisory.affected_products) - 10} weitere)"
        self._detail_products.setText(products_text or "Keine Produktangaben")

        self._detail_cvss.setText(
            f"{advisory.cvss_score:.1f}" if advisory.cvss_score is not None else "—"
        )
        self._detail_date.setText(
            f"{advisory.initial_release} (Initial) / {advisory.current_release} (Aktuell)"
        )
        self._detail_summary.setText(
            advisory.summary or "Keine Zusammenfassung vorhanden."
        )

        if match:
            action_labels = {
                "update": "Update empfohlen",
                "workaround": "Workaround anwenden",
                "monitor": "Beobachten",
            }
            action_text = action_labels.get(
                match.action_required, match.action_required
            )
            self._detail_match.setText(
                f"Betrifft: {match.matched_component} {match.matched_version}"
                f" (Confidence: {match.confidence:.0%}) — {action_text}"
            )
            self._detail_match.setStyleSheet(
                f"color: {t.WARNING}; font-size: {theme.FONT_SIZE_BODY_SM}px; border: none;"
            )
        else:
            self._detail_match.setText("Kein Treffer im Software-Inventar")
            self._detail_match.setStyleSheet(
                f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_BODY_SM}px; border: none;"
            )

        self._btn_open_url.setEnabled(bool(advisory.source_url))
        self._btn_copy_cves.setEnabled(bool(advisory.cve_ids))

    def clear(self) -> None:
        """Leert alle Felder und deaktiviert die Action-Buttons."""
        self._current_advisory = None
        t = theme.get()
        self._detail_title.setText("Kein Advisory ausgewählt")
        self._detail_title.setStyleSheet(
            f"color: {t.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY}px; font-weight: bold; border: none;"
        )
        for lbl in (
            self._detail_publisher,
            self._detail_cves,
            self._detail_products,
            self._detail_cvss,
            self._detail_date,
            self._detail_match,
            self._detail_summary,
        ):
            lbl.setText("")
        self._btn_open_url.setEnabled(False)
        self._btn_copy_cves.setEnabled(False)

    # ------------------------------------------------------------------
    # Slots (intern)
    # ------------------------------------------------------------------

    @Slot()
    def _on_open_source_url(self) -> None:
        """Oeffnet die Source-URL des aktuellen Advisory im Browser."""
        if self._current_advisory and self._current_advisory.source_url:
            QDesktopServices.openUrl(QUrl(self._current_advisory.source_url))

    @Slot()
    def _on_copy_cves(self) -> None:
        """Kopiert CVE-IDs des aktuellen Advisory in die Zwischenablage."""
        if self._current_advisory and self._current_advisory.cve_ids:
            text = ", ".join(self._current_advisory.cve_ids)
            QApplication.clipboard().setText(text)
            self.status_message.emit("CVE-IDs in Zwischenablage kopiert.")

    @staticmethod
    def _btn_style() -> str:
        """Standardisiertes Button-Styling fuer dieses Panel."""
        t = theme.get()
        return (
            f"QPushButton {{ background-color: {t.BG_BUTTON}; color: {t.TEXT_MAIN};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px;"
            f" padding: 5px 12px; font-size: {theme.FONT_SIZE_BODY_SM}px; }}"
            f"QPushButton:hover {{ background-color: {t.ACCENT}; color: {t.BG_MAIN}; }}"
        )
