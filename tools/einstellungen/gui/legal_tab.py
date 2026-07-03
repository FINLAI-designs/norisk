"""
legal_tab — Rechtliches-Tab für die Einstellungen.

Zeigt Nutzungsvereinbarung und Datenschutzerklärung mit Zustimmungsdatum
sowie einen Button zum Zurückziehen der Zustimmung.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiConfirmDialog
from core.legal.agreement_dialog import AgreementDialog
from core.ui_settings import UISettings


class LegalTab(QWidget):
    """Tab für rechtliche Dokumente und DSGVO-Einwilligungsverwaltung.

    Zeigt Zustimmungsdaten für Nutzungsvereinbarung und Datenschutzerklärung
    und ermöglicht das Zurückziehen der Zustimmung.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = UISettings.load()
        self._build_ui()

        # ------------------------------------------------------------------
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        layout = self.layout()
        item = layout.takeAt(0)
        if item and item.widget():
            item.widget().deleteLater()
        layout.insertWidget(0, self._build_card())

    def _build_ui(self) -> None:
        """Erstellt die gesamte Tab-Oberfläche."""
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        card = self._build_card()
        outer.addWidget(card)
        outer.addStretch()

    def _build_card(self) -> QWidget:
        """Baut die Card mit allen rechtlichen Inhalten."""
        c = theme.get()

        card = QWidget()
        card.setStyleSheet(
            f"QWidget#legal_card {{"
            f" background: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER};"
            f" border-radius: 8px;"
            f"}}"
        )
        card.setObjectName("legal_card")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(0)

        # Header
        header = QLabel("Rechtliche Dokumente")
        header.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 14px; font-weight: bold;"
            f" color: {c.ACCENT};"
        )
        layout.addWidget(header)

        sep1 = self._make_separator()
        layout.addSpacing(10)
        layout.addWidget(sep1)
        layout.addSpacing(16)

        # Nutzungsvereinbarung
        layout.addWidget(
            self._build_doc_row(
                icon="",
                title="Nutzungsvereinbarung",
                date_str=self._settings.terms_accepted,
                version=self._settings.terms_version,
                mode="terms",
            )
        )
        layout.addSpacing(16)

        # Datenschutzerklärung
        layout.addWidget(
            self._build_doc_row(
                icon="",
                title="Datenschutzerklärung (DSGVO)",
                date_str=self._settings.privacy_accepted,
                version=self._settings.terms_version,
                mode="privacy",
            )
        )

        layout.addSpacing(16)
        layout.addWidget(self._make_separator())
        layout.addSpacing(16)

        # Zustimmung zurückziehen
        layout.addWidget(self._build_withdraw_section())

        return card

    # ------------------------------------------------------------------
    def _build_doc_row(
        self,
        icon: str,
        title: str,
        date_str: str,
        version: str,
        mode: str,
    ) -> QWidget:
        """Baut eine Zeile für ein Rechtsdokument mit Anzeige-Button."""
        c = theme.get()

        row = QWidget()
        row_layout = QVBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(4)

        # Titel
        lbl_title = QLabel(f"{icon}  {title}")
        lbl_title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {c.TEXT_MAIN};"
        )
        row_layout.addWidget(lbl_title)

        # Versions- und Zustimmungszeile
        version_str = f"Version {version}" if version else "Version —"
        consent_label = self._format_date(date_str)
        lbl_info = QLabel(f"{version_str}  ·  {consent_label}")
        lbl_info.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_DIM};"
        )
        row_layout.addWidget(lbl_info)

        # Anzeigen-Button
        btn_show = QPushButton("  Anzeigen")
        btn_show.setFixedHeight(32)
        btn_show.setFixedWidth(130)
        btn_show.setStyleSheet(
            f"QPushButton {{"
            f" background: {c.BG_BUTTON};"
            f" color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER};"
            f" border-radius: 4px;"
            f" font-family: 'Raleway'; font-size: 12px;"
            f"}}"
            f"QPushButton:hover {{"
            f" background: {c.ACCENT};"
            f" color: {theme.get().BG_DARK};"
            f" border-color: {c.ACCENT};"
            f"}}"
        )
        btn_show.clicked.connect(lambda checked=False, m=mode: self._show_dialog(m))
        row_layout.addWidget(btn_show)

        return row

    def _build_withdraw_section(self) -> QWidget:
        """Baut den Bereich zum Zurückziehen der Zustimmung."""
        c = theme.get()

        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        lbl_warn = QLabel("[WARN] Zustimmung zurückziehen")
        lbl_warn.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {c.DANGER};"
        )
        layout.addWidget(lbl_warn)

        lbl_desc = QLabel(
            "Dies beendet FINLAI und erfordert beim nächsten Start\n"
            "eine erneute Zustimmung."
        )
        lbl_desc.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_DIM};"
        )
        layout.addWidget(lbl_desc)

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 4, 0, 0)
        btn_withdraw = QPushButton("Zustimmung zurückziehen")
        btn_withdraw.setFixedHeight(34)
        btn_withdraw.setFixedWidth(230)
        btn_withdraw.setStyleSheet(
            f"QPushButton {{"
            f" background: transparent;"
            f" color: {c.DANGER};"
            f" border: 1px solid {c.DANGER};"
            f" border-radius: 4px;"
            f" font-family: 'Raleway'; font-size: 12px;"
            f"}}"
            f"QPushButton:hover {{"
            f" background: {c.DANGER};"
            f" color: {theme.DARK_TEXT_ON_ACCENT};"
            f"}}"
        )
        btn_withdraw.clicked.connect(self._on_withdraw)
        btn_row.addWidget(btn_withdraw)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return section

    # ------------------------------------------------------------------
    def _show_dialog(self, mode: str) -> None:
        """Öffnet AgreementDialog im Lese-Modus."""
        dialog = AgreementDialog(mode=mode, read_only=True, parent=self)
        dialog.exec()

    def _on_withdraw(self) -> None:
        """Bestätigungsdialog vor Zurückziehen der Zustimmung."""
        dlg = FinlaiConfirmDialog(
            title="Wirklich zurückziehen?",
            message=(
                "FINLAI wird beendet. Beim nächsten Start müssen Sie "
                "erneut zustimmen."
            ),
            confirm_text="Zurückziehen",
            parent=self,
        )
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._settings.terms_accepted = ""
            self._settings.privacy_accepted = ""
            self._settings.terms_version = ""
            self._settings.save()
            app = QApplication.instance()
            if app is not None:
                app.quit()

    # ------------------------------------------------------------------
    @staticmethod
    def _format_date(date_str: str) -> str:
        """Formatiert einen ISO-Zeitstempel als lesbares Datum.

        Args:
            date_str: ISO-8601-Zeitstempel oder leerer String.

        Returns:
            Formatierter String oder "Noch nicht zugestimmt".
        """
        if not date_str:
            return "Noch nicht zugestimmt"
        try:
            dt = datetime.fromisoformat(date_str)
            return (
                f"Zugestimmt am {dt.strftime('%d.%m.%Y')} um {dt.strftime('%H:%M')} Uhr"
            )
        except ValueError:
            return "Noch nicht zugestimmt"

    # ------------------------------------------------------------------
    @staticmethod
    def _make_separator() -> QFrame:
        """Erzeugt eine horizontale Trennlinie."""
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {theme.get().BORDER}; border: none;")
        return sep
