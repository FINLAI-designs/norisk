"""
agreement_dialog — Nutzungsvereinbarungs-Dialog für FINLAI

Zeigt Nutzungsvereinbarung oder DSGVO-Erklärung zur Zustimmung an.
Unterstützt Zustimmungs-Modus (erster Start) und Lese-Modus (Einstellungen).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

from core import theme
from core.audit_log import AuditLogger
from core.icons import Icons, get_icon
from core.legal.terms import PRIVACY_POLICY, TERMS_OF_USE

_AGREEMENT_VERSION = "3.0"


class FinLaiCheckBox(QCheckBox):
    """QCheckBox mit benutzerdefiniertem Häkchen via QPainter."""

    def paintEvent(self, event) -> None:  # type: ignore[override]
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        box = QRect(0, (self.height() - 20) // 2, 20, 20)
        accent = QColor(theme.get().ACCENT)
        if self.isChecked():
            painter.setBrush(accent)
            painter.setPen(QPen(accent, 2))
        else:
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(accent, 2))
        painter.drawRoundedRect(box, 4, 4)
        if self.isChecked():
            pen = QPen(
                QColor(theme.get().BG_MAIN),
                2.5,
                Qt.PenStyle.SolidLine,
                Qt.PenCapStyle.RoundCap,
            )
            painter.setPen(pen)
            painter.drawLine(4, (self.height() // 2) + 2, 8, (self.height() // 2) + 6)
            painter.drawLine(8, (self.height() // 2) + 6, 16, (self.height() // 2) - 2)


class AgreementDialog(QDialog):
    """Zeigt Nutzungsvereinbarung oder DSGVO-Erklärung zur Zustimmung.

    Kann im Zustimmungs-Modus (beim ersten Start) oder im Lese-Modus
    (in Einstellungen) angezeigt werden.
    """

    def __init__(
        self,
        mode: str,
        read_only: bool = False,
        parent=None,
    ) -> None:
        """Initialisiert den Dialog.

        Args:
            mode: "terms" für Nutzungsvereinbarung, "privacy" für DSGVO.
            read_only: True = nur lesen, kein Zustimmen-Button.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._read_only = read_only
        self._accepted = False
        self._mode = mode

        if mode == "terms":
            title = "Nutzungsvereinbarung"
            text = TERMS_OF_USE
        else:
            title = "Datenschutzerklärung"
            text = PRIVACY_POLICY

        self.setWindowTitle(f"FINLAI — {title}")
        self.setMinimumSize(640, 520)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        # Header
        header = QLabel(title)
        header.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 18px; font-weight: bold;"
            f" color: {theme.get().ACCENT};"
        )
        layout.addWidget(header)

        # Text-Bereich (scrollbar)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setPlainText(text)
        text_edit.setStyleSheet(
            f"QTextEdit {{"
            f" background: {theme.get().CARD_BG};"
            f" color: {theme.get().TEXT_MAIN};"
            f" border: 1px solid {theme.get().BORDER};"
            f" border-radius: 6px;"
            f" padding: 12px;"
            f" font-family: 'Raleway';"
            f" font-size: 12px;"
            f"}}"
        )
        layout.addWidget(text_edit)

        if not read_only:
            # Checkbox für Zustimmung
            self._checkbox = FinLaiCheckBox(
                f"Ich habe die {title} gelesen und stimme zu."
            )
            # Indicator reserviert 28 px Breite damit der Text rechts neben dem
            # custom-painted 20-px-Kasten startet (sonst Ueberlappung — der
            # Custom-Painter zeichnet auf x=0..20, ohne reservierte Breite
            # rendert Qt den Label-Text ebenfalls bei x=0).
            self._checkbox.setStyleSheet(
                f"QCheckBox {{"
                f" color: {theme.get().TEXT_MAIN};"
                f" font-size: 13px;"
                f" spacing: 8px;"
                f"}}"
                f"QCheckBox::indicator {{"
                f" width: 28px; height: 20px;"
                f"}}"
            )
            self._checkbox.stateChanged.connect(self._on_checkbox)
            layout.addWidget(self._checkbox)

            # Buttons
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()

            self._btn_decline = QPushButton("Ablehnen")
            self._btn_decline.clicked.connect(self._on_decline)
            # background-color explizit gesetzt, sonst cascadiert das globale
            # QPushButton:hover (bg=DARK_ACCENT_DIM teal) und roter Text wird
            # auf Teal-Hintergrund unleserlich.
            self._btn_decline.setStyleSheet(
                f"QPushButton {{"
                f" background-color: transparent;"
                f" color: {theme.get().TEXT_DIM};"
                f" border: 1px solid {theme.get().BORDER};"
                f" border-radius: 6px;"
                f" padding: 8px 20px;"
                f"}}"
                f"QPushButton:hover {{"
                f" background-color: {theme.get().BG_MAIN};"
                f" color: {theme.ERROR_RED};"
                f" border-color: {theme.ERROR_RED};"
                f"}}"
            )

            self._btn_accept = QPushButton("Zustimmen")
            # Weißes Icon + explizites Button-Stylesheet. Die globale
            # ``[class="primary"]``-QSS-Füllung wird durch das
            # ``QWidget{background}``-Stylesheet des Eltern-StartupWindow
            # überschrieben (Qt-Cascade) → der Button blieb ohne Teal-Füllung
            # und mit unlesbarer dunkler Schrift. Ein direkt am Widget gesetztes
            # Stylesheet hat höchste Priorität und macht Schrift + Icon weiß.
            c = theme.get()
            self._btn_accept.setIcon(get_icon(Icons.CHECK_CIRCLE, color="#ffffff"))
            self._btn_accept.setEnabled(False)
            self._btn_accept.clicked.connect(self._on_accept)
            self._btn_accept.setObjectName("primary")
            self._btn_accept.setStyleSheet(
                f"QPushButton {{"
                f" background-color: {c.ACCENT};"
                f" color: #ffffff;"
                f" border: none;"
                f" border-radius: 6px;"
                f" padding: 8px 20px;"
                f" font-family: 'Raleway'; font-weight: bold;"
                f"}}"
                f"QPushButton:hover {{"
                f" background-color: {c.ACCENT_DIM}; color: #ffffff;"
                f"}}"
                f"QPushButton:pressed {{"
                f" background-color: {c.ACCENT_DARK}; color: #ffffff;"
                f"}}"
                f"QPushButton:disabled {{"
                f" background-color: {c.BG_BUTTON_DISABLED};"
                f" color: {c.TEXT_BUTTON_DISABLED};"
                f"}}"
            )

            btn_layout.addWidget(self._btn_decline)
            btn_layout.addWidget(self._btn_accept)
            layout.addLayout(btn_layout)

        else:
            # Nur Schließen-Button
            btn_close = QPushButton("Schließen")
            btn_close.clicked.connect(self.accept)
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            btn_layout.addWidget(btn_close)
            layout.addLayout(btn_layout)
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme.

        Wird bei Theme-Wechsel aufgerufen (register_listener).
        TODO: setStyleSheet-Aufrufe mit theme.get-Farben ersetzen.
        """
        from core import theme  # noqa: PLC0415

        c = theme.get()  # noqa: F841

    def _on_checkbox(self, state: int) -> None:
        """Aktiviert/deaktiviert den Zustimmen-Button je nach Checkbox-Zustand."""
        self._btn_accept.setEnabled(state == Qt.CheckState.Checked.value)

    def _on_accept(self) -> None:
        """Setzt das Accepted-Flag und schließt den Dialog positiv."""
        self._accepted = True
        event = "TERMS_ACCEPTED" if self._mode == "terms" else "PRIVACY_ACCEPTED"
        AuditLogger().log_action(
            event,
            {
                "version": _AGREEMENT_VERSION,
                "accepted_at": datetime.now().isoformat(timespec="seconds"),
            },
        )
        self.accept()

    def _on_decline(self) -> None:
        """Schreibt ein Decline-Audit und schließt den Dialog negativ."""
        event = "TERMS_DECLINED" if self._mode == "terms" else "PRIVACY_DECLINED"
        AuditLogger().log_action(
            event,
            {
                "version": _AGREEMENT_VERSION,
                "accepted_at": datetime.now().isoformat(timespec="seconds"),
            },
        )
        self.reject()

    @property
    def was_accepted(self) -> bool:
        """True wenn der User aktiv auf 'Zustimmen' geklickt hat."""
        return self._accepted
