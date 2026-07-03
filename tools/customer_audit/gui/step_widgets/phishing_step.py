"""
phishing_step — Schritt: Phishing-/E-Mail-Sicherheit.

Erfasst vier Ja/Nein/Teilweise-Kategorien zur E-Mail-Sicherheit. Speist den
Phishing-Risikowert in der BSI-200-3-Matrix (statt eines statischen Defaults)
über:func:`tools.customer_audit.domain.risk_derivation.derive_risk_seeds`.

Schichtzugehörigkeit: gui/ — nur UI-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.customer_audit.domain.entities import JA_NEIN_OPTIONEN, PhishingData
from tools.customer_audit.gui.step_widgets import field_styles


class PhishingStep(QWidget):
    """Wizard-Schritt: Phishing-/E-Mail-Sicherheit.

    Vier Ja/Nein/Teilweise-Kategorien (MFA, Phishing-Schulung, SPF/DKIM/DMARC,
    Mailfilter). Die Antworten leiten den Phishing-Risikowert ab.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        c = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        hdr = QLabel("Phishing- / E-Mail-Sicherheit")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway;"
            " font-weight: 700; font-size: 14px;"
        )
        root.addWidget(hdr)

        info = QLabel(
            "Diese Angaben bestimmen die Eintrittswahrscheinlichkeit des "
            "Risikos Phishing / Spear-Phishing in der Risiko-Matrix."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
        root.addWidget(info)

        # geteilte Feld-Styles (einheitliche Fokus-Hervorhebung +
        # feste Dropdown-Breite) statt pro-Step dupliziertem QSS.
        _combo_style = field_styles.combo_style()
        _lbl_style = f"color: {c.TEXT_MAIN}; font-size: 13px;"

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        def _make_combo() -> QComboBox:
            cb = QComboBox()
            cb.addItems(JA_NEIN_OPTIONEN)
            cb.setCurrentText("Nein")
            cb.setStyleSheet(_combo_style)
            return cb

        self._combo_mfa = _make_combo()
        self._combo_mfa.setToolTip(
            "Mehr-Faktor-Authentifizierung für kritische Zugänge "
            "(Mail, VPN, Admin-Konten)."
        )
        form.addRow(
            self._make_label("MFA für kritische Zugänge", _lbl_style),
            self._combo_mfa,
        )

        self._combo_schulung = _make_combo()
        self._combo_schulung.setToolTip(
            "Wurden die Mitarbeiter in den letzten 12 Monaten zu Phishing "
            "sensibilisiert/geschult?"
        )
        form.addRow(
            self._make_label("Phishing-Schulung < 12 Monate", _lbl_style),
            self._combo_schulung,
        )

        self._combo_spoofing = _make_combo()
        self._combo_spoofing.setToolTip(
            "SPF, DKIM und DMARC für die eigene Domain aktiv (Schutz vor "
            "Absender-Fälschung)?"
        )
        form.addRow(
            self._make_label("SPF/DKIM/DMARC aktiv", _lbl_style),
            self._combo_spoofing,
        )

        self._combo_filter = _make_combo()
        self._combo_filter.setToolTip(
            "Spam-/Phishing-Mailfilter (Gateway oder Cloud) im Einsatz?"
        )
        form.addRow(
            self._make_label("Spam-/Phishing-Mailfilter", _lbl_style),
            self._combo_filter,
        )

        root.addLayout(form)
        root.addStretch()

        # Tab-Reihenfolge (F4) — logische Feld-Folge explizit setzen.
        for prev, nxt in (
            (self._combo_mfa, self._combo_schulung),
            (self._combo_schulung, self._combo_spoofing),
            (self._combo_spoofing, self._combo_filter),
        ):
            QWidget.setTabOrder(prev, nxt)

    @staticmethod
    def _make_label(text: str, style: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(style)
        return lbl

    def is_valid(self) -> bool:
        """Schritt ist immer gültig (alle Felder optional)."""
        return True

    def get_data(self) -> PhishingData:
        """Gibt die eingegebenen Phishing-/E-Mail-Sicherheits-Daten zurück."""
        return PhishingData(
            mfa_aktiv=self._combo_mfa.currentText(),
            phishing_schulung_aktuell=self._combo_schulung.currentText(),
            mail_spoofing_schutz=self._combo_spoofing.currentText(),
            mail_filter_aktiv=self._combo_filter.currentText(),
        )

    def set_data(self, data: PhishingData) -> None:
        """Befüllt das Formular mit vorhandenen Daten."""
        for combo, value in (
            (self._combo_mfa, data.mfa_aktiv),
            (self._combo_schulung, data.phishing_schulung_aktuell),
            (self._combo_spoofing, data.mail_spoofing_schutz),
            (self._combo_filter, data.mail_filter_aktiv),
        ):
            idx = combo.findText(value)
            if idx >= 0:
                combo.setCurrentIndex(idx)
