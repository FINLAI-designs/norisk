"""
customer_data_step — Schritt 1: Kundenstammdaten.

Erfasst Firmenname (Pflicht), Ansprechpartner, Branche, Größe, Datum.

Schichtzugehörigkeit: gui/ — nur UI-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import date

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.customer_audit.domain.entities import (
    BRANCHEN,
    MAX_TEXT_LENGTH,
    UNTERNEHMENSGROESSEN,
    CustomerData,
    sanitize_text,
)
from tools.customer_audit.gui.step_widgets import field_styles


class CustomerDataStep(QWidget):
    """Wizard-Schritt 1: Kundenstammdaten.

    Attributes:
        _input_firma: Firmennamen-Eingabe (Pflicht).
        _lbl_err_firma: Fehlermeldung für Firmennamen.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert den Schritt.

        Args:
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        """Baut das Formular-Layout auf."""
        c = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        hdr = QLabel("Kundenstammdaten")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway;"
            " font-weight: 700; font-size: 14px;"
        )
        root.addWidget(hdr)

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(
            __import__("PySide6.QtCore", fromlist=["Qt"]).Qt.AlignmentFlag.AlignRight
        )

        # geteilte Feld-Styles (einheitliche Fokus-Hervorhebung +
        # feste Dropdown-Breite) statt pro-Step dupliziertem QSS.
        _input_style = field_styles.input_style()
        _combo_style = field_styles.combo_style()
        _lbl_style = f"color: {c.TEXT_MAIN}; font-size: 12px;"
        _err_style = f"color: {c.DANGER}; font-size: 11px;"

        # Firmenname (Pflicht)
        self._input_firma = QLineEdit()
        self._input_firma.setPlaceholderText("Firmenname (Pflichtfeld)")
        self._input_firma.setMaxLength(MAX_TEXT_LENGTH)
        self._input_firma.setStyleSheet(_input_style)
        self._input_firma.textChanged.connect(self._validate_firma)
        form.addRow(self._make_label("Firmenname *", _lbl_style), self._input_firma)

        self._lbl_err_firma = QLabel("")
        self._lbl_err_firma.setStyleSheet(_err_style)
        form.addRow("", self._lbl_err_firma)

        # Ansprechpartner
        self._input_ap_name = QLineEdit()
        self._input_ap_name.setPlaceholderText("Max Mustermann")
        self._input_ap_name.setMaxLength(MAX_TEXT_LENGTH)
        self._input_ap_name.setStyleSheet(_input_style)
        form.addRow(
            self._make_label("Ansprechpartner", _lbl_style), self._input_ap_name
        )

        self._input_ap_email = QLineEdit()
        self._input_ap_email.setPlaceholderText("email@firma.de")
        self._input_ap_email.setMaxLength(MAX_TEXT_LENGTH)
        self._input_ap_email.setStyleSheet(_input_style)
        form.addRow(self._make_label("E-Mail", _lbl_style), self._input_ap_email)

        self._input_ap_tel = QLineEdit()
        self._input_ap_tel.setPlaceholderText("+43 1 234 5678")
        self._input_ap_tel.setMaxLength(50)
        self._input_ap_tel.setStyleSheet(_input_style)
        form.addRow(self._make_label("Telefon", _lbl_style), self._input_ap_tel)

        # Branche
        self._combo_branche = QComboBox()
        self._combo_branche.addItems(BRANCHEN)
        self._combo_branche.setStyleSheet(_combo_style)
        form.addRow(self._make_label("Branche", _lbl_style), self._combo_branche)

        # Unternehmensgröße
        self._combo_groesse = QComboBox()
        self._combo_groesse.addItems(UNTERNEHMENSGROESSEN)
        self._combo_groesse.setStyleSheet(_combo_style)
        form.addRow(self._make_label("Mitarbeiter", _lbl_style), self._combo_groesse)

        # Privatperson / Kleinstbetrieb — neutralisiert enterprise-typische Items
        self._chk_privat = QCheckBox(
            "Privatperson / Kleinstbetrieb — Enterprise-Anforderungen nicht werten"
        )
        self._chk_privat.setToolTip(
            "Fuer Einzelpersonen/Kleinstbetriebe aktivieren: enterprise-typische "
            "Punkte (Zugangskontrollen, Netzwerksegmentierung, IDS/IPS, Pentest) "
            "fliessen dann NICHT negativ in den Score ein — ihr Fehlen ist hier "
            "kein Sicherheitsdefizit."
        )
        self._chk_privat.setStyleSheet(
            f"QCheckBox {{ color: {c.TEXT_MAIN}; font-size: 12px; }}"
        )
        form.addRow("", self._chk_privat)

        # Erstellungsdatum
        self._input_datum = QLineEdit()
        self._input_datum.setText(date.today().isoformat())
        self._input_datum.setMaxLength(20)
        self._input_datum.setStyleSheet(_input_style)
        form.addRow(self._make_label("Erstellungsdatum", _lbl_style), self._input_datum)

        root.addLayout(form)
        root.addStretch()

        # Tab-Reihenfolge (F4) — logische Feld-Folge explizit setzen.
        for prev, nxt in (
            (self._input_firma, self._input_ap_name),
            (self._input_ap_name, self._input_ap_email),
            (self._input_ap_email, self._input_ap_tel),
            (self._input_ap_tel, self._combo_branche),
            (self._combo_branche, self._combo_groesse),
            (self._combo_groesse, self._chk_privat),
            (self._chk_privat, self._input_datum),
        ):
            QWidget.setTabOrder(prev, nxt)

    @staticmethod
    def _make_label(text: str, style: str) -> QLabel:
        """Erstellt ein Formular-Label.

        Args:
            text: Label-Text.
            style: QSS-Stylesheet.

        Returns:
            Formatiertes QLabel.
        """
        lbl = QLabel(text)
        lbl.setStyleSheet(style)
        return lbl

    def _validate_firma(self, text: str) -> None:
        """Validiert den Firmennamen und zeigt ggf. Fehlermeldung.

        Args:
            text: Aktueller Eingabetext.
        """
        c = theme.get()
        if not text.strip():
            self._lbl_err_firma.setText("Firmenname ist ein Pflichtfeld.")
            # Fehler-Rahmen ueber den geteilten Helfer -> behaelt die feste
            # Feldbreite (das fruehere Inline-QSS ohne max-width liess das Feld
            # im Fehlerfall auf volle Breite springen).
            self._input_firma.setStyleSheet(
                field_styles.input_style(border_color=c.DANGER)
            )
        else:
            self._lbl_err_firma.setText("")
            self._input_firma.setStyleSheet(field_styles.input_style())

    def is_valid(self) -> bool:
        """Prüft ob alle Pflichtfelder ausgefüllt sind.

        Returns:
            True wenn gültig.
        """
        return bool(self._input_firma.text().strip())

    def get_data(self) -> CustomerData:
        """Gibt die eingegebenen Kundendaten zurück.

        Returns:
            CustomerData mit den Formularwerten.
        """
        return CustomerData(
            firmenname=sanitize_text(self._input_firma.text().strip()),
            ansprechpartner_name=sanitize_text(self._input_ap_name.text().strip()),
            ansprechpartner_email=sanitize_text(self._input_ap_email.text().strip()),
            ansprechpartner_telefon=sanitize_text(self._input_ap_tel.text().strip()),
            branche=self._combo_branche.currentText(),
            unternehmensgroesse=self._combo_groesse.currentText(),
            erstellungsdatum=self._input_datum.text().strip(),
            ist_privatperson=self._chk_privat.isChecked(),
        )

    def set_data(self, data: CustomerData) -> None:
        """Befüllt das Formular mit vorhandenen Daten.

        Args:
            data: Vorhandene CustomerData.
        """
        self._input_firma.setText(data.firmenname)
        self._input_ap_name.setText(data.ansprechpartner_name)
        self._input_ap_email.setText(data.ansprechpartner_email)
        self._input_ap_tel.setText(data.ansprechpartner_telefon)
        idx = self._combo_branche.findText(data.branche)
        if idx >= 0:
            self._combo_branche.setCurrentIndex(idx)
        idx = self._combo_groesse.findText(data.unternehmensgroesse)
        if idx >= 0:
            self._combo_groesse.setCurrentIndex(idx)
        self._chk_privat.setChecked(data.ist_privatperson)
        self._input_datum.setText(data.erstellungsdatum)
