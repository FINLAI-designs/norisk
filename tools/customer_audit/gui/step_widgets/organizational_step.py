"""
organizational_step — Schritt 3: Organisatorische Sicherheit.

Erfasst 7 Ja/Nein/Teilweise-Kategorien zu organisatorischen Maßnahmen.

Iter 3f-ii: Siebte Kategorie "AVV-Schluessel-Trennung"
fuer Encryption-Audit aus NoRisk-Audit-Paket-3 §6.3 (Verwahrung
kryptographischer Schluessel getrennt vom jeweiligen Speicher-Medium).

Schichtzugehörigkeit: gui/ — nur UI-Logik.

Author: Patrick Riederich
Version: 1.1 (3f-ii, 2026-05-17)
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.customer_audit.domain.entities import (
    JA_NEIN_OPTIONEN,
    OrganizationalData,
)
from tools.customer_audit.gui.step_widgets import field_styles


class OrganizationalStep(QWidget):
    """Wizard-Schritt 3: Organisatorische Sicherheit.

    Jede der 6 Kategorien wird mit einem Ja/Nein/Teilweise-Dropdown erfasst.
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

        hdr = QLabel("Organisatorische Sicherheit")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway;"
            " font-weight: 700; font-size: 14px;"
        )
        root.addWidget(hdr)

        info = QLabel(
            "Bitte gib an, welche organisatorischen Sicherheitsmaßnahmen "
            "im Unternehmen vorhanden sind."
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
        form.setLabelAlignment(
            __import__("PySide6.QtCore", fromlist=["Qt"]).Qt.AlignmentFlag.AlignRight
        )

        def _make_combo() -> QComboBox:
            cb = QComboBox()
            cb.addItems(JA_NEIN_OPTIONEN)
            cb.setCurrentText("Nein")
            cb.setStyleSheet(_combo_style)
            return cb

        # Zugangskontrollen
        self._combo_zugang = _make_combo()
        form.addRow(
            self._make_label("Zugangskontrollen", _lbl_style), self._combo_zugang
        )

        # Backup-Strategie
        self._combo_backup = _make_combo()
        form.addRow(
            self._make_label("Backup-Strategie", _lbl_style), self._combo_backup
        )

        # Update-Management
        self._combo_updates = _make_combo()
        form.addRow(
            self._make_label("Update-Management", _lbl_style), self._combo_updates
        )

        # Mitarbeitersensibilisierung
        self._combo_sensibilisierung = _make_combo()
        form.addRow(
            self._make_label("Mitarbeitersensibilisierung", _lbl_style),
            self._combo_sensibilisierung,
        )

        # Incident-Response-Plan
        self._combo_incident = _make_combo()
        form.addRow(
            self._make_label("Incident-Response-Plan", _lbl_style), self._combo_incident
        )

        # DSGVO-Konformität
        self._combo_dsgvo = _make_combo()
        form.addRow(
            self._make_label("DSGVO-Konformität", _lbl_style), self._combo_dsgvo
        )

        # AVV-Schluessel-Trennung (3f-ii, Encryption-Audit §6.3)
        self._combo_avv_key = _make_combo()
        self._combo_avv_key.setToolTip(
            "Werden kryptographische Schluessel "
            "(AVV-Dokumente, BitLocker-Recovery, Backup-Verschluesselung) "
            "physisch + logisch getrennt vom jeweiligen Speicher-Medium "
            "verwahrt? Ja heisst: ein Schluessel-Kompromiss hebelt nicht "
            "alle Schutzebenen gleichzeitig aus."
        )
        form.addRow(
            self._make_label("AVV-/Crypto-Schluessel-Trennung", _lbl_style),
            self._combo_avv_key,
        )

        root.addLayout(form)
        root.addStretch()

        # Tab-Reihenfolge (F4) — logische Feld-Folge explizit setzen.
        for prev, nxt in (
            (self._combo_zugang, self._combo_backup),
            (self._combo_backup, self._combo_updates),
            (self._combo_updates, self._combo_sensibilisierung),
            (self._combo_sensibilisierung, self._combo_incident),
            (self._combo_incident, self._combo_dsgvo),
            (self._combo_dsgvo, self._combo_avv_key),
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

    def is_valid(self) -> bool:
        """Schritt ist immer gültig.

        Returns:
            True.
        """
        return True

    def get_data(self) -> OrganizationalData:
        """Gibt die eingegebenen Organisations-Daten zurück.

        Returns:
            OrganizationalData mit den Formularwerten.
        """
        return OrganizationalData(
            zugangskontrollen=self._combo_zugang.currentText(),
            backup_strategie=self._combo_backup.currentText(),
            update_management=self._combo_updates.currentText(),
            mitarbeitersensibilisierung=self._combo_sensibilisierung.currentText(),
            incident_response_plan=self._combo_incident.currentText(),
            dsgvo_konformitaet=self._combo_dsgvo.currentText(),
            avv_key_separate_storage=self._combo_avv_key.currentText(),
        )

    def set_data(self, data: OrganizationalData) -> None:
        """Befüllt das Formular mit vorhandenen Daten.

        Args:
            data: Vorhandene OrganizationalData.
        """
        _combos = [
            (self._combo_zugang, data.zugangskontrollen),
            (self._combo_backup, data.backup_strategie),
            (self._combo_updates, data.update_management),
            (self._combo_sensibilisierung, data.mitarbeitersensibilisierung),
            (self._combo_incident, data.incident_response_plan),
            (self._combo_dsgvo, data.dsgvo_konformitaet),
            (self._combo_avv_key, data.avv_key_separate_storage),
        ]
        for combo, value in _combos:
            idx = combo.findText(value)
            if idx >= 0:
                combo.setCurrentIndex(idx)
