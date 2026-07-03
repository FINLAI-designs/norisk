"""
mode_select_step — Erste Wizard-Seite: Selbst-Audit oder Kunden-Audit?

Patrick-Entscheidung: das Customer-Assessment
deckt zwei Use-Cases ab, die wir ueber einen Mode-Switch trennen:

- **Selbst-Audit:** Anwender bewertet die eigene Kanzlei. Automatische
  Scans (DNS-MX, Software-Inventory, Backup-Detection) werden aktiv
  und ergaenzen den Fragebogen.
- **Kunden-Audit:** Anwalt/Berater bewertet einen externen Mandanten.
  Nur Fragebogen — Scanner laufen nicht auf einer fremden Maschine.

Schichtzugehoerigkeit: gui/ — nur UI-Logik.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QLabel,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.customer_audit.domain.entities import AuditMode

_DESCRIPTION_SELF = (
    "Auditiert die eigene Kanzlei mit automatischen Hintergrund-Scans "
    "(DNS-/Mail-Domain-Pruefung, installierte Backup-Software, Daten-"
    "Souveraenitaets-Check). Der Fragebogen ergaenzt nur das, was die "
    "Scans nicht abdecken."
)
_DESCRIPTION_CUSTOMER = (
    "Auditiert einen externen Kunden oder Mandanten. Klassischer "
    "Fragebogen — Scanner laufen NICHT auf der Kunden-Maschine. Pflicht-"
    "Eingaben: Firmenname und Ansprechpartner."
)


class ModeSelectStep(QWidget):
    """Wizard-Schritt 0: Audit-Modus waehlen.

    Signals:
        mode_changed(AuditMode): Emitted whenever the user toggles the
            radio buttons. Wizard kann darauf reagieren und z. B.
            unnoetige Pflichtfelder verstecken.
    """

    mode_changed = Signal(object)  # AuditMode

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._mode: AuditMode = AuditMode.SELF
        self._build_ui()

    # ------------------------------------------------------------------
    def get_mode(self) -> AuditMode:
        return self._mode

    def set_mode(self, mode: AuditMode) -> None:
        self._mode = mode
        if mode is AuditMode.SELF:
            self._radio_self.setChecked(True)
        else:
            self._radio_customer.setChecked(True)

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        c = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        hdr = QLabel("Wer soll auditiert werden?")
        hdr.setObjectName("AuditModeHeader")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway; "
            f"font-weight: 700; font-size: 14px;"
        )
        root.addWidget(hdr)

        # Selbst-Audit
        self._radio_self = QRadioButton("Selbst-Audit")
        self._radio_self.setObjectName("ModeRadioSelf")
        self._radio_self.setChecked(True)
        self._radio_self.toggled.connect(self._on_toggled)
        root.addWidget(self._radio_self)

        desc_self = QLabel(_DESCRIPTION_SELF)
        desc_self.setWordWrap(True)
        desc_self.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; "
            f"padding-left: 24px; padding-bottom: 6px;"
        )
        root.addWidget(desc_self)

        # Kunden-Audit
        self._radio_customer = QRadioButton("Externer Kunde / Mandant")
        self._radio_customer.setObjectName("ModeRadioCustomer")
        self._radio_customer.toggled.connect(self._on_toggled)
        root.addWidget(self._radio_customer)

        desc_customer = QLabel(_DESCRIPTION_CUSTOMER)
        desc_customer.setWordWrap(True)
        desc_customer.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; "
            f"padding-left: 24px; padding-bottom: 6px;"
        )
        root.addWidget(desc_customer)

        root.addStretch()

    def _on_toggled(self, checked: bool) -> None:
        if not checked:
            return  # ignoriere das "uncheck"-Event des anderen Radios
        sender = self.sender()
        new_mode = (
            AuditMode.SELF if sender is self._radio_self else AuditMode.CUSTOMER
        )
        if new_mode != self._mode:
            self._mode = new_mode
            self.mode_changed.emit(new_mode)

    def is_valid(self) -> bool:  # pragma: no cover - trivial
        return True

    def focus_first(self) -> None:  # pragma: no cover - convenience
        self._radio_self.setFocus(Qt.FocusReason.OtherFocusReason)
