"""
offboarding_dialog — Modaler Editor fuer die Vendor-Off-Boarding-Checkliste.

Iter 2d-i: Analog:class:`AvvChecklistDialog`,
aber mit 10 Off-Boarding-spezifischen Default-Checks. Beim ersten
Oeffnen fuer einen Vendor laeuft der Service-Start (Initial-Checks
werden persistiert), bei spaeteren Aufrufen wird die bestehende
Checkliste geladen.

Author: Patrick Riederich
Version: 0.1-i, 2026-05-15)
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.dialogs import (
    FinlaiConfirmDialog,
    FinlaiInfoDialog,
    FinlaiSuccessDialog,
)
from core.icons import Icons
from core.logger import get_logger
from tools.supply_chain_monitor.application.offboarding_service import (
    OffBoardingService,
)
from tools.supply_chain_monitor.domain.models import (
    OffBoarding,
    OffBoardingCheck,
    OffBoardingChecklistEntry,
    OffBoardingStatus,
)

_log = get_logger(__name__)

# Off-Boarding-Pflichtschritte mit explizitem DSGVO-Bezug. Macht im
# Dialog nachvollziehbar, WELCHE Dokumentationspflicht jeder Schritt erfuellt
# (Art. 28/30/32) — die Checkliste IST die Offboarding-Dokumentation. Reine
# Kennzeichnung der Pflicht, keine Rechtsberatung.
_CHECK_DESCRIPTIONS: dict[OffBoardingCheck, str] = {
    OffBoardingCheck.DATA_EXPORT: (
        "Alle Mandanten-/Geschaeftsdaten beim Vendor exportiert "
        "(Rueckgabe, Art. 28 Abs. 3 lit. g DSGVO)"
    ),
    OffBoardingCheck.DATA_DELETION_CONFIRMED: (
        "Loeschnachweis vom Vendor erhalten "
        "(Loeschung, Art. 28 Abs. 3 lit. g DSGVO)"
    ),
    OffBoardingCheck.AVV_TERMINATED: (
        "AVV gekuendigt + Kuendigungsbestaetigung im Akt (Art. 28 DSGVO)"
    ),
    OffBoardingCheck.ACCOUNTS_DEACTIVATED: (
        "Alle Mitarbeiter-Accounts deaktiviert / geloescht "
        "(Zugriffsentzug, Art. 32 DSGVO)"
    ),
    OffBoardingCheck.CREDENTIALS_ROTATED: (
        "Geteilte Credentials rotiert — Passwoerter, API-Keys, Tokens "
        "(Art. 32 DSGVO)"
    ),
    OffBoardingCheck.INTEGRATIONS_REMOVED: (
        "Integrationen, Webhooks, SAML-Apps entfernt (Art. 32 DSGVO)"
    ),
    OffBoardingCheck.PAYMENT_STOPPED: (
        "Zahlung beendet — Lastschrift, Kreditkarte, Subscription (organisatorisch)"
    ),
    OffBoardingCheck.SUBPROCESSORS_NOTIFIED: (
        "Sub-Auftragnehmer informiert / Daten ueberfuehrt "
        "(Art. 28 Abs. 3 lit. d DSGVO)"
    ),
    OffBoardingCheck.BACKUP_RETAINED: (
        "Eigene Backup-Kopie fuer Rechtsfrist gesichert "
        "(Aufbewahrung trotz Loeschung, Art. 17 Abs. 3 DSGVO)"
    ),
    OffBoardingCheck.DOCUMENTATION_UPDATED: (
        "AV-Verzeichnis / Inventar aktualisiert "
        "(Verzeichnis von Verarbeitungstaetigkeiten, Art. 30 DSGVO)"
    ),
}

_HEADERS: list[str] = ["Pflichtschritt", "Erledigt", "Typ"]


class OffBoardingDialog(QDialog):
    """Off-Boarding-Editor (Start oder Edit) fuer einen Vendor.

    Bei *erstem* Aufruf fuer einen Vendor: legt via Service ein neues
    Off-Boarding mit 10 Default-Checks an. Folge-Aufrufe laden die
    bestehende Instanz und ihre Checkliste.

    Nach Accept werden die Aenderungen ueber den Service persistiert.
    Wenn alle Default-Checks erledigt sind, kann der User ueber den
    "Abschliessen"-Button das Off-Boarding als COMPLETED markieren.
    """

    def __init__(
        self,
        vendor_id: int,
        vendor_name: str,
        service: OffBoardingService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._vendor_id = int(vendor_id)
        self._vendor_name = vendor_name
        self._service = service
        self.setWindowTitle(f"Off-Boarding — {vendor_name}")
        self.setMinimumSize(760, 520)

        self._offboarding: OffBoarding | None = service.get_for_vendor(vendor_id)
        if self._offboarding is None:
            self._offboarding = service.start(
                vendor_id=vendor_id,
                reason=f"Off-Boarding von '{vendor_name}'",
            )
        self._entries: list[OffBoardingChecklistEntry] = list(
            service.get_checklist(self._offboarding.id)
            if self._offboarding.id is not None
            else []
        )
        self._build_ui()
        self._reload()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        info = QLabel(
            "Schrittweise Vendor-Abwicklung — zugleich die Dokumentation der "
            "DSGVO-Offboarding-Pflichten (Art. 28/30/32: Rueckgabe/Loeschnachweis, "
            "Subunternehmer, AV-Verzeichnis, Zugriffsentzug). Jeder Schritt nennt "
            "seinen Pflicht-Bezug. Sind alle 10 Pflichtschritte erledigt, wird der "
            "'Abschliessen'-Button aktiv und das Off-Boarding formal beendet."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self._status_label = QLabel()
        self._status_label.setObjectName("OffBoardingStatusLabel")
        layout.addWidget(self._status_label)

        self._table = QTableWidget(0, len(_HEADERS))
        self._table.setHorizontalHeaderLabels(_HEADERS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self._table, stretch=1)

        # Custom-Check-Buttons
        row = QHBoxLayout()
        self._add_custom_btn = QPushButton("Custom-Schritt hinzufuegen ...")
        self._add_custom_btn.clicked.connect(self._on_add_custom)
        row.addWidget(self._add_custom_btn)
        self._remove_custom_btn = QPushButton("Custom-Schritt entfernen")
        self._remove_custom_btn.clicked.connect(self._on_remove_custom)
        row.addWidget(self._remove_custom_btn)
        row.addStretch(1)

        self._complete_btn = QPushButton("Off-Boarding abschliessen")
        self._complete_btn.setObjectName("OffBoardingCompleteButton")
        self._complete_btn.clicked.connect(self._on_complete)
        row.addWidget(self._complete_btn)

        self._cancel_obj_btn = QPushButton("Off-Boarding abbrechen")
        self._cancel_obj_btn.clicked.connect(self._on_cancel_offb)
        row.addWidget(self._cancel_obj_btn)

        layout.addLayout(row)

        # Standard-Save/Cancel-Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Speichern")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Abbrechen")
        buttons.accepted.connect(self._on_save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _reload(self) -> None:
        # Defaults zuerst (10 fixe Off-Boarding-Checks), dann Customs.
        default_order: dict[OffBoardingCheck, int] = {
            c: i for i, c in enumerate(OffBoardingCheck)
        }
        self._entries.sort(
            key=lambda e: (
                1 if e.is_custom else 0,
                default_order.get(e.check_key, 99) if not e.is_custom else 0,
                e.custom_label if e.is_custom else "",
            )
        )
        self._table.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            self._set_row(row, entry)
        self._update_status()

    def _set_row(self, row: int, entry: OffBoardingChecklistEntry) -> None:
        if entry.is_custom:
            label = entry.custom_label
        elif entry.check_key is not None:
            label = _CHECK_DESCRIPTIONS.get(entry.check_key, entry.check_key.value)
        else:
            label = "?"
        label_item = QTableWidgetItem(label)
        label_item.setData(Qt.ItemDataRole.UserRole, row)
        self._table.setItem(row, 0, label_item)

        # Checkbox
        host = QWidget()
        host_layout = QHBoxLayout(host)
        host_layout.setContentsMargins(8, 0, 8, 0)
        host_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cb = QCheckBox()
        cb.setChecked(entry.is_done)
        cb.toggled.connect(lambda checked, r=row: self._on_toggle(r, checked))
        host_layout.addWidget(cb)
        self._table.setCellWidget(row, 1, host)

        kind = QTableWidgetItem("Custom" if entry.is_custom else "Default")
        kind.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        self._table.setItem(row, 2, kind)

    def _on_toggle(self, row: int, checked: bool) -> None:
        if not 0 <= row < len(self._entries):
            return
        e = self._entries[row]
        self._entries[row] = OffBoardingChecklistEntry(
            id=e.id,
            offboarding_id=e.offboarding_id,
            is_done=checked,
            check_key=e.check_key,
            custom_label=e.custom_label,
            is_custom=e.is_custom,
            notes=e.notes,
        )
        self._update_status()

    def _update_status(self) -> None:
        if self._offboarding is None:
            self._status_label.setText("")
            self._complete_btn.setEnabled(False)
            return
        total = len(self._entries)
        done = sum(1 for e in self._entries if e.is_done)
        defaults_done = sum(
            1 for e in self._entries if not e.is_custom and e.is_done
        )
        status_text = {
            OffBoardingStatus.IN_PROGRESS: "Status: in Bearbeitung",
            OffBoardingStatus.COMPLETED: "Status: ABGESCHLOSSEN",
            OffBoardingStatus.CANCELLED: "Status: abgebrochen",
        }[self._offboarding.status]
        self._status_label.setText(
            f"{status_text}  —  Erledigt: {done}/{total} "
            f"(Defaults: {defaults_done}/{len(OffBoardingCheck)})"
        )
        self._complete_btn.setEnabled(
            self._offboarding.status is OffBoardingStatus.IN_PROGRESS
            and defaults_done == len(OffBoardingCheck)
        )

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_add_custom(self) -> None:
        if self._offboarding is None or self._offboarding.id is None:
            return
        label, ok = QInputDialog.getText(
            self,
            "Custom-Schritt hinzufuegen",
            "Bezeichnung des zusaetzlichen Off-Boarding-Schritts:",
        )
        if not ok or not label.strip():
            return
        try:
            new_entry = OffBoardingChecklistEntry(
                id=None,
                offboarding_id=self._offboarding.id,
                is_done=False,
                custom_label=label,
                is_custom=True,
            )
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._entries.append(new_entry)
        self._reload()

    def _on_remove_custom(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if not 0 <= idx < len(self._entries):
            return
        if not self._entries[idx].is_custom:
            FinlaiInfoDialog(
                title="Default-Schritt",
                message="Default-Schritte koennen nicht entfernt werden (nur Custom).",
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        del self._entries[idx]
        self._reload()

    def _on_save(self) -> None:
        if self._offboarding is None or self._offboarding.id is None:
            self.reject()
            return
        self._service.update_checklist(self._offboarding.id, self._entries)
        self.accept()

    def _on_complete(self) -> None:
        if self._offboarding is None or self._offboarding.id is None:
            return
        # Vor dem Abschliessen die aktuellen Checks persistieren.
        self._service.update_checklist(self._offboarding.id, self._entries)
        try:
            self._offboarding = self._service.complete(self._offboarding.id)
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Abschluss nicht moeglich",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        FinlaiSuccessDialog(
            title="Off-Boarding abgeschlossen",
            message=f"Off-Boarding fuer '{self._vendor_name}' wurde abgeschlossen.",
            parent=self,
        ).exec()
        self.accept()

    def _on_cancel_offb(self) -> None:
        if self._offboarding is None or self._offboarding.id is None:
            return
        dlg = FinlaiConfirmDialog(
            title="Off-Boarding abbrechen",
            message=(
                f"Das Off-Boarding fuer '{self._vendor_name}' wirklich abbrechen?\n\n"
                "Die Checkliste bleibt erhalten, der Status wird auf CANCELLED gesetzt."
            ),
            confirm_text="Off-Boarding abbrechen",
            cancel_text="Zurück",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._service.update_checklist(self._offboarding.id, self._entries)
        self._offboarding = self._service.cancel(self._offboarding.id)
        self.accept()
