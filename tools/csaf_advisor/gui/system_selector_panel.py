"""
system_selector_panel — System-Selector + Profil-CRUD fuer den CSAF Advisory-Monitor.

Sprint 6 Phase 2c2: Vierter und letzter Panel-Extract aus dem
``CsafAdvisorWidget``-God-Class-Refactor.

Funktionen:

* **Combobox** zur Auswahl des aktiven SystemProfile (eigenes System oder
  Kundensystem).
* **Edit-Button** -- oeffnet TechStackDialog fuer das gewaehlte Profil.
* **Delete-Button** -- nur fuer Kundensysteme aktiv (eigenes System
  kann nicht geloescht werden), oeffnet Confirm-Dialog.
* **"[+] Neues Kundensystem"-Button** -- oeffnet AddCustomerSystemDialog
  und direkt im Anschluss TechStackDialog.

Nach jeder Aenderung wird das ``_inventory`` (TechStack als Liste von
``SoftwareComponent``) neu berechnet und das ``service.run_matching``
aufgerufen. Anschliessend wird ``inventory_changed`` emittiert -- das
Hauptwidget reagiert mit Refresh der Advisory-Liste.

Public API:
    get_inventory -> list[SoftwareComponent] -- fuer FetchWorker

Signal:
    inventory_changed -- emittiert wenn das aktive Inventar oder
                            das Matching-Resultat sich geaendert hat.
                            Hauptwidget reagiert mit _refresh_list.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon
from tools.csaf_advisor.application.advisory_service import AdvisoryService
from tools.csaf_advisor.application.product_matcher import SoftwareComponent
from tools.csaf_advisor.gui.customer_system_dialog import AddCustomerSystemDialog
from tools.csaf_advisor.gui.techstack_dialog import TechStackDialog
from tools.security_scoring.application.tech_stack.manage_profiles_use_case import (
    ManageProfilesUseCase,
)
from tools.security_scoring.domain.tech_stack.entities import SystemProfile, TechStack


class SystemSelectorPanel(QWidget):
    """System-Selector + Profil-CRUD-Buttons in einer einzigen QHBoxLayout-Zeile.

    Das Panel haelt den ``service``- und ``techstack_repo``-Reference selbst
    (Dependency-Injection) und kapselt die komplette Profil-Lebenszyklus-
    Logik (Load, Add, Edit, Delete, Matching).
    """

    inventory_changed = Signal()

    def __init__(
        self,
        service: AdvisoryService,
        profile_use_case: ManageProfilesUseCase | None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Panel.

        Args:
            service: Vollstaendig konfigurierter AdvisoryService.
            profile_use_case: ``ManageProfilesUseCase`` fuer Profil-CRUD
: GUI haengt am application-Layer
                              statt am Repository). ``None`` wenn das
                              Repository nicht initialisierbar war —
                              Edit/Delete/Add sind dann no-ops.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._service = service
        self._profile_use_case = profile_use_case
        self._profiles: list[SystemProfile] = []
        self._inventory: list[SoftwareComponent] = []
        self._build_ui()
        self._load_profiles()

    def _build_ui(self) -> None:
        """Combobox + Edit/Delete/Add-Buttons in eine HBoxLayout-Zeile."""
        t = theme.get()
        row = QHBoxLayout(self)
        row.setSpacing(8)
        row.setContentsMargins(0, 0, 0, 0)

        lbl = QLabel("System:")
        lbl.setStyleSheet(f"color: {t.TEXT_DIM}; font-size: 13px;")
        row.addWidget(lbl)

        self._combo_system = QComboBox()
        self._combo_system.setMinimumWidth(260)
        self._combo_system.setStyleSheet(
            f"QComboBox {{ background-color: {t.CARD_BG}; color: {t.TEXT_MAIN};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px; padding: 4px 8px;"
            f" font-size: 13px; }}"
            f"QComboBox::drop-down {{ border: none; }}"
            f"QComboBox QAbstractItemView {{ background-color: {t.CARD_BG};"
            f" color: {t.TEXT_MAIN}; selection-background-color: {t.ACCENT}; }}"
        )
        self._combo_system.currentIndexChanged.connect(self._on_system_changed)
        row.addWidget(self._combo_system)

        self._btn_edit_system = QPushButton()
        self._btn_edit_system.setIcon(get_icon(Icons.EDIT))
        self._btn_edit_system.setToolTip("Tech-Stack bearbeiten")
        self._btn_edit_system.setFixedSize(32, 32)
        self._btn_edit_system.setStyleSheet(
            f"QPushButton {{ background: transparent; border: 1px solid {t.BORDER};"
            f" border-radius: 4px; padding: 4px; }}"
            f"QPushButton:hover {{ background: {t.BG_SIDEBAR_HOVER}; }}"
        )
        self._btn_edit_system.clicked.connect(self._on_edit_system)
        row.addWidget(self._btn_edit_system)

        danger_hex = t.DANGER.lstrip("#")
        dr, dg, db = (
            int(danger_hex[0:2], 16),
            int(danger_hex[2:4], 16),
            int(danger_hex[4:6], 16),
        )
        self._btn_delete_system = QPushButton()
        self._btn_delete_system.setObjectName("sysDeleteButton")
        self._btn_delete_system.setIcon(get_icon(Icons.DELETE))
        self._btn_delete_system.setToolTip("Kundensystem löschen")
        self._btn_delete_system.setFixedSize(32, 32)
        self._btn_delete_system.setStyleSheet(
            f"QPushButton#sysDeleteButton {{ background: transparent;"
            f" border: 1px solid {t.BORDER}; border-radius: 4px; padding: 4px; }}"
            f"QPushButton#sysDeleteButton:hover {{ background: rgba({dr},{dg},{db},25);"
            f" border-color: {t.DANGER}; }}"
            f"QPushButton#sysDeleteButton:disabled {{ opacity: 0.4; }}"
        )
        self._btn_delete_system.clicked.connect(self._on_delete_system)
        row.addWidget(self._btn_delete_system)

        btn_add_system = QPushButton("[+] Neues Kundensystem")
        btn_add_system.setStyleSheet(self._btn_style())
        btn_add_system.clicked.connect(self._on_add_customer_system)
        row.addWidget(btn_add_system)

        row.addStretch()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_inventory(self) -> list[SoftwareComponent]:
        """Aktive Software-Komponenten fuer Advisory-Matching/Fetch."""
        return list(self._inventory)

    # ------------------------------------------------------------------
    # Profil-Load
    # ------------------------------------------------------------------

    def _load_profiles(self) -> None:
        """Laedt SystemProfile aus dem Repository und befuellt die Combobox."""
        if self._profile_use_case is None:
            return

        try:
            self._profiles = self._profile_use_case.get_all_profiles()
        except Exception:  # noqa: BLE001
            self._profiles = []
            return

        self._combo_system.blockSignals(True)
        self._combo_system.clear()
        for profile in self._profiles:
            self._combo_system.addItem(profile.display_name)
        self._combo_system.blockSignals(False)

        if self._profiles:
            self._inventory = self._techstack_to_components(
                self._profiles[0].tech_stack
            )
        self._update_btn_state()

    @staticmethod
    def _techstack_to_components(stack: TechStack) -> list[SoftwareComponent]:
        """Konvertiert einen TechStack in SoftwareComponent-Liste fuers Matching."""
        components: list[SoftwareComponent] = []

        for os_entry in stack.operating_systems:
            if os_entry.name:
                components.append(
                    SoftwareComponent(os_entry.name, os_entry.version, "OS")
                )

        for browser in stack.browsers:
            if browser.name:
                components.append(
                    SoftwareComponent(browser.name, browser.version, "Browser")
                )

        if stack.antivirus.name:
            components.append(SoftwareComponent(stack.antivirus.name, "", "Antivirus"))

        if stack.firewall.name:
            components.append(SoftwareComponent(stack.firewall.name, "", "Firewall"))

        if stack.vpn:
            components.append(SoftwareComponent(stack.vpn, "", "VPN"))

        for ra in stack.remote_access:
            if ra:
                components.append(SoftwareComponent(ra, "", "Remote Access"))

        for sw in stack.custom_software:
            if sw:
                components.append(SoftwareComponent(sw, "", "Software"))

        return components

    def _update_btn_state(self) -> None:
        """Aktiviert Delete-Button nur fuer Kundensysteme (nicht eigenes)."""
        from tools.security_scoring.domain.tech_stack.enums import (
            SystemType,  # noqa: PLC0415
        )

        idx = self._combo_system.currentIndex()
        is_own = False
        if 0 <= idx < len(self._profiles):
            is_own = self._profiles[idx].system_type == SystemType.EIGENES
        self._btn_delete_system.setEnabled(not is_own)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @Slot(int)
    def _on_system_changed(self, index: int) -> None:
        """Reagiert auf System-Wechsel, berechnet Matching neu, emittiert Signal."""
        if index < 0 or index >= len(self._profiles):
            self._inventory = []
            return

        profile = self._profiles[index]
        self._inventory = self._techstack_to_components(profile.tech_stack)

        if self._inventory:
            self._service.run_matching(self._inventory)
        self._update_btn_state()
        self.inventory_changed.emit()

    @Slot()
    def _on_delete_system(self) -> None:
        """Loescht das aktuell ausgewaehlte Kundensystem nach Bestaetigung."""
        from core.dialogs import FinlaiConfirmDialog  # noqa: PLC0415

        idx = self._combo_system.currentIndex()
        if idx < 0 or idx >= len(self._profiles):
            return
        profile = self._profiles[idx]

        dlg = FinlaiConfirmDialog(
            title="Kundensystem löschen",
            message=(
                f'Kundensystem "{profile.name}" und alle Matching-Daten löschen?\n'
                "Dieser Vorgang kann nicht rückgängig gemacht werden."
            ),
            confirm_text="Löschen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        if self._profile_use_case is None:
            return
        self._profile_use_case.delete_customer_profile(profile.id)
        self._load_profiles()

    @Slot()
    def _on_edit_system(self) -> None:
        """Oeffnet TechStackDialog fuer das aktuell gewaehlte Profil."""
        idx = self._combo_system.currentIndex()
        if idx < 0 or idx >= len(self._profiles):
            return
        profile = self._profiles[idx]

        dialog = TechStackDialog(profile.name, initial=profile.tech_stack, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        if self._profile_use_case is None:
            return

        profile.tech_stack = dialog.get_tech_stack()
        self._profile_use_case.update_profile(profile)

        self._inventory = self._techstack_to_components(profile.tech_stack)
        if self._inventory:
            self._service.run_matching(self._inventory)
        self.inventory_changed.emit()

    @Slot()
    def _on_add_customer_system(self) -> None:
        """Oeffnet AddCustomerSystemDialog, danach optional TechStackDialog."""
        dialog = AddCustomerSystemDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        name, description = dialog.get_values()
        if not name:
            return

        if self._profile_use_case is None:
            return

        new_profile = self._profile_use_case.create_customer_profile(
            name=name, description=description
        )
        self._load_profiles()

        # Nach Anlegen direkt Tech-Stack-Dialog oeffnen
        stack_dialog = TechStackDialog(name, parent=self)
        if stack_dialog.exec() == QDialog.DialogCode.Accepted:
            new_profile.tech_stack = stack_dialog.get_tech_stack()
            self._profile_use_case.update_profile(new_profile)
            self._inventory = self._techstack_to_components(new_profile.tech_stack)
            if self._inventory:
                self._service.run_matching(self._inventory)
            self.inventory_changed.emit()

        # Neu erstelltes System im Selector waehlen
        for i, p in enumerate(self._profiles):
            if p.id == new_profile.id:
                self._combo_system.setCurrentIndex(i)
                break

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _btn_style() -> str:
        t = theme.get()
        return (
            f"QPushButton {{ background-color: {t.BG_BUTTON}; color: {t.TEXT_MAIN};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px;"
            f" padding: 5px 12px; font-size: 12px; }}"
            f"QPushButton:hover {{ background-color: {t.ACCENT}; color: {t.BG_MAIN}; }}"
        )
