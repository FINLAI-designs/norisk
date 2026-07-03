"""
avv_perspective_tabs — AVV-Tracker mit Lieferanten- und Kunden-Bereich.

Der AVV-Tracker ist das Herzstueck des Supply-Chain-Monitors (Position 1). Zwei
klar getrennte Sub-Tabs (Patrick-Entscheid 2026-06-30):

- **Lieferanten** — wir sind Kunde: oben die Lieferanten-Verwaltung
  (:class:`VendorManagementView`), darunter deren AVVs (:class:`AvvTabView`).
- **Kunden** — wir sind Auftragsverarbeiter: oben die Kunden-Verwaltung
  (:class:`CustomerManagementView`, Subject/KUNDE), darunter deren AVVs
  (:class:`CustomerAvvTabView`). LAZY beim ersten Anzeigen gebaut.

Innerhalb jedes Bereichs sind Verwaltung + AVVs in einem vertikalen, ziehbaren
:class:`QSplitter` gestapelt (beides gleichzeitig sichtbar).

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

Author: Patrick Riederich
Version: 0.2 (IA-Umbau, 2026-06-30)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QSplitter, QTabWidget, QVBoxLayout, QWidget

from core.security_subject.ports import SubjectStore
from core.security_subject.resolver import create_subject_store
from tools.supply_chain_monitor.application.avv_service import AvvService
from tools.supply_chain_monitor.application.customer_avv_service import (
    CustomerAvvService,
)
from tools.supply_chain_monitor.application.offboarding_service import (
    OffBoardingService,
)
from tools.supply_chain_monitor.application.patch_monitor_linker import (
    PatchMonitorLinker,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.gui.avv_tab_view import AvvTabView
from tools.supply_chain_monitor.gui.customer_avv_tab_view import CustomerAvvTabView
from tools.supply_chain_monitor.gui.customer_management_view import (
    CustomerManagementView,
)
from tools.supply_chain_monitor.gui.vendor_management_view import VendorManagementView

_LIEFERANTEN_LABEL = "Lieferanten"
_KUNDEN_LABEL = "Kunden"


class AvvPerspectiveTabs(QWidget):
    """AVV-Tracker mit Lieferanten- + Kunden-Bereich (je Verwaltung + AVVs).

    Signals:
        avv_changed: weitergereicht von beiden Perspektiven (loest u. a. den
            Vendor-Reload im umgebenden Supply-Chain-Widget aus).
    """

    avv_changed = Signal()

    def __init__(
        self,
        *,
        vendor_service: VendorService | None = None,
        avv_service: AvvService | None = None,
        customer_avv_service: CustomerAvvService | None = None,
        subject_store: SubjectStore | None = None,
        patch_linker: PatchMonitorLinker | None = None,
        offboarding_service: OffBoardingService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._vendor_service = vendor_service or VendorService()
        self._avv_service = avv_service
        self._customer_avv_service = customer_avv_service
        self._subject_store = subject_store
        self._patch_linker = patch_linker
        self._offboarding_service = offboarding_service
        self._vendor_mgmt: VendorManagementView | None = None
        self._customer_built = False
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._tabs = QTabWidget()

        # Lieferanten-Bereich (eager): Verwaltung oben + AVVs unten.
        self._tabs.addTab(self._build_lieferanten_area(), _LIEFERANTEN_LABEL)

        # Kunden-Bereich (lazy): Platzhalter, erst beim ersten Anzeigen gebaut.
        self._customer_host = QWidget()
        self._customer_host_layout = QVBoxLayout(self._customer_host)
        self._customer_host_layout.setContentsMargins(0, 0, 0, 0)
        self._tabs.addTab(self._customer_host, _KUNDEN_LABEL)

        self._tabs.currentChanged.connect(self._ensure_customer_built)
        layout.addWidget(self._tabs)

    def _build_lieferanten_area(self) -> QWidget:
        splitter = QSplitter(Qt.Orientation.Vertical)

        self._vendor_mgmt = VendorManagementView(
            vendor_service=self._vendor_service,
            patch_linker=self._patch_linker,
            offboarding_service=self._offboarding_service,
        )
        self._supplier_avv = AvvTabView(
            vendor_service=self._vendor_service,
            avv_service=self._avv_service,
        )
        # Neuer/geaenderter Lieferant -> AVV-Sicht aktualisiert ihre Namens-Map.
        self._vendor_mgmt.vendors_changed.connect(self._supplier_avv._reload)
        # AVV-Aenderung weiterreichen (Vendor-Reload im umgebenden Widget).
        self._supplier_avv.avv_changed.connect(self.avv_changed)

        splitter.addWidget(self._vendor_mgmt)
        splitter.addWidget(self._supplier_avv)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        return splitter

    def _ensure_customer_built(self, index: int) -> None:
        """Baut den Kunden-Bereich beim ersten Anzeigen (lazy)."""
        if self._customer_built:
            return
        if index != self._tabs.indexOf(self._customer_host):
            return
        self._customer_built = True
        # Store einmal aufloesen und an Verwaltung + AVV-Sicht durchreichen
        # (eine security_scoring-DB-Verbindung, fail-soft None).
        store = self._subject_store or create_subject_store()

        splitter = QSplitter(Qt.Orientation.Vertical)
        self._customer_mgmt = CustomerManagementView(subject_store=store)
        self._customer_avv = CustomerAvvTabView(
            customer_avv_service=self._customer_avv_service,
            subject_store=store,
        )
        # Neuer/geaenderter Kunde -> AVV-Sicht aktualisiert Namens-Map + Picker.
        self._customer_mgmt.customers_changed.connect(self._customer_avv._reload)
        self._customer_avv.avv_changed.connect(self.avv_changed)

        splitter.addWidget(self._customer_mgmt)
        splitter.addWidget(self._customer_avv)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        self._customer_host_layout.addWidget(splitter)

    def reload_suppliers(self) -> None:
        """Laedt die Lieferanten-Verwaltung neu (z. B. nach Auto-Detection)."""
        if self._vendor_mgmt is not None:
            self._vendor_mgmt.reload()
