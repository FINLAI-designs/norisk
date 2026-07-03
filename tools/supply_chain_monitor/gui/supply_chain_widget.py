"""
supply_chain_widget — Hauptansicht des Supply-Chain-Monitors.

IA-Umbau 2026-06-30 (Patrick): Der AVV-Tracker ist Position 1 und vereint die
Geschaeftspartner-Verwaltung — getrennt nach **Lieferanten** (wir sind Kunde)
und **Kunden** (wir sind Auftragsverarbeiter), je mit Partner-Verwaltung oben und
AVVs darunter. Die fruehere eigenstaendige 'Vendoren'-Startseite ist entfallen
(ihre Verwaltung lebt jetzt im Lieferanten-Bereich).

Tabs:
- **AVV-Tracker** (Position 1) —:class:`AvvPerspectiveTabs` (Lieferanten/Kunden).
- **Auto-Detection** — Vendor-Vorschlaege aus Installed-Apps/MX/Cert.
- **Sub-Auftragnehmer** — Konzentrationsrisiko.
- **Reports** — Compliance-Report (NIST/BSI).

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

Author: Patrick Riederich
Version: 0.2 (IA-Umbau, 2026-06-30)
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QLabel,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.logger import get_logger
from tools.supply_chain_monitor.application.avv_service import AvvService
from tools.supply_chain_monitor.application.catalog_seeder import CatalogSeeder
from tools.supply_chain_monitor.application.compliance_assessor import (
    ComplianceAssessor,
)
from tools.supply_chain_monitor.application.customer_avv_service import (
    CustomerAvvService,
)
from tools.supply_chain_monitor.application.detection_service import DetectionService
from tools.supply_chain_monitor.application.offboarding_service import (
    OffBoardingService,
)
from tools.supply_chain_monitor.application.patch_monitor_linker import (
    PatchMonitorLinker,
)
from tools.supply_chain_monitor.application.subprocessor_service import (
    SubprocessorService,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.gui.auto_detection_view import AutoDetectionView
from tools.supply_chain_monitor.gui.avv_perspective_tabs import AvvPerspectiveTabs
from tools.supply_chain_monitor.gui.reports_tab_view import ReportsTabView
from tools.supply_chain_monitor.gui.subprocessor_tab_view import SubprocessorTabView
from tools.supply_chain_monitor.gui.widgets.vendor_risk_heatmap import (
    VendorRiskHeatmap,
)

_log = get_logger(__name__)

_INFO_TEXT = (
    "Verwalten Sie hier Ihre Geschaeftspartner und deren Auftragsverarbeitungs-"
    "vertraege (AVV, DSGVO Art. 28). Der AVV-Tracker trennt klar nach "
    "Lieferanten (wir sind Kunde) und Kunden (wir sind Auftragsverarbeiter). "
    "Das Partner-Inventar ist die Basis fuer die NIS2-Supply-Chain-Anforderung "
    "Art. 21(2)(d)."
)


class SupplyChainWidget(QWidget):
    """Hauptansicht des Supply-Chain-Monitors."""

    def __init__(
        self,
        service: VendorService | None = None,
        *,
        detection_service: DetectionService | None = None,
        avv_service: AvvService | None = None,
        customer_avv_service: CustomerAvvService | None = None,
        subprocessor_service: SubprocessorService | None = None,
        offboarding_service: OffBoardingService | None = None,
        patch_monitor_linker: PatchMonitorLinker | None = None,
        compliance_assessor: ComplianceAssessor | None = None,
        catalog_seeder: CatalogSeeder | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service or VendorService()
        self._detection_service = detection_service or DetectionService()
        self._avv_service = avv_service or AvvService()
        # Kunden-AVV-Service: lazy — der Kunden-Bereich baut den Default
        # erst beim ersten Anzeigen (Perf/Cross-DB).
        self._customer_avv_service = customer_avv_service
        self._subprocessor_service = subprocessor_service or SubprocessorService()
        self._offboarding_service = offboarding_service or OffBoardingService()
        self._patch_linker = patch_monitor_linker or PatchMonitorLinker()
        self._compliance_assessor = compliance_assessor or ComplianceAssessor(
            vendor_service=self._service,
            avv_service=self._avv_service,
            subprocessor_service=self._subprocessor_service,
            offboarding_service=self._offboarding_service,
        )
        # Erst-Befuellung des Catalogs (idempotent; tut nichts wenn schon
        # befuellt). Einmalig beim ersten Tool-Oeffnen, damit der Tool-Import
        # keinen DB-Seitenwurf hat.
        seeder = catalog_seeder or CatalogSeeder()
        try:
            seeded = seeder.seed_if_empty()
            if seeded:
                _log.info("Supply-Chain-Catalog initialisiert (%d Eintraege).", seeded)
        except Exception:  # noqa: BLE001 — Seed-Fehler darf Tool-Start nicht blockieren
            _log.exception("Catalog-Seed fehlgeschlagen — Tool startet trotzdem.")
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        title = QLabel("Supply-Chain-Monitor")
        title.setObjectName("SupplyChainTitle")
        layout.addWidget(title)

        info = QLabel(_INFO_TEXT)
        info.setObjectName("SupplyChainInfo")
        info.setWordWrap(True)
        layout.addWidget(info)

        self._tabs = QTabWidget()

        # Position 1: AVV-Tracker (Lieferanten + Kunden, je Verwaltung + AVVs).
        self._avv_tab_view = AvvPerspectiveTabs(
            vendor_service=self._service,
            avv_service=self._avv_service,
            customer_avv_service=self._customer_avv_service,
            patch_linker=self._patch_linker,
            offboarding_service=self._offboarding_service,
        )
        self._tabs.addTab(self._avv_tab_view, "AVV-Tracker")

        # Auto-Detection: akzeptierte Vorschlaege -> Lieferanten-Verwaltung neu laden.
        self._auto_detection_view = AutoDetectionView(service=self._detection_service)
        self._auto_detection_view.vendor_accepted.connect(
            self._avv_tab_view.reload_suppliers
        )
        self._tabs.addTab(self._auto_detection_view, "Auto-Detection")

        self._subprocessor_tab_view = SubprocessorTabView(
            subprocessor_service=self._subprocessor_service,
            vendor_service=self._service,
        )
        self._tabs.addTab(self._subprocessor_tab_view, "Sub-Auftragnehmer")

        self._reports_tab_view = ReportsTabView(
            vendor_service=self._service,
            avv_service=self._avv_service,
            compliance_assessor=self._compliance_assessor,
        )
        self._tabs.addTab(self._reports_tab_view, "Reports")

        # Konzentrationsrisiko-Heatmap (Kritikalitaet x AVV-Health) — lazy
        # befuellt beim Anzeigen des Tabs, damit der Tool-Start keinen DB-Read hat.
        self._risk_heatmap = VendorRiskHeatmap()
        self._risk_tab_index = self._tabs.addTab(
            self._risk_heatmap, "Konzentrationsrisiko"
        )
        self._tabs.currentChanged.connect(self._on_tab_changed)

        layout.addWidget(self._tabs, stretch=1)

    def apply_navigation(self, *, focus: str | None = None, **_kwargs) -> None:
        """Deeplink-Ziel (Cockpit-Inc-2): ``focus='open'`` zeigt den AVV-Tracker
        (Position 1, Lieferanten-Bereich mit offenen/ueberfaelligen AVVs)."""
        if focus == "open" and getattr(self, "_tabs", None) is not None:
            self._tabs.setCurrentIndex(0)  # AVV-Tracker

    def _on_tab_changed(self, index: int) -> None:
        """Befuellt die Konzentrationsrisiko-Heatmap beim Anzeigen (immer frisch)."""
        if index == self._risk_tab_index:
            self._refresh_risk_heatmap()

    def _refresh_risk_heatmap(self) -> None:
        """Laedt Vendoren + AVVs und fuellt die Konzentrationsrisiko-Heatmap.

        Fail-safe: ein Fehler darf den Tab nicht crashen. Reload bei jedem
        Anzeigen -> reflektiert neu aufgenommene Lieferanten.
        """
        try:
            vendors = self._service.list_vendors()
            avvs_by_vendor = {
                v.id: self._avv_service.list_for_vendor(v.id)
                for v in vendors
                if v.id is not None
            }
            self._risk_heatmap.set_data(vendors, avvs_by_vendor)
        except Exception:  # noqa: BLE001 — Heatmap-Fehler darf das Tool nicht crashen
            _log.exception("Konzentrationsrisiko-Heatmap konnte nicht geladen werden.")
