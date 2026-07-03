"""
advisory_tree_panel — Advisory-Liste als QTreeWidget fuer den CSAF Advisory-Monitor.

Sprint 6 Phase 2c: Dritter Panel-Extract aus dem
``CsafAdvisorWidget``-God-Class-Refactor. Zeigt eine bereits gefilterte
Advisory-Liste mit Severity-Farbe + optionalem MATCH-Badge.

Trennung: Das Panel UEBERNIMMT KEINE Filterung -- die passiert im
Hauptwidget anhand des FilterPanel-States. Das Panel zeigt nur an,
was es ueber ``show_advisories`` bekommt.

Public API:
    show_advisories(advisories, matches_by_id) -- Tree leeren + neu fuellen
    get_visible_advisory_ids -> list[str] -- fuer Export
    clear

Signal:
    advisory_selected(str) -- Advisory-ID des neu selektierten Items.
                              Leerer String wenn Selection cleared.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem, QWidget

from core import theme
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch
from tools.csaf_advisor.gui.severity_helpers import sev_color, sev_label


class AdvisoryTreePanel(QTreeWidget):
    """Tabellarische Anzeige fuer CSAF-Advisories mit 4 Spalten.

    Spalten: Advisory-Titel (mit MATCH-Badge), Schweregrad,
    CVSS-Score, Veroeffentlichungsdatum.
    """

    advisory_selected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert den Tree mit Header-Konfiguration und Styling.

        Args:
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._build_ui()
        self.currentItemChanged.connect(self._on_current_item_changed)

    def _build_ui(self) -> None:
        """Header-Labels, Spalten-Breiten und Styling setzen."""
        t = theme.get()
        self.setHeaderLabels(["Advisory", "Schweregrad", "CVSS", "Veröffentlicht"])
        self.setColumnWidth(0, 420)
        self.setColumnWidth(1, 90)
        self.setColumnWidth(2, 60)
        self.setColumnWidth(3, 120)
        self.setAlternatingRowColors(True)
        self.setRootIsDecorated(False)
        self.setStyleSheet(
            f"""
            QTreeWidget {{
                background-color: {t.CARD_BG};
                color: {t.TEXT_MAIN};
                border: 1px solid {t.BORDER};
                border-radius: 4px;
                font-size: 13px;
            }}
            QTreeWidget::item {{
                padding: 3px 4px;
            }}
            QTreeWidget::item:selected {{
                background-color: {t.ACCENT};
                color: {t.BG_MAIN};
            }}
            QHeaderView::section {{
                background-color: {t.BG_DARK};
                color: {t.TEXT_MAIN};
                border: 1px solid {t.BORDER};
                padding: 4px;
                font-size: 12px;
            }}
            """
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def show_advisories(
        self,
        advisories: list[CsafAdvisory],
        matches_by_id: dict[str, AdvisoryMatch],
    ) -> None:
        """Leert den Tree und fuellt ihn mit den uebergebenen Advisories.

        Args:
            advisories: Bereits gefilterte Advisory-Liste.
            matches_by_id: Advisory-ID -> AdvisoryMatch, fuer das
                           MATCH-Badge in der ersten Spalte.
        """
        self.clear()
        for advisory in advisories:
            has_match = advisory.id in matches_by_id
            item = self._make_advisory_item(advisory, has_match)
            self.addTopLevelItem(item)

    def get_visible_advisory_ids(self) -> list[str]:
        """Gibt die IDs aller aktuell angezeigten Advisories zurueck.

        Wird vom Hauptwidget fuer Export-Funktionen genutzt -- der
        Caller muss die IDs selbst zu Advisory-Objekten aufloesen.
        """
        ids: list[str] = []
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if item is None:
                continue
            advisory_id = item.data(0, Qt.ItemDataRole.UserRole)
            if advisory_id:
                ids.append(str(advisory_id))
        return ids

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _make_advisory_item(
        advisory: CsafAdvisory, has_match: bool
    ) -> QTreeWidgetItem:
        """Erstellt einen QTreeWidgetItem fuer ein Advisory.

        Args:
            advisory: Das Advisory.
            has_match: True wenn ein Treffer im Software-Inventar vorliegt.

        Returns:
            Konfigurierter QTreeWidgetItem mit Severity-Farbe.
        """
        match_badge = " [MATCH]" if has_match else ""
        title = f"{advisory.tracking_id}{match_badge}  —  {advisory.title}"

        cvss_text = (
            f"{advisory.cvss_score:.1f}" if advisory.cvss_score is not None else "—"
        )

        item = QTreeWidgetItem(
            [
                title,
                sev_label(advisory.severity),
                cvss_text,
                advisory.current_release or advisory.initial_release or "—",
            ]
        )

        color = QColor(sev_color(advisory.severity))
        for col in range(4):
            item.setForeground(col, color)

        item.setData(0, Qt.ItemDataRole.UserRole, advisory.id)
        item.setToolTip(0, advisory.summary[:200] if advisory.summary else "")

        return item

    @Slot(object, object)
    def _on_current_item_changed(
        self,
        current: QTreeWidgetItem | None,
        _previous: QTreeWidgetItem | None,
    ) -> None:
        """Translatiert Qt-Selection-Change in advisory_selected-Signal.

        Args:
            current: Neu ausgewaehltes Item.
            _previous: Vorheriges Item (ignoriert).
        """
        if current is None:
            self.advisory_selected.emit("")
            return
        advisory_id = current.data(0, Qt.ItemDataRole.UserRole)
        self.advisory_selected.emit(str(advisory_id) if advisory_id else "")
