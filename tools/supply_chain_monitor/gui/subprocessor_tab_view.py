"""
subprocessor_tab_view — Sub-Auftragnehmer-Tab im Supply-Chain-Monitor.

Iter 2c-ii:

- Liste aller Sub-Auftragnehmer mit Add/Edit/Delete.
- Konzentrationsrisiko-Spalte (Anzahl Vendoren, die diesen Sub nutzen).
- Per-Vendor-Linking ueber separaten Dialog (oeffnet ueber den
  "Verknuepfungen verwalten..."-Button).

Schichtzugehoerigkeit: gui/ — darf application + core importieren.

Author: Patrick Riederich
Version: 0.1-ii, 2026-05-15)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog
from core.icons import Icons
from core.logger import get_logger
from core.security_subject.models import SubjectKind
from core.security_subject.ports import SubjectStore
from tools.supply_chain_monitor.application.subprocessor_service import (
    ConcentrationFinding,
    SubprocessorService,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.domain.models import (
    Subprocessor,
    Vendor,
)
from tools.supply_chain_monitor.gui._tab_style import (
    supply_chain_tab_stylesheet,
)
from tools.supply_chain_monitor.gui.subprocessor_form_dialog import (
    SubprocessorFormDialog,
)

_log = get_logger(__name__)

_HEADERS: list[str] = ["Name", "Land", "Kategorie", "Genutzt von (Vendoren)"]


class SubprocessorTabView(QWidget):
    """Sub-Auftragnehmer-Tab — Sub-Catalog + Vendor-Linking + Konzentrationsrisiko.

    Signals:
        subprocessor_changed: emittiert bei CRUD- oder Link-Operationen.
    """

    subprocessor_changed = Signal()

    def __init__(
        self,
        *,
        subprocessor_service: SubprocessorService | None = None,
        vendor_service: VendorService | None = None,
        subject_store: SubjectStore | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = subprocessor_service or SubprocessorService()
        self._vendor_service = vendor_service or VendorService()
        # H (Live-Test 2026-07-01): Kunden-Identitaet ueber den core
        # SubjectStore-Port (Cross-DB). Lazy — erst beim Oeffnen des
        # Verknuepfungs-Dialogs aufgeloest, damit die Tab-Konstruktion keinen
        # Cross-DB-Seitenwurf hat.
        self._subject_store = subject_store
        self._build_ui()
        self._reload()

    def _build_ui(self) -> None:
        self.setStyleSheet(supply_chain_tab_stylesheet())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        title = QLabel("Sub-Auftragnehmer")
        title.setObjectName("SupplyChainSectionTitle")
        layout.addWidget(title)

        info = QLabel(
            "Sub-Auftragnehmer (Subprocessors) sind Drittparteien, die fuer "
            "deine Vendoren Daten verarbeiten — z. B. AWS unter Microsoft 365, "
            "T-Systems unter Google Workspace. Konzentrationsrisiko: wenn "
            "viele Vendoren denselben Sub nutzen, ist ein Ausfall dieses "
            "Subs ein Sammelausfall."
        )
        info.setWordWrap(True)
        info.setObjectName("SubprocessorTabInfo")
        layout.addWidget(info)

        # Concentration-Banner als Card statt nackter Label.
        self._concentration_card = QFrame()
        self._concentration_card.setObjectName("SubprocessorConcentrationCard")
        card_layout = QVBoxLayout(self._concentration_card)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(2)
        card_title = QLabel("Konzentrationsrisiko")
        card_title.setObjectName("SupplyChainCardTitle")
        card_layout.addWidget(card_title)
        self._concentration_banner = QLabel()
        self._concentration_banner.setWordWrap(True)
        self._concentration_banner.setObjectName("SubprocessorConcentrationBanner")
        card_layout.addWidget(self._concentration_banner)
        layout.addWidget(self._concentration_card)

        # Buttons
        row = QHBoxLayout()
        self._add_btn = QPushButton("Sub hinzufuegen ...")
        self._add_btn.clicked.connect(self._on_add)
        row.addWidget(self._add_btn)

        self._edit_btn = QPushButton("Bearbeiten")
        self._edit_btn.setEnabled(False)
        self._edit_btn.clicked.connect(self._on_edit)
        row.addWidget(self._edit_btn)

        self._link_btn = QPushButton("Verknuepfungen verwalten ...")
        self._link_btn.setEnabled(False)
        self._link_btn.clicked.connect(self._on_manage_links)
        row.addWidget(self._link_btn)

        self._delete_btn = QPushButton("Loeschen")
        self._delete_btn.setEnabled(False)
        self._delete_btn.clicked.connect(self._on_delete)
        row.addWidget(self._delete_btn)
        row.addStretch(1)
        layout.addLayout(row)

        # Tabelle
        self._table = QTableWidget(0, len(_HEADERS))
        self._table.setHorizontalHeaderLabels(_HEADERS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table, stretch=1)

        self._empty_hint = QLabel(
            "Noch keine Sub-Auftragnehmer erfasst. 'Sub hinzufuegen ...' "
            "fuegt einen ersten Eintrag hinzu."
        )
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_hint.setObjectName("SubprocessorEmptyHint")
        layout.addWidget(self._empty_hint)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_add(self) -> None:
        dialog = SubprocessorFormDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            sub = dialog.collected()
            self._service.add_subprocessor(
                name=sub.name,
                country=sub.country,
                category=sub.category,
                notes=sub.notes,
            )
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eintrag abgelehnt",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload()
        self.subprocessor_changed.emit()

    def _on_edit(self) -> None:
        sub = self._selected_sub()
        if sub is None:
            return
        dialog = SubprocessorFormDialog(parent=self, subprocessor=sub)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            updated = dialog.collected()
            self._service.update_subprocessor(updated)
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Update fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload()
        self.subprocessor_changed.emit()

    def _on_delete(self) -> None:
        sub = self._selected_sub()
        if sub is None or sub.id is None:
            return
        link_count = len(self._service.links_for_subprocessor(sub.id))
        question = (
            f"Sub-Auftragnehmer '{sub.name}' wirklich loeschen?"
            + (
                f"\n\nAchtung: {link_count} Vendor-Verknuepfung(en) werden "
                "ebenfalls entfernt."
                if link_count
                else ""
            )
        )
        dlg = FinlaiConfirmDialog(
            title="Sub-Auftragnehmer loeschen",
            message=question,
            confirm_text="Loeschen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._service.delete_subprocessor(sub.id)
        self._reload()
        self.subprocessor_changed.emit()

    def _on_manage_links(self) -> None:
        sub = self._selected_sub()
        if sub is None or sub.id is None:
            return
        vendors = self._vendor_service.list_vendors()
        customers = self._load_customers()
        dialog = _LinkManagementDialog(
            parent=self,
            subprocessor=sub,
            vendors=vendors,
            customers=customers,
            service=self._service,
        )
        dialog.exec()
        self._reload()
        self.subprocessor_changed.emit()

    def _load_customers(self) -> list[tuple[str, str]]:
        """Laedt die Kunden (Subject/kind=KUNDE) fail-soft ueber den SubjectStore.

        Cross-DB-Port; bei Fehler leere Liste — dann ist im Verknuepfungs-Dialog
        nur die Lieferanten-Perspektive verfuegbar (kein Crash).

        Returns:
            Liste von ``(subject_id, name)``-Tupeln der Kunden.
        """
        store = self._subject_store
        if store is None:
            from core.security_subject.resolver import (  # noqa: PLC0415
                create_subject_store,
            )

            try:
                store = create_subject_store()
            except Exception as exc:  # noqa: BLE001 — fail-soft (nur Lieferanten)
                _log.debug(
                    "SubjectStore nicht verfuegbar (%s)", type(exc).__name__
                )
                return []
            self._subject_store = store
        try:
            return [
                (s.subject_id, s.name)
                for s in store.list_all()
                if s.kind is SubjectKind.KUNDE
            ]
        except Exception as exc:  # noqa: BLE001 — fail-soft (nur Lieferanten)
            _log.debug("Kunden-Liste nicht ladbar (%s)", type(exc).__name__)
            return []

    def _on_selection_changed(self) -> None:
        has_selection = bool(self._table.selectionModel().selectedRows())
        self._edit_btn.setEnabled(has_selection)
        self._delete_btn.setEnabled(has_selection)
        self._link_btn.setEnabled(has_selection)

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------

    def _reload(self) -> None:
        subs = self._service.list_subprocessors()
        self._subs: list[Subprocessor] = subs
        findings: dict[int, ConcentrationFinding] = {
            f.subprocessor.id: f
            for f in self._service.concentration_findings()
            if f.subprocessor.id is not None
        }

        self._table.setRowCount(len(subs))
        for row, sub in enumerate(subs):
            self._set_row(row, sub, findings.get(sub.id) if sub.id is not None else None)

        self._empty_hint.setVisible(len(subs) == 0)
        self._table.setVisible(len(subs) > 0)
        self._table.clearSelection()
        self._edit_btn.setEnabled(False)
        self._delete_btn.setEnabled(False)
        self._link_btn.setEnabled(False)

        # Konzentrations-Banner
        concentrated = [f for f in findings.values() if f.is_concentrated]
        if concentrated:
            text = "Konzentrationsrisiko: " + ", ".join(
                f"{f.subprocessor.name} ({f.vendor_count})"
                for f in concentrated[:5]
            )
            if len(concentrated) > 5:
                text += f", +{len(concentrated) - 5} weitere"
            self._concentration_banner.setText(text)
        elif findings:
            self._concentration_banner.setText(
                "Kein Konzentrationsrisiko — kein Sub wird von 3 oder mehr "
                "Vendoren genutzt."
            )
        else:
            self._concentration_banner.setText(
                "Noch keine Vendor-Verknuepfungen — Konzentrationsrisiko nicht "
                "berechenbar."
            )

    def _set_row(
        self,
        row: int,
        sub: Subprocessor,
        finding: ConcentrationFinding | None,
    ) -> None:
        name_item = QTableWidgetItem(sub.name)
        name_item.setData(Qt.ItemDataRole.UserRole, sub.id)
        self._table.setItem(row, 0, name_item)
        self._table.setItem(row, 1, QTableWidgetItem(sub.country))
        self._table.setItem(
            row, 2, QTableWidgetItem(sub.category.value.replace("_", " ").title())
        )
        count = finding.vendor_count if finding else 0
        usage_item = QTableWidgetItem(str(count))
        usage_item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        self._table.setItem(row, 3, usage_item)

    def _selected_sub(self) -> Subprocessor | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        idx = rows[0].row()
        if 0 <= idx < len(self._subs):
            return self._subs[idx]
        return None


# ---------------------------------------------------------------------------
# Link-Management-Dialog (modal, pro Sub)
# ---------------------------------------------------------------------------


class _LinkManagementDialog(QDialog):
    """Modaler Dialog: Verknuepfungen eines Subprocessors mit Vendoren."""

    def __init__(
        self,
        *,
        subprocessor: Subprocessor,
        vendors: list[Vendor],
        customers: list[tuple[str, str]],
        service: SubprocessorService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if subprocessor.id is None:
            raise ValueError(
                "_LinkManagementDialog braucht einen persistierten Subprocessor."
            )
        self._sub = subprocessor
        self._vendors = vendors
        # H: Kunden als (subject_id, name)-Tupel — Cross-DB-Soft-FK, Namen
        # bereits ueber den SubjectStore-Port aufgeloest (kein N+1).
        self._customers = customers
        self._service = service
        self.setWindowTitle(f"Verknuepfungen — {subprocessor.name}")
        self.setMinimumSize(560, 380)
        self._build_ui()
        self._reload()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        info = QLabel(
            f"Verknuepfungen von '{self._sub.name}' mit Lieferanten und Kunden. "
            "Pro Verknuepfung eine Rolle (z. B. 'Storage', 'CDN', "
            "'Email-Versand')."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # Tabelle: Typ (Lieferant/Kunde) / Partner / Rolle
        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Typ", "Partner", "Rolle"])
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        layout.addWidget(self._table, stretch=1)

        # Buttons
        row = QHBoxLayout()
        self._add_btn = QPushButton("Verknuepfung anlegen ...")
        self._add_btn.clicked.connect(self._on_add_link)
        row.addWidget(self._add_btn)

        self._remove_btn = QPushButton("Verknuepfung entfernen")
        self._remove_btn.setEnabled(False)
        self._remove_btn.clicked.connect(self._on_remove_link)
        row.addWidget(self._remove_btn)

        row.addStretch(1)
        layout.addLayout(row)

        self._table.itemSelectionChanged.connect(self._on_selection_changed)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("Schliessen")
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _reload(self) -> None:
        # ``__init__`` garantiert dass self._sub.id gesetzt ist — explizite
        # Check fuer Bandit/mypy.
        sub_id = self._sub.id
        if sub_id is None:
            return
        vendor_links = self._service.links_for_subprocessor(sub_id)
        customer_links = self._service.customer_links_for_subprocessor(sub_id)
        vendor_map = {v.id: v.name for v in self._vendors if v.id is not None}
        customer_map = dict(self._customers)  # subject_id -> name

        self._table.setRowCount(len(vendor_links) + len(customer_links))
        row = 0
        for link in vendor_links:
            name = vendor_map.get(link.vendor_id, f"Vendor #{link.vendor_id}")
            # UserRole traegt (kind, link_id) — steuert das richtige Unlink.
            self._set_link_row(row, "Lieferant", name, link.role, ("vendor", link.id))
            row += 1
        for clink in customer_links:
            name = customer_map.get(clink.subject_id, "(unbekannter Kunde)")
            self._set_link_row(row, "Kunde", name, clink.role, ("customer", clink.id))
            row += 1
        self._table.clearSelection()
        self._remove_btn.setEnabled(False)

    def _set_link_row(
        self, row: int, typ: str, partner: str, role: str, meta: tuple[str, int | None]
    ) -> None:
        typ_item = QTableWidgetItem(typ)
        typ_item.setData(Qt.ItemDataRole.UserRole, meta)
        self._table.setItem(row, 0, typ_item)
        self._table.setItem(row, 1, QTableWidgetItem(partner))
        self._table.setItem(row, 2, QTableWidgetItem(role or "-"))

    def _on_selection_changed(self) -> None:
        has_selection = bool(self._table.selectionModel().selectedRows())
        self._remove_btn.setEnabled(has_selection)

    def _on_add_link(self) -> None:
        if not self._vendors and not self._customers:
            FinlaiInfoDialog(
                title="Keine Partner",
                message=(
                    "Legen Sie zuerst einen Lieferanten (Vendoren/AVV-Tracker) "
                    "oder einen Kunden (AVV-Tracker) an."
                ),
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        dialog = _AddLinkDialog(
            parent=self, vendors=self._vendors, customers=self._customers
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        perspective = dialog.selected_perspective()
        party_ref = dialog.selected_party_ref()
        role = dialog.selected_role()
        if party_ref is None or self._sub.id is None:
            return
        if perspective == "customer":
            self._service.link_customer(
                subject_id=str(party_ref), subprocessor_id=self._sub.id, role=role
            )
        else:
            self._service.link(
                vendor_id=int(party_ref), subprocessor_id=self._sub.id, role=role
            )
        self._reload()

    def _on_remove_link(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        item = self._table.item(rows[0].row(), 0)
        if item is None:
            return
        meta = item.data(Qt.ItemDataRole.UserRole)
        if not (isinstance(meta, tuple) and len(meta) == 2):
            return
        kind, link_id = meta
        if not isinstance(link_id, int):
            return
        if kind == "customer":
            self._service.unlink_customer(link_id)
        else:
            self._service.unlink(link_id)
        self._reload()


class _AddLinkDialog(QDialog):
    """Mini-Dialog fuer eine neue Verknuepfung: Partner-Typ + Partner + Rolle.

    Der Partner-Typ (Lieferant/Kunde) waehlt, ob die Partner-Auswahl aus den
    Vendoren (Lieferanten) oder aus den Kunden (Subject/kind=KUNDE) befuellt
    wird (H, Live-Test 2026-07-01). Nur Typen mit vorhandenen Partnern werden
    angeboten.
    """

    def __init__(
        self,
        *,
        vendors: list[Vendor],
        customers: list[tuple[str, str]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._vendors = vendors
        self._customers = customers
        self.setWindowTitle("Verknuepfung anlegen")
        self.setMinimumWidth(360)
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._perspective_combo = QComboBox()
        if vendors:
            self._perspective_combo.addItem("Lieferant", "vendor")
        if customers:
            self._perspective_combo.addItem("Kunde", "customer")
        self._perspective_combo.currentIndexChanged.connect(self._fill_party_combo)
        form.addRow("Partner-Typ", self._perspective_combo)

        self._party_combo = QComboBox()
        form.addRow("Partner", self._party_combo)

        self._role_input = QLineEdit()
        self._role_input.setPlaceholderText("z. B. Storage, CDN, Email-Versand")
        form.addRow("Rolle", self._role_input)

        layout.addLayout(form)

        # Hinweis zu Idempotenz
        hint = QLabel(
            "<i>Hinweis: Identische Verknuepfungen (gleicher Partner + gleiche "
            "Rolle) werden nicht dupliziert.</i>"
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("OK")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Abbrechen")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._fill_party_combo()

    def _fill_party_combo(self) -> None:
        """Befuellt die Partner-Auswahl passend zum gewaehlten Partner-Typ."""
        self._party_combo.clear()
        if self._perspective_combo.currentData() == "customer":
            for subject_id, name in self._customers:
                self._party_combo.addItem(name, subject_id)
        else:
            for v in self._vendors:
                self._party_combo.addItem(v.name, v.id)

    def selected_perspective(self) -> str:
        """``"vendor"`` (Lieferant) oder ``"customer"`` (Kunde)."""
        return str(self._perspective_combo.currentData() or "vendor")

    def selected_party_ref(self) -> int | str | None:
        """Vendor-ID (int) bei Lieferant, subject_id (str) bei Kunde, sonst None."""
        return self._party_combo.currentData()

    def selected_role(self) -> str:
        return self._role_input.text().strip()


# silence ruff for unused QInputDialog (we keep import for symmetry, may
# evolve to inline role prompt later if needed)
_ = QInputDialog
