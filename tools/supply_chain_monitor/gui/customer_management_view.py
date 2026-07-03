"""
customer_management_view — Kunden-Verwaltung (Subject/KUNDE / IA-Umbau).

Gegenstueck zu:class:`VendorManagementView` fuer den Kunden-Bereich: listet die
Kunden (``Subject``/kind=KUNDE) und erlaubt Anlegen/Bearbeiten/Loeschen ueber den
``SubjectStore``-Port. Kunde = dieselbe geteilte Identitaet wie Audit + Score
(subject_id) — kein zweites Kundenmodell (Patrick-Entscheid 2026-06-30).

Loeschen geht ueber ``delete_subject_if_unreferenced`` und ist fail-closed
geblockt, solange Audit/Score/AVV das Subjekt referenzieren E4).

Schichtzugehoerigkeit: gui/ — die Kunden-Identitaet kommt ausschliesslich ueber
den core ``SubjectStore``-Port.

Author: Patrick Riederich
Version: 0.1 (IA-Umbau, 2026-06-30)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog
from core.icons import Icons
from core.logger import get_logger
from core.security_subject.models import Subject, SubjectKind
from core.security_subject.ports import SubjectStore
from core.security_subject.resolver import create_subject_store
from tools.supply_chain_monitor.gui._tab_style import supply_chain_tab_stylesheet
from tools.supply_chain_monitor.gui.customer_form_dialog import CustomerFormDialog

_log = get_logger(__name__)

_HEADERS: list[str] = ["Firmenname", "Branche", "Groesse", "Ansprechpartner"]


class CustomerManagementView(QWidget):
    """Kunden-Inventar (Subjects, kind=KUNDE) mit Anlegen/Bearbeiten/Loeschen.

    Signals:
        customers_changed: emittiert, wenn ein Kunde angelegt/geaendert/geloescht
            wurde — die AVV-Sicht darunter kann ihre Namensaufloesung + den Picker
            aktualisieren.
    """

    customers_changed = Signal()

    def __init__(
        self,
        *,
        subject_store: SubjectStore | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = subject_store or create_subject_store()
        self._subjects: list[Subject] = []
        self._build_ui()
        self.reload()

    def _build_ui(self) -> None:
        self.setStyleSheet(supply_chain_tab_stylesheet())
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        title = QLabel("Kunden verwalten")
        title.setObjectName("SupplyChainSectionTitle")
        layout.addWidget(title)

        button_row = QHBoxLayout()
        self._add_btn = QPushButton("Kunde hinzufuegen")
        self._add_btn.setObjectName("SupplyChainAddButton")
        self._add_btn.clicked.connect(self._on_add_clicked)
        button_row.addWidget(self._add_btn)

        self._edit_btn = QPushButton("Bearbeiten")
        self._edit_btn.setObjectName("SupplyChainEditButton")
        self._edit_btn.setEnabled(False)
        self._edit_btn.clicked.connect(self._on_edit_clicked)
        button_row.addWidget(self._edit_btn)

        self._delete_btn = QPushButton("Loeschen")
        self._delete_btn.setObjectName("SupplyChainDeleteButton")
        self._delete_btn.setEnabled(False)
        self._delete_btn.clicked.connect(self._on_delete_clicked)
        button_row.addWidget(self._delete_btn)

        button_row.addStretch(1)
        layout.addLayout(button_row)

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
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table, stretch=1)

        self._empty_hint = QLabel(
            "Noch keine Kunden erfasst — legen Sie ueber den Button oben einen "
            "ersten Kunden an. Kunden sind dieselben wie in Security-Audit + Score."
        )
        self._empty_hint.setObjectName("SupplyChainEmptyHint")
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._empty_hint)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_add_clicked(self) -> None:
        if self._store is None:
            self._warn(
                "Kunden-Verwaltung nicht verfuegbar",
                "Die Kunden-Verwaltung ist derzeit nicht verfuegbar.",
            )
            return
        dialog = CustomerFormDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        values = dialog.collected_values()
        try:
            subject = self._store.find_or_create_client(values.name)
            self._store.update_stammdaten(
                subject.subject_id,
                branche=values.branche,
                groesse=values.groesse,
                contact=values.contact,
            )
        except Exception as exc:  # noqa: BLE001 — Cross-DB-Store-Grenze, fail-soft
            _log.exception("Kunde anlegen fehlgeschlagen")
            self._warn("Kunde konnte nicht angelegt werden", str(exc))
            return
        self.reload()
        self.customers_changed.emit()

    def _on_edit_clicked(self) -> None:
        subject = self._selected_subject()
        if subject is None or self._store is None:
            return
        dialog = CustomerFormDialog(
            parent=self,
            name=subject.name,
            branche=subject.branche,
            groesse=subject.groesse,
            contact=subject.contact,
            editing=True,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        values = dialog.collected_values()
        try:
            self._store.update_stammdaten(
                subject.subject_id,
                branche=values.branche,
                groesse=values.groesse,
                contact=values.contact,
            )
        except Exception as exc:  # noqa: BLE001 — Cross-DB-Store-Grenze, fail-soft
            _log.exception("Kunde bearbeiten fehlgeschlagen")
            self._warn("Aktualisierung fehlgeschlagen", str(exc))
            return
        self.reload()
        self.customers_changed.emit()

    def _on_delete_clicked(self) -> None:
        subject = self._selected_subject()
        if subject is None or self._store is None:
            return
        confirm = FinlaiConfirmDialog(
            title="Kunde loeschen",
            message=(
                f"Den Kunden '{subject.name}' wirklich loeschen?\n\n"
                "Das ist nur moeglich, wenn KEIN Audit, Score, AVV oder "
                "Subunternehmer-Verknuepfung mehr auf den Kunden verweist."
            ),
            confirm_text="Loeschen",
            parent=self,
        )
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            removed = self._store.delete_subject_if_unreferenced(subject.subject_id)
        except Exception as exc:  # noqa: BLE001 — Cross-DB-Store-Grenze, fail-soft
            _log.exception("Kunde loeschen fehlgeschlagen")
            self._warn("Loeschen fehlgeschlagen", str(exc))
            return
        if not removed:
            self._warn(
                "Kunde kann nicht geloescht werden",
                "Der Kunde wird noch referenziert (Audit, Score, ein "
                "aufbewahrungspflichtiger AVV oder eine Subunternehmer-"
                "Verknuepfung). Entfernen Sie zuerst die Bezuege.",
            )
            return
        self.reload()
        self.customers_changed.emit()

    def _on_selection_changed(self) -> None:
        has_selection = bool(self._table.selectionModel().selectedRows())
        self._edit_btn.setEnabled(has_selection)
        self._delete_btn.setEnabled(has_selection)

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------

    def reload(self) -> None:
        self._subjects = self._list_customers()
        self._table.setRowCount(len(self._subjects))
        for row, subject in enumerate(self._subjects):
            self._set_row(row, subject)
        self._empty_hint.setVisible(len(self._subjects) == 0)
        self._table.setVisible(len(self._subjects) > 0)
        self._table.clearSelection()
        self._add_btn.setEnabled(self._store is not None)
        self._edit_btn.setEnabled(False)
        self._delete_btn.setEnabled(False)

    def _list_customers(self) -> list[Subject]:
        if self._store is None:
            return []
        try:
            return [s for s in self._store.list_all() if s.kind is SubjectKind.KUNDE]
        except Exception:  # noqa: BLE001 — Cross-DB-Store-Grenze, fail-soft
            _log.exception("Kundenliste konnte nicht geladen werden")
            return []

    def _set_row(self, row: int, subject: Subject) -> None:
        name_item = QTableWidgetItem(subject.name)
        name_item.setData(Qt.ItemDataRole.UserRole, subject.subject_id)
        self._table.setItem(row, 0, name_item)
        self._table.setItem(row, 1, QTableWidgetItem(subject.branche))
        self._table.setItem(row, 2, QTableWidgetItem(subject.groesse))
        self._table.setItem(row, 3, QTableWidgetItem(subject.contact))

    def _selected_subject(self) -> Subject | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        idx = rows[0].row()
        if 0 <= idx < len(self._subjects):
            return self._subjects[idx]
        return None

    def _warn(self, title: str, message: str) -> None:
        FinlaiInfoDialog(
            title=title, message=message, icon_name=Icons.WARNING, parent=self
        ).exec()
