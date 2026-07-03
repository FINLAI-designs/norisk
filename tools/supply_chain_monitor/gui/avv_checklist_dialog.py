"""
avv_checklist_dialog — Bearbeitungs-Dialog fuer die Art-28-Pflichtcheckliste.

Iter 2c-i: Zeigt fuer ein AVV die 10 Default-Checks aus
:class:`Art28Check` plus alle Custom-Checks. Pro Eintrag drei States:
**Ja / Nein / Ungeprueft**. User kann Custom-Checks hinzufuegen/loeschen.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
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

from core import theme
from tools.supply_chain_monitor.domain.avv_conformity import (
    VERDICT_COMPLETE,
    VERDICT_CRITICAL,
    AvvConformity,
    assess_art28_conformity,
)
from tools.supply_chain_monitor.domain.models import (
    Art28Check,
    AvvChecklistEntry,
)

# Kurz-Labels fuer die Anzeige fehlender (sicherheits-)kritischer Klauseln.
_SHORT_LABELS: dict[Art28Check, str] = {
    Art28Check.WEISUNGSBINDUNG: "Weisungsbindung",
    Art28Check.VERSCHWIEGENHEIT: "Verschwiegenheit",
    Art28Check.TOMS: "TOMs",
    Art28Check.SUB_AUFTRAGNEHMER: "Subunternehmer",
    Art28Check.BETROFFENENRECHTE: "Betroffenenrechte",
    Art28Check.UNTERSTUETZUNG: "DSFA/Meldepflicht-Unterstuetzung",
    Art28Check.LOESCHUNG: "Rueckgabe/Loeschung",
    Art28Check.AUDIT_RECHTE: "Audit-/Pruefrechte",
    Art28Check.DPIA_HILFE: "DPIA-Mitwirkung",
    Art28Check.EU_STANDARDVERTRAGSKLAUSELN: "EU-SCC (Drittland)",
}

_CHECK_DESCRIPTIONS: dict[Art28Check, str] = {
    Art28Check.WEISUNGSBINDUNG: "(a) Weisungsbindung des Auftragsverarbeiters",
    Art28Check.VERSCHWIEGENHEIT: "(b) Verschwiegenheits-Verpflichtung",
    Art28Check.TOMS: "(c) Technisch-Organisatorische Massnahmen (TOMs)",
    Art28Check.SUB_AUFTRAGNEHMER: "(d) Sub-Auftragnehmer nur mit Genehmigung",
    Art28Check.BETROFFENENRECHTE: "(e) Unterstuetzung bei Betroffenenrechten",
    Art28Check.UNTERSTUETZUNG: "(f) Unterstuetzung bei DSFA / Meldepflichten",
    Art28Check.LOESCHUNG: "(g) Rueckgabe / Loeschung der Daten",
    Art28Check.AUDIT_RECHTE: "(h) Audit-/Pruefrechte des Auftraggebers",
    Art28Check.DPIA_HILFE: "DPIA-Mitwirkung explizit geregelt",
    Art28Check.EU_STANDARDVERTRAGSKLAUSELN: "EU-Standardvertragsklauseln bei Drittland",
}

_STATE_OPTIONS: list[tuple[str, bool | None]] = [
    ("Ungeprueft", None),
    ("Ja, erfuellt", True),
    ("Nein, fehlt", False),
]

_HEADERS: list[str] = ["Pflichtinhalt", "Status", "Typ"]


class AvvChecklistDialog(QDialog):
    """Modaler Editor fuer die AVV-Checkliste."""

    def __init__(
        self,
        avv_id: int,
        entries: list[AvvChecklistEntry],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._avv_id = avv_id
        self._entries = list(entries)
        self.setWindowTitle("Art-28-Pflichtcheckliste")
        self.setMinimumSize(720, 480)
        self._build_ui()
        self._reload()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        info = QLabel(
            "Pro Pflichtinhalt aus DSGVO Art. 28 Abs. 3 die Einschaetzung "
            "setzen. Custom-Checks lassen sich ergaenzen — sie werden nicht "
            "automatisch gegen Art. 28 gemappt."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # Konformitaets-Banner — Vollstaendigkeits-Auswertung der Art-28-
        # Pflichtinhalte (KEINE Rechtsberatung, nur welche Klauseln dokumentiert
        # sind + sicherheitskritische Luecken). Aktualisiert live bei Statuswahl.
        self._conformity_label = QLabel("")
        self._conformity_label.setWordWrap(True)
        self._conformity_label.setObjectName("AvvConformityBanner")
        layout.addWidget(self._conformity_label)

        # Tabelle
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

        # Buttons
        row = QHBoxLayout()
        self._add_custom_btn = QPushButton("Custom-Check hinzufuegen ...")
        self._add_custom_btn.clicked.connect(self._on_add_custom)
        row.addWidget(self._add_custom_btn)
        self._remove_custom_btn = QPushButton("Custom-Check entfernen")
        self._remove_custom_btn.clicked.connect(self._on_remove_custom)
        row.addWidget(self._remove_custom_btn)
        row.addStretch(1)
        layout.addLayout(row)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Speichern")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Abbrechen")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _reload(self) -> None:
        # Defaults zuerst (10 fixe Art-28-Checks), dann Customs.
        default_order: dict[Art28Check, int] = {c: i for i, c in enumerate(Art28Check)}
        self._entries.sort(
            key=lambda e: (
                1 if e.is_custom else 0,
                default_order.get(e.art28_check, 99) if not e.is_custom else 0,
                e.custom_label if e.is_custom else "",
            )
        )
        self._table.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            self._set_row(row, entry)
        self._update_conformity()

    def _update_conformity(self) -> None:
        """Aktualisiert das Konformitaets-Banner.

        Rein deskriptiv: zeigt die Art-28-Vollstaendigkeits-Quote, das Verdict
        und sicherheits-/compliance-kritische Luecken. KEINE Rechtsberatung.
        """
        conf: AvvConformity = assess_art28_conformity(self._entries)
        c = theme.get()
        if conf.verdict == VERDICT_COMPLETE:
            color = c.SUCCESS
            kern = "Alle 10 Art-28-Pflichtinhalte dokumentiert."
        else:
            color = c.DANGER if conf.verdict == VERDICT_CRITICAL else c.WARNING
            fehlend = ", ".join(
                _SHORT_LABELS.get(x, x.value) for x in conf.missing
            )
            kern = f"Es fehlen: {fehlend}."
            if conf.security_gaps:
                kritisch = ", ".join(
                    _SHORT_LABELS.get(x, x.value) for x in conf.security_gaps
                )
                kern += f" Sicherheitskritisch offen: {kritisch}."
        self._conformity_label.setText(
            f"Art-28-Vollstaendigkeit: {conf.present_count}/{conf.total} "
            f"dokumentiert ({conf.verdict}). {kern} "
            "Hinweis: reine Vollstaendigkeits-Pruefung, keine Rechtsberatung."
        )
        self._conformity_label.setStyleSheet(
            f"color: {color}; font-size: 12px; padding: 6px 0;"
        )

    def _set_row(self, row: int, entry: AvvChecklistEntry) -> None:
        # Spalte 0: Label
        if entry.is_custom:
            label = entry.custom_label
        elif entry.art28_check is not None:
            label = _CHECK_DESCRIPTIONS.get(entry.art28_check, entry.art28_check.value)
        else:
            label = "?"
        label_item = QTableWidgetItem(label)
        label_item.setData(Qt.ItemDataRole.UserRole, row)  # row → entries-Index
        self._table.setItem(row, 0, label_item)

        # Spalte 1: Status-Combo
        combo = QComboBox()
        for text, value in _STATE_OPTIONS:
            combo.addItem(text, value)
        current_idx = next(
            (i for i, (_t, v) in enumerate(_STATE_OPTIONS) if v == entry.is_present),
            0,
        )
        combo.setCurrentIndex(current_idx)
        combo.currentIndexChanged.connect(
            lambda _idx, r=row, c=combo: self._on_status_changed(r, c)
        )
        self._table.setCellWidget(row, 1, combo)

        # Spalte 2: Typ
        kind_item = QTableWidgetItem("Custom" if entry.is_custom else "Art. 28")
        kind_item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        self._table.setItem(row, 2, kind_item)

    def _on_status_changed(self, row: int, combo: QComboBox) -> None:
        if not 0 <= row < len(self._entries):
            return
        new_value = combo.currentData()
        current = self._entries[row]
        self._entries[row] = AvvChecklistEntry(
            id=current.id,
            avv_id=current.avv_id,
            is_present=new_value,
            art28_check=current.art28_check,
            custom_label=current.custom_label,
            is_custom=current.is_custom,
            notes=current.notes,
        )
        # Banner live nachziehen (ohne Tabellen-Rebuild).
        self._update_conformity()

    def _on_add_custom(self) -> None:
        label, ok = QInputDialog.getText(
            self,
            "Custom-Check hinzufuegen",
            "Bezeichnung des zusaetzlichen Pflichtinhalts:",
        )
        if not ok or not label.strip():
            return
        try:
            new_entry = AvvChecklistEntry(
                id=None,
                avv_id=self._avv_id,
                is_present=None,
                custom_label=label,
                is_custom=True,
            )
        except ValueError:
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
            return  # Default-Checks koennen nicht entfernt werden
        del self._entries[idx]
        self._reload()

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    def collected_entries(self) -> list[AvvChecklistEntry]:
        return list(self._entries)
