"""
risk_matrix_step — Wizard-Step "Risiko-Bewertung" nach BSI 200-3.

Iter 2e: 4x4-Matrix mit 10 Default-Risiken plus
User-Custom-Erweiterungen. Pro Eintrag waehlt der Auditor
Eintrittswahrscheinlichkeit + Schadenshoehe; das aggregierte
Risiko-Level (gering/mittel/hoch/sehr hoch) wird live angezeigt.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog
from core.icons import ICON_SIZE_DIALOG, Icons, get_icon
from core.widgets.button_styles import primary_button_qss, secondary_button_qss
from tools.customer_audit.domain.risk_entities import (
    DEFAULT_RISK_CATALOG_BY_KEY,
    RiskAssessment,
    RiskCategory,
    RiskImpact,
    RiskLevel,
    RiskProbability,
)
from tools.customer_audit.gui.step_widgets import field_styles
from tools.customer_audit.gui.widgets.bsi_risk_matrix_widget import (
    BsiRiskMatrixWidget,
)

_PROB_OPTIONS: list[tuple[RiskProbability, str]] = [
    (p, f"{p.value} — {p.label}")
    for p in (
        RiskProbability.SELTEN,
        RiskProbability.MITTEL,
        RiskProbability.HAEUFIG,
        RiskProbability.SEHR_HAEUFIG,
    )
]
_IMPACT_OPTIONS: list[tuple[RiskImpact, str]] = [
    (i, f"{i.value} — {i.label}")
    for i in (
        RiskImpact.VERNACHLAESSIGBAR,
        RiskImpact.BEGRENZT,
        RiskImpact.BETRAECHTLICH,
        RiskImpact.EXISTENZBEDROHEND,
    )
]
_CATEGORY_OPTIONS: list[tuple[RiskCategory, str]] = [
    (RiskCategory.CYBER, "Cyber"),
    (RiskCategory.DATEN, "Daten"),
    (RiskCategory.TECHNIK, "Technik"),
    (RiskCategory.ORGANISATION, "Organisation"),
    (RiskCategory.EXTERN, "Extern"),
    (RiskCategory.COMPLIANCE, "Compliance"),
]

_LEVEL_LABELS: dict[RiskLevel, str] = {
    RiskLevel.GERING: "GERING",
    RiskLevel.MITTEL: "MITTEL",
    RiskLevel.HOCH: "HOCH",
    RiskLevel.SEHR_HOCH: "SEHR HOCH",
}

_HEADERS: list[str] = [
    "Risiko",
    "Kategorie",
    "Eintritt",
    "Schaden",
    "Level",
    "Akzeptiert",
    "Typ",
]


class RiskMatrixStep(QWidget):
    """Wizard-Step zur BSI-200-3-Risiko-Bewertung.

    Signals:
        risks_changed: emittiert nach jeder Mutation — Wizard kann
            ggf. Validity recheck triggern.
    """

    risks_changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._assessments: list[RiskAssessment] = []
        # zuletzt aus dem Audit ABGELEITETE (P, S) je Katalog-Key. Dient
        # als Baseline, um eine manuelle Anpassung zu erkennen (current != prev)
        # und sie beim Re-Seeding NICHT zu ueberschreiben.
        self._seeded_values: dict[str, tuple[RiskProbability, RiskImpact]] = {}
        self._build_ui()
        self._init_defaults()
        self._reload()

    def _init_defaults(self) -> None:
        """Fuellt den Step mit den 10 Default-Risiken (transient, kein DB-Save)."""
        from tools.customer_audit.domain.risk_entities import (  # noqa: PLC0415
            DEFAULT_RISK_CATALOG,
        )

        self._assessments = [
            RiskAssessment(
                id=None,
                audit_id="",  # vom Wizard beim Save mit echter UUID gesetzt
                catalog_key=entry.key,
                probability=entry.default_probability,
                impact=entry.default_impact,
            )
            for entry in DEFAULT_RISK_CATALOG
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_assessments(self, assessments: list[RiskAssessment]) -> None:
        """Belegt den Step mit der Liste aus dem Service."""
        self._assessments = list(assessments)
        # K-1-Folge): Mit einer NEUEN Bewertungs-Liste ist die alte
        # Seeding-Baseline gegenstandslos. Ohne Reset koennte ein folgendes
        # ``seed_from_audit`` in einer Multi-Audit-Session (zweites
        # ``load_for_edit`` auf derselben Step-Instanz) einen manuell gesetzten
        # Wert des neuen Audits faelschlich als „abgeleitet" einstufen und
        # ueberschreiben — die Baseline gehoerte zum vorigen Audit.
        self._seeded_values.clear()
        self._reload()

    def seed_from_audit(
        self,
        seeds: dict[str, tuple[RiskProbability, RiskImpact]],
    ) -> None:
        """Leitet Katalog-Start-P/S aus den Audit-Antworten ab.

 seedete EINMALIG. Seit (Patrick-Entscheid 2026-06-27) bei
        JEDEM Betreten des Risiko-Schritts — sodass geaenderte Audit-Antworten
        (z. B. Phishing auf „Ja") die Matrix aktualisieren. MANUELL angepasste
        Eintraege bleiben erhalten: ein Katalog-Risiko wird nur neu abgeleitet,
        wenn sein aktueller Wert noch der zuletzt abgeleiteten Baseline (bzw. dem
        Katalog-Default beim ersten Lauf) entspricht; weicht er ab, hat der
        Auditor ihn von Hand gesetzt → unveraendert. Custom-Risiken und Risiken
        ohne Audit-Signal bleiben unberuehrt.

        Args:
            seeds: ``{catalog_key: (RiskProbability, RiskImpact)}``.
        """
        from dataclasses import replace as dc_replace  # noqa: PLC0415

        updated: list[RiskAssessment] = []
        for a in self._assessments:
            seed = None if a.is_custom else seeds.get(a.catalog_key)
            if seed is None:
                updated.append(a)
                continue
            current = (a.probability, a.impact)
            prev = self._seeded_values.get(a.catalog_key)
            if prev is None:
                # Erstes Seeding dieses Keys in der Session.
                default = self._catalog_default(a.catalog_key)
                if current in (seed, default):
                    # Automatisch (Default oder bereits = Ableitung) → ableiten.
                    updated.append(dc_replace(a, probability=seed[0], impact=seed[1]))
                else:
                    # Geladene manuelle Anpassung → behalten.
                    updated.append(a)
                # Baseline = die Ableitung (so bleibt eine Abweichung "manuell").
                self._seeded_values[a.catalog_key] = seed
            elif current == prev:
                # Seit dem letzten Ableiten unveraendert → neu ableiten.
                updated.append(dc_replace(a, probability=seed[0], impact=seed[1]))
                self._seeded_values[a.catalog_key] = seed
            else:
                # Manuell angepasst → behalten; Baseline NICHT aktualisieren,
                # sonst wuerde der manuelle Wert beim naechsten Lauf abgeleitet.
                updated.append(a)
        self._assessments = updated
        self._reload()

    @staticmethod
    def _catalog_default(
        catalog_key: str,
    ) -> tuple[RiskProbability, RiskImpact] | None:
        """(Wahrscheinlichkeit, Schaden)-Default eines Katalog-Risikos."""
        entry = DEFAULT_RISK_CATALOG_BY_KEY.get(catalog_key)
        if entry is None:
            return None
        return (entry.default_probability, entry.default_impact)

    def collected_assessments(self) -> list[RiskAssessment]:
        """Liefert die aktuellen Bewertungen (vom Wizard beim Save geholt)."""
        return list(self._assessments)

    def is_valid(self) -> bool:
        # Risiko-Bewertung ist optional — der Wizard kann immer fortfahren.
        return True

    def validate(self) -> str:
        return ""

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        c = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        hdr = QLabel("Risiko-Bewertung (BSI 200-3 vereinfacht)")
        hdr.setObjectName("RiskMatrixHeader")
        hdr.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: Raleway; "
            f"font-weight: 700; font-size: 14px;"
        )
        root.addWidget(hdr)

        info = QLabel(
            "Pro Risiko die Eintrittswahrscheinlichkeit (selten/mittel/haeufig/"
            "sehr haeufig) und Schadenshoehe (vernachlaessigbar/begrenzt/"
            "betraechtlich/existenzbedrohend) waehlen. Das resultierende Level "
            "(gering/mittel/hoch/sehr hoch) wird automatisch berechnet."
        )
        info.setObjectName("RiskMatrixInfo")
        info.setWordWrap(True)
        root.addWidget(info)

        self._summary_label = QLabel("")
        self._summary_label.setObjectName("RiskMatrixSummary")
        self._summary_label.setWordWrap(True)
        root.addWidget(self._summary_label)

        # View-Toggle: Matrix / Tabelle
        toggle_row = QHBoxLayout()
        toggle_row.setSpacing(8)
        self._matrix_btn = QPushButton("Matrix")
        self._matrix_btn.setCheckable(True)
        self._matrix_btn.setChecked(True)
        self._table_btn = QPushButton("Tabelle")
        self._table_btn.setCheckable(True)
        self._toggle_group = QButtonGroup(self)
        self._toggle_group.setExclusive(True)
        self._toggle_group.addButton(self._matrix_btn, 0)
        self._toggle_group.addButton(self._table_btn, 1)
        self._toggle_group.idToggled.connect(self._on_view_toggled)
        toggle_row.addWidget(self._matrix_btn)
        toggle_row.addWidget(self._table_btn)
        toggle_row.addStretch(1)
        root.addLayout(toggle_row)

        # Stacked: Seite 0 = Matrix, Seite 1 = Tabelle
        self._stack = QStackedWidget()
        self._matrix_widget = BsiRiskMatrixWidget()
        self._stack.addWidget(self._matrix_widget)

        table_page = QWidget()
        table_layout = QVBoxLayout(table_page)
        table_layout.setContentsMargins(0, 0, 0, 0)

        # Table
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
        for col in range(1, len(_HEADERS)):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        table_layout.addWidget(self._table, stretch=1)

        self._stack.addWidget(table_page)
        root.addWidget(self._stack, stretch=1)

        # Buttons
        button_row = QHBoxLayout()
        self._add_custom_btn = QPushButton("Custom-Risiko hinzufuegen ...")
        self._add_custom_btn.clicked.connect(self._on_add_custom)
        button_row.addWidget(self._add_custom_btn)

        self._remove_custom_btn = QPushButton("Custom-Risiko entfernen")
        self._remove_custom_btn.clicked.connect(self._on_remove_custom)
        button_row.addWidget(self._remove_custom_btn)

        self._notes_btn = QPushButton("Notiz bearbeiten ...")
        self._notes_btn.clicked.connect(self._on_edit_notes)
        button_row.addWidget(self._notes_btn)

        button_row.addStretch(1)
        root.addLayout(button_row)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _reload(self) -> None:
        # Sortierung: Score desc, dann Titel
        catalog = DEFAULT_RISK_CATALOG_BY_KEY
        self._assessments.sort(
            key=lambda a: (
                -(a.probability.value * a.impact.value),
                a.display_title(catalog),
            )
        )
        self._table.setRowCount(len(self._assessments))
        for row, assessment in enumerate(self._assessments):
            self._set_row(row, assessment)
        self._matrix_widget.set_assessments(self._assessments)
        self._update_summary()
        self.risks_changed.emit()

    def _on_view_toggled(self, button_id: int, checked: bool) -> None:
        if checked:
            self._stack.setCurrentIndex(button_id)

    def _set_row(self, row: int, assessment: RiskAssessment) -> None:
        catalog = DEFAULT_RISK_CATALOG_BY_KEY
        title_item = QTableWidgetItem(assessment.display_title(catalog))
        title_item.setData(Qt.ItemDataRole.UserRole, row)
        self._table.setItem(row, 0, title_item)

        cat = assessment.category(catalog)
        cat_item = QTableWidgetItem(
            next((label for c, label in _CATEGORY_OPTIONS if c is cat), cat.value)
        )
        self._table.setItem(row, 1, cat_item)

        # Probability combo
        prob_combo = QComboBox()
        for prob, label in _PROB_OPTIONS:
            prob_combo.addItem(label, prob)
        prob_combo.setCurrentIndex(
            next(i for i, (p, _) in enumerate(_PROB_OPTIONS) if p is assessment.probability)
        )
        prob_combo.currentIndexChanged.connect(
            lambda _idx, r=row, c=prob_combo: self._on_prob_changed(r, c)
        )
        self._table.setCellWidget(row, 2, prob_combo)

        # Impact combo
        impact_combo = QComboBox()
        for imp, label in _IMPACT_OPTIONS:
            impact_combo.addItem(label, imp)
        impact_combo.setCurrentIndex(
            next(i for i, (im, _) in enumerate(_IMPACT_OPTIONS) if im is assessment.impact)
        )
        impact_combo.currentIndexChanged.connect(
            lambda _idx, r=row, c=impact_combo: self._on_impact_changed(r, c)
        )
        self._table.setCellWidget(row, 3, impact_combo)

        # Level
        level_item = QTableWidgetItem(_LEVEL_LABELS[assessment.level])
        level_item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        self._table.setItem(row, 4, level_item)

        # Accepted-Checkbox
        host = QWidget()
        host_layout = QHBoxLayout(host)
        host_layout.setContentsMargins(8, 0, 8, 0)
        host_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cb = QCheckBox()
        cb.setChecked(assessment.is_accepted)
        cb.setToolTip("Risiko bewusst akzeptiert (nicht weiter mitigiert)")
        cb.toggled.connect(lambda checked, r=row: self._on_accepted_changed(r, checked))
        host_layout.addWidget(cb)
        self._table.setCellWidget(row, 5, host)

        # Typ
        kind = QTableWidgetItem("Custom" if assessment.is_custom else "Default")
        kind.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        self._table.setItem(row, 6, kind)

    def _replace_at(self, row: int, *, replacements: dict) -> None:
        """Hilfsfunktion: erstellt einen neuen RiskAssessment mit override-Werten
        und ersetzt den Eintrag an Position ``row``. Triggert Reload."""
        if not 0 <= row < len(self._assessments):
            return
        existing = self._assessments[row]
        from datetime import UTC, datetime  # noqa: PLC0415

        kwargs = {
            "id": existing.id,
            "audit_id": existing.audit_id,
            "catalog_key": existing.catalog_key,
            "probability": existing.probability,
            "impact": existing.impact,
            "custom_title": existing.custom_title,
            "custom_description": existing.custom_description,
            "custom_category": existing.custom_category,
            "notes": existing.notes,
            "is_custom": existing.is_custom,
            "is_accepted": existing.is_accepted,
            "created_at": existing.created_at,
            "updated_at": datetime.now(UTC),
        }
        kwargs.update(replacements)
        try:
            self._assessments[row] = RiskAssessment(**kwargs)
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload()

    def _on_prob_changed(self, row: int, combo: QComboBox) -> None:
        new_value = combo.currentData()
        if isinstance(new_value, RiskProbability):
            self._replace_at(row, replacements={"probability": new_value})

    def _on_impact_changed(self, row: int, combo: QComboBox) -> None:
        new_value = combo.currentData()
        if isinstance(new_value, RiskImpact):
            self._replace_at(row, replacements={"impact": new_value})

    def _on_accepted_changed(self, row: int, checked: bool) -> None:
        self._replace_at(row, replacements={"is_accepted": checked})

    def _on_add_custom(self) -> None:
        dialog = _CustomRiskDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        data = dialog.collected()
        if data is None:
            return
        from datetime import UTC, datetime  # noqa: PLC0415

        audit_id = self._assessments[0].audit_id if self._assessments else ""
        try:
            new_entry = RiskAssessment(
                id=None,
                audit_id=audit_id,
                catalog_key="",
                custom_title=data["title"],
                custom_description=data["description"],
                custom_category=data["category"],
                probability=data["probability"],
                impact=data["impact"],
                is_custom=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._assessments.append(new_entry)
        self._reload()

    def _on_remove_custom(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if not 0 <= idx < len(self._assessments):
            return
        if not self._assessments[idx].is_custom:
            FinlaiInfoDialog(
                title="Default-Risiko",
                message=(
                    "Default-Risiken aus dem Catalog koennen nicht entfernt werden "
                    "(nur Custom-Risiken)."
                ),
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        del self._assessments[idx]
        self._reload()

    def _on_edit_notes(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if not 0 <= idx < len(self._assessments):
            return
        existing = self._assessments[idx]
        text, ok = QInputDialog.getMultiLineText(
            self,
            "Notiz",
            f"Notiz zu '{existing.display_title(DEFAULT_RISK_CATALOG_BY_KEY)}':",
            existing.notes,
        )
        if not ok:
            return
        self._replace_at(idx, replacements={"notes": text})

    # ------------------------------------------------------------------
    # Aggregat-Banner
    # ------------------------------------------------------------------

    def _update_summary(self) -> None:
        by_level: dict[RiskLevel, int] = {level: 0 for level in RiskLevel}
        accepted = 0
        for a in self._assessments:
            by_level[a.level] += 1
            if a.is_accepted:
                accepted += 1
        parts = [f"{by_level[level]} {_LEVEL_LABELS[level]}" for level in RiskLevel]
        suffix = f" — {accepted} bewusst akzeptiert" if accepted else ""
        self._summary_label.setText(
            f"<b>{len(self._assessments)}</b> Risiken bewertet: "
            + ", ".join(parts)
            + suffix
            + "."
        )


# ---------------------------------------------------------------------------
# Add-Custom-Dialog
# ---------------------------------------------------------------------------


class _CustomRiskDialog(QDialog):
    """FINLAI-Popup zum Anlegen eines Custom-Risikos.

    vorher ein rohes ``QDialog`` mit nativem Fenstertitel und
    ``QDialogButtonBox`` (Betriebssystem-Optik). Jetzt ein rahmenloser,
    Theme-konformer Dialog analog zur ``core.dialogs``-Familie
    (Header mit Icon + Titel, gestylte FINLAI-Buttons). Daten-Vertrag
    unveraendert::meth:`collected` liefert dasselbe Dict, ``exec`` liefert
    weiter ``Accepted``/``Rejected``.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(True)
        self._build_ui()

    def _build_ui(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 8px; }}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        # Header: Icon + Titel (analog FinlaiInfoDialog)
        header = QHBoxLayout()
        header.setSpacing(10)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(
            get_icon(Icons.ADD, color=c.ACCENT).pixmap(
                ICON_SIZE_DIALOG, ICON_SIZE_DIALOG
            )
        )
        header.addWidget(icon_lbl)
        title_lbl = QLabel("Custom-Risiko hinzufügen")
        title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_H3}px;"
            f" font-weight: 700; color: {c.TEXT_MAIN};"
        )
        header.addWidget(title_lbl)
        header.addStretch()
        root.addLayout(header)

        # Formular
        form = QFormLayout()
        form.setSpacing(8)
        _input_style = field_styles.input_style()
        _combo_style = field_styles.combo_style()

        self._title_input = QLineEdit()
        self._title_input.setPlaceholderText("z. B. Lieferketten-Ausfall")
        self._title_input.setStyleSheet(_input_style)
        form.addRow(self._make_label("Titel *", c), self._title_input)

        self._description_input = QTextEdit()
        self._description_input.setAcceptRichText(False)
        self._description_input.setPlaceholderText(
            "Optional: 1-3 Saetze, was das Risiko bedeutet."
        )
        self._description_input.setFixedHeight(72)
        self._description_input.setStyleSheet(field_styles.textedit_style())
        form.addRow(self._make_label("Beschreibung", c), self._description_input)

        self._category_combo = QComboBox()
        for cat, label in _CATEGORY_OPTIONS:
            self._category_combo.addItem(label, cat)
        self._category_combo.setStyleSheet(_combo_style)
        form.addRow(self._make_label("Kategorie", c), self._category_combo)

        self._prob_combo = QComboBox()
        for prob, label in _PROB_OPTIONS:
            self._prob_combo.addItem(label, prob)
        self._prob_combo.setCurrentIndex(1)  # MITTEL Default
        self._prob_combo.setStyleSheet(_combo_style)
        form.addRow(
            self._make_label("Eintrittswahrscheinlichkeit", c), self._prob_combo
        )

        self._impact_combo = QComboBox()
        for imp, label in _IMPACT_OPTIONS:
            self._impact_combo.addItem(label, imp)
        self._impact_combo.setCurrentIndex(1)  # BEGRENZT Default
        self._impact_combo.setStyleSheet(_combo_style)
        form.addRow(self._make_label("Schadenshoehe", c), self._impact_combo)

        root.addLayout(form)

        # Inline-Fehlerhinweis fuer das Pflichtfeld "Titel"
        self._err_label = QLabel("")
        self._err_label.setStyleSheet(f"color: {c.DANGER}; font-size: 11px;")
        self._err_label.setVisible(False)
        root.addWidget(self._err_label)

        # Button-Leiste: Abbrechen (sekundaer) | Hinzufuegen (primaer)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_cancel = QPushButton("Abbrechen")
        btn_cancel.setStyleSheet(secondary_button_qss())
        btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_ok = QPushButton("Hinzufügen")
        btn_ok.setDefault(True)
        btn_ok.setStyleSheet(primary_button_qss())
        btn_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_ok.clicked.connect(self._on_accept)
        btn_row.addWidget(btn_ok)
        root.addLayout(btn_row)

        self.setMinimumWidth(440)

        # Tab-Reihenfolge (F4) — logische Feld-Folge explizit setzen.
        self.setTabOrder(self._title_input, self._description_input)
        self.setTabOrder(self._description_input, self._category_combo)
        self.setTabOrder(self._category_combo, self._prob_combo)
        self.setTabOrder(self._prob_combo, self._impact_combo)
        self.setTabOrder(self._impact_combo, btn_ok)
        self.setTabOrder(btn_ok, btn_cancel)

    @staticmethod
    def _make_label(text: str, c: object) -> QLabel:
        """Erstellt ein Theme-konformes Formular-Label."""
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: 12px;")  # type: ignore[attr-defined]
        return lbl

    def _on_accept(self) -> None:
        if not self._title_input.text().strip():
            self._err_label.setText("Titel ist ein Pflichtfeld.")
            self._err_label.setVisible(True)
            self._title_input.setFocus()
            return
        self.accept()

    def collected(self) -> dict | None:
        prob = self._prob_combo.currentData()
        imp = self._impact_combo.currentData()
        cat = self._category_combo.currentData()
        if not isinstance(prob, RiskProbability) or not isinstance(imp, RiskImpact):
            return None
        if not isinstance(cat, RiskCategory):
            return None
        return {
            "title": self._title_input.text(),
            "description": self._description_input.toPlainText(),
            "category": cat,
            "probability": prob,
            "impact": imp,
        }
