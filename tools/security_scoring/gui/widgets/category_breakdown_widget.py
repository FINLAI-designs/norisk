"""
category_breakdown_widget — Kategorie-Breakdown-Panel fuer den Hardening-Score (Phase 4c).

Klappbares Panel, das die 5 Kategorien aus
:class:`tools.security_scoring.domain.hardening_categories.HardeningCategory`
mit Mini-Balken, Findings-Counts und ggf. Hard-Cap-Hinweisen aufschluesselt.

Single-Tenant-OSS — kein Free/Pro-Gating mehr; die volle
5-Kategorien-Tabelle inkl. Hard-Cap-Hinweise (Trigger-IDs + Begruendung)
wird immer angezeigt.

Hard-Cap-Hinweise kommen aus:attr:`HardeningScoreResult.hard_cap_events`
und werden in der Reihenfolge der niedrigsten Cap-Werte (= staerkste
Score-Reduktion) sortiert. Wenn ein Cap aktiv war, zeigt das Panel
zusaetzlich den Raw-Score-Hinweis ``"Score gedeckelt von X auf Y"``.

Schichtzugehoerigkeit: gui/ — keine Domain-Logik. Konsumiert ausschliesslich
das Read-Only:class:`HardeningScoreResult`.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.security_scoring.domain.hardening_categories import (
    HardeningCategory,
)

if TYPE_CHECKING:
    from tools.security_scoring.domain.hardening_score import (
        CategoryScore,
        HardeningScoreResult,
    )


#: Anzeige-Reihenfolge der Kategorien v2 §3 — feste Reihenfolge,
#: damit der Breakdown zwischen Scans visuell stabil bleibt). Identisch
#: zur Enum-Definition in:class:`HardeningCategory`.
_CATEGORY_DISPLAY_ORDER: Final[tuple[HardeningCategory, ...]] = (
    HardeningCategory.CVE_PATCH,
    HardeningCategory.NETWORK,
    HardeningCategory.PASSWORD,
    HardeningCategory.API_SECURITY,
    HardeningCategory.SYSTEM_HARDENING,
)

#: Anzeige-Label je Kategorie. Eigenes Mapping, weil die Enum-Werte
#: technische Slugs sind (``cve_patch``) und der Breakdown lesbar bleiben
#: soll. Aenderungen am Mapping nicht direkt im Domain-Modul, sondern
#: hier — GUI-Schicht.
_CATEGORY_LABELS: Final[dict[HardeningCategory, str]] = {
    HardeningCategory.CVE_PATCH:        "CVE / Patch",
    HardeningCategory.NETWORK:          "Netzwerk",
    HardeningCategory.PASSWORD:         "Passwoerter",
    HardeningCategory.API_SECURITY:     "API-Security",
    HardeningCategory.SYSTEM_HARDENING: "System-Hardening",
}

class CategoryBreakdownWidget(QWidget):
    """Klappbares Breakdown-Panel mit 5 Kategorien + Hard-Cap-Hinweisen.

    Public API:

    *:meth:`set_result(result)` — Neuer Score-Stand. ``None`` blendet
      Inhalt aus.
    *:meth:`set_collapsed(collapsed)` — Body sichtbar (False) oder
      eingeklappt (True).

    Signals:
        collapsed_changed(bool): Emittiert wenn der User den Header-Button
            klickt. ``True`` wenn Body danach eingeklappt ist.
    """

    collapsed_changed = Signal(bool)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._collapsed = False
        self._result: HardeningScoreResult | None = None

        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(4)

        # Header: Toggle + Titel
        self._header = QWidget(self)
        header_layout = QHBoxLayout(self._header)
        header_layout.setContentsMargins(8, 4, 8, 4)
        header_layout.setSpacing(8)

        self._toggle_button = QPushButton("−", self._header)
        self._toggle_button.setFixedWidth(28)
        self._toggle_button.setFlat(True)
        self._toggle_button.clicked.connect(self._on_toggle_clicked)
        header_layout.addWidget(self._toggle_button)

        self._title_label = QLabel("Kategorie-Breakdown", self._header)
        self._title_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        font_title = self._title_label.font()
        font_title.setBold(True)
        self._title_label.setFont(font_title)
        header_layout.addWidget(self._title_label)

        root.addWidget(self._header)

        # Body: VBox mit Kategorie-Zeilen + Cap-Hinweisen
        self._body = QWidget(self)
        body_layout = QVBoxLayout(self._body)
        body_layout.setContentsMargins(8, 0, 8, 4)
        body_layout.setSpacing(4)
        self._body_layout = body_layout
        root.addWidget(self._body)

        # Map Kategorie → Row-Widgets fuer schnelle Updates
        self._category_rows: dict[HardeningCategory, _CategoryRow] = {}
        for cat in _CATEGORY_DISPLAY_ORDER:
            row = _CategoryRow(cat, _CATEGORY_LABELS[cat], self._body)
            self._body_layout.addWidget(row)
            self._category_rows[cat] = row

        # Cap-Hinweise-Container (am Ende des Body)
        self._cap_container = QWidget(self._body)
        cap_layout = QVBoxLayout(self._cap_container)
        cap_layout.setContentsMargins(0, 4, 0, 0)
        cap_layout.setSpacing(2)
        self._cap_layout = cap_layout
        self._body_layout.addWidget(self._cap_container)
        self._cap_container.setVisible(False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_result(self, result: HardeningScoreResult | None) -> None:
        """Aktualisiert die Anzeige aus einem ``HardeningScoreResult``.

        Args:
            result: Berechnetes Ergebnis. ``None`` blendet alle
                Kategorie-Zeilen auf ``"—"`` zurueck (initialer Zustand).
        """
        self._result = result
        if result is None:
            for row in self._category_rows.values():
                row.set_data(None)
            self._clear_cap_hints()
            self._cap_container.setVisible(False)
            return

        scores_by_cat = {cs.category: cs for cs in result.category_scores}
        for cat, row in self._category_rows.items():
            row.set_data(scores_by_cat.get(cat))

        self._render_cap_hints(result)

    def set_collapsed(self, collapsed: bool) -> None:
        """Steuert die Sichtbarkeit des Body-Bereichs."""
        if self._collapsed == collapsed:
            return
        self._collapsed = collapsed
        self._body.setVisible(not collapsed)
        self._toggle_button.setText("+" if collapsed else "−")
        self.collapsed_changed.emit(collapsed)

    @property
    def is_collapsed(self) -> bool:
        """Body eingeklappt? Read-only."""
        return self._collapsed

    def category_row(
        self, category: HardeningCategory
    ) -> _CategoryRow:
        """Zugriff auf eine Kategorie-Zeile — fuer Tests."""
        return self._category_rows[category]

    def cap_hint_widgets(self) -> list[QLabel]:
        """Alle aktuellen Cap-Hinweis-QLabels — fuer Tests."""
        return [
            w
            for w in self._cap_container.findChildren(QLabel)
            if w.parent() is self._cap_container
        ]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _on_toggle_clicked(self) -> None:
        self.set_collapsed(not self._collapsed)

    def _clear_cap_hints(self) -> None:
        while self._cap_layout.count():
            item = self._cap_layout.takeAt(0)
            if item is None:
                break
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def _render_cap_hints(self, result: HardeningScoreResult) -> None:
        self._clear_cap_hints()
        if not result.hard_cap_events:
            self._cap_container.setVisible(False)
            return

        self._cap_container.setVisible(True)
        c = theme.get()

        # Sortiert nach Cap-Value aufsteigend — niedrigster Cap zuerst
        # (= staerkste Auswirkung).
        events = sorted(result.hard_cap_events, key=lambda e: e.cap_value)

        capped = result.overall_score
        raw = result.raw_weighted_score
        if raw > capped:
            summary = QLabel(
                f"Hinweis: Score gedeckelt von {raw:.0f} auf {capped:.0f}",
                self._cap_container,
            )
            font = summary.font()
            font.setBold(True)
            summary.setFont(font)
            summary.setStyleSheet(f"color: {c.WARNING};")
            self._cap_layout.addWidget(summary)

        for event in events:
            detail_suffix = f" — {event.details}" if event.details else ""
            line = QLabel(
                f"  • {event.label} (max {event.cap_value}, "
                f"ausgeloest von {event.triggered_by}){detail_suffix}",
                self._cap_container,
            )
            line.setStyleSheet(f"color: {c.TEXT_DIM};")
            line.setWordWrap(True)
            self._cap_layout.addWidget(line)


# ---------------------------------------------------------------------------
# Sub-Widgets
# ---------------------------------------------------------------------------


class _CategoryRow(QFrame):
    """Eine Kategorie-Zeile mit Label + Mini-Balken + Findings-Counts."""

    def __init__(
        self,
        category: HardeningCategory,
        label: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._category = category

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._label = QLabel(label, self)
        self._label.setMinimumWidth(140)
        layout.addWidget(self._label)

        self._bar = QProgressBar(self)
        self._bar.setMinimum(0)
        self._bar.setMaximum(100)
        # Polish 2026-05-12: Text aus dem Balken raus — auf Neon-
        # Teal-Chunk war weiße Schrift unlesbar (Patrick-Smoke). Score
        # bekommt eigenes Label rechts vom Balken, gleiches Pattern wie
        # FinlaiProgressBar-Konvention).
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(16)
        layout.addWidget(self._bar, stretch=1)

        self._score_label = QLabel("— / 100", self)
        self._score_label.setFixedWidth(72)
        self._score_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        layout.addWidget(self._score_label)

        self._weight_label = QLabel("—", self)
        self._weight_label.setFixedWidth(56)
        self._weight_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        layout.addWidget(self._weight_label)

        self._findings_label = QLabel("", self)
        self._findings_label.setMinimumWidth(80)
        layout.addWidget(self._findings_label)

        self.set_data(None)

    def set_data(self, cscore: CategoryScore | None) -> None:
        """Aktualisiert Bar + Labels. ``None`` zeigt den 'fehlt'-Zustand."""
        if cscore is None:
            self._bar.setValue(0)
            self._score_label.setText("— / 100")
            self._weight_label.setText("—")
            self._findings_label.setText("")
            self.setToolTip(
                "Kategorie nicht verfuegbar (Stub-Strategie aktiv)"
            )
            return
        self._bar.setValue(int(round(cscore.score)))
        self._score_label.setText(f"{cscore.score:.0f} / 100")
        self._weight_label.setText(f"{cscore.weight * 100:.0f}%")
        self._findings_label.setText(
            f"{cscore.components_count} Komp."
        )
        self.setToolTip(
            f"Kategorie {self._category.value} | "
            f"Score {cscore.score:.1f} | "
            f"Gewicht {cscore.weight * 100:.1f}% | "
            f"{cscore.components_count} Komponenten"
        )

    @property
    def category(self) -> HardeningCategory:
        return self._category

    @property
    def bar_value(self) -> int:
        return self._bar.value()

    @property
    def weight_text(self) -> str:
        return self._weight_label.text()

    @property
    def findings_text(self) -> str:
        return self._findings_label.text()
