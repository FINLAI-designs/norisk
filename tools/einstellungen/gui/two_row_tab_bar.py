"""einstellungen.gui.two_row_tab_bar — Tab-Container mit zwei Tab-Reihen.

Qt's ``QTabBar`` unterstuetzt nativ keine mehrzeiligen Tabs **und** keine
Deselektion via ``setCurrentIndex(-1)`` (Qt6 behandelt das als No-Op,
sobald Tabs vorhanden sind). Beide Eigenschaften brauchen wir aber, um
zwoelf Einstellungen-Tabs auf zwei Reihen zu verteilen, ohne dass beide
Reihen gleichzeitig einen aktiven Tab zeigen.

Loesung: zwei Reihen von ``QPushButton``\\ s (``setCheckable(True)``) in
einer einzigen ``QButtonGroup`` mit ``setExclusive(True)``. Qt sichert
damit nativ zu, dass immer genau **ein** Button ueber beide Reihen
hinweg aktiv ist. Der Content liegt in einem gemeinsamen
``QStackedWidget`` darunter.

Optisch sehen die Buttons aus wie Tabs — runde obere Ecken, keine
Bottom-Border, ``:checked``-Pseudostate fuer die Akzentfarbe.

 (Einstellungen-UX, 2026-05-26).
"""

from __future__ import annotations

from typing import Final

from PySide6.QtCore import Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QButtonGroup,
    QHBoxLayout,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

#: Reihen-Indizes — exportiert fuer Aufrufer.
ROW_TOP: Final[int] = 0
ROW_BOTTOM: Final[int] = 1


class TwoRowTabBar(QWidget):
    """Tab-Container mit zwei horizontalen Reihen + gemeinsamem Content.

    API analog ``QTabWidget`` (``currentChanged``-Signal, ``current_index``,
    ``set_current_index``), aber mit ``add_tab(..., row=...)`` und
    ``set_tab_widget`` fuer Lazy-Loading. Intern keine ``QTabBar``-Widgets:
    Qt6 erlaubt ``setCurrentIndex(-1)`` auf einer ``QTabBar`` mit Tabs
    nicht, was Cross-Row-Deselektion verhindert. Stattdessen ein
    exklusiver ``QButtonGroup`` ueber zwei Reihen ``QPushButton``\\ s.

    Args:
        parent: Optionales Eltern-Widget.
    """

    #: Emittiert, wenn ein anderer Tab aktiv wird. Argument: globaler Index.
    currentChanged = Signal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._stack = QStackedWidget(self)

        self._buttons: list[QPushButton] = []     # global_idx -> button
        self._button_rows: list[int] = []         # global_idx -> ROW_TOP/ROW_BOTTOM
        self._current_global: int = -1
        self._button_style_sheet: str = ""

        # Reihen-Container: jede Reihe ist ein QWidget mit horizontalem Layout.
        # So koennen wir die Buttons jeder Reihe links-buendig fuellen, ohne
        # dass die andere Reihe Einfluss auf die Anordnung hat.
        self._row_top_widget = QWidget(self)
        self._row_top_layout = QHBoxLayout(self._row_top_widget)
        self._row_top_layout.setContentsMargins(0, 0, 0, 0)
        self._row_top_layout.setSpacing(2)
        self._row_top_layout.addStretch()

        self._row_bottom_widget = QWidget(self)
        self._row_bottom_layout = QHBoxLayout(self._row_bottom_widget)
        self._row_bottom_layout.setContentsMargins(0, 0, 0, 0)
        self._row_bottom_layout.setSpacing(2)
        self._row_bottom_layout.addStretch()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(2)
        outer.addWidget(self._row_top_widget)
        outer.addWidget(self._row_bottom_widget)
        outer.addWidget(self._stack, stretch=1)

        self._group.idClicked.connect(self._on_button_clicked)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_tab(
        self,
        widget: QWidget,
        icon: QIcon,
        label: str,
        *,
        row: int = ROW_TOP,
    ) -> int:
        """Haengt einen Tab an das Ende der gewuenschten Reihe an.

        Der **erste** Tab (``global_idx == 0``) wird automatisch aktiv —
        analog ``QTabWidget``. Alle weiteren ``add_tab``-Aufrufe veraendern
        die Selektion **nicht**.

        Args:
            widget: Inhalts-Widget (kommt in den Stack).
            icon: Tab-Icon.
            label: Tab-Beschriftung.
            row: ``ROW_TOP`` (oben) oder ``ROW_BOTTOM`` (unten).

        Returns:
            Globaler Index des Tabs (= Index im internen Stack). Stabil
            ueber spaetere Widget-Ersetzungen via:meth:`set_tab_widget`.

        Raises:
            ValueError: Wenn ``row`` weder ``ROW_TOP`` noch ``ROW_BOTTOM`` ist.
        """
        if row not in (ROW_TOP, ROW_BOTTOM):
            msg = f"Ungueltige Reihe: {row} (erlaubt: 0=top, 1=bottom)"
            raise ValueError(msg)

        global_idx = len(self._buttons)
        button = self._make_button(icon, label)
        self._buttons.append(button)
        self._button_rows.append(row)
        self._group.addButton(button, global_idx)
        self._stack.addWidget(widget)

        # Vor dem Stretch einfuegen, damit Buttons links-buendig stehen.
        layout = self._row_top_layout if row == ROW_TOP else self._row_bottom_layout
        layout.insertWidget(layout.count() - 1, button)

        if global_idx == 0:
            button.setChecked(True)
            self._current_global = 0
            self._stack.setCurrentIndex(0)
        return global_idx

    def set_tab_widget(
        self,
        global_idx: int,
        widget: QWidget,
        icon: QIcon,
        label: str,
    ) -> None:
        """Ersetzt das Inhalts-Widget am gegebenen globalen Index.

        Vorgesehen fuer Lazy-Loading: initial wird ein Stub eingehaengt,
        beim ersten Tab-Klick ersetzt der Aufrufer das Stub durch das
        echte Widget. Button-Icon und Label werden mit aktualisiert.

        Args:
            global_idx: Globaler Index (von:meth:`add_tab` zurueckgegeben).
            widget: Neues Inhalts-Widget.
            icon: Neues Tab-Icon.
            label: Neue Tab-Beschriftung.
        """
        old = self._stack.widget(global_idx)
        self._stack.insertWidget(global_idx, widget)
        self._stack.removeWidget(old)
        old.deleteLater()

        button = self._buttons[global_idx]
        button.setIcon(icon)
        button.setText(label)

        if self._current_global == global_idx:
            self._stack.setCurrentIndex(global_idx)

    def current_index(self) -> int:
        """Aktueller globaler Tab-Index oder ``-1`` wenn keiner aktiv ist."""
        return self._current_global

    def set_current_index(self, global_idx: int) -> None:
        """Aktiviert den Tab mit dem gegebenen globalen Index.

        Args:
            global_idx: Index aus:meth:`add_tab`.
        """
        if global_idx < 0 or global_idx >= len(self._buttons):
            return
        if global_idx == self._current_global:
            return
        button = self._buttons[global_idx]
        was_blocked = self._group.signalsBlocked()
        self._group.blockSignals(True)
        button.setChecked(True)
        self._group.blockSignals(was_blocked)
        self._current_global = global_idx
        self._stack.setCurrentIndex(global_idx)
        self.currentChanged.emit(global_idx)

    def tab_count(self) -> int:
        """Gesamtzahl der Tabs ueber beide Reihen."""
        return self._stack.count()

    # ------------------------------------------------------------------
    # Style-Hooks
    # ------------------------------------------------------------------

    def set_tab_bar_style_sheet(self, style_sheet: str) -> None:
        """Wendet das gegebene Stylesheet auf alle Tab-Buttons an.

        Im Stylesheet sollten ``QPushButton``-Selektoren mit
        ``:checked``-Pseudostate fuer den aktiven Tab und
        ``:hover:!checked`` fuer den Hover-Effekt verwendet werden.
        """
        self._button_style_sheet = style_sheet
        for button in self._buttons:
            button.setStyleSheet(style_sheet)

    def stack(self) -> QStackedWidget:
        """Direkter Zugriff auf den Content-Stack (fuer Tests/Diagnostik)."""
        return self._stack

    def button(self, global_idx: int) -> QPushButton:
        """Direkter Zugriff auf den Tab-Button (fuer Tests/Diagnostik)."""
        return self._buttons[global_idx]

    def row_of(self, global_idx: int) -> int:
        """Reihe, in der der Tab steht (``ROW_TOP``/``ROW_BOTTOM``)."""
        return self._button_rows[global_idx]

    # ------------------------------------------------------------------
    # Interne Helfer
    # ------------------------------------------------------------------

    def _make_button(self, icon: QIcon, label: str) -> QPushButton:
        """Erzeugt einen Tab-Button mit den Default-Eigenschaften."""
        button = QPushButton(icon, label, self)
        button.setCheckable(True)
        button.setAutoExclusive(False)  # Exklusivitaet uebernimmt QButtonGroup.
        button.setFocusPolicy(button.focusPolicy())
        if self._button_style_sheet:
            button.setStyleSheet(self._button_style_sheet)
        return button

    def _on_button_clicked(self, global_idx: int) -> None:
        """``QButtonGroup.idClicked``-Slot."""
        if global_idx == self._current_global:
            return
        self._current_global = global_idx
        self._stack.setCurrentIndex(global_idx)
        self.currentChanged.emit(global_idx)
