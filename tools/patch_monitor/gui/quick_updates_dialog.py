"""quick_updates_dialog — Pop-up nach dem Quick-Check „Schnell nach Updates suchen".

Zeigt nach einem on-demand Update-Check die gefundenen, patchbaren
Programme in einem eigenen, modalen Fenster — mit derselben Konfigurations-
moeglichkeit wie im Haupt-Patchmonitor (Kanal + Strategie je App) und einer
direkten Installations-Moeglichkeit. Aenderungen an Kanal/Strategie werden
sofort persistiert und ueber den ``on_reload``-Rueckruf in den normalen
Patchmonitor uebernommen (Live-Test-Wunsch Patrick, 2026-07-02).

Bewusst schlank gehalten: Das Dialog buendelt NUR die Update-Zeilen (der
Haupt-Patchmonitor bleibt die volle Uebersicht). Installations-Pipeline,
Kanal-/Strategie-Persistenz und der DB-Reload werden ueber Rueckrufe an das
aufrufende:class:`PatchConsoleWidget` delegiert — keine Duplizierung der
Batch-Worker-Logik, kein direkter ``data/``-Zugriff aus dieser ``gui/``-Datei.

Schicht: ``gui/``. Die eigentliche Konfigurations-Persistenz laeuft ueber den
injizierten Inventar-Service (``set_channel_override``/``set_strategy``), der
Batch-Start ueber den ``on_install``-Rueckruf.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
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

from core import theme
from core.logger import get_logger
from core.patch_result import PatchScanResult
from core.widgets.button_styles import primary_button_qss, secondary_button_qss

_log = get_logger(__name__)

# Spalten der kompakten Update-Tabelle (bewusst weniger als im Haupt-Monitor).
_C_CHECK = 0
_C_NAME = 1
_C_VER = 2
_C_SRC = 3
_C_CHAN = 4
_C_STRAT = 5
_C_COUNT = 6


class QuickUpdatesDialog(QDialog):
    """Modaler Dialog mit den gefundenen Updates + Konfig + Direkt-Installation.

    Args:
        updates: Die gefundenen, aktualisierbaren:class:`PatchScanResult`-Zeilen
            (bereits auf „Update verfuegbar" gefiltert). Darf nicht leer sein —
            der Aufrufer oeffnet den Dialog nur bei mindestens einem Update.
        channel_labels: Kanal-Schluessel -> Anzeigetext (Reihenfolge = Anzeige).
        strategy_labels: Strategie-Enum -> Anzeigetext (Reihenfolge = Anzeige).
        is_upgradeable: Praedikat, ob eine Zeile direkt installierbar ist
            (bekommt eine aktive Checkbox).
        source_label: Formatiert die Herkunft (``result.source``) lesbar.
        service: Inventar-Service mit ``set_channel_override(name, winget_id,
            channel)`` und ``set_strategy(winget_id, strategy)`` — persistiert
            die Konfig-Aenderung (wirkt damit auch im Haupt-Monitor).
        on_reload: Rueckruf, der nach einer Konfig-Aenderung den Haupt-Monitor
            aus der DB neu laedt UND die frische Update-Liste zurueckgibt (so
            spiegelt der Dialog denselben Stand wie der Haupt-Monitor).
        on_install: Rueckruf mit den ausgewaehlten Zeilen — startet die
            bestehende Bestaetigungs-/Batch-Pipeline im Haupt-Widget.
        parent: Eltern-Widget (Modal-Anchor + Memory-Management).
    """

    def __init__(
        self,
        *,
        updates: Sequence[PatchScanResult],
        channel_labels: Mapping[str, str],
        strategy_labels: Mapping[object, str],
        is_upgradeable: Callable[[PatchScanResult], bool],
        source_label: Callable[[str], str],
        service: object,
        on_reload: Callable[[], list[PatchScanResult]],
        on_install: Callable[[list[PatchScanResult]], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._updates = list(updates)
        self._channel_labels = channel_labels
        self._strategy_labels = strategy_labels
        self._is_upgradeable = is_upgradeable
        self._source_label = source_label
        self._service = service
        self._on_reload = on_reload
        self._on_install = on_install

        self.setWindowTitle("Gefundene Updates")
        # Anwendungsmodal (blockiert Eingaben in anderen Fenstern), aber via
        # ``show`` geoeffnet — KEIN nested ``exec``-Event-Loop (vermeidet
        # Qt-Reentrancy/Freeze und haelt den Aufrufer testbar).
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setMinimumSize(720, 420)
        self._build_ui()
        self._populate()

    # ------------------------------------------------------------------
    # Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
        )
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 16)
        root.setSpacing(12)

        title = QLabel("Gefundene Updates")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 17px; font-weight: 700;"
            f" color: {c.TEXT_MAIN};"
        )
        root.addWidget(title)

        info = QLabel(
            "Diese Programme haben ein Update. Wählen Sie die zu installierenden "
            "aus und passen Sie bei Bedarf Kanal und Strategie an — Änderungen "
            "werden in den Patchmonitor übernommen."
        )
        info.setWordWrap(True)
        info.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {c.TEXT_DIM};"
        )
        root.addWidget(info)

        self._table = QTableWidget(0, _C_COUNT)
        self._table.setHorizontalHeaderLabels(
            ["", "Programm", "Version", "Quelle", "Kanal", "Strategie"]
        )
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(_C_NAME, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(_C_CHECK, 32)
        self._table.setColumnWidth(_C_VER, 150)
        self._table.setColumnWidth(_C_SRC, 110)
        self._table.setColumnWidth(_C_CHAN, 130)
        self._table.setColumnWidth(_C_STRAT, 150)
        # EINMAL verbinden (nicht in _populate — das laeuft bei jedem Reload und
        # wuerde den Slot sonst mehrfach anhaengen, Signal-Leak).
        self._table.itemChanged.connect(self._on_item_changed)
        root.addWidget(self._table, stretch=1)

        hint = QLabel(
            "Hinweis: Die Installation erfordert in der Regel Administrator-Rechte; "
            "Windows fragt diese beim Einspielen ab."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_DIM};"
            f" background: {c.CARD_BG}; border-radius: 4px; padding: 6px 8px;"
        )
        root.addWidget(hint)

        buttons = QHBoxLayout()
        self._select_all_btn = QPushButton("Alle markieren")
        self._select_all_btn.setStyleSheet(secondary_button_qss())
        self._select_all_btn.clicked.connect(self._select_all)
        buttons.addWidget(self._select_all_btn)

        self._count_label = QLabel("")
        self._count_label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_DIM};"
        )
        buttons.addWidget(self._count_label)
        buttons.addStretch()

        self._close_btn = QPushButton("Schließen")
        self._close_btn.setStyleSheet(secondary_button_qss())
        self._close_btn.clicked.connect(self.reject)
        buttons.addWidget(self._close_btn)

        self._install_btn = QPushButton("Ausgewählte installieren")
        self._install_btn.setStyleSheet(primary_button_qss())
        self._install_btn.setEnabled(False)
        self._install_btn.clicked.connect(self._on_install_clicked)
        buttons.addWidget(self._install_btn)

        root.addLayout(buttons)

    # ------------------------------------------------------------------
    # Tabelle
    # ------------------------------------------------------------------

    def _populate(self, preselect: set[str] | None = None) -> None:
        """Baut die Tabelle neu auf.

        Args:
            preselect: Identitaets-Schluessel (:meth:`_result_key`) der
                Zeilen, die nach dem Neuaufbau wieder markiert werden sollen —
                erhaelt die Nutzer-Auswahl ueber einen Reload hinweg.
        """
        c = theme.get()
        keep = preselect or set()
        self._table.blockSignals(True)
        self._table.setRowCount(0)
        for result in self._updates:
            row = self._table.rowCount()
            self._table.insertRow(row)

            check = QTableWidgetItem("")
            if self._is_upgradeable(result):
                check.setFlags(
                    Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled
                )
                checked = _result_key(result) in keep
                check.setCheckState(
                    Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
                )
            else:
                check.setFlags(Qt.ItemFlag.ItemIsEnabled)
            check.setData(Qt.ItemDataRole.UserRole, result)
            self._table.setItem(row, _C_CHECK, check)

            self._table.setItem(row, _C_NAME, QTableWidgetItem(result.name))
            self._table.setItem(row, _C_VER, QTableWidgetItem(_version_text(result)))
            self._table.setItem(
                row, _C_SRC, QTableWidgetItem(self._source_label(result.source))
            )
            self._fill_channel_cell(row, result, c)
            self._fill_strategy_cell(row, result, c)
        self._table.blockSignals(False)
        self._update_count()

    def _selected_keys(self) -> set[str]:
        """Identitaets-Schluessel der aktuell markierten Zeilen (fuer Reload-Erhalt)."""
        return {_result_key(r) for r in self._selected_results()}

    def _fill_channel_cell(
        self, row: int, result: PatchScanResult, c: object
    ) -> None:
        if not result.winget_id:
            self._table.setItem(row, _C_CHAN, _dash_item(c))
            return
        combo = QComboBox()
        for ch, label in self._channel_labels.items():
            combo.addItem(label, ch)
        idx = combo.findData(result.channel)
        if idx >= 0:
            combo.setCurrentIndex(idx)
        name = result.name
        winget_id = result.winget_id
        combo.activated.connect(
            lambda _i, cb=combo, n=name, w=winget_id: self._on_channel_changed(
                n, w, cb.currentData()
            )
        )
        self._table.setCellWidget(row, _C_CHAN, combo)

    def _fill_strategy_cell(
        self, row: int, result: PatchScanResult, c: object
    ) -> None:
        if not result.winget_id:
            self._table.setItem(row, _C_STRAT, _dash_item(c))
            return
        combo = QComboBox()
        for strat, label in self._strategy_labels.items():
            combo.addItem(label, strat)
        idx = combo.findData(result.patch_strategy)
        if idx >= 0:
            combo.setCurrentIndex(idx)
        winget_id = result.winget_id
        combo.activated.connect(
            lambda _i, cb=combo, w=winget_id: self._on_strategy_changed(
                w, cb.currentData()
            )
        )
        self._table.setCellWidget(row, _C_STRAT, combo)

    # ------------------------------------------------------------------
    # Interaktion
    # ------------------------------------------------------------------

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() == _C_CHECK:
            self._update_count()

    def _select_all(self) -> None:
        self._table.blockSignals(True)
        for row in range(self._table.rowCount()):
            check = self._table.item(row, _C_CHECK)
            if check is None:
                continue
            if not (check.flags() & Qt.ItemFlag.ItemIsUserCheckable):
                continue
            check.setCheckState(Qt.CheckState.Checked)
        self._table.blockSignals(False)
        self._update_count()

    def _selected_results(self) -> list[PatchScanResult]:
        selected: list[PatchScanResult] = []
        for row in range(self._table.rowCount()):
            check = self._table.item(row, _C_CHECK)
            if check is None or check.checkState() != Qt.CheckState.Checked:
                continue
            result = check.data(Qt.ItemDataRole.UserRole)
            if isinstance(result, PatchScanResult):
                selected.append(result)
        return selected

    def _update_count(self) -> None:
        n = len(self._selected_results())
        self._count_label.setText(f"{n} ausgewählt" if n else "")
        self._install_btn.setEnabled(n > 0)

    def _on_channel_changed(self, name: str, winget_id: str, channel: object) -> None:
        try:
            self._service.set_channel_override(name, winget_id, channel)
        except Exception:  # noqa: BLE001 — Persistenz darf den Dialog nicht crashen
            _log.exception("Kanal-Aenderung nicht persistiert (winget_id=%s)", winget_id)
            return
        # Verzoegert neu laden: das ausloesende QComboBox darf nicht mitten in
        # seiner eigenen ``activated``-Verarbeitung zerstoert werden (wie im
        # Haupt-Monitor/).
        QTimer.singleShot(0, self._reload)

    def _on_strategy_changed(self, winget_id: str, strategy: object) -> None:
        try:
            self._service.set_strategy(winget_id, strategy)
        except Exception:  # noqa: BLE001 — Persistenz darf den Dialog nicht crashen
            _log.exception(
                "Strategie-Aenderung nicht persistiert (winget_id=%s)", winget_id
            )
            return
        QTimer.singleShot(0, self._reload)

    def _reload(self) -> None:
        """Laedt den Stand nach einer Konfig-Aenderung neu (Dialog + Haupt-Monitor)."""
        # Auswahl VOR dem Neuaufbau sichern, damit eine Kanal-/Strategie-Aenderung
        # nicht die bereits gesetzten Haekchen verwirft (Live-Test-Bug 2026-07-02).
        keep = self._selected_keys()
        try:
            self._updates = self._on_reload()
        except Exception:  # noqa: BLE001 — Reload darf den Dialog nicht crashen
            _log.exception("Quick-Update-Reload fehlgeschlagen")
            return
        if not self._updates:
            # Keine Updates mehr (z. B. alle auf „Nicht patchen" gestellt) —
            # Dialog schliessen, der Haupt-Monitor ist bereits aktualisiert.
            self.accept()
            return
        self._populate(preselect=keep)

    def _on_install_clicked(self) -> None:
        selected = self._selected_results()
        if not selected:
            return
        # Bestaetigung + Batch-Start laufen im Haupt-Widget (bestehende Pipeline);
        # der Fortschritt ist danach dort im Live-Log sichtbar.
        self._on_install(selected)
        self.accept()


# ---------------------------------------------------------------------------
# Modul-Helfer
# ---------------------------------------------------------------------------


def _version_text(result: PatchScanResult) -> str:
    """Formatiert die Versionszeile als ``"1.0 -> 2.0"`` bzw. Teilangaben."""
    frm = result.installed_version or ""
    to = result.available_version or ""
    if frm and to:
        return f"{frm} → {to}"
    if to:
        return f"→ {to}"
    return frm


def _dash_item(c: object) -> QTableWidgetItem:
    item = QTableWidgetItem("—")  # em-dash
    item.setForeground(QColor(c.TEXT_DIM))  # type: ignore[attr-defined]
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    return item


def _result_key(result: PatchScanResult) -> str:
    """Stabiler Identitaets-Schluessel einer Update-Zeile (Reload-Auswahl-Erhalt).

    Bevorzugt die ``winget_id`` (stabil ueber einen DB-Reload); faellt auf den
    Programmnamen zurueck, falls keine ID vorliegt.
    """
    return result.winget_id or result.name


__all__ = ["QuickUpdatesDialog"]
