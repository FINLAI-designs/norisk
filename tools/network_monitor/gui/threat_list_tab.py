"""network_monitor.gui.threat_list_tab — Tab „Bedrohungslisten" F-D-GUI).

Macht das bislang headless laufende F-D-Feature sichtbar und bedienbar (Pro):

  - **Feeds aktualisieren**: ein „Jetzt aktualisieren"-Button stößt einen
    erzwungenen Refresh der abuse.ch-CC0-Feeds an. Der Netzwerk-Download läuft im
:class:`ThreatFeedRefreshOnceWorker` (QThread) — nie im UI-Thread
    (frontend-design F3). Das Ergebnis tauscht der Parent atomar in den laufenden
:class:`ThreatChecker` (``entries_refreshed``-Signal).
  - **Whitelist (Ausnahmen)**: anzeigen/hinzufügen/entfernen von Netzen, die einen
    Treffer aufheben (gegen Fehlalarme). Persistenz über den DB-freien
:class:`WhitelistService`; jede Änderung meldet der Tab als ``whitelist_changed``
    an den Parent, der sie live in den Checker übernimmt.

Schicht: GUI (Qt). Importiert nur die Application-Schicht (gui→application) —
``MonitorService``-Factories, ``WhitelistService`` und den GUI-Worker.

Author: Patrick Riederich
Version: 1.0 F-D-GUI)
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.widgets.button_styles import (
    danger_button_qss,
    outline_button_qss,
    primary_button_qss,
)
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.network_monitor.domain.exceptions import WhitelistEntryError

if TYPE_CHECKING:
    from tools.network_monitor.application.threat_feed_service import ThreatFeedService
    from tools.network_monitor.application.whitelist_service import WhitelistService
    from tools.network_monitor.domain.models import Network
    from tools.network_monitor.gui.threat_feed_worker import ThreatFeedRefreshOnceWorker


class ThreatListTab(QWidget):
    """Pro-Tab zum Aktualisieren der Threat-Feeds und Pflegen der Whitelist.

    Signals:
        entries_refreshed(list, list): (entries, whitelist) nach einem manuellen
            Refresh — der Parent ruft damit ``ThreatChecker.replace_entries``.
        whitelist_changed(list): Neue Whitelist-Netze nach Add/Remove — der Parent
            ruft damit ``ThreatChecker.replace_whitelist``.

    Args:
        whitelist_service: DB-freier Service für die Whitelist-Pflege. Default:
:meth:`MonitorService.create_whitelist_service`. Tests injizieren einen
            Service mit ``tmp_path``.
        refresh_service_factory: Liefert den:class:`ThreatFeedService` für den
            Refresh-Worker. ``None`` nutzt die Default-Factory (echte Feed-Cache-DB);
            Tests injizieren eine Fake-Factory (keine DB/Netz).
    """

    entries_refreshed = Signal(list, list)
    whitelist_changed = Signal(list)

    def __init__(
        self,
        whitelist_service: WhitelistService | None = None,
        refresh_service_factory: Callable[[], ThreatFeedService] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._log = get_logger(__name__)
        if whitelist_service is None:
            from tools.network_monitor.application.monitor_service import (  # noqa: PLC0415
                MonitorService,
            )

            whitelist_service = MonitorService.create_whitelist_service()
        self._whitelist_service = whitelist_service
        self._refresh_service_factory = refresh_service_factory
        self._refresh_worker: ThreatFeedRefreshOnceWorker | None = None
        self._networks: list[Network] = []

        self._build_layout()
        self._reload_whitelist()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        colors = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)

        root.addLayout(self._build_refresh_section(colors))
        root.addWidget(self._build_separator(colors))
        root.addLayout(self._build_whitelist_section(colors), 1)

    def _build_refresh_section(self, colors: object) -> QVBoxLayout:
        section = QVBoxLayout()
        section.setSpacing(8)

        header = QLabel("Feeds aktualisieren")
        header.setStyleSheet(
            f"font-size: 14px; font-weight: 600; color: {colors.ACCENT};"
        )
        section.addWidget(header)

        desc = QLabel(
            "NoRisk gleicht Verbindungen gegen lokale und online gepflegte "
            "Bedrohungslisten ab (abuse.ch, CC0). Die Listen aktualisieren sich "
            "automatisch im Hintergrund — hier lädst du sie sofort neu."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {colors.TEXT_DIM};")
        section.addWidget(desc)

        row = QHBoxLayout()
        row.setSpacing(10)
        self._refresh_btn = QPushButton("Jetzt aktualisieren")
        self._refresh_btn.setIcon(get_icon(Icons.REFRESH))
        self._refresh_btn.setStyleSheet(primary_button_qss())
        self._refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_btn.setAccessibleName("Bedrohungslisten jetzt aktualisieren")
        self._refresh_btn.clicked.connect(self._on_refresh_clicked)
        row.addWidget(self._refresh_btn, 0)

        # Ehrlicher First-Run-Hinweis (F-D): die ausgelieferte lokale
        # blocklist.txt ist leer, der Abgleich greift erst nach einem
        # erfolgreichen Online-Refresh. Wird nach dem ersten Refresh durch
        # die N-Netze-aktiv-Meldung ersetzt.
        self._refresh_status = QLabel(
            "Tipp: Direkt nach der Installation ist die lokale Bedrohungsliste "
            "leer, bis der erste Online-Abgleich erfolgreich war — die "
            "Schaltfläche oben holt die Listen sofort."
        )
        self._refresh_status.setWordWrap(True)
        self._refresh_status.setStyleSheet(f"color: {colors.TEXT_DIM};")
        row.addWidget(self._refresh_status, 1)
        section.addLayout(row)

        self._refresh_progress = FinlaiProgressBar()
        self._refresh_progress.setVisible(False)
        section.addWidget(self._refresh_progress)

        return section

    def _build_whitelist_section(self, colors: object) -> QVBoxLayout:
        section = QVBoxLayout()
        section.setSpacing(8)

        header = QLabel("Whitelist (Ausnahmen)")
        header.setStyleSheet(
            f"font-size: 14px; font-weight: 600; color: {colors.ACCENT};"
        )
        section.addWidget(header)

        desc = QLabel(
            "Netze in der Whitelist gelten nie als verdächtig — nützlich gegen "
            "Fehlalarme, etwa für deinen eigenen VPN-Endpunkt. Erlaubt sind IPv4/"
            "IPv6 als einzelne Adresse oder als CIDR-Bereich."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {colors.TEXT_DIM};")
        section.addWidget(desc)

        input_row = QHBoxLayout()
        input_row.setSpacing(10)
        self._entry_input = QLineEdit()
        self._entry_input.setPlaceholderText(
            "z. B. 203.0.113.10 oder 10.0.0.0/8"
        )
        self._entry_input.setAccessibleName("Neue Whitelist-Ausnahme")
        self._entry_input.returnPressed.connect(self._on_add_clicked)
        input_row.addWidget(self._entry_input, 1)

        self._add_btn = QPushButton("Hinzufügen")
        self._add_btn.setIcon(get_icon(Icons.ADD))
        self._add_btn.setStyleSheet(outline_button_qss())
        self._add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._add_btn.setAccessibleName("Ausnahme zur Whitelist hinzufügen")
        self._add_btn.clicked.connect(self._on_add_clicked)
        input_row.addWidget(self._add_btn, 0)
        section.addLayout(input_row)

        self._input_error = QLabel("")
        self._input_error.setWordWrap(True)
        self._input_error.setStyleSheet(f"color: {colors.DANGER}; font-size: 12px;")
        self._input_error.setVisible(False)
        section.addWidget(self._input_error)

        # Empty-State (frontend-design F1) — sichtbar wenn die Liste leer ist.
        self._empty_state = QLabel(
            "Noch keine Ausnahmen. Füge ein Netz hinzu, um Fehlalarme "
            "gezielt zu unterdrücken."
        )
        self._empty_state.setWordWrap(True)
        self._empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_state.setStyleSheet(
            f"color: {colors.TEXT_DIM}; padding: 16px;"
        )
        section.addWidget(self._empty_state)

        self._list = QListWidget()
        self._list.setAccessibleName("Whitelist-Ausnahmen")
        self._list.itemSelectionChanged.connect(self._update_remove_state)
        section.addWidget(self._list, 1)

        self._remove_btn = QPushButton("Entfernen")
        self._remove_btn.setIcon(get_icon(Icons.DELETE))
        self._remove_btn.setStyleSheet(danger_button_qss())
        self._remove_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._remove_btn.setEnabled(False)
        self._remove_btn.setAccessibleName("Ausgewählte Ausnahme entfernen")
        self._remove_btn.clicked.connect(self._on_remove_clicked)
        section.addWidget(self._remove_btn, 0, Qt.AlignmentFlag.AlignRight)

        # Eigene Status-/Feedback-Zeile der Whitelist-Sektion (Add/Remove/IO) —
        # getrennt vom Feed-Refresh-Status, damit sich beide nicht überschreiben.
        self._whitelist_status = QLabel("")
        self._whitelist_status.setWordWrap(True)
        self._whitelist_status_color = colors.TEXT_DIM
        self._whitelist_status_error_color = colors.DANGER
        self._whitelist_status.setStyleSheet(
            f"color: {self._whitelist_status_color};"
        )
        section.addWidget(self._whitelist_status)

        return section

    def _build_separator(self, colors: object) -> QWidget:
        line = QWidget()
        line.setFixedHeight(1)
        line.setStyleSheet(f"background-color: {colors.BORDER};")
        return line

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    @Slot()
    def _on_refresh_clicked(self) -> None:
        """Startet einen einmaligen, erzwungenen Feed-Refresh im Worker-Thread."""
        if self._refresh_worker is not None:
            return  # läuft bereits
        from tools.network_monitor.gui.threat_feed_worker import (  # noqa: PLC0415
            ThreatFeedRefreshOnceWorker,
        )

        self._refresh_btn.setEnabled(False)
        self._refresh_status.setText("Aktualisiere Bedrohungslisten …")
        self._refresh_progress.setVisible(True)
        self._refresh_progress.start_indeterminate()

        worker = ThreatFeedRefreshOnceWorker(self._refresh_service_factory)
        worker.refreshed.connect(self._on_refresh_done)
        worker.failed.connect(self._on_refresh_failed)
        worker.finished.connect(self._clear_refresh_worker)
        self._refresh_worker = worker
        worker.start()

    @Slot(list, list, int, int)
    def _on_refresh_done(
        self,
        entries: list,
        _worker_whitelist: list,
        updated_sources: int,
        source_errors: int,
    ) -> None:
        """Übernimmt das Refresh-Ergebnis in die Anzeige + meldet es dem Parent."""
        self._finish_refresh_ui()
        if source_errors:
            self._refresh_status.setText(
                f"{len(entries)} Netze aktiv · {updated_sources} Quellen "
                f"aktualisiert · {source_errors} nicht erreichbar."
            )
        else:
            self._refresh_status.setText(
                f"{len(entries)} Netze aktiv · {updated_sources} Quellen "
                "aktualisiert."
            )
        # ``whitelist`` aus dem Worker-Snapshot wird bewusst NICHT für den Live-Swap
        # genutzt: er kann eine zwischenzeitliche Whitelist-Änderung des Nutzers
        # überschreiben (Lost Update). Stattdessen frisch aus dem Service laden
        # (autoritativ, persistiert) und die Anzeige synchronisieren.
        self._reload_whitelist()
        self.entries_refreshed.emit(entries, list(self._networks))

    @Slot(str)
    def _on_refresh_failed(self, message: str) -> None:
        """Zeigt eine nutzerlesbare Fehlermeldung (kein Roh-Exception-Text)."""
        self._finish_refresh_ui()
        self._refresh_status.setText(message)

    def _finish_refresh_ui(self) -> None:
        """Setzt Button/Progress nach Abschluss (Erfolg ODER Fehler) zurück."""
        self._refresh_progress.reset()
        self._refresh_progress.setVisible(False)
        self._refresh_btn.setEnabled(True)

    @Slot()
    def _clear_refresh_worker(self) -> None:
        """Gibt die Worker-Referenz frei, sobald der Thread beendet ist."""
        self._refresh_worker = None

    # ------------------------------------------------------------------
    # Whitelist
    # ------------------------------------------------------------------

    @Slot()
    def _on_add_clicked(self) -> None:
        """Fügt die Eingabe als Whitelist-Ausnahme hinzu (Inline-Validierung)."""
        token = self._entry_input.text().strip()
        if not token:
            return
        try:
            network = self._whitelist_service.add(token)
        except WhitelistEntryError as exc:
            self._show_input_error(str(exc))
            return
        except OSError as exc:
            self._log.warning("Whitelist speichern fehlgeschlagen: %s", exc)
            self._set_whitelist_status(
                "Ausnahme konnte nicht gespeichert werden — prüfe die "
                "Schreibrechte im Profil-Ordner.",
                error=True,
            )
            return
        self._input_error.setVisible(False)
        self._entry_input.clear()
        self._reload_whitelist()
        self._set_whitelist_status(f"{network} zur Whitelist hinzugefügt.")
        self.whitelist_changed.emit(list(self._networks))

    @Slot()
    def _on_remove_clicked(self) -> None:
        """Entfernt die ausgewählte Ausnahme nach Bestätigung (FinlaiConfirmDialog)."""
        row = self._list.currentRow()
        if row < 0 or row >= len(self._networks):
            return
        network = self._networks[row]

        from PySide6.QtWidgets import QDialog  # noqa: PLC0415

        from core.dialogs import FinlaiConfirmDialog  # noqa: PLC0415

        dlg = FinlaiConfirmDialog(
            "Ausnahme entfernen?",
            f"Soll {network} aus der Whitelist entfernt werden? Treffer auf "
            "dieses Netz werden danach wieder als verdächtig markiert.",
            confirm_text="Entfernen",
            parent=self.window(),
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._whitelist_service.remove(network)
        except OSError as exc:
            self._log.warning("Whitelist speichern fehlgeschlagen: %s", exc)
            self._set_whitelist_status(
                "Ausnahme konnte nicht entfernt werden — prüfe die "
                "Schreibrechte im Profil-Ordner.",
                error=True,
            )
            return
        self._reload_whitelist()
        self._set_whitelist_status(f"{network} aus der Whitelist entfernt.")
        self.whitelist_changed.emit(list(self._networks))

    def _reload_whitelist(self) -> None:
        """Lädt die Whitelist neu und füllt Liste + Empty-State (Single Source: Datei)."""
        self._networks = self._whitelist_service.load()
        self._list.clear()
        for network in self._networks:
            self._list.addItem(str(network))
        has_entries = bool(self._networks)
        self._list.setVisible(has_entries)
        self._empty_state.setVisible(not has_entries)
        self._update_remove_state()

    @Slot()
    def _update_remove_state(self) -> None:
        """Aktiviert „Entfernen" nur bei aktueller Auswahl."""
        self._remove_btn.setEnabled(self._list.currentRow() >= 0)

    def _show_input_error(self, message: str) -> None:
        """Zeigt einen Inline-Validierungsfehler am Eingabefeld (rot)."""
        self._input_error.setText(message)
        self._input_error.setVisible(True)

    def _set_whitelist_status(self, message: str, *, error: bool = False) -> None:
        """Schreibt eine Status-/Fehlermeldung in die Whitelist-Sektionszeile.

        Getrennt vom Feed-Refresh-Status, damit Whitelist-Aktionen und Feed-Refresh
        sich nicht gegenseitig überschreiben.

        Args:
            message: Anzuzeigender Text (Sie-Form).
            error: ``True`` rendert die Zeile in der Fehler-Farbe (DANGER).
        """
        color = (
            self._whitelist_status_error_color
            if error
            else self._whitelist_status_color
        )
        self._whitelist_status.setStyleSheet(f"color: {color};")
        self._whitelist_status.setText(message)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        """Stoppt einen ggf. laufenden Refresh-Worker sauber (Parent-Shutdown).

        Der Netzwerk-Download kann bis zum Client-Timeout (~20 s) laufen und ist
        nicht hart unterbrechbar. Beendet sich der Worker nicht im Warte-Fenster,
        wird die Referenz **bewusst gehalten** (nicht auf ``None`` gesetzt): würde
        die letzte Python-Referenz auf einen noch laufenden ``QThread`` fallen,
        zerstörte der GC das C++-Objekt unter dem laufenden Thread → „QThread:
        Destroyed while thread is still running" / Absturz. ``shutdown`` wird bei
        JEDEM Tab-Wechsel weg vom Tool aufgerufen, nicht nur beim App-Ende — daher
        ist das hier kritisch. ``_clear_refresh_worker`` (an ``finished`` gebunden)
        gibt die Referenz frei, sobald der Download tatsächlich endet.
        """
        worker = self._refresh_worker
        if worker is None:
            return
        try:
            worker.requestInterruption()
            if worker.wait(2000):
                self._refresh_worker = None
            else:
                # Noch im (nicht abbrechbaren) Download — Referenz HALTEN.
                self._log.warning(
                    "Threat-Refresh-Worker läuft nach 2s noch — Referenz gehalten "
                    "bis Abschluss (kein QThread-Teardown unter laufendem Thread)."
                )
        except RuntimeError:
            self._refresh_worker = None
