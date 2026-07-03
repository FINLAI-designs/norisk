"""network_monitor.gui.scan_link — geteilter „Diese IP scannen"-Deep-Link.

Ein einziges Kontextmenü-Muster für alle Netzwerkmonitor-Tabellen
(ConnectionTable, AnomalyAlertTab, ConversationTab) statt 3 Kopien (Review ARCH-02):
Rechtsklick → „Diese IP scannen: <ip>" → ``MainWindow.navigate_to('network_scanner',
target=<ip>)``. Der Tool-Key liegt zentral als Konstante (war zuvor 3× hartkodiert).

:func:`navigate_to_scan` kapselt die (testbare) Navigations-Logik; das modale
:func:`show_scan_ip_menu` baut + zeigt das themed Menü und ruft sie bei Auswahl.

Schicht: gui/ (Qt-Helfer).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QPoint
from PySide6.QtWidgets import QMenu, QWidget

from core.widgets.button_styles import menu_qss

#: Tool-Key des Netzwerk-Scanners für den Deep-Link (zentral statt 3× hartkodiert).
NETWORK_SCANNER_TOOL_KEY = "network_scanner"


def navigate_to_scan(widget: QWidget, ip: str) -> None:
    """Öffnet den Netzwerk-Scanner für ``ip`` über ``window.navigate_to``.

    No-op bei leerer IP oder wenn das Fenster keine ``navigate_to``-API hat
    (z. B. abgedockt/Test) — kein Crash.

    Args:
        widget: Ein Widget im Fenster-Baum (liefert ``window``).
        ip: Ziel-IP für den Scan.
    """
    if not ip:
        return
    navigate = getattr(widget.window(), "navigate_to", None)
    if callable(navigate):
        navigate(NETWORK_SCANNER_TOOL_KEY, target=ip)


def show_scan_ip_menu(widget: QWidget, ip: str, global_pos: QPoint) -> None:
    """Zeigt das Kontextmenü „Diese IP scannen: <ip>" und navigiert bei Auswahl.

    No-op bei leerer IP. Das Menü ist über:func:`core.widgets.button_styles.menu_qss`
    themed (QMenu hat keine globale Theme-Regel).

    Args:
        widget: Parent-Widget des Menüs (auch Fenster-Anker für die Navigation).
        ip: Ziel-IP (leer/„–" → kein Menü).
        global_pos: Globale Mausposition (``viewport.mapToGlobal(pos)``).
    """
    if not ip:
        return
    menu = QMenu(widget)
    menu.setStyleSheet(menu_qss())
    action = menu.addAction(f"Diese IP scannen: {ip}")
    if menu.exec(global_pos) is action:
        navigate_to_scan(widget, ip)
