"""GUI-Tests fuer den eingebetteten Live-Tab im Network-Scanner
(Sprint S5a).

Deckt ab:
  - ``NetworkMonitorWidget(auto_start_worker=False)`` startet keinen Worker.
  - ``start_worker``/``stop_worker`` sind idempotent.
  - ``NetworkScannerWidget`` hat 3 Tabs in der Reihenfolge
    Scan (Discovery+Port-Scan vereint, D2) / Verlauf / Live.
  -: der Live-Tab wird LAZY gebaut — erst der erste Wechsel auf den
    Live-Tab konstruiert das eingebettete ``NetworkMonitorWidget`` (vorher
    eager im Scan-Tab-Aufbau -> Ladezeit-Regression).
  - Tab-Wechsel zum Live-Tab startet den Worker, Tab-Wechsel weg stoppt ihn.
  - ``apply_navigation(target=...)`` wechselt zum "Scan"-Tab (Index 0)
    und fuellt das Ziel-Eingabefeld.
  - ``closeEvent`` stoppt den Live-Worker (kein Memory-Leak).
  - ``app_config`` hat keinen ``network_monitor``-Eintrag in der
    Sidebar-Gruppe ``scanner_tools``.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtGui import QCloseEvent

from tools.network_monitor.gui.network_monitor_widget import NetworkMonitorWidget
from tools.network_scanner.application.network_service import NetworkService
from tools.network_scanner.gui.network_scanner_widget import (
    _LIVE_TAB_INDEX,
    NetworkScannerWidget,
)

pytestmark = pytest.mark.gui

# ---------------------------------------------------------------------------
# NetworkMonitorWidget: auto_start_worker / start_worker
# ---------------------------------------------------------------------------


@pytest.fixture
def monitor_no_autostart(qtbot, app):  # noqa: ARG001
    """Monitor-Widget ohne Auto-Start des Workers."""
    w = NetworkMonitorWidget(auto_start_worker=False)
    qtbot.add_widget(w)
    yield w
    w.stop_worker()


def test_monitor_auto_start_worker_false_startet_keinen_worker(
    monitor_no_autostart,
):
    """Mit ``auto_start_worker=False`` ist ``_worker`` ``None``."""
    assert monitor_no_autostart._worker is None  # noqa: SLF001


def test_monitor_start_worker_initialisiert_worker(monitor_no_autostart):
    """``start_worker`` legt einen Worker an, wenn keiner laeuft."""
    monitor_no_autostart.start_worker()
    assert monitor_no_autostart._worker is not None  # noqa: SLF001


def test_monitor_start_worker_idempotent(monitor_no_autostart):
    """``start_worker`` aufgerufen waehrend ein Worker laeuft -> No-op."""
    monitor_no_autostart.start_worker()
    first = monitor_no_autostart._worker  # noqa: SLF001
    monitor_no_autostart.start_worker()
    assert monitor_no_autostart._worker is first  # noqa: SLF001


def test_monitor_stop_worker_setzt_worker_auf_none(monitor_no_autostart):
    """``stop_worker`` raeumt den Worker-Slot auf."""
    monitor_no_autostart.start_worker()
    assert monitor_no_autostart._worker is not None  # noqa: SLF001
    monitor_no_autostart.stop_worker()
    assert monitor_no_autostart._worker is None  # noqa: SLF001


def test_monitor_stop_worker_ohne_worker_kein_crash(monitor_no_autostart):
    """``stop_worker`` ohne aktiven Worker ist idempotent."""
    monitor_no_autostart.stop_worker()
    monitor_no_autostart.stop_worker()  # zweimal: kein Crash


# ---------------------------------------------------------------------------
# NetworkScannerWidget: 3 Tabs + Live-Embedding
# ---------------------------------------------------------------------------


@pytest.fixture
def scanner_widget(qtbot, app):  # noqa: ARG001
    """NetworkScannerWidget mit gemocktem Service + Live-Tab."""
    service = MagicMock(spec=NetworkService)
    # GUI ruft eigene_netzwerk_info/lade_letzte_scans jetzt
    # ueber den Service. Ohne explizite Return-Werte liefert der Mock
    # MagicMock-Objekte zurueck, die nicht entpackbar sind.
    service.eigene_netzwerk_info.return_value = ("", "", "")
    service.lade_letzte_scans.return_value = []
    w = NetworkScannerWidget(service)
    qtbot.add_widget(w)
    yield w
    # Worker des eingebetteten Monitors auf jeden Fall stoppen.: der
    # Live-Tab wird lazy gebaut -> ohne Live-Besuch existiert kein Widget.
    if w._monitor_widget is not None:  # noqa: SLF001
        try:
            w._monitor_widget.stop_worker()  # noqa: SLF001
        except RuntimeError:
            pass


def test_scanner_hat_drei_tabs(scanner_widget):
    """Scan (Discovery+Port-Scan, D2) / Verlauf / Live = 3 Tabs."""
    assert scanner_widget._tabs.count() == 3  # noqa: SLF001


def test_scanner_tab_titel(scanner_widget):
    """Tab-Reihenfolge nach D2: Scan (0) / Verlauf (1) / Live (2)."""
    titles = [
        scanner_widget._tabs.tabText(i)  # noqa: SLF001
        for i in range(scanner_widget._tabs.count())  # noqa: SLF001
    ]
    assert titles == ["Scan", "Verlauf", "Live"]


def test_scan_tab_enthaelt_discovery_und_port_scan(scanner_widget):
    """Der vereinte "Scan"-Tab (D2) haelt Discovery- UND Port-Scan-Widgets.

    Beide Stufen liegen jetzt in EINEM Tab (vertikaler Splitter), daher
    muessen sowohl das Discovery-Subnetz-Feld als auch das Port-Scan-
    Ziel-Feld existieren und gerendert sein.
    """
    from PySide6.QtWidgets import QSplitter

    scan_tab = scanner_widget._tabs.widget(0)  # noqa: SLF001
    assert scan_tab.findChild(QSplitter) is not None
    # Beide Eingabefelder existieren (Discovery + Port-Scan).
    assert scanner_widget._subnet_input is not None  # noqa: SLF001
    assert scanner_widget._ziel_input is not None  # noqa: SLF001


def test_live_tab_lazy_erst_bei_tab_wechsel_gebaut(scanner_widget):
    """: Der Live-Tab wird NICHT eager gebaut.

    Beim Oeffnen des Scanners (Scan-Tab aktiv) existiert noch kein
    ``NetworkMonitorWidget`` — der Tab haelt nur einen Platzhalter. Erst der
    erste Wechsel auf den Live-Tab konstruiert das Monitor-Widget und haengt
    es in den Live-Container. So zahlt der Scan-Tab-Aufbau keine Monitor-/
    DB-Last (Ladezeit-Regression: 2-4 GROUP-BY-Queries + bis 4 DB-Opens).
    """
    # Vor dem ersten Live-Besuch existiert kein Monitor-Widget — der Tab traegt
    # nur den Platzhalter. (Der Swap selbst wird worker-frei in
    # ``test_ensure_live_tab_baut_und_tauscht_platzhalter`` verifiziert, damit
    # die Swap-Zusicherung nicht am flaky Qt-Worker-Teardown haengt.)
    assert scanner_widget._monitor_widget is None  # noqa: SLF001

    # Erster Wechsel auf den Live-Tab baut das Monitor-Widget lazy.
    scanner_widget._tabs.setCurrentIndex(_LIVE_TAB_INDEX)  # noqa: SLF001
    assert isinstance(scanner_widget._monitor_widget, NetworkMonitorWidget)  # noqa: SLF001


def test_ensure_live_tab_baut_und_tauscht_platzhalter(scanner_widget):
    """``_ensure_live_tab`` baut das Monitor-Widget (ohne Worker) und ersetzt
    den Platzhalter im Live-Container.

    Worker-frei (ruft ``_ensure_live_tab`` direkt, nicht ueber den Tab-Wechsel),
    daher teardown-stabil — verifiziert den Platzhalter->Monitor-Swap und dass
    ``auto_start_worker=False`` greift.
    """
    live_container = scanner_widget._tabs.widget(_LIVE_TAB_INDEX)  # noqa: SLF001
    # Vorzustand: Platzhalter da, kein Monitor im Container.
    assert scanner_widget._live_placeholder is not None  # noqa: SLF001
    assert live_container.findChild(NetworkMonitorWidget) is None

    scanner_widget._ensure_live_tab()  # noqa: SLF001

    assert scanner_widget._monitor_widget is not None  # noqa: SLF001
    assert scanner_widget._monitor_widget._worker is None  # noqa: SLF001
    # Platzhalter ersetzt (Python-Referenz geloescht), Monitor im Container.
    assert scanner_widget._live_placeholder is None  # noqa: SLF001
    assert (
        live_container.findChild(NetworkMonitorWidget)
        is scanner_widget._monitor_widget  # noqa: SLF001
    )


def test_ensure_live_tab_idempotent(scanner_widget):
    """Mehrfacher Aufruf baut KEIN zweites Monitor-Widget."""
    scanner_widget._ensure_live_tab()  # noqa: SLF001
    first = scanner_widget._monitor_widget  # noqa: SLF001
    scanner_widget._ensure_live_tab()  # noqa: SLF001
    assert scanner_widget._monitor_widget is first  # noqa: SLF001


# ---------------------------------------------------------------------------
# Tab-Lifecycle
# ---------------------------------------------------------------------------


def test_tab_wechsel_zum_live_tab_startet_worker(scanner_widget):
    """``setCurrentIndex(_LIVE_TAB_INDEX)`` baut den Live-Tab lazy + startet ``start_worker``."""
    scanner_widget._tabs.setCurrentIndex(_LIVE_TAB_INDEX)  # noqa: SLF001
    assert scanner_widget._monitor_widget is not None  # noqa: SLF001 -- lazy gebaut
    assert scanner_widget._monitor_widget._worker is not None  # noqa: SLF001


def test_tab_wechsel_weg_vom_live_tab_stoppt_worker(scanner_widget):
    """Wechsel auf Tab 0 nach Live-Aktivierung stoppt den Worker."""
    scanner_widget._tabs.setCurrentIndex(_LIVE_TAB_INDEX)  # noqa: SLF001
    assert scanner_widget._monitor_widget is not None  # noqa: SLF001 -- lazy gebaut
    assert scanner_widget._monitor_widget._worker is not None  # noqa: SLF001
    scanner_widget._tabs.setCurrentIndex(0)  # noqa: SLF001
    assert scanner_widget._monitor_widget._worker is None  # noqa: SLF001


def test_close_event_stoppt_live_worker(scanner_widget):
    """``closeEvent`` ruft ``monitor.stop_worker`` auf."""
    scanner_widget._tabs.setCurrentIndex(_LIVE_TAB_INDEX)  # noqa: SLF001
    assert scanner_widget._monitor_widget is not None  # noqa: SLF001 -- lazy gebaut
    assert scanner_widget._monitor_widget._worker is not None  # noqa: SLF001
    scanner_widget.closeEvent(QCloseEvent())
    assert scanner_widget._monitor_widget._worker is None  # noqa: SLF001


# ---------------------------------------------------------------------------
# apply_navigation switcht zum vereinten "Scan"-Tab (Index 0, D2)
# ---------------------------------------------------------------------------


def test_apply_navigation_target_wechselt_zu_scan_tab(scanner_widget):
    """``apply_navigation(target=...)`` wechselt auf den "Scan"-Tab (Index 0)."""
    scanner_widget._tabs.setCurrentIndex(1)  # noqa: SLF001 -- Verlauf aktiv
    scanner_widget.apply_navigation(target="10.0.0.5")
    assert scanner_widget._tabs.currentIndex() == 0  # noqa: SLF001
    assert scanner_widget._ziel_input.text() == "10.0.0.5"  # noqa: SLF001


def test_apply_navigation_ohne_target_aendert_tab_nicht(scanner_widget):
    """Ohne ``target`` bleibt der aktuelle Tab unveraendert."""
    scanner_widget._tabs.setCurrentIndex(1)  # noqa: SLF001 -- Verlauf
    scanner_widget.apply_navigation(domain="x.de")  # nicht erkannt
    assert scanner_widget._tabs.currentIndex() == 1  # noqa: SLF001


def test_apply_navigation_target_leerstring_aendert_tab_nicht(scanner_widget):
    """Whitespace-only ``target`` wird ignoriert (auch kein Tab-Wechsel)."""
    scanner_widget._tabs.setCurrentIndex(1)  # noqa: SLF001 -- Verlauf
    scanner_widget.apply_navigation(target="   ")
    assert scanner_widget._tabs.currentIndex() == 1  # noqa: SLF001


# ---------------------------------------------------------------------------
# Ziel-Placeholder zeigt ein internes Beispiel-F4)
# ---------------------------------------------------------------------------


def test_ziel_placeholder_zeigt_internes_beispiel(scanner_widget):
    """Der Placeholder darf kein oeffentliches Hostname-Beispiel zeigen.

    Hintergrund-F4): Ein Hostname wie ``example.com`` wird vom
    Scanner durch die 202c-Schranke (nur interne IPs) IMMER blockiert —
    ``example.com`` als Beispiel ist daher irrefuehrend. Der Placeholder
    soll ein internes (RFC-1918) Beispiel zeigen.
    """
    placeholder = scanner_widget._ziel_input.placeholderText()  # noqa: SLF001
    assert "example.com" not in placeholder
    # Mindestens ein RFC-1918-Beispiel als Hinweis auf "intern".
    assert any(
        token in placeholder
        for token in ("10.", "192.168.", "172.16.")
    ), f"kein internes IP-Beispiel im Placeholder: {placeholder!r}"


# ---------------------------------------------------------------------------
# closeEvent defensive
# ---------------------------------------------------------------------------


def test_close_event_ueberlebt_runtime_error_im_stop(scanner_widget):
    """Wenn ``stop_worker`` einen ``RuntimeError`` wirft, wird er gefressen."""
    scanner_widget._ensure_live_tab()  # noqa: SLF001 -- Monitor-Widget bauen
    with patch.object(
        scanner_widget._monitor_widget,  # noqa: SLF001
        "stop_worker",
        side_effect=RuntimeError("zerstoertes Widget"),
    ):
        scanner_widget.closeEvent(QCloseEvent())  # darf nicht crashen


def test_close_event_ohne_live_besuch_kein_crash(scanner_widget):
    """: Ohne ersten Live-Besuch existiert kein Monitor-Widget —
    ``closeEvent`` darf trotzdem nicht crashen (None-Guard)."""
    assert scanner_widget._monitor_widget is None  # noqa: SLF001
    scanner_widget.closeEvent(QCloseEvent())  # darf nicht crashen


# ---------------------------------------------------------------------------
# Sidebar-Eintrag entfernt
# ---------------------------------------------------------------------------


def test_app_config_pruefen_group_haelt_network_scanner():
    """``apps.app_config.NORISK_CONFIG`` listet ``network_scanner`` im
    ``pruefen``-Bereich, Phase 3 — 6-Bereiche-IA).

    Triage P1: der Standalone-``network_monitor`` wurde aus der Sidebar
    entfernt (kein eigener Eintrag mehr) — er lebt nur noch als eingebetteter
    Live-Tab im network_scanner. Daher ist er in KEINER Sidebar-Gruppe."""
    from apps.app_config import NORISK_CONFIG

    pruefen_group = next(
        g for g in NORISK_CONFIG.sidebar_groups if g["key"] == "pruefen"
    )
    assert "network_scanner" in pruefen_group["tool_keys"]
    assert "network_monitor" not in pruefen_group["tool_keys"]
    ueberwachen_group = next(
        g for g in NORISK_CONFIG.sidebar_groups if g["key"] == "ueberwachen"
    )
    # P1: nicht mehr als Standalone in ueberwachen.
    assert "network_monitor" not in ueberwachen_group["tool_keys"]


def test_app_config_tool_modules_behaelt_network_monitor():
    """Modul-Registrierung bleibt erhalten — der Live-Tab importiert
    ``NetworkMonitorWidget`` direkt, der PyInstaller-Spec listet das
    Tool-Modul, und ein hypothetischer ``navigate_to('network_monitor')``
    soll nicht crashen."""
    from apps.app_config import NORISK_CONFIG

    assert "tools.network_monitor.tool" in NORISK_CONFIG.tool_modules


# ---------------------------------------------------------------------------
# Host-Discovery: Zeilen-Selektion statt Item-Checkboxen
# ---------------------------------------------------------------------------


def test_discovery_uses_row_selection_not_checkboxes(scanner_widget):
    """: Auswahl ueber Zeilen-Selektion (ExtendedSelection), nicht ueber
    (im Dark-Theme unsichtbare) Item-Checkboxen; ``_ausgewaehlte_scannen``
    liest ``selectedItems`` und uebertraegt die IP ins Port-Scan-Feld."""
    from types import SimpleNamespace

    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QAbstractItemView

    hosts = [
        SimpleNamespace(
            ip="192.168.50.1", hostname="r1", mac_adresse="AA", quelle="arp"
        ),
        SimpleNamespace(
            ip="192.168.50.2", hostname="r2", mac_adresse="BB", quelle="arp"
        ),
        SimpleNamespace(
            ip="192.168.50.3", hostname="r3", mac_adresse=None, quelle="ping"
        ),
    ]
    result = SimpleNamespace(hosts=hosts, dauer_s=1.0)

    scanner_widget._discovery_ergebnis_empfangen(result)  # noqa: SLF001
    tree = scanner_widget._discovery_tree  # noqa: SLF001

    # Checkbox-Spalte raus (3 Spalten), 3 Zeilen, IP in UserRole.
    assert tree.columnCount() == 3
    assert tree.topLevelItemCount() == 3
    assert tree.topLevelItem(0).data(0, Qt.ItemDataRole.UserRole) == "192.168.50.1"

    # Zeilen-Selektion aktiv.
    assert tree.selectionMode() == QAbstractItemView.SelectionMode.ExtendedSelection
    assert (
        tree.selectionBehavior() == QAbstractItemView.SelectionBehavior.SelectRows
    )

    # Standard: alle vorausgewaehlt; Buttons schalten die Selektion.
    assert len(tree.selectedItems()) == 3
    scanner_widget._auswahl_aufheben()  # noqa: SLF001
    assert tree.selectedItems() == []
    scanner_widget._alle_auswaehlen()  # noqa: SLF001
    assert len(tree.selectedItems()) == 3

    # Genau eine Zeile markiert -> Scan uebernimmt diese IP (Multi-Host-Queue,
    # laeuft jetzt ueber _start_scan_thread statt _scan_starten).
    tree.clearSelection()
    tree.topLevelItem(1).setSelected(True)
    with patch.object(scanner_widget, "_start_scan_thread") as scan_mock:  # noqa: SLF001
        scanner_widget._ausgewaehlte_scannen()  # noqa: SLF001
    assert scanner_widget._ziel_input.text() == "192.168.50.2"  # noqa: SLF001
    scan_mock.assert_called_once_with("192.168.50.2")

    # ALLE selektierten Hosts landen in der Queue (vorher nur der erste +
    # ein "bitte manuell eingeben"-Dialog). 3 selektiert -> 1 gestartet + 2 in Queue.
    scanner_widget._alle_auswaehlen()  # noqa: SLF001 -- 3 Hosts
    with patch.object(scanner_widget, "_start_scan_thread") as multi_mock:  # noqa: SLF001
        scanner_widget._ausgewaehlte_scannen()  # noqa: SLF001
    assert scanner_widget._scanning_queue is True  # noqa: SLF001
    multi_mock.assert_called_once()  # erster Host sofort gestartet
    assert len(scanner_widget._scan_queue) == 2  # noqa: SLF001 -- 2 warten


# ---------------------------------------------------------------------------
# AV-Block-Hinweis (erreichbar, aber 0 Ports)
# ---------------------------------------------------------------------------


def test_av_block_hinweis_bei_erreichbar_aber_null_ports(scanner_widget):
    """Erreichbarer Host ohne offene Ports -> neutraler AV-Block-Hinweis.

    Haeufige Live-Ursache: Bitdefender Network Attack Defense blockt die
    aggressiven Scan-Probes -> 0 Ports trotz erreichbarem Host. Der Hinweis
    erscheint, ist aber kein roter Befund; ein Reset blendet ihn wieder aus.
    """
    from datetime import UTC, datetime

    from tools.network_scanner.domain.models import HostInfo, NetworkScanResult

    t = datetime(2026, 1, 1, tzinfo=UTC)
    result = NetworkScanResult(
        ziel="192.168.50.147",
        hosts=[HostInfo(host="192.168.50.147", erreichbar=True, offene_ports=[])],
        gestartet_am=t,
        beendet_am=t,
        scanner_typ="nmap",
    )
    scanner_widget._scan_ergebnis_empfangen(result)  # noqa: SLF001
    assert not scanner_widget._lbl_av_hint.isHidden()  # noqa: SLF001
    assert "Antiviren" in scanner_widget._lbl_av_hint.text()  # noqa: SLF001
    # Reset (neuer Scan / Abbruch) blendet den Hinweis wieder aus.
    scanner_widget._reset_scan_ui()  # noqa: SLF001
    assert scanner_widget._lbl_av_hint.isHidden()  # noqa: SLF001
