"""
network_scanner_widget — PySide6-GUI für den Netzwerk-Scanner.

Drei Tabs:
    [Scan] — Vertikaler Splitter: OBEN Host-Discovery (ARP + Ping-Sweep,
                 Host-Auswahl), UNTEN Port-Scan (Ziel-Eingabe, Ergebnis,
                 Export). Beide Stufen in EINEM Tab, weil die Discovery
                 direkt den Port-Scan fuettert (D2, 2026-06-25 — vorher zwei
                 getrennte Tabs trotz durchgehendem Zwei-Stufen-Ablauf).
    [Verlauf] — Letzte Scans, Details
    [Live] — Eingebetteter Network-Monitor (Bandbreite +
                 Verbindungstabelle in Echtzeit). Worker startet/
                 stoppt mit Tab-Wechsel — kein CPU-Verbrauch wenn
                 der User auf einem anderen Tab arbeitet.

Zwei-Stufen-Workflow (jetzt ohne Tab-Wechsel, beide Haelften sichtbar):
    1. Discovery (oben): Hosts entdecken → Zeile(n) markieren → scannen
    2. Port-Scan (unten): Wird automatisch befüllt, gestartet und angezeigt

Discovery läuft in _DiscoveryThread, Port-Scan in _ScanThread.
Alle UI-Updates erfolgen über Qt-Signals (thread-safe).

Sicherheitsdesign:
  - Ziel-Input wird von NetworkService.starte_scan validiert
  - Discovery: nur ARP-Cache-Lesen + Ping, kein Port-Scan
  - Kein direkter Netzwerkzugriff im GUI-Thread
  - Export-Pfad über QFileDialog (kein freies Text-Input)

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import html
import time

from PySide6.QtCore import QPoint, Qt, QThread, Signal, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog
from core.exceptions import ValidationError
from core.export import export_actions
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.network_monitor.application.monitor_service import MonitorService
from tools.network_monitor.gui.network_monitor_widget import NetworkMonitorWidget
from tools.network_scanner.application.network_exporter import NetworkExporter
from tools.network_scanner.application.network_service import NetworkService
from tools.network_scanner.domain.models import (
    NetworkDiscoveryResult,
    NetworkScanResult,
    PortRisk,
)

# Tab-Index der eingebetteten Live-Sektion (Network-Monitor). Wird im
# ``currentChanged``-Slot benoetigt, um Worker-Lifecycle-Aktionen ans
# Verlassen oder Betreten zu koppeln.
# D2: Discovery + Neuer Scan wurden zu EINEM "Scan"-Tab (0)
# vereint -> Live rueckt von Index 3 auf 2 (Scan=0, Verlauf=1, Live=2).
_LIVE_TAB_INDEX = 2

log = get_logger(__name__)

# Farben pro Risikoklasse — konsistent mit FINLAI Severity-Palette
_RISK_COLORS: dict[PortRisk, str] = {
    PortRisk.KRITISCH: theme.SEVERITY_SIGNAL_CRITICAL,
    PortRisk.HOCH: theme.SEVERITY_SIGNAL_HIGH,
    PortRisk.MITTEL: theme.SEVERITY_SIGNAL_MEDIUM,
    PortRisk.NIEDRIG: theme.SEVERITY_SIGNAL_LOW,
    PortRisk.INFO: theme.SEVERITY_SIGNAL_INFO,
}

# Abhilfe-Tooltips für bekannte Hochrisiko-Ports
_PORT_TOOLTIPS: dict[int, str] = {
    21: "FTP überträgt Daten unverschlüsselt.\nEmpfehlung: FTP deaktivieren, stattdessen SFTP (Port 22) oder FTPS verwenden.",
    22: "SSH-Zugang offen — passwortbasierter Login ist anfällig für Brute-Force.\nEmpfehlung: Passwort-Auth deaktivieren, nur Key-basierte Authentifizierung erlauben.\nEmpfehlung: Fail2Ban oder ähnliche Schutzmaßnahmen einsetzen.",
    23: "Telnet überträgt alles im Klartext (inkl. Passwörter).\nEmpfehlung: Telnet sofort deaktivieren, SSH als Ersatz nutzen.",
    25: "SMTP-Port direkt erreichbar — kann für Open-Relay missbraucht werden.\nEmpfehlung: Relay-Regeln prüfen, SPF/DKIM/DMARC konfigurieren.",
    53: "DNS-Port offen — Rekursion nach außen kann für Amplification-Angriffe missbraucht werden.\nEmpfehlung: Rekursive Anfragen auf interne Clients beschränken.",
    80: "HTTP (unverschlüsselt) erreichbar.\nEmpfehlung: HTTP -> HTTPS-Weiterleitung einrichten (301-Redirect), HSTS aktivieren.",
    135: "Windows RPC (MSRPC) offen — häufiges Ziel für Remote-Exploits.\nEmpfehlung: Port in der Firewall für externe Zugriffe sperren.",
    139: "NetBIOS-Session-Service offen — verbreitet bei SMB-Angriffen.\nEmpfehlung: NetBIOS deaktivieren, Firewall-Regel für externe Zugriffe setzen.",
    443: "HTTPS — TLS-Konfiguration prüfen.\nEmpfehlung: TLS 1.0/1.1 deaktivieren, nur TLS 1.2+ erlauben. Zertifikat-Ablauf überwachen.",
    445: "SMB direkt aus dem Internet erreichbar — kritisches Angriffsziel (z.B. EternalBlue/WannaCry).\nEmpfehlung: Port 445 in der Firewall für externe Zugriffe sofort sperren.",
    1433: "MSSQL-Datenbank direkt erreichbar.\nEmpfehlung: DB-Port in der Firewall für externe Zugriffe sperren, Zugriff nur über VPN.",
    1521: "Oracle DB direkt erreichbar.\nEmpfehlung: DB-Port in der Firewall für externe Zugriffe sperren, Zugriff nur über VPN.",
    3306: "MySQL direkt erreichbar.\nEmpfehlung: DB-Port in der Firewall für externe Zugriffe sperren, Zugriff nur über VPN.",
    3389: "RDP (Remote Desktop) direkt aus dem Internet erreichbar — häufiges Angriffsziel.\nEmpfehlung: RDP in der Firewall sperren, nur über VPN-Tunnel zulassen.\nEmpfehlung: NLA (Network Level Authentication) aktivieren, starke Passwörter erzwingen.",
    5432: "PostgreSQL direkt erreichbar.\nEmpfehlung: DB-Port in der Firewall für externe Zugriffe sperren, Zugriff nur über VPN.",
    5900: "VNC-Zugang offen — häufig schwach gesichert.\nEmpfehlung: VNC deaktivieren oder nur über verschlüsselten SSH-Tunnel zulassen.",
    5901: "VNC-Zugang (Display 1) offen.\nEmpfehlung: VNC deaktivieren oder nur über verschlüsselten SSH-Tunnel zulassen.",
    6379: "Redis ohne Authentifizierung typischerweise offen.\nEmpfehlung: Firewall-Regel setzen, requirepass in redis.conf konfigurieren.",
    8080: "Alternativer HTTP-Port offen — oft Entwicklungs- oder Proxy-Server.\nEmpfehlung: Prüfen ob Dienst produktionsreif gesichert ist, ggf. HTTPS erzwingen.",
    8443: "Alternativer HTTPS-Port offen.\nEmpfehlung: TLS-Konfiguration prüfen, TLS 1.0/1.1 deaktivieren.",
    27017: "MongoDB direkt erreichbar — häufig ohne Auth konfiguriert.\nEmpfehlung: Firewall-Regel setzen, MongoDB-Authentifizierung aktivieren.",
}


class _DiscoveryThread(QThread):
    """QThread für den Host-Discovery-Scan.

    Signals:
        fortschritt: (aktuell, gesamt) für Fortschrittsanzeige.
        ergebnis: Emittiert das fertige NetworkDiscoveryResult.
        fehler: Emittiert eine Fehlermeldung als String.
    """

    fortschritt: Signal = Signal(int, int)
    ergebnis: Signal = Signal(object)
    fehler: Signal = Signal(str)

    def __init__(
        self,
        service: NetworkService,
        subnetz: str,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den Discovery-Thread.

 (RUN2-GUI): Thread bekommt den ``NetworkService`` statt
        einer direkten ``NetworkDiscovery``-Instanz.
        """
        super().__init__(parent)
        self._service = service
        self._subnetz = subnetz

    def run(self) -> None:
        """Führt den Discovery-Scan aus."""
        try:
            result = self._service.discover_hosts(
                self._subnetz,
                progress_callback=lambda c, t: self.fortschritt.emit(c, t),
            )
            self.ergebnis.emit(result)
        except Exception as exc:  # noqa: BLE001 -- Worker-Thread Catch-All, fail-safe Error-Signal
            self.fehler.emit(f"Discovery-Fehler: {type(exc).__name__}: {exc}")


class _ScanThread(QThread):
    """QThread für den Netzwerk-Scan.

    Signals:
        ergebnis: Emittiert das fertige NetworkScanResult.
        fehler: Emittiert eine technische Fehlermeldung als String
            (z. B. Netzwerk-/Backend-Fehler) — Anzeige im Status-Label.
        validierung: Emittiert eine abgelehnte Ziel-/Policy-Eingabe als
            String (ungültiges Ziel ODER §202c-Schranke) — Anzeige als
            prominenter modaler Hinweis.
    """

    ergebnis: Signal = Signal(object)
    fehler: Signal = Signal(str)
    validierung: Signal = Signal(str)

    def __init__(
        self,
        service: NetworkService,
        ziel: str,
        nmap: bool,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den Scan-Thread."""
        super().__init__(parent)
        self._service = service
        self._ziel = ziel
        self._nmap = nmap

    def run(self) -> None:
        """Führt den Scan aus und emittiert das Ergebnis."""
        try:
            result = self._service.starte_scan(
                ziel=self._ziel,
                nmap_bevorzugt=self._nmap,
            )
            self.ergebnis.emit(result)
        except ValidationError as exc:
            # Ungültiges Ziel ODER §202c-Schranke (externes Ziel ohne
            # Auftrag) — eine Eingabe-/Policy-Ablehnung, die der User
            # prominent sehen muss. Eigenes Signal → modaler Hinweis statt
            # nur Status-Label (ValidationError ist ValueError-Subklasse,
            # daher MUSS dieser except-Block zuerst stehen).
            self.validierung.emit(str(exc))
        except ValueError as exc:
            self.fehler.emit(str(exc))
        except Exception as exc:  # noqa: BLE001 -- Worker-Thread Catch-All, fail-safe Error-Signal
            self.fehler.emit(f"Scan-Fehler: {type(exc).__name__}: {exc}")


# Mindesthoehe des vereinten Scan-Tabs (Discovery + Port-Scan).
#
# Effekt: In ``_build_scan_und_discovery_tab`` haelt eine AEUSSERE QScrollArea
# den vertikalen Splitter. Faellt die verfuegbare Tab-Hoehe unter diesen Wert,
# scrollt die GANZE Scan-Seite vertikal, statt beide Stufen zu eng zu quetschen
# (Patrick-Live: "Seite muss nach unten scrollbar sein" reichte nicht).
_SCAN_TAB_MIN_HEIGHT = 640

# Hinweis, wenn ein Host erreichbar ist, der Scan aber 0 Ports liefert.
#
# Effekt: In ``_scan_ergebnis_empfangen`` (Einzel-Host) und ``_finalize_multi_scan``
# (Multi-Host) als ``_lbl_av_hint`` eingeblendet. Haeufige Ursache: eine
# Antiviren-/Sicherheitssoftware (Bitdefender Network Attack Defense /
# "Online-Gefahrenabwehr") blockt die aggressiven Scan-Probes -> 0 Ports trotz
# erreichbarem Host. KEIN NoRisk-Bug; neutraler Hinweis (Mess-Fehlschlag nie als
# roter Befund, vgl./).
_AV_BLOCK_HINT = (
    "Hinweis: Host erreichbar, aber keine offenen Ports gefunden. Falls Ports "
    "erwartet wurden, blockt evtl. eine Antiviren-/Sicherheitssoftware "
    "(z. B. Bitdefender „Online-Gefahrenabwehr“) die aggressiven Scan-Probes. "
    "Abhilfe: im AV-Programm eine Ausnahme für NoRisk hinzufügen oder die "
    "nmap-Option deaktivieren (der Standard-Socket-Scan ist unauffälliger)."
)


class NetworkScannerWidget(QWidget):
    """Hauptwidget des Netzwerk-Scanners.

    Args:
        service: NetworkService-Instanz.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        service: NetworkService,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Widget."""
        super().__init__(parent)
        self._service = service
        self._scan_thread: _ScanThread | None = None
        self._discovery_thread: _DiscoveryThread | None = None
        self._letztes_ergebnis: NetworkScanResult | None = None
        # sequenzielles Scannen MEHRERER ausgewaehlter Hosts. ``_scan_queue``
        # haelt die noch ausstehenden Ziele, ``_multi_results`` die bereits
        # gescannten Ergebnisse; ``_scanning_queue`` unterscheidet den Multi-Lauf
        # vom Einzel-Scan (``_scan_starten``).
        self._scan_queue: list[str] = []
        self._multi_results: list[NetworkScanResult] = []
        self._scanning_queue: bool = False
        # der Live-Tab wird lazy gebaut. Die Attribute hier (vor
        # ``_build_ui``) typdeklarieren, damit die im Datei-Layout frueher
        # stehenden Methoden ``_on_tab_changed``/``_ensure_live_tab`` sie
        # typkorrekt sehen (sonst „Cannot determine type"). Der tatsaechliche
        # Aufbau (Container/Platzhalter) passiert in ``_build_ui``,
        # ``_monitor_widget`` erst beim ersten Live-Wechsel.
        self._monitor_widget: NetworkMonitorWidget | None = None
        self._live_layout: QVBoxLayout
        self._live_placeholder: QLabel | None = None
        self._exporter = NetworkExporter()
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()
        self._netzwerk_info_laden()

    # ------------------------------------------------------------------
    # Cross-Tool-Deep-Link (Sprint S3d)
    # ------------------------------------------------------------------

    def apply_navigation(self, **kwargs: object) -> None:
        """Empfangs-Pattern fuer ``MainWindow.navigate_to(..., target=...)``.

        Erkannte kwargs:
            ``target`` -- IP oder Hostname ins Ziel-Feld vorausfuellen
                (z. B. wenn der Live-Tab auf eine verdaechtige IP
                klickt -> "Diese IP scannen"-Kontextmenue). Sprint S5a:
                Wechselt zusaetzlich auf den ``Neuer Scan``-Tab, damit
                der User die vorgefuellte Eingabe sofort sieht.

        Andere kwargs werden ignoriert (forward-kompatibel).
        """
        target = kwargs.get("target")
        if target is None:
            return
        text = str(target).strip()
        if not text:
            return
        # Der vereinte "Scan"-Tab hat Index 0 (Scan=0, Verlauf=1, Live=2; D2).
        # Cross-Tab-Sprung muss vor setText laufen, damit der Fokus auf dem
        # aktiven Tab landet.
        self._tabs.setCurrentIndex(0)
        self._ziel_input.setText(text)
        self._ziel_input.setFocus()

    # ------------------------------------------------------------------
    # Tab-Lifecycle (Sprint S5a)
    # ------------------------------------------------------------------

    @Slot(int)
    def _on_tab_changed(self, index: int) -> None:
        """Baut den Live-Tab lazy und startet/stoppt seinen Worker.

        Sprint S5a — Performance-Regel R3 (Poll-Intervalle nach Kosten
        staffeln): Der Network-Monitor-Worker laeuft im 1-Sekunden-Takt
        und sollte nicht im Hintergrund weiterlaufen, wenn der User auf
        einem anderen Tab Discovery oder Port-Scans startet.: das Widget selbst wird zudem erst beim ersten Betreten
        konstruiert (:meth:`_ensure_live_tab`), nicht schon beim Oeffnen des
        Scanners — sonst zahlt der Scan-Tab-Aufbau die volle Monitor-/DB-Last.
        """
        if index == _LIVE_TAB_INDEX:
            # Freeze-Watchdog bewaffnen: blockiert der Live-Aufbau oder der
            # Worker den UI-Thread (DB-I/O), dumpt faulthandler nach 8s ALLE
            # Thread-Stacks nach logs/crash_native.log (Patrick-Live: Einfrieren
            # ohne Crash-Signal -> sonst keine Spur).
            from core.crash_handler import arm_freeze_watchdog  # noqa: PLC0415

            arm_freeze_watchdog(8.0, "netzwerk-scanner-live")
            log.info("Netzwerk-Scanner: Live-Tab wird aktiviert (Aufbau + Worker) …")
            _t0 = time.perf_counter()
            # Erst-Aufbau (lazy) + Worker starten. ``_ensure_live_tab`` liefert
            # das garantiert vorhandene Monitor-Widget zurueck -> kein
            # None-Guard noetig (ein Aufbau-Fehler propagiert sichtbar statt
            # still verschluckt zu werden).
            monitor = self._ensure_live_tab()
            log.info(
                "Netzwerk-Scanner: Live-Tab-Aufbau fertig in %.0f ms — starte Worker.",
                (time.perf_counter() - _t0) * 1000.0,
            )
            monitor.start_worker()
        elif self._monitor_widget is not None:
            self._monitor_widget.stop_worker()

    def _ensure_live_tab(self) -> NetworkMonitorWidget:
        """Konstruiert den eingebetteten Live-Monitor beim ersten Oeffnen.

        Lazy-Aufbau: Der ``NetworkMonitorWidget`` und seine History-Repositories
        oeffnen mehrere verschluesselte DBs und laufen 24h-Aggregat-Queries
        synchron im Konstruktor (ConversationTab/ProcessTrafficView). Erst hier
        — beim ersten Wechsel auf den Live-Tab — zu konstruieren haelt den
        Scan-Tab-Aufbau frei von dieser Last (Patrick-Live-Test: extrem langsame
        Ladezeit, "stuerzt quasi ab"). Idempotent: ein bereits gebautes Widget
        wird nicht erneut erzeugt.

        Returns:
            Das eingebettete ``NetworkMonitorWidget`` (frisch gebaut oder
            gecacht) — nie ``None``.
        """
        if self._monitor_widget is not None:
            return self._monitor_widget
        # Der Aufbau oeffnet verschluesselte DBs + laeuft Aggregat-Queries
        # synchron im UI-Thread (QWidgets muessen im UI-Thread entstehen) —
        # kurzer Warte-Cursor, damit der erste Live-Klick nicht als
        # eingefrorene App wirkt (Frontend-Review).
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            # D3: History-Repositories mitgeben (gleiche
            # Application-Factory wie das Standalone-Tool) — sonst persistiert
            # der Live-Tab nichts und der CSV-Export-Button reagierte stumm.
            _conn_repo, _traffic_repo = MonitorService.build_history_repositories()
            self._monitor_widget = NetworkMonitorWidget(
                auto_start_worker=False,
                repository=_conn_repo,
                process_traffic_repo=_traffic_repo,
            )
            # Platzhalter gegen das echte Monitor-Widget tauschen; die
            # Python-Referenz loeschen (deleteLater verzoegert nur den C++-Abbau).
            if self._live_placeholder is not None:
                self._live_layout.removeWidget(self._live_placeholder)
                self._live_placeholder.deleteLater()
                self._live_placeholder = None
            self._live_layout.addWidget(self._monitor_widget)
        finally:
            QApplication.restoreOverrideCursor()
        return self._monitor_widget

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: D401 — Qt-Override
        """Stoppt den eingebetteten Live-Monitor-Worker beim Schliessen."""
        # der Live-Tab wird lazy gebaut — ohne ersten Live-Besuch gibt
        # es kein Monitor-Widget zu stoppen.
        if self._monitor_widget is not None:
            try:
                self._monitor_widget.stop_worker()
            except RuntimeError:
                # Widget wurde evtl. schon abgebaut — defensive ignorieren.
                pass
        super().closeEvent(event)

    def _build_ui(self) -> None:
        """Erstellt das Tab-Layout."""
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        _hc = HelpRegistry.get("network_scanner")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            root.addWidget(self._help_panel)

        self._tabs = QTabWidget()
        # D2: Discovery (oben) + Port-Scan (unten) in EINEM Tab.
        self._tabs.addTab(
            self._build_scan_und_discovery_tab(), get_icon(Icons.SCAN), "Scan"
        )
        self._tabs.addTab(
            self._build_verlauf_tab(), get_icon(Icons.SCHEDULE), "Verlauf"
        )

        # Sprint S5a — Tab "Live": eingebetteter Network-Monitor.
        # LAZY konstruiert. Der ``NetworkMonitorWidget``
        # oeffnet ueber seine Sub-Tabs (ConversationTab/ProcessTrafficView)
        # und die History-Repositories MEHRERE verschluesselte DBs UND laeuft
        # 24h-Aggregat-Queries SYNCHRON im Konstruktor. Frueher lief das alles
        # schon beim Oeffnen des Scanners (Scan-Tab aktiv), obwohl der Live-Tab
        # evtl. nie betreten wird -> "Ladezeit extrem schlecht, stuerzt quasi
        # ab" (Patrick-Live-Test). Deshalb erst beim ersten Wechsel auf den
        # Live-Tab bauen (:meth:`_ensure_live_tab`), analog zum lazy
        # Dock-Pattern (core/dock_mixin.py). Bis dahin haelt ein Platzhalter
        # den Tab; der Scan-Tab-Aufbau zahlt keine Monitor-/DB-Last.
        self._monitor_widget = None
        live_container = QWidget()
        self._live_layout = QVBoxLayout(live_container)
        self._live_layout.setContentsMargins(0, 0, 0, 0)
        self._live_placeholder = QLabel("Live-Monitor wird beim Öffnen geladen …")
        self._live_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._live_placeholder.setObjectName("liveLoadingPlaceholder")
        # Gedaempfter Hinweis-Stil ueber Theme-Token (kein hardcodiertes Hex).
        self._live_placeholder.setStyleSheet(f"color: {theme.get().TEXT_DIM};")
        self._live_layout.addWidget(self._live_placeholder)
        self._tabs.addTab(
            live_container, get_icon(Icons.NETWORK_MONITOR), "Live"
        )
        self._tabs.currentChanged.connect(self._on_tab_changed)

        root.addWidget(self._tabs)

    def _build_scan_und_discovery_tab(self) -> QWidget:
        """Vereinter Scan-Tab: Host-Discovery (oben) + Port-Scan (unten).

        D2: Discovery und Port-Scan lagen in zwei getrennten
        Tabs, obwohl die Discovery den Port-Scan direkt fuettert (Host
        auswaehlen →:meth:`_ausgewaehlte_scannen` → Ziel setzen + Scan
        starten). Beide liegen jetzt in einem vertikalen Splitter, sodass der
        Zwei-Stufen-Ablauf ohne Tab-Wechsel sichtbar bleibt. Die einzelnen
        Bauteile (``_build_discovery_tab`` / ``_build_scan_tab``) bleiben
        unveraendert — nur die Verpackung ist neu.

        Returns:
            Ein ``QSplitter`` mit Discovery oben, Port-Scan unten.
        """
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._build_discovery_tab())
        splitter.addWidget(self._build_scan_tab())
        # Keine Haelfte komplett kollabieren lassen — sonst verschwindet eine
        # Stufe und der Tab wirkt wieder "halb".
        splitter.setChildrenCollapsible(False)
        splitter.setStretchFactor(0, 3)  # Discovery (Host-Liste braucht Platz)
        splitter.setStretchFactor(1, 3)  # Port-Scan (ausgewogen entschlackt)
        # GANZE Scan-Seite vertikal scrollbar. Frueher hatte jede
        # Splitter-Haelfte eine EIGENE QScrollArea — das fixte zwar die
        # Ueberlappung, hielt die Seite aber weiter "zu eng" (Patrick). Jetzt
        # haelt EINE aeussere QScrollArea den Splitter: oberhalb von
        # _SCAN_TAB_MIN_HEIGHT verteilt der Splitter normal (Divider ziehbar),
        # darunter scrollt die gesamte Seite (kein verschachteltes Scrollen,
        # beide Stufen behalten nutzbare Hoehe).
        splitter.setMinimumHeight(_SCAN_TAB_MIN_HEIGHT)
        outer = QScrollArea()
        outer.setObjectName("scanTabScrollArea")
        outer.setWidgetResizable(True)
        outer.setFrameShape(QScrollArea.Shape.NoFrame)
        # Nur vertikal scrollen; ObjectName-Selektor, damit das transparente
        # Stylesheet keine Kinder-Buttons in die Kaskaden-Falle zieht.
        outer.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.setStyleSheet(
            "QScrollArea#scanTabScrollArea { background: transparent; border: none; }"
        )
        outer.setWidget(splitter)
        return outer

    # ------------------------------------------------------------------
    # Tab: Host-Discovery
    # ------------------------------------------------------------------

    def _build_discovery_tab(self) -> QWidget:
        """Erstellt den Host-Discovery-Tab.

        Returns:
            Fertiges QWidget.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Netz-Info-Zeile
        info_row = QHBoxLayout()
        self._lbl_eigene_ip = QLabel("Eigene IP: …")
        self._lbl_subnetz = QLabel("Subnetz: …")
        self._lbl_gateway = QLabel("Gateway: …")
        for lbl in (self._lbl_eigene_ip, self._lbl_subnetz, self._lbl_gateway):
            lbl.setStyleSheet("font-size: 11px;")
            info_row.addWidget(lbl)
        info_row.addStretch()
        layout.addLayout(info_row)

        # Subnetz-Eingabe + Discovery-Button
        subnet_row = QHBoxLayout()
        subnet_row.addWidget(QLabel("Subnetz:"))
        self._subnet_input = QLineEdit()
        self._subnet_input.setPlaceholderText("z.B. 192.168.1.0/24")
        self._subnet_input.setMinimumWidth(200)
        self._subnet_input.returnPressed.connect(self._discovery_starten)
        subnet_row.addWidget(self._subnet_input, stretch=1)

        self._btn_discovery = QPushButton("Hosts entdecken")
        self._btn_discovery.setIcon(get_icon(Icons.SEARCH))
        self._btn_discovery.setFixedHeight(30)
        self._btn_discovery.clicked.connect(self._discovery_starten)
        subnet_row.addWidget(self._btn_discovery)
        _tip_dis = self._help_tip("btn_discovery")
        if _tip_dis:
            subnet_row.addWidget(HelpButton(_tip_dis))
        layout.addLayout(subnet_row)

        # Fortschrittsbalken: kanonischer FinlaiProgressBar)
        self._discovery_progress = FinlaiProgressBar(total=100)
        self._discovery_progress.setVisible(False)
        layout.addWidget(self._discovery_progress)

        # Status-Label
        self._lbl_discovery_status = QLabel("")
        self._lbl_discovery_status.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(self._lbl_discovery_status)

        # Host-Liste — Auswahl ueber Zeilen-Selektion (Mehrfach via Strg/Umschalt),
        # NICHT ueber Item-Checkboxen: das Dark-Theme stylt QTreeWidget::indicator
        # nicht -> Checkboxen waeren unsichtbar/unbedienbar.
        self._discovery_tree = QTreeWidget()
        self._discovery_tree.setColumnCount(3)
        self._discovery_tree.setHeaderLabels(["IP-Adresse", "Hostname", "MAC / Quelle"])
        self._discovery_tree.setRootIsDecorated(False)
        self._discovery_tree.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self._discovery_tree.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._discovery_tree.setMinimumHeight(160)
        self._discovery_tree.setToolTip(
            "Host(s) markieren (Mehrfachauswahl mit Strg/Umschalt), "
            "dann 'Ausgewählte Hosts scannen'."
        )
        self._discovery_tree.setColumnWidth(0, 150)
        self._discovery_tree.setColumnWidth(1, 220)
        self._discovery_tree.header().setStretchLastSection(True)
        layout.addWidget(self._discovery_tree, stretch=1)

        # Aktions-Zeile
        action_row = QHBoxLayout()
        self._btn_alle_auswaehlen = QPushButton("Alle auswählen")
        self._btn_alle_auswaehlen.setFixedHeight(28)
        self._btn_alle_auswaehlen.clicked.connect(self._alle_auswaehlen)
        action_row.addWidget(self._btn_alle_auswaehlen)

        self._btn_auswahl_aufheben = QPushButton("Auswahl aufheben")
        self._btn_auswahl_aufheben.setFixedHeight(28)
        self._btn_auswahl_aufheben.clicked.connect(self._auswahl_aufheben)
        action_row.addWidget(self._btn_auswahl_aufheben)
        action_row.addStretch()

        self._btn_ausgewaehlte_scannen = QPushButton("Ausgewählte Hosts scannen")
        self._btn_ausgewaehlte_scannen.setIcon(get_icon(Icons.NETWORK_SCAN))
        self._btn_ausgewaehlte_scannen.setFixedHeight(30)
        self._btn_ausgewaehlte_scannen.setEnabled(False)
        self._btn_ausgewaehlte_scannen.clicked.connect(self._ausgewaehlte_scannen)
        action_row.addWidget(self._btn_ausgewaehlte_scannen)
        layout.addLayout(action_row)

        # Tab-Reihenfolge (F4): Subnetz-Eingabe -> Discovery-Button.
        QWidget.setTabOrder(self._subnet_input, self._btn_discovery)

        return widget

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("network_scanner")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "network_scanner", parent=self.window()
        )
        dlg.show()

    def _netzwerk_info_laden(self) -> None:
        """Lädt Netzwerk-Info beim Start und befüllt die Eingabefelder."""
        eigene_ip, subnetz, gateway = self._service.eigene_netzwerk_info()
        if eigene_ip:
            self._lbl_eigene_ip.setText(f"Eigene IP: {eigene_ip}")
            self._lbl_subnetz.setText(f"Subnetz: {subnetz}")
            self._lbl_gateway.setText(f"Gateway: {gateway}")
            self._subnet_input.setText(subnetz)
        else:
            self._lbl_eigene_ip.setText("Eigene IP: nicht ermittelbar")

    @Slot()
    def _discovery_starten(self) -> None:
        """Startet den Host-Discovery-Thread."""
        if self._discovery_thread and self._discovery_thread.isRunning():
            return

        subnetz = self._subnet_input.text().strip()
        if not subnetz:
            FinlaiInfoDialog(
                title="Eingabe fehlt",
                message="Bitte ein Subnetz eingeben.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return

        self._btn_discovery.setEnabled(False)
        self._btn_ausgewaehlte_scannen.setEnabled(False)
        self._discovery_progress.setRange(0, 100)
        self._discovery_progress.setValue(0)
        self._discovery_progress.setVisible(True)
        self._lbl_discovery_status.setText(f"Scanne {subnetz}…")
        self._discovery_tree.clear()

        self._discovery_thread = _DiscoveryThread(
            service=self._service,
            subnetz=subnetz,
            parent=self,
        )
        self._discovery_thread.fortschritt.connect(self._discovery_fortschritt)
        self._discovery_thread.ergebnis.connect(self._discovery_ergebnis_empfangen)
        self._discovery_thread.fehler.connect(self._discovery_fehler_empfangen)
        self._discovery_thread.start()

    @Slot(int, int)
    def _discovery_fortschritt(self, aktuell: int, gesamt: int) -> None:
        """Aktualisiert die Fortschrittsanzeige.

        Args:
            aktuell: Bereits verarbeitete Hosts.
            gesamt: Gesamtzahl der zu prüfenden Hosts.
        """
        if gesamt > 0:
            self._discovery_progress.setRange(0, gesamt)
            self._discovery_progress.setValue(aktuell)

    @Slot(object)
    def _discovery_ergebnis_empfangen(self, result: NetworkDiscoveryResult) -> None:
        """Zeigt die Discovery-Ergebnisse in der Host-Liste an.

        Args:
            result: Fertiges NetworkDiscoveryResult.
        """
        self._discovery_progress.setVisible(False)
        self._btn_discovery.setEnabled(True)
        self._discovery_tree.clear()

        anzahl = len(result.hosts)
        self._lbl_discovery_status.setText(
            f"{anzahl} Host(s) gefunden — {result.dauer_s:.1f}s"
        )

        for host in result.hosts:
            mac_info = host.mac_adresse or "—"
            quelle_info = f"{mac_info}  [{host.quelle}]"
            item = QTreeWidgetItem([host.ip, host.hostname or "—", quelle_info])
            item.setData(0, Qt.ItemDataRole.UserRole, host.ip)
            self._discovery_tree.addTopLevelItem(item)

        if anzahl > 0:
            # Standard: alle vorausgewaehlt (wie zuvor "alle angehakt") — der
            # Nutzer grenzt per Strg/Umschalt ein. Scan-Button wird bedienbar.
            self._discovery_tree.selectAll()
            self._btn_ausgewaehlte_scannen.setEnabled(True)

    @Slot(str)
    def _discovery_fehler_empfangen(self, msg: str) -> None:
        """Zeigt einen Discovery-Fehler an.

        Args:
            msg: Fehlermeldung.
        """
        self._discovery_progress.setVisible(False)
        self._btn_discovery.setEnabled(True)
        self._lbl_discovery_status.setText(f"Fehler: {msg}")
        log.warning("Discovery-Fehler: %s", msg)

    @Slot()
    def _alle_auswaehlen(self) -> None:
        """Markiert alle Hosts (Zeilen-Selektion)."""
        self._discovery_tree.selectAll()

    @Slot()
    def _auswahl_aufheben(self) -> None:
        """Hebt die Host-Auswahl auf (Zeilen-Selektion)."""
        self._discovery_tree.clearSelection()

    @Slot()
    def _ausgewaehlte_scannen(self) -> None:
        """Scannt ALLE ausgewählten Hosts der Reihe nach.

        D2: Discovery und Port-Scan liegen im selben Tab. Frueher
        wurde nur der ERSTE ausgewählte Host gescannt und die uebrigen als
        "bitte manuell eingeben"-Liste angezeigt — "Alle auswählen + scannen"
        prüfte damit faktisch nur einen Host (Live-Test-Bug). Jetzt werden alle
        Ziele in eine Queue gelegt und sequenziell gescannt; die Ergebnisse
        sammeln sich, je Host mit einer Trennzeile, in der Port-Tabelle.
        """
        if self._scan_thread and self._scan_thread.isRunning():
            return

        ausgewaehlte: list[str] = []
        for item in self._discovery_tree.selectedItems():
            ip = item.data(0, Qt.ItemDataRole.UserRole)
            if ip:
                ausgewaehlte.append(ip)

        if not ausgewaehlte:
            FinlaiInfoDialog(
                title="Keine Auswahl",
                message="Bitte mindestens einen Host auswählen.",
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return

        # Multi-Host-Lauf vorbereiten: Tabelle leeren, Queue fuellen, los.
        self._port_tree.clear()
        self._detail_text.clear()
        self._btn_json.setEnabled(False)
        self._btn_xlsx.setEnabled(False)
        self._btn_pdf.setEnabled(False)
        self._multi_results = []
        self._scan_queue = list(ausgewaehlte)
        self._scanning_queue = True
        self._scan_next_queued()

    def _scan_next_queued(self) -> None:
        """Startet den naechsten Host aus der Multi-Host-Queue."""
        if not self._scan_queue:
            self._finalize_multi_scan()
            return
        ziel = self._scan_queue.pop(0)
        offen = len(self._scan_queue)
        self._ziel_input.setText(ziel)
        self._btn_scan.setEnabled(False)
        self._progress.setVisible(True)
        self._lbl_status.setText(
            f"Scanne {ziel}… (noch {offen} weitere)" if offen else f"Scanne {ziel}…"
        )
        self._start_scan_thread(ziel)

    def _finalize_multi_scan(self) -> None:
        """Schliesst den Multi-Host-Lauf ab (Status, Export, Verlauf)."""
        self._scanning_queue = False
        self._reset_scan_ui()
        erreichbar = [
            r for r in self._multi_results if r.hosts and r.hosts[0].erreichbar
        ]
        ports_gesamt = sum(len(r.hosts[0].offene_ports) for r in erreichbar)
        self._lbl_status.setText(
            f"{len(self._multi_results)} Host(s) gescannt — "
            f"{ports_gesamt} offene Port(s) gesamt"
        )
        # erreichbare Hosts, aber 0 Ports gesamt -> evtl. AV-Block.
        self._lbl_av_hint.setVisible(bool(erreichbar) and ports_gesamt == 0)
        if erreichbar and ports_gesamt == 0:
            self._lbl_av_hint.setText(_AV_BLOCK_HINT)
        if self._multi_results:
            # Export-Hinweis: der Export deckt aktuell den ZULETZT gescannten
            # Host ab (Einzel-Ergebnis-Format) — Multi-Host-Export ist Folgearbeit.
            self._letztes_ergebnis = self._multi_results[-1]
            self._btn_json.setEnabled(True)
            self._btn_xlsx.setEnabled(True)
            self._btn_pdf.setEnabled(True)
        self._verlauf_laden()

    # ------------------------------------------------------------------
    # Tab: Neuer Scan
    # ------------------------------------------------------------------

    def _build_scan_tab(self) -> QWidget:
        """Erstellt den Scan-Tab.

        Returns:
            Fertiges QWidget.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Eingabe-Zeile
        input_row = QHBoxLayout()
        input_row.addWidget(QLabel("Ziel (IP / Hostname):"))
        self._ziel_input = QLineEdit()
        self._ziel_input.setPlaceholderText("z.B. 192.168.1.1 oder 10.0.0.5")
        self._ziel_input.setMinimumWidth(280)
        self._ziel_input.returnPressed.connect(self._scan_starten)
        input_row.addWidget(self._ziel_input, stretch=1)
        layout.addLayout(input_row)

        # Optionen-Zeile
        opt_row = QHBoxLayout()
        self._nmap_check = QCheckBox("nmap (erweiterte Service-Erkennung)")
        nmap_da = self._service.nmap_verfuegbar()
        self._nmap_check.setEnabled(nmap_da)
        if not nmap_da:
            # Sichtbar machen, dass nmap fehlt (nicht nur Hover-Tooltip) — sonst
            # wirkt die ausgegraute Option "tot" (Patrick-Live-Test 2026-06-25).
            self._nmap_check.setText("nmap (nicht installiert — Basis-Scan)")
            self._nmap_check.setToolTip(
                "nmap nicht gefunden (PATH + Standard-Installationsorte). "
                "Installieren Sie nmap (nmap.org) für die erweiterte Service-Erkennung."
            )
        opt_row.addWidget(self._nmap_check)
        opt_row.addStretch()
        self._btn_scan = QPushButton("Scan starten")
        self._btn_scan.setIcon(get_icon(Icons.SCAN))
        self._btn_scan.setFixedHeight(30)
        self._btn_scan.clicked.connect(self._scan_starten)
        opt_row.addWidget(self._btn_scan)
        _tip_ps = self._help_tip("btn_port_scan")
        if _tip_ps:
            opt_row.addWidget(HelpButton(_tip_ps))
        layout.addLayout(opt_row)

        # Fortschrittsbalken: kanonischer FinlaiProgressBar — indeterminate)
        self._progress = FinlaiProgressBar()
        self._progress.setVisible(False)
        layout.addWidget(self._progress)

        # Status-Label
        self._lbl_status = QLabel("")
        self._lbl_status.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(self._lbl_status)

        # AV-Block-Hinweis (erreichbar, aber 0 Ports). Eigenes Label statt
        # ueberladenem Status: word-wrap + gedaempft + standardmaessig versteckt.
        self._lbl_av_hint = QLabel("")
        self._lbl_av_hint.setWordWrap(True)
        self._lbl_av_hint.setVisible(False)
        self._lbl_av_hint.setStyleSheet(
            f"color: {theme.get().TEXT_DIM}; font-size: 11px;"
        )
        layout.addWidget(self._lbl_av_hint)

        # Splitter: Port-Tabelle oben, Detail unten
        splitter = QSplitter(Qt.Orientation.Vertical)

        self._port_tree = QTreeWidget()
        # Spalte „Banner" (F-B): macht den TLS-Handshake-Fingerprint
        # (Version/Cipher/ALPN) direkt in der Tabelle sichtbar — vorher nur
        # nach einem Klick im Detail-Panel erkennbar.
        self._port_tree.setColumnCount(5)
        self._port_tree.setHeaderLabels(
            ["Port", "Dienst", "Risiko", "Hinweis", "Banner"]
        )
        self._port_tree.setColumnWidth(0, 70)
        self._port_tree.setColumnWidth(1, 150)
        self._port_tree.setColumnWidth(2, 90)
        self._port_tree.setColumnWidth(3, 320)
        self._port_tree.setColumnWidth(4, 220)
        self._port_tree.itemClicked.connect(self._port_ausgewaehlt)
        # Sprint S3d: Cross-Tool-Deep-Links via Rechtsklick-Kontextmenue.
        self._port_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._port_tree.customContextMenuRequested.connect(
            self._on_port_context_menu
        )
        splitter.addWidget(self._port_tree)

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setMaximumHeight(120)
        self._detail_text.setPlaceholderText("Port anklicken für Details…")
        splitter.addWidget(self._detail_text)

        layout.addWidget(splitter, stretch=1)

        # Export-Leiste
        export_row = QHBoxLayout()
        export_row.addStretch()
        self._btn_json = QPushButton("JSON")
        self._btn_json.setIcon(get_icon(Icons.DATA_OBJECT))
        self._btn_json.setToolTip("Als JSON exportieren")
        self._btn_json.setEnabled(False)
        self._btn_json.clicked.connect(self._on_export_json)
        export_row.addWidget(self._btn_json)
        self._btn_xlsx = QPushButton("Excel")
        self._btn_xlsx.setIcon(get_icon(Icons.TABLE_VIEW))
        self._btn_xlsx.setToolTip("Als Excel-Datei exportieren")
        self._btn_xlsx.setEnabled(False)
        self._btn_xlsx.clicked.connect(self._on_export_xlsx)
        export_row.addWidget(self._btn_xlsx)
        self._btn_pdf = QPushButton("PDF")
        self._btn_pdf.setIcon(get_icon(Icons.PDF))
        self._btn_pdf.setToolTip("Als PDF-Report exportieren")
        self._btn_pdf.setEnabled(False)
        self._btn_pdf.clicked.connect(self._on_export_pdf)
        export_row.addWidget(self._btn_pdf)
        layout.addLayout(export_row)

        # Tab-Reihenfolge (F4): Ziel-IP -> nmap-Option -> Scan-Button.
        QWidget.setTabOrder(self._ziel_input, self._nmap_check)
        QWidget.setTabOrder(self._nmap_check, self._btn_scan)

        return widget

    # ------------------------------------------------------------------
    # Tab: Verlauf
    # ------------------------------------------------------------------

    def _build_verlauf_tab(self) -> QWidget:
        """Erstellt den Verlauf-Tab.

        Returns:
            Fertiges QWidget.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header_row = QHBoxLayout()
        header_row.addWidget(QLabel("Letzte Scans:"))
        header_row.addStretch()
        btn_refresh = QPushButton("Aktualisieren")
        btn_refresh.setIcon(get_icon(Icons.REFRESH))
        btn_refresh.setFixedHeight(28)
        btn_refresh.clicked.connect(self._verlauf_laden)
        header_row.addWidget(btn_refresh)

        self._btn_verlauf_loeschen = QPushButton("Verlauf löschen")
        self._btn_verlauf_loeschen.setIcon(get_icon(Icons.DELETE_SWEEP))
        self._btn_verlauf_loeschen.setFixedHeight(28)
        self._btn_verlauf_loeschen.clicked.connect(self._on_verlauf_loeschen)
        header_row.addWidget(self._btn_verlauf_loeschen)
        layout.addLayout(header_row)

        self._verlauf_tree = QTreeWidget()
        self._verlauf_tree.setColumnCount(4)
        self._verlauf_tree.setHeaderLabels(["Datum", "Ziel", "Scanner", "Offene Ports"])
        self._verlauf_tree.setColumnWidth(0, 150)
        self._verlauf_tree.setColumnWidth(1, 200)
        self._verlauf_tree.setColumnWidth(2, 80)
        self._verlauf_tree.setColumnWidth(3, 100)
        self._verlauf_tree.itemClicked.connect(self._verlauf_ausgewaehlt)
        layout.addWidget(self._verlauf_tree, stretch=1)

        self._verlauf_detail = QTextEdit()
        self._verlauf_detail.setReadOnly(True)
        self._verlauf_detail.setMaximumHeight(150)
        self._verlauf_detail.setPlaceholderText("Scan anklicken für Details…")
        layout.addWidget(self._verlauf_detail)

        self._verlauf_laden()
        return widget

    # ------------------------------------------------------------------
    # Scan-Logik
    # ------------------------------------------------------------------

    @Slot()
    def _scan_starten(self) -> None:
        """Startet einen Einzel-Host-Scan (Button / Enter / manuelle Eingabe)."""
        if self._scan_thread and self._scan_thread.isRunning():
            return

        ziel = self._ziel_input.text().strip()
        if not ziel:
            FinlaiInfoDialog(
                title="Eingabe fehlt",
                message="Bitte ein Scan-Ziel eingeben.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return

        # Einzel-Scan: eine evtl. laufende Multi-Host-Queue verwerfen.
        self._scanning_queue = False
        self._scan_queue = []

        self._btn_scan.setEnabled(False)
        self._progress.setVisible(True)
        self._lbl_status.setText(f"Scanne {ziel}…")
        self._port_tree.clear()
        self._detail_text.clear()
        self._btn_json.setEnabled(False)
        self._btn_xlsx.setEnabled(False)
        self._btn_pdf.setEnabled(False)

        self._start_scan_thread(ziel)

    def _start_scan_thread(self, ziel: str) -> None:
        """Erstellt + startet den Scan-Thread fuer ein Ziel (Einzel + Queue)."""
        self._scan_thread = _ScanThread(
            service=self._service,
            ziel=ziel,
            nmap=self._nmap_check.isChecked(),
            parent=self,
        )
        self._scan_thread.ergebnis.connect(self._scan_ergebnis_empfangen)
        self._scan_thread.fehler.connect(self._scan_fehler_empfangen)
        self._scan_thread.validierung.connect(
            self._scan_validierung_fehlgeschlagen
        )
        self._scan_thread.start()

    def _reset_scan_ui(self) -> None:
        """Setzt Fortschritt + Scan-Button nach Abschluss/Abbruch zurück."""
        self._progress.setVisible(False)
        self._btn_scan.setEnabled(True)
        self._lbl_av_hint.setVisible(False)  # alten Hinweis ausblenden

    @Slot(object)
    def _scan_ergebnis_empfangen(self, result: NetworkScanResult) -> None:
        """Verarbeitet das Scan-Ergebnis im GUI-Thread.

        Args:
            result: Fertiges Scan-Ergebnis.
        """
        self._letztes_ergebnis = result

        # Multi-Host-Lauf: Ergebnis sammeln, unter einer Host-Trennzeile
        # anhaengen (KEIN clear) und den naechsten Host der Queue starten.
        if self._scanning_queue:
            self._multi_results.append(result)
            self._append_host_results(result)
            self._scan_next_queued()
            return

        # Einzel-Host: bisheriges Verhalten (Tabelle leeren, flach befuellen).
        self._reset_scan_ui()
        host = result.hosts[0] if result.hosts else None
        if not host or not host.erreichbar:
            self._lbl_status.setText(f"Host nicht erreichbar: {result.ziel}")
            return

        anzahl = len(host.offene_ports)
        self._lbl_status.setText(
            f"{anzahl} offene Port(s) — {result.dauer_s:.1f}s ({result.scanner_typ})"
        )
        # erreichbar, aber 0 Ports -> evtl. AV-Block; neutralen Hinweis zeigen.
        self._lbl_av_hint.setVisible(anzahl == 0)
        if anzahl == 0:
            self._lbl_av_hint.setText(_AV_BLOCK_HINT)
        self._port_tree.clear()
        for port_info in host.offene_ports:
            self._port_tree.addTopLevelItem(self._make_port_item(port_info))

        self._btn_json.setEnabled(True)
        self._btn_xlsx.setEnabled(True)
        self._btn_pdf.setEnabled(True)
        self._verlauf_laden()

    def _make_port_item(self, port_info) -> QTreeWidgetItem:  # noqa: ANN001
        """Baut eine Port-Tabellenzeile (Einzel- + Multi-Host)."""
        item = QTreeWidgetItem(
            [
                str(port_info.port),
                port_info.service or "—",
                port_info.risk.value.upper(),
                port_info.hinweis,
                port_info.banner or "—",
            ]
        )
        farbe = _RISK_COLORS.get(port_info.risk, "#42a5f5")  # noqa: material-blue-400-fallback
        item.setForeground(2, _hex_zu_qcolor(farbe))
        item.setData(0, Qt.ItemDataRole.UserRole, port_info)
        tooltip = _PORT_TOOLTIPS.get(port_info.port)
        if tooltip:
            for col in range(5):
                item.setToolTip(col, tooltip)
        if port_info.banner:
            # Vollständiges Banner als Tooltip — lange TLS-Banner können in der
            # Spaltenbreite abgeschnitten werden. Server-kontrolliert (Plaintext-
            # Port) → escapen, sonst rendert Qt es als Auto-RichText (R22).
            item.setToolTip(4, html.escape(port_info.banner))
        return item

    def _host_header(self, ziel: str, detail: str) -> QTreeWidgetItem:
        """Baut eine Host-Trennzeile (fett, gedaempft, nicht selektierbar).

        Hat KEINE PortInfo im UserRole → der Klick-/Kontextmenue-Handler
        ignoriert sie (beide guarden ``port_info is None``).
        """
        header = QTreeWidgetItem([f"▸ {ziel}", "", "", detail, ""])
        dim = _hex_zu_qcolor(theme.get().TEXT_DIM)
        header_font = header.font(0)
        header_font.setBold(True)
        for col in range(5):
            header.setFont(col, header_font)
            header.setForeground(col, dim)
        header.setFlags(Qt.ItemFlag.ItemIsEnabled)
        return header

    def _append_host_results(self, result: NetworkScanResult) -> None:
        """Haengt die Ergebnisse EINES Hosts unter einer Trennzeile an."""
        host = result.hosts[0] if result.hosts else None
        if not host or not host.erreichbar:
            detail = "Host nicht erreichbar"
        else:
            n = len(host.offene_ports)
            detail = f"{n} offene Port(s)" if n else "keine offenen Ports"
        self._port_tree.addTopLevelItem(self._host_header(result.ziel, detail))
        if host and host.erreichbar:
            for port_info in host.offene_ports:
                self._port_tree.addTopLevelItem(self._make_port_item(port_info))

    @Slot(str)
    def _scan_fehler_empfangen(self, msg: str) -> None:
        """Zeigt eine Fehlermeldung an.

        Args:
            msg: Fehlermeldung.
        """
        log.warning("Scan-Fehler: %s", msg)
        if self._scanning_queue:
            # Fehler bei EINEM Host: Trennzeile vermerken + Queue fortsetzen.
            self._port_tree.addTopLevelItem(
                self._host_header(self._ziel_input.text().strip(), f"Fehler: {msg}")
            )
            self._scan_next_queued()
            return
        self._reset_scan_ui()
        self._lbl_status.setText(f"Fehler: {msg}")

    @Slot(str)
    def _scan_validierung_fehlgeschlagen(self, msg: str) -> None:
        """Zeigt eine abgelehnte Ziel-/Policy-Eingabe als prominenten Hinweis.

        ``ValidationError`` deckt sowohl ungültige Ziele als auch die
        §202c-Schranke (externe Ziele ohne Auftrag) ab — beides sind
        Eingabe-/Policy-Probleme, die der User klar sehen muss. Daher als
        modaler Dialog (wie bei leerer Eingabe), nicht nur im leicht zu
        übersehenden rechtsbündigen Status-Label.

        Args:
            msg: Klartext-Begründung aus dem Service (enthält das Ziel).
        """
        if self._scanning_queue:
            # Multi-Host: abgelehntes Ziel als Trennzeile vermerken und
            # mit der Queue fortfahren — kein modaler Dialog pro Host (die Ziele
            # stammen aus der lokalen Subnetz-Discovery, §202c-Schranke greift
            # praktisch nicht; ein Stillstand der Queue waere schlimmer).
            log.info("Scan-Ziel abgelehnt im Multi-Lauf (Validierung/§202c).")
            self._port_tree.addTopLevelItem(
                self._host_header(
                    self._ziel_input.text().strip(), "Scan nicht erlaubt"
                )
            )
            self._scan_next_queued()
            return
        self._reset_scan_ui()
        self._lbl_status.setText("Scan nicht gestartet — siehe Hinweis.")
        # ``msg`` enthält das vom User eingegebene Ziel (kann Markup tragen) →
        # FinlaiInfoDialog rendert die Nachricht intern als PlainText (R22),
        # sodass kein Auto-RichText aus untrusted Eingaben entsteht.
        FinlaiInfoDialog(
            title="Scan-Ziel nicht erlaubt",
            message=msg,
            icon_name=Icons.WARNING,
            parent=self,
        ).exec()
        # Kein PII-Logging: das Ziel steckt in ``msg`` (R8 / F-F No-Content).
        log.info("Scan-Ziel abgelehnt (Validierung/§202c-Schranke).")

    @Slot(object)
    def _port_ausgewaehlt(self, item: QTreeWidgetItem) -> None:
        """Zeigt Details zum ausgewählten Port.

        Args:
            item: Angeklicktes QTreeWidgetItem.
        """
        port_info = item.data(0, Qt.ItemDataRole.UserRole)
        if port_info is None:
            return
        text = (
            f"Port {port_info.port} — {port_info.service or 'unbekannt'}\n"
            f"Zustand: {port_info.state.value}\n"
            f"Risiko:  {port_info.risk.value.upper()}\n"
            f"Hinweis: {port_info.hinweis or '—'}\n"
        )
        if port_info.banner:
            text += f"Banner:  {port_info.banner}\n"
        self._detail_text.setPlainText(text)

    # ------------------------------------------------------------------
    # Cross-Tool-Deep-Links (Sprint S3d)
    # ------------------------------------------------------------------

    # Web-Ports, fuer die ein API-Scan sinnvoll ist (HTTP-basierte
    # Standard-Schemas). Andere Ports bieten den API-Scan-Punkt nicht
    # an -- "API-Scan auf SSH" waere ein UX-Bug.
    _API_SCAN_PORTS: dict[int, str] = {
        80: "http",
        443: "https",
        8080: "http",
        8443: "https",
    }

    @Slot(QPoint)
    def _on_port_context_menu(self, pos: QPoint) -> None:
        """Rechtsklick auf eine Port-Zeile → Kontextmenue mit Deep-Links.

        Per Strategie-Sprint S3d zwei Aktionen:
          * "→ API-Scan starten" (nur fuer HTTP/HTTPS-Ports)
          * "→ Cert-Monitor: Domain anlegen" (nur HTTPS und 443/8443)
        """
        item = self._port_tree.itemAt(pos)
        if item is None:
            return
        port_info = item.data(0, Qt.ItemDataRole.UserRole)
        if port_info is None:
            return
        host = self._scan_host()
        if not host:
            return

        menu = QMenu(self._port_tree)

        scheme = self._API_SCAN_PORTS.get(int(port_info.port))
        if scheme is not None:
            url = self._build_url(scheme, host, int(port_info.port))
            api_act = menu.addAction(
                f"Port {port_info.port} → API-Scan starten ({url})"
            )
            api_act.triggered.connect(
                lambda checked=False, u=url: self._open_api_scan(u)
            )

        if scheme == "https":
            cert_act = menu.addAction(
                f"Port {port_info.port} → Cert-Monitor: {host} anlegen"
            )
            cert_act.triggered.connect(
                lambda checked=False, h=host: self._open_cert_monitor(h)
            )

        if menu.actions():
            menu.exec(self._port_tree.viewport().mapToGlobal(pos))

    def _scan_host(self) -> str:
        """Liefert den Ziel-Host des letzten Scans (oder leeren String)."""
        if self._letztes_ergebnis is None:
            return ""
        return (self._letztes_ergebnis.ziel or "").strip()

    @staticmethod
    def _build_url(scheme: str, host: str, port: int) -> str:
        """Baut eine URL aus Schema/Host/Port; Standardports ohne Suffix."""
        is_default = (scheme == "http" and port == 80) or (
            scheme == "https" and port == 443
        )
        if is_default:
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def _open_api_scan(self, url: str) -> None:
        """Oeffnet ``api_security`` mit vorausgefuellter URL."""
        window = self.window()
        navigate = getattr(window, "navigate_to", None)
        if callable(navigate):
            navigate("api_security", url=url)

    def _open_cert_monitor(self, domain: str) -> None:
        """Oeffnet ``cert_monitor`` mit vorausgefuellter Domain."""
        window = self.window()
        navigate = getattr(window, "navigate_to", None)
        if callable(navigate):
            navigate("cert_monitor", domain=domain)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @Slot()
    def _on_export_json(self) -> None:
        """Exportiert das letzte Scan-Ergebnis als JSON."""
        if self._letztes_ergebnis is not None:
            export_actions.run_json_export(self._exporter, self._letztes_ergebnis, self)

    @Slot()
    def _on_export_xlsx(self) -> None:
        """Exportiert das letzte Scan-Ergebnis als Excel-Datei."""
        if self._letztes_ergebnis is not None:
            export_actions.run_xlsx_export(self._exporter, self._letztes_ergebnis, self)

    @Slot()
    def _on_export_pdf(self) -> None:
        """Exportiert das letzte Scan-Ergebnis als PDF-Report."""
        if self._letztes_ergebnis is not None:
            export_actions.run_pdf_export(self._exporter, self._letztes_ergebnis, self)

    # ------------------------------------------------------------------
    # Verlauf
    # ------------------------------------------------------------------

    def _verlauf_laden(self) -> None:
        """Lädt und zeigt die letzten Scans."""
        self._verlauf_tree.clear()
        scans = self._service.lade_letzte_scans(limit=20)
        for scan in scans:
            datum = scan.gestartet_am.strftime("%d.%m.%Y %H:%M")
            item = QTreeWidgetItem(
                [
                    datum,
                    scan.ziel,
                    scan.scanner_typ,
                    str(scan.anzahl_offene_ports),
                ]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, scan)
            self._verlauf_tree.addTopLevelItem(item)
        has_scans = self._verlauf_tree.topLevelItemCount() > 0
        self._btn_verlauf_loeschen.setEnabled(has_scans)

    @Slot()
    def _on_verlauf_loeschen(self) -> None:
        """Löscht den gesamten Scan-Verlauf nach Bestätigung."""
        count = self._verlauf_tree.topLevelItemCount()
        dlg = FinlaiConfirmDialog(
            title="Verlauf löschen",
            message=(
                f"Gesamten Scan-Verlauf löschen? ({count} Einträge)\n"
                "Dieser Vorgang kann nicht rückgängig gemacht werden."
            ),
            confirm_text="Löschen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._service.delete_all_scans()
        self._verlauf_tree.clear()
        self._verlauf_detail.clear()
        self._btn_verlauf_loeschen.setEnabled(False)
        log.info("Scan-Verlauf gelöscht durch Benutzer")

    @Slot(object)
    def _verlauf_ausgewaehlt(self, item: QTreeWidgetItem) -> None:
        """Zeigt Details eines Verlaufs-Scans.

        Args:
            item: Angeklicktes QTreeWidgetItem.
        """
        scan: NetworkScanResult = item.data(0, Qt.ItemDataRole.UserRole)
        if scan is None:
            return

        lines = [
            f"Scan: {scan.ziel}  ({scan.scanner_typ})",
            f"Dauer: {scan.dauer_s:.1f}s",
            "",
        ]
        for host in scan.hosts:
            if not host.erreichbar:
                lines.append(f"  {host.host}: nicht erreichbar")
                continue
            lines.append(f"  {host.host}: {len(host.offene_ports)} offene Port(s)")
            for p in host.offene_ports:
                lines.append(
                    f"    {p.port:5d}  {p.service or '?':20s}  [{p.risk.value.upper()}]  {p.hinweis}"
                )
        self._verlauf_detail.setPlainText("\n".join(lines))

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"QWidget {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
            f"QPushButton {{ background-color: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 5px 14px; min-height: 28px; }}"
            f"QPushButton:hover {{ background-color: {c.ACCENT_DIM};"
            f" border-color: {c.ACCENT}; color: {c.TEXT_MAIN}; }}"
            f"QPushButton:pressed {{ background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; padding-top: 6px; padding-bottom: 4px; }}"
            f"QPushButton:disabled {{ background-color: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
            f"QScrollBar:vertical {{ background: {c.BG_MAIN}; width: 8px; border: none; }}"
            f"QScrollBar::handle:vertical {{ background: {c.BORDER};"
            f" border-radius: 4px; min-height: 30px; }}"
            f"QScrollBar::handle:vertical:hover {{ background: {c.ACCENT}80; }}"
            f"QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}"
        )
        tree_style = (
            f"QTreeWidget {{ background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; }}"
            f"QTreeWidget::item {{ padding: 3px 4px; }}"
            f"QTreeWidget::item:hover {{ background-color: {c.ACCENT}30; }}"
            f"QTreeWidget::item:selected {{ background-color: {c.ACCENT}50;"
            f" color: {theme.DARK_TEXT_ON_ACCENT}; }}"
            f"QHeaderView::section {{ background-color: {c.BG_DARK};"
            f" color: {c.TEXT_DIM}; padding: 6px 8px; border: none;"
            f" border-right: 1px solid {c.ACCENT_LINE}; border-bottom: 1px solid {c.ACCENT_LINE};"
            f" font-size: 11px; font-weight: 600; }}"
            f"QTreeWidget::indicator {{ width: 14px; height: 14px;"
            f" border: 2px solid {c.BORDER}; border-radius: 2px;"
            f" background: {c.BG_INPUT}; }}"
            f"QTreeWidget::indicator:checked {{ background: {c.ACCENT};"
            f" border-color: {c.ACCENT}; }}"
            f"QTreeWidget::indicator:hover {{ border-color: {c.ACCENT}; }}"
        )
        self._port_tree.setStyleSheet(tree_style)
        self._verlauf_tree.setStyleSheet(tree_style)
        self._discovery_tree.setStyleSheet(tree_style)
        self._detail_text.setStyleSheet(
            f"QTextEdit {{ background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; }}"
        )
        self._verlauf_detail.setStyleSheet(
            f"QTextEdit {{ background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; }}"
        )


def _hex_zu_qcolor(hex_farbe: str):
    """Konvertiert einen Hex-Farbstring in ein QColor-Objekt.

    Args:
        hex_farbe: Hex-Farbcode (z.B. "#e53935").

    Returns:
        QColor-Objekt.
    """
    from PySide6.QtGui import QColor

    return QColor(hex_farbe)
