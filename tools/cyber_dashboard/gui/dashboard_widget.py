"""
dashboard_widget — Cyberrisiko-Dashboard GUI (Etappe 4).

Tab-Layout, 2026-06-29 — KI-Lagebild auf Pos. 2, CVE-Uebersicht auf Pos. 4):
  [🛡️ Risikobriefing] — erklaertes Risikobild (RisikoPunkt-Engine, off-thread)
  [🤖 KI-Lagebild] — Tägliches Ollama-Briefing (on-demand)
  [⚠️ Phishing-Wellen] — Phishing-Meldungen als Karten (lazy)
  [🐞 CVE-Uebersicht] — Schwachstellen-Aggregat (NVD/KEV/CSAF/Techstack, lazy)
  [🔍 CVEs] — NVD CVE-Tabelle mit Suche
  [📰 Warnungen] — RSS-Meldungen mit Filter
  [📄 Wochenbericht] — PDF-Export (lazy)

NVD API-Key-Verwaltung liegt seit 2026-04-21 global (Einstellungen).

Tech-Stack ist seit 2026-04-20 ein eigenständiges Tool
(:mod:`tools.techstack`) und kein Tab mehr in diesem Dashboard.

Statistik-Kacheln oben: Kritisch / Hoch / KEV.
Hintergrund-Laden via _LadeThread, _CveSearchThread.
Auto-Refresh alle 60 Minuten.

KI-Briefing: NICHT automatisch — nur auf Benutzer-Anforderung (Button im Lagebild-Tab).
Videos: Aus dem Dashboard entfernt. UI-Bindung ersatzlos gestrichen.

Author: Patrick Riederich
Version: 4.0
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from PySide6.QtCore import Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import ICON_SIZE_HERO, Icons, get_icon
from core.logger import get_logger
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.cyber_dashboard.application.dashboard_service import (
    DashboardService,
    create_default_dashboard_service,
)
from tools.cyber_dashboard.domain.models import (
    CveEintrag,
    CyberMeldung,
    QuelleTyp,
    Schweregrad,
)
from tools.cyber_dashboard.gui.kacheln_widget import StatistikKacheln
from tools.cyber_dashboard.gui.lagebild_tab import LagebildTab
from tools.cyber_dashboard.gui.phishing_wellen_tab import PhishingWellenTab
from tools.cyber_dashboard.gui.risiko_lage_tab import RisikoLageTab
from tools.cyber_dashboard.gui.wochenbericht_tab import WochenberichtTab

log = get_logger(__name__)

# Farben und Emojis je Schweregrad (Severity-Signal-Palette aus core.theme)
_ALLOWED_URL_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def _open_external_url(url: str) -> None:
    """Öffnet eine externe URL **nur** wenn das Scheme http/https ist.

    Schutz gegen ``file://``/``javascript:``/``ms-msdt:`` (Follina-Klasse)
    in Feeds — vgl. Security-Review follow-up P1. Andere Schemes
    werden mit einer Warnung im Log abgelehnt.
    """
    if not url:
        return
    parsed = QUrl(url)
    scheme = parsed.scheme().lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        log.warning(
            "URL-Open verweigert — Scheme %r nicht in Whitelist (url=%r)",
            scheme,
            url[:120],
        )
        return
    QDesktopServices.openUrl(parsed)


_FARBEN: dict[Schweregrad, str] = {
    Schweregrad.KRITISCH: theme.SEVERITY_SIGNAL_CRITICAL,
    Schweregrad.HOCH: theme.SEVERITY_SIGNAL_HIGH,
    Schweregrad.MITTEL: theme.SEVERITY_SIGNAL_MEDIUM,
    Schweregrad.NIEDRIG: theme.SEVERITY_SIGNAL_LOW,
    Schweregrad.INFO: theme.SEVERITY_SIGNAL_INFO,
}

_SCHWERE_PREFIX: dict[Schweregrad, str] = {
    Schweregrad.KRITISCH: "[K]",
    Schweregrad.HOCH: "[H]",
    Schweregrad.MITTEL: "[M]",
    Schweregrad.NIEDRIG: "[N]",
    Schweregrad.INFO: "[I]",
}


def _cve_farben() -> dict[str, tuple[str, str]]:
    """Gibt Severity-Farben (bg, text) passend zum aktiven Theme zurück.

    Leerer String bedeutet: keinen eigenen Hintergrund/keine eigene Textfarbe setzen.

    Returns:
        Dict {schweregrad_upper: (bg_hex, text_hex)}.
    """
    c = theme.get()
    return {
        "CRITICAL": (c.SEVERITY_CRITICAL_BG, c.SEVERITY_CRITICAL_TEXT),
        "HIGH": (c.SEVERITY_HIGH_BG, c.SEVERITY_HIGH_TEXT),
        "MEDIUM": (c.SEVERITY_MEDIUM_BG, c.SEVERITY_MEDIUM_TEXT),
    }


def _cve_badge_farben() -> dict[str, tuple[str, str]]:
    """Vivid-Palette fuer die Schweregrad-Spalte als Badge.

    Anders als:func:`_cve_farben` (dezenter Zeilen-Tint) liefert diese
    Funktion die kraeftigen ``SEVERITY_SIGNAL_*``-Farben und schwarzen
    Kontrast-Text — damit ist die ``Schweregrad``-Spalte unabhaengig
    vom Theme deutlich erkennbar..

    Returns:
        Dict ``{schweregrad_upper: (bg_hex, text_hex)}`` fuer alle
        bekannten Stufen inkl. ``LOW`` und ``INFO`` (im Zeilen-Tint
        bisher leer).
    """
    # FE-5 (Code-Review 2026-05-19): vorher hartcodiertes "#1a1a1a" als
    # Text-Auf-Severity-BG. theme.TEXT_ON_ACCENT_DEEP (#0b1e1c) ist genau
    # dafuer gedacht — dunkler Teal-Schwarz auf hellem Akzent-/Severity-
    # Hintergrund. Single-Source-of-Truth fuer Theme-Wechsel/White-Label.
    return {
        "CRITICAL": (theme.SEVERITY_SIGNAL_CRITICAL, theme.TEXT_ON_ACCENT_DEEP),
        "HIGH": (theme.SEVERITY_SIGNAL_HIGH, theme.TEXT_ON_ACCENT_DEEP),
        "MEDIUM": (theme.SEVERITY_SIGNAL_MEDIUM, theme.TEXT_ON_ACCENT_DEEP),
        "LOW": (theme.SEVERITY_SIGNAL_LOW, theme.TEXT_ON_ACCENT_DEEP),
        "INFO": (theme.SEVERITY_SIGNAL_INFO, theme.TEXT_ON_ACCENT_DEEP),
    }


def _apply_severity_badge(item: QTableWidgetItem) -> None:
    """Faerbt eine Schweregrad-Zelle als kraeftiges Badge.

    Verwendet die ``_cve_badge_farben``-Palette und schaltet Fett-Stil
    plus zentrierte Ausrichtung. Macht die Schweregrad-Spalte auch dann
    erkennbar wenn der Zeilen-Tint dezent ist.
    """
    bg_hex, text_hex = _cve_badge_farben().get(item.text().upper(), ("", ""))
    if not bg_hex:
        return
    item.setBackground(QColor(bg_hex))
    item.setForeground(QColor(text_hex))
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    fett = item.font()
    fett.setBold(True)
    item.setFont(fett)


# ---------------------------------------------------------------------------
# Hintergrund-Threads
# ---------------------------------------------------------------------------


class _LadeThread(QThread):
    """Lädt RSS-Feeds und CVE-Statistiken im Hintergrund.

    Videos und KI-Briefing werden NICHT automatisch geladen:
    - Videos: aus dem Dashboard entfernt.
    - Briefing: nur auf Benutzer-Anforderung (Button im Lagebild-Tab).

    Signals:
        meldungen_geladen: Emittiert geladene Meldungen.
        statistiken_geladen: Emittiert CVE-Zähler nach Schweregrad.
        fertig: Emittiert nach Abschluss aller Ladevorgänge.
    """

    meldungen_geladen: Signal = Signal(list)
    statistiken_geladen: Signal = Signal(dict)
    fertig: Signal = Signal()
    # (percent 0-100, step description) — treibt den Ladescreen-Fortschrittsbalken
    fortschritt: Signal = Signal(int, str)

    def __init__(
        self,
        service: DashboardService,
        erzwingen: bool = False,
    ) -> None:
        """Initialisiert den Lade-Thread.

        Args:
            service: DashboardService-Instanz.
            erzwingen: True = Cache ignorieren.
        """
        super().__init__()
        self._service = service
        self._erzwingen = erzwingen

    def run(self) -> None:
        """Lädt RSS-Meldungen, CVE-Datenbank und Statistiken sequentiell.

        Fortschritt: RSS-Feeds 0–40 %, CVE-Datenbank 40–80 %, Statistiken 80–100 %.

        Robustheits-Vertrag: jeder Sub-Service-Aufruf darf scheitern, ohne
        dass der Thread crasht — sonst hängt das Dashboard im Ladescreen
        bei 5 % statt zur ``fertig``-Signal-Emission zu kommen. Wir fangen
        deshalb pro Schritt das volle:class:`Exception` (BLE001 ist hier
        bewusst per ``noqa`` erlaubt; gleicher Aggregator-Vertrag wie in
:class:`tools.security_scoring.application.scoring_service.ScoringService`).
        """
        self.fortschritt.emit(5, "Sicherheitsmeldungen werden abgerufen …")
        try:
            meldungen = self._service.lade_meldungen(erzwingen=self._erzwingen)
            self.meldungen_geladen.emit(meldungen)
        except Exception as exc:  # noqa: BLE001 -- Worker-Robustheit: kein Step darf den Lade-Thread crashen
            log.error("Meldungen laden fehlgeschlagen: %s", exc)
            self.meldungen_geladen.emit([])
        self.fortschritt.emit(40, "Sicherheitsmeldungen geladen")

        self.fortschritt.emit(45, "CVE-Datenbank wird geprüft …")
        try:
            self._service.lade_cves(erzwingen=self._erzwingen)
        except Exception as exc:  # noqa: BLE001 -- Worker-Robustheit
            log.error("CVEs laden fehlgeschlagen: %s", exc)
        self.fortschritt.emit(80, "CVE-Datenbank geladen")

        self.fortschritt.emit(82, "Statistiken werden berechnet …")
        try:
            zaehler = self._service.zaehle_statistiken()
            self.statistiken_geladen.emit(zaehler)
        except Exception as exc:  # noqa: BLE001 -- Worker-Robustheit
            log.error("Statistiken laden fehlgeschlagen: %s", exc)
            self.statistiken_geladen.emit({})
        self.fortschritt.emit(100, "Dashboard bereit")

        self.fertig.emit()


class _CveSearchThread(QThread):
    """Sucht CVEs für ein Produkt via NVD API im Hintergrund.

    Signals:
        ergebnis: Emittiert die gefundenen CVE-Einträge.
    """

    ergebnis: Signal = Signal(list)

    def __init__(
        self,
        service: DashboardService,
        produkt: str,
        tage: int,
    ) -> None:
        """Initialisiert den CVE-Such-Thread.

        Args:
            service: DashboardService-Instanz.
            produkt: Suchbegriff (Produktname).
            tage: Zeitraum in Tagen.
        """
        super().__init__()
        self._service = service
        self._produkt = produkt
        self._tage = tage

    def run(self) -> None:
        """Führt die NVD-Produktsuche aus."""
        try:
            cves = self._service.suche_cves_produkt(self._produkt, self._tage)
            self.ergebnis.emit(cves)
        except (OSError, RuntimeError, ConnectionError, ValueError) as exc:
            log.error("CVE-Produktsuche fehlgeschlagen: %s", exc)
            self.ergebnis.emit([])


# ---------------------------------------------------------------------------
# Lade-Overlay
# ---------------------------------------------------------------------------

_TIMEOUT_SEKUNDEN = 30


class _LadeOverlay(QWidget):
    """Ladescreen für das Cyberrisiko-Dashboard.

    Zeigt ein zentriertes Karten-Widget mit Icon, Titel, Fortschrittsbalken
    und aktuellem Schritt-Text. Wird zu Beginn des ersten Ladevorgangs
    angezeigt und verschwindet sobald alle Daten geladen sind oder ein
    Timeout aufgetreten ist.

    Args:
        parent: Optionales Eltern-Widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        """Erstellt das zentrierte Karten-Layout."""
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Karte
        self._card = QFrame()
        self._card.setObjectName("lade_card")
        self._card.setFixedWidth(420)

        card_layout = QVBoxLayout(self._card)
        card_layout.setContentsMargins(40, 36, 40, 36)
        card_layout.setSpacing(0)
        card_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Shield-Icon
        lbl_icon = QLabel()
        lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_icon.setPixmap(get_icon(Icons.SHIELD).pixmap(ICON_SIZE_HERO, ICON_SIZE_HERO))
        lbl_icon.setFixedHeight(64)
        card_layout.addWidget(lbl_icon)

        # Titel
        lbl_titel = QLabel("Risikobriefing")
        lbl_titel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_titel.setStyleSheet(
            "font-family: 'Raleway'; font-size: 16px; font-weight: bold;"
            " background: transparent; border: none; margin-top: 8px;"
        )
        card_layout.addWidget(lbl_titel)

        # Untertitel
        lbl_sub = QLabel("wird geladen …")
        lbl_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_sub.setObjectName("lade_sub")
        lbl_sub.setStyleSheet(
            "font-family: 'Raleway'; font-size: 13px;"
            " background: transparent; border: none; margin-bottom: 20px;"
        )
        card_layout.addWidget(lbl_sub)

        # Fortschrittsbalken: kanonischer FinlaiProgressBar)
        self._progress = FinlaiProgressBar(total=100)
        card_layout.addWidget(self._progress)
        card_layout.addSpacing(10)

        # Schritt-Text
        self._lbl_schritt = QLabel("Initialisierung …")
        self._lbl_schritt.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_schritt.setObjectName("lade_schritt")
        self._lbl_schritt.setWordWrap(True)
        self._lbl_schritt.setFixedHeight(36)
        card_layout.addWidget(self._lbl_schritt)

        outer.addWidget(self._card)

    def set_progress(self, percent: int, schritt: str) -> None:
        """Aktualisiert Fortschrittsbalken und Schritt-Text.

        Args:
            percent: Fortschritt in Prozent (0–100).
            schritt: Beschreibung des aktuellen Schritts.
        """
        self._progress.setValue(max(self._progress.value(), percent))
        self._lbl_schritt.setText(schritt)

    def apply_theme(self) -> None:
        """Aktualisiert Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(f"QWidget {{ background-color: {c.BG_MAIN}; }}")
        self._card.setStyleSheet(
            f"QFrame#lade_card {{"
            f" background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER};"
            f" border-radius: 12px;"
            f"}}"
        )
        self._lbl_schritt.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 12px;"
            f" font-family: 'Raleway'; background: transparent; border: none;"
        )
        # FinlaiProgressBar erbt sein Aussehen aus dem globalen Theme-
        # Stylesheet (#FinlaiProgressBar) — kein lokaler Override mehr noetig.


# ---------------------------------------------------------------------------
# Meldungs-Karte
# ---------------------------------------------------------------------------


class _MeldungsKarte(QFrame):
    """Eine einzelne Cybersicherheits-Meldung als Karten-Widget.

    Args:
        meldung: Anzuzeigende CyberMeldung.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        meldung: CyberMeldung,
        parent: QWidget | None = None,
    ) -> None:
        """Baut die Karte auf."""
        super().__init__(parent)
        self._meldung = meldung
        self._farbe = _FARBEN[meldung.schweregrad]
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        """Erstellt das Karten-Layout."""
        m = self._meldung
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(2)

        # Kopfzeile: Emoji + Quelle + Datum
        kopf = QHBoxLayout()
        datum_str = m.veroeffentlicht.strftime("%d.%m. %H:%M")
        self._lbl_kopf = QLabel(f"<b>{m.quelle.value}</b> — {datum_str}")
        self._lbl_kopf.setTextFormat(Qt.TextFormat.RichText)
        self._lbl_kopf.setStyleSheet("background: transparent; border: none;")
        kopf.addWidget(self._lbl_kopf)
        kopf.addStretch()

        btn_link = QPushButton("Details")
        btn_link.setIcon(get_icon(Icons.LINK))
        btn_link.setFixedWidth(82)
        btn_link.setFixedHeight(22)
        btn_link.clicked.connect(lambda: _open_external_url(m.url))
        kopf.addWidget(btn_link)
        layout.addLayout(kopf)

        # Titel
        lbl_titel = QLabel(m.titel)
        lbl_titel.setWordWrap(True)
        lbl_titel.setStyleSheet(
            "font-weight: bold; background: transparent; border: none;"
        )
        layout.addWidget(lbl_titel)

        # Beschreibung (gekürzt auf 150 Zeichen)
        if m.beschreibung:
            kurz = m.beschreibung[:150]
            if len(m.beschreibung) > 150:
                kurz += "…"
            lbl_desc = QLabel(kurz)
            lbl_desc.setWordWrap(True)
            lbl_desc.setStyleSheet(
                "font-size: 11px; background: transparent; border: none;"
            )
            layout.addWidget(lbl_desc)

    def apply_theme(self) -> None:
        """Aktualisiert Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"QFrame {{ background-color: {c.CARD_BG};"
            f" border-left: 3px solid {self._farbe};"
            f" border-radius: 4px; margin: 2px 0px; }}"
        )


# ---------------------------------------------------------------------------
# Haupt-Widget
# ---------------------------------------------------------------------------


class CyberDashboardWidget(QWidget):
    """Cyberrisiko-Dashboard — RSS + NVD CVE API + Statistik-Kacheln.

    7 Tabs: Risikobriefing, KI-Lagebild, Phishing-Wellen,
    CVE-Uebersicht, CVEs, Warnungen, Wochenbericht.
    Statistik-Kacheln zeigen Kritisch/Hoch/KEV.

    Args:
        parent: Optionales Eltern-Widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert das Dashboard und startet den ersten Ladevorgang."""
        super().__init__(parent)
        self._meldungen: list[CyberMeldung] = []
        self._lade_thread: _LadeThread | None = None
        self._cve_search_thread: _CveSearchThread | None = None
        self._zaehler: dict[str, int] = {}
        self._lagebild_tab: LagebildTab | None = None
        self._wochenbericht_tab: WochenberichtTab | None = None
        self._erster_ladevorgang: bool = True
        # Lazy-Tab-Cache: Index → erstelltes Widget (verhindert Doppel-Init)
        self._tab_instances: dict[int, QWidget] = {}
        # Lazy-Tab-Config: (Tab-Index, Beschriftung, Icon-Name, Factory)
        self._lazy_tab_configs: list[tuple[int, str, str, Callable[[], QWidget]]] = []

        # Service via Factory (CISA KEV primaer, NVD optional,
        # TechStack-Repository) — Widget kennt die data-Klassen nicht
        # mehr direkt.
        self._service = create_default_dashboard_service()

        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

        # Auto-Refresh alle 60 Minuten (silent — kein Ladescreen)
        self._timer = QTimer(self)
        self._timer.setInterval(60 * 60 * 1000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

        # Timeout-Timer: falls Ladevorgang nach 30 s noch läuft → Dashboard trotzdem zeigen
        self._timeout_timer = QTimer(self)
        self._timeout_timer.setSingleShot(True)
        self._timeout_timer.setInterval(_TIMEOUT_SEKUNDEN * 1000)
        self._timeout_timer.timeout.connect(self._lade_timeout)

        # Cache-first: im nächsten Event-Loop-Tick aus Cache anzeigen (deferred),
        # dann im Hintergrund aktualisieren. QTimer(0) gibt dem Dock-System Zeit
        # das Widget vollständig einzubetten bevor Daten verarbeitet werden.
        QTimer.singleShot(0, self._aus_cache_laden)
        self._refresh()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt das vollständige Widget-Layout.

        Layout-Hierarchie::

            QVBoxLayout (root)
            ├── Header (QHBoxLayout) — immer sichtbar
            └── QStackedWidget
                ├── Index 0: _LadeOverlay (erster Ladevorgang)
                └── Index 1: Content-Widget (Kacheln + Tabs)
        """
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        root.addLayout(self._build_header())

        _hc = HelpRegistry.get("cyber_dashboard")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            root.addWidget(self._help_panel)

        # Stacked: Ladescreen ↔ Inhalt
        self._main_stack = QStackedWidget()

        # Index 0 — Ladescreen
        self._lade_overlay = _LadeOverlay(self)
        self._main_stack.addWidget(self._lade_overlay)

        # Index 1 — Haupt-Inhalt
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(6)

        # Statistik-Kacheln
        self._kacheln = StatistikKacheln(self)
        content_layout.addWidget(self._kacheln)

        # Tab-Widget — Tab 0 ist Startseite
        self._tabs = QTabWidget()

        # / · Tab-Reorder (Patrick 2026-06-29: KI-Lagebild
        # Pos. 4 -> 2, CVE-Uebersicht Pos. 3 -> 4):
        # 0 Risikobriefing (eager) · 1 KI-Lagebild (eager) ·
        # 2 Phishing-Wellen (lazy) · 3 CVE-Uebersicht (lazy) · 4 CVEs ·
        # 5 Warnungen · 6 Wochenbericht (lazy).
        # Tab 0 — Risikobriefing: erklaertes Risikobild aus Patch-Monitor +
        # Security-Audit + Security-Score + betroffenen CVEs (off-thread).
        self._risiko_tab = RisikoLageTab(parent=self)
        self._tabs.addTab(self._risiko_tab, get_icon(Icons.SHIELD), "Risikobriefing")

        # Tab 1 — KI-Lagebild (eager): taegliches Ollama-Briefing on-demand.
        self._lagebild_tab = LagebildTab(self._service, self)
        self._tabs.addTab(self._lagebild_tab, get_icon(Icons.CHAT), "KI-Lagebild")

        # Lazy-Platzhalter fuer Phishing-Wellen (Index 2) + CVE-Uebersicht (Index 3).
        # Der dedizierte Phishing-Tab kehrt aufgewertet zurueck (Karten + Ueberblick,
        # Patrick 2026-06-29; vgl. Entfernung 2026-06-28). CVE-Uebersicht ist die
        # bisherige "Schwachstellen"-Aggregatsicht (NVD/KEV/CSAF/Techstack, S3a)
        # plus "System betroffen"-Filter.
        self._tabs.addTab(QWidget(), get_icon(Icons.WARNING), "Phishing-Wellen")
        self._tabs.addTab(QWidget(), get_icon(Icons.VULNERABILITY), "CVE-Uebersicht")

        self._tabs.addTab(self._build_cve_tab(), get_icon(Icons.VULNERABILITY), "CVEs")
        self._tabs.addTab(
            self._build_warnungen_tab(), get_icon(Icons.WARNING), "Warnungen"
        )
        self._tabs.addTab(QWidget(), get_icon(Icons.PDF), "Wochenbericht")

        # HelpButton rechts oben in der Tabbar-Ecke
        _tip_warn = self._help_tip("tab_warnings")
        if _tip_warn:
            self._tabs.setCornerWidget(
                HelpButton(_tip_warn), Qt.Corner.TopRightCorner
            )
        # Lazy-Tabs (Index 2/3/6) — erst beim ersten Anklicken gebaut. Der
        # Einstellungen-Tab liegt seit 2026-04-21 global (Einstellungen -> API-Keys).
        self._lazy_tab_configs = [
            (
                2,
                "Phishing-Wellen",
                Icons.WARNING,
                lambda: PhishingWellenTab(self._service, self),
            ),
            (
                3,
                "CVE-Uebersicht",
                Icons.VULNERABILITY,
                lambda: self._build_vulnerability_overview_tab(),
            ),
            (
                6,
                "Wochenbericht",
                Icons.PDF,
                lambda: WochenberichtTab(self._service, self),
            ),
        ]

        self._tabs.currentChanged.connect(self._on_tab_changed)
        self._tabs.setCurrentIndex(0)
        content_layout.addWidget(self._tabs)

        self._main_stack.addWidget(content)
        root.addWidget(self._main_stack)

        # Ladescreen initial anzeigen
        self._main_stack.setCurrentIndex(0)

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("cyber_dashboard")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "cyber_dashboard", parent=self.window()
        )
        dlg.show()

    def _build_header(self) -> QHBoxLayout:
        """Erstellt die Kopfzeile mit Titel, Status und Refresh-Button."""
        layout = QHBoxLayout()

        lbl = QLabel("Risikobriefing")
        lbl.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(lbl)
        layout.addStretch()

        self._lbl_status = QLabel("Lade …")
        layout.addWidget(self._lbl_status)

        self._btn_refresh = QPushButton("Aktualisieren")
        self._btn_refresh.setIcon(get_icon(Icons.SYNC))
        self._btn_refresh.setMinimumHeight(36)
        self._btn_refresh.clicked.connect(lambda: self._refresh(erzwingen=True))
        layout.addWidget(self._btn_refresh)
        return layout

    def _on_tab_changed(self, index: int) -> None:
        """Lazy-Initialisierung: Erstellt Tab-Inhalt beim ersten Anklicken.

        Lazy-Tabs (Index 2 Phishing-Wellen, 3 CVE-Uebersicht, 6 Wochenbericht)
        werden als leere QWidget-Platzhalter angelegt und erst hier durch das
        echte Widget ersetzt. Eager: 0 Risikobriefing, 1 KI-Lagebild, 4 CVEs,
        5 Warnungen. Bereits erstellte Tabs (in ``_tab_instances``) werden sofort
        zurückgegeben — kein Doppel-Init.

        Args:
            index: Angeklickter Tab-Index (0-basiert).
        """
        if index in self._tab_instances:
            return  # Bereits erstellt — nichts zu tun

        config = next((c for c in self._lazy_tab_configs if c[0] == index), None)
        if config is None:
            return  # Eager Tab (0/1/4/5) oder unbekannter Index — keine Lazy-Config

        _, text, icon_name, factory = config
        try:
            widget = factory()
        except Exception as exc:  # noqa: BLE001 -- Tab-Factory kann beliebige Widget-Init-Errors werfen, kein Crash erlaubt
            log.warning(
                "Dashboard Tab %d (%s) konnte nicht erstellt werden: %s",
                index,
                text,
                exc,
            )
            return  # Platzhalter bleibt — kein Crash

        self._tab_instances[index] = widget
        # Platzhalter-Tab durch echtes Widget ersetzen (Index bleibt gleich)
        self._tabs.removeTab(index)
        self._tabs.insertTab(index, widget, get_icon(icon_name), text)
        self._tabs.setCurrentIndex(index)
        # WochenberichtTab-Referenz für Datenbefüllung aktualisieren.
        # Tab-Reihenfolge seit: 0-Risikobriefing, 1-KI-Lagebild,
        # 2-Phishing-Wellen (lazy), 3-CVE-Uebersicht (lazy), 4-CVEs, 5-Warnungen,
        # 6-Wochenbericht (lazy).
        if index == 6:
            self._wochenbericht_tab = widget  # type: ignore[assignment]
        log.debug("Dashboard Tab %d (%s) lazy initialisiert", index, text)

    def _build_vulnerability_overview_tab(self) -> QWidget:
        """Sprint S3a Tab-Factory — VulnerabilityOverviewTab mit Aggregator-Service.

        DI-Setup analog zu:mod:`tools.csaf_advisor.tool` /:mod:`tools.techstack.tool`:
        AdvisoryService aus dem CSAF-Repo, NvdService + TechstackRepo aus
        dem laufenden DashboardService, NvdCacheRepository fresh.

        Wenn ein Sub-Service nicht aufzubauen ist, übergibt die Factory
        ``None`` an den:class:`VulnerabilityOverviewService` — die
        zugehörige Sektion liefert dann eine leere Liste, der Tab bleibt
        funktional.
        """
        from tools.cyber_dashboard.application.vulnerability_overview_service import (  # noqa: PLC0415
            create_default_vulnerability_overview_service,
        )
        from tools.cyber_dashboard.gui.vulnerability_overview_tab import (  # noqa: PLC0415
            VulnerabilityOverviewTab,
        )

        nvd_service = (
            self._service.nvd_service
            if hasattr(self._service, "nvd_service")
            else None
        )
        if nvd_service is None:
            nvd_service = getattr(self._service, "_nvd", None)

        # Factory baut die Defensive-Sub-Initialisierung selbst
        # auf — Widget braucht keine ``data/``-Direktimporte mehr.
        service = create_default_vulnerability_overview_service(
            nvd_service=nvd_service
        )
        widget = VulnerabilityOverviewTab(service, self)
        widget.refresh()
        return widget

    def _build_warnungen_tab(self) -> QWidget:
        """Erstellt den Warnungen-Tab mit Filter-Leiste und Meldungsliste."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(6)

        layout.addLayout(self._build_filter())

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)

        self._meldungen_container = QWidget()
        self._meldungen_layout = QVBoxLayout(self._meldungen_container)
        self._meldungen_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._meldungen_layout.setSpacing(4)
        self._meldungen_layout.setContentsMargins(0, 0, 4, 0)

        self._scroll.setWidget(self._meldungen_container)
        layout.addWidget(self._scroll)
        return container

    def _build_filter(self) -> QHBoxLayout:
        """Erstellt die Filter-Leiste (Quelle, Schweregrad, Suche)."""
        layout = QHBoxLayout()
        layout.setSpacing(12)

        layout.addWidget(QLabel("Quelle:"))
        self._combo_quelle = QComboBox()
        self._combo_quelle.addItem("Alle Quellen", None)
        for qt in QuelleTyp:
            if qt != QuelleTyp.YOUTUBE:
                self._combo_quelle.addItem(qt.value, qt)
        self._combo_quelle.currentIndexChanged.connect(self._filter_anwenden)
        layout.addWidget(self._combo_quelle)

        layout.addWidget(QLabel("Schweregrad:"))
        self._combo_schwere = QComboBox()
        self._combo_schwere.addItem("Alle", None)
        for sg in Schweregrad:
            self._combo_schwere.addItem(sg.value.capitalize(), sg)
        self._combo_schwere.currentIndexChanged.connect(self._filter_anwenden)
        layout.addWidget(self._combo_schwere)

        self._suche = QLineEdit()
        self._suche.setPlaceholderText("Suchen …")
        self._suche.setMinimumWidth(180)
        self._suche.textChanged.connect(self._filter_anwenden)
        layout.addWidget(self._suche)
        layout.addStretch()
        return layout

    def _build_cve_tab(self) -> QWidget:
        """Erstellt den CVE-Tab mit Suchzeile und Tabelle."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(6)

        # Suchzeile
        suche_layout = QHBoxLayout()
        suche_layout.setSpacing(12)

        self._cve_suche = QLineEdit()
        self._cve_suche.setPlaceholderText(
            "Produkt suchen (z.B. Windows, Python, Apache)"
        )
        suche_layout.addWidget(self._cve_suche)

        self._combo_zeitraum = QComboBox()
        self._combo_zeitraum.addItem("7 Tage", 7)
        self._combo_zeitraum.addItem("14 Tage", 14)
        self._combo_zeitraum.addItem("30 Tage", 30)
        suche_layout.addWidget(self._combo_zeitraum)

        # Quelle/Scope: bestimmt aus welchem Pool gelesen wird.
        # Werte sind Tags die _cve_tab_laden in nur_kev/schweregrad/nur_stack
        # uebersetzt — die Combobox selbst kennt keine DB-Details.
        self._combo_quelle_cve = QComboBox()
        self._combo_quelle_cve.addItem("Alle CVEs", "alle")
        self._combo_quelle_cve.addItem("Aktiv ausgenutzt (KEV)", "kev")
        self._combo_quelle_cve.addItem("CRITICAL (NVD)", "critical")
        self._combo_quelle_cve.addItem("Mein Stack betroffen", "stack")
        self._combo_quelle_cve.currentIndexChanged.connect(self._cve_filter_anwenden)
        suche_layout.addWidget(self._combo_quelle_cve)

        self._combo_schwere_cve = QComboBox()
        self._combo_schwere_cve.addItem("Alle", None)
        self._combo_schwere_cve.addItem("CRITICAL", "CRITICAL")
        self._combo_schwere_cve.addItem("HIGH", "HIGH")
        self._combo_schwere_cve.addItem("MEDIUM", "MEDIUM")
        self._combo_schwere_cve.addItem("LOW", "LOW")
        self._combo_schwere_cve.currentIndexChanged.connect(self._cve_filter_anwenden)
        suche_layout.addWidget(self._combo_schwere_cve)

        self._btn_cve_suchen = QPushButton("Suchen")
        self._btn_cve_suchen.setIcon(get_icon(Icons.SEARCH))
        self._btn_cve_suchen.setMinimumHeight(36)
        self._btn_cve_suchen.clicked.connect(self._cve_suchen)
        suche_layout.addWidget(self._btn_cve_suchen)

        self._lbl_cve_status = QLabel("")
        self._lbl_cve_status.setStyleSheet(f"color: {theme.get().TEXT_DIM}; font-size: 11px;")
        suche_layout.addWidget(self._lbl_cve_status)

        layout.addLayout(suche_layout)

        # CVE-Tabelle
        self._cve_tabelle = QTableWidget()
        self._cve_tabelle.setColumnCount(6)
        self._cve_tabelle.setHorizontalHeaderLabels(
            ["CVE-ID", "CVSS", "Schweregrad", "Beschreibung", "KEV", "Details"]
        )
        self._cve_tabelle.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._cve_tabelle.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._cve_tabelle.verticalHeader().setVisible(False)
        self._cve_tabelle.setAlternatingRowColors(False)
        self._cve_tabelle.setSortingEnabled(True)

        header = self._cve_tabelle.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        layout.addWidget(self._cve_tabelle)
        return container

    # ------------------------------------------------------------------
    # Lade-Logik
    # ------------------------------------------------------------------

    def _aus_cache_laden(self) -> None:
        """Lädt Meldungen aus dem Cache für sofortige Anzeige.

        Liest NUR den lokalen Cache — keine Live-Feed-Abfragen.
        Blockiert nicht die UI. Live-Daten werden von _refresh geladen.
        """
        try:
            meldungen = self._service.lade_meldungen(nur_cache=True)
            if meldungen:
                self._meldungen = meldungen
                self._filter_anwenden()
        except (OSError, RuntimeError) as exc:
            log.debug("Cache-Meldungen nicht verfügbar: %s", type(exc).__name__)

    def _ladescreen_ausblenden(self) -> None:
        """Blendet den Ladescreen aus und zeigt den Dashboard-Inhalt.

        Ist ein No-op wenn der Inhalt bereits angezeigt wird.
        Stoppt außerdem den Timeout-Timer.
        """
        if self._main_stack.currentIndex() == 0:
            self._main_stack.setCurrentIndex(1)
        self._timeout_timer.stop()

    def _lade_timeout(self) -> None:
        """Wird aufgerufen wenn der erste Ladevorgang nach 30 s noch läuft.

        Zeigt das Dashboard trotzdem an — mit einem Hinweis dass Daten
        möglicherweise unvollständig sind.
        """
        log.warning(
            "Lade-Timeout nach %d Sekunden — Dashboard wird trotzdem angezeigt.",
            _TIMEOUT_SEKUNDEN,
        )
        self._lade_overlay.set_progress(
            100, "Timeout — einige Daten fehlen möglicherweise"
        )
        self._lbl_status.setText("Teilweise geladen (Timeout)")
        self._btn_refresh.setEnabled(True)
        self._ladescreen_ausblenden()

    def _refresh(self, erzwingen: bool = False) -> None:
        """Startet den Hintergrund-Ladevorgang.

        Beim ersten Ladevorgang wird der Fortschrittsbalken getrieben und
        der Timeout-Timer gestartet. Alle folgenden Aufrufe (Auto-Refresh,
        manuell) laufen still im Hintergrund ohne Ladescreen.

        Args:
            erzwingen: True = Cache ignorieren, Feeds neu abrufen.
        """
        if self._lade_thread and self._lade_thread.isRunning():
            return

        self._lbl_status.setText("Lade …")
        self._btn_refresh.setEnabled(False)

        self._lade_thread = _LadeThread(self._service, erzwingen)
        self._lade_thread.meldungen_geladen.connect(self._meldungen_empfangen)
        self._lade_thread.statistiken_geladen.connect(self._statistiken_empfangen)
        self._lade_thread.fertig.connect(self._laden_fertig)

        if self._erster_ladevorgang:
            # Fortschrittsbalken treiben + Timeout starten
            self._lade_thread.fortschritt.connect(self._lade_overlay.set_progress)
            self._timeout_timer.start()

        self._lade_thread.start()

    @Slot(list)
    def _meldungen_empfangen(self, meldungen: list[CyberMeldung]) -> None:
        """Übernimmt geladene Meldungen und aktualisiert die Ansicht."""
        self._meldungen = meldungen
        self._filter_anwenden()

    @Slot(dict)
    def _statistiken_empfangen(self, zaehler: dict) -> None:
        """Übernimmt CVE-Statistiken und aktualisiert die Kacheln."""
        self._zaehler = zaehler
        self._kacheln_aktualisieren()
        # CVE-Tab mit gecachten Daten befüllen
        self._cve_tab_laden()

    @Slot()
    def _laden_fertig(self) -> None:
        """Aktualisiert Status-Label und blendet ggf. den Ladescreen aus."""
        jetzt = datetime.now(UTC).strftime("%H:%M")
        self._lbl_status.setText(f"Aktualisiert: {jetzt}")
        self._btn_refresh.setEnabled(True)
        self._kacheln_aktualisieren()

        if self._erster_ladevorgang:
            self._erster_ladevorgang = False
            self._ladescreen_ausblenden()

    def _kacheln_aktualisieren(self) -> None:
        """Aktualisiert alle Statistik-Kacheln mit aktuellen Daten."""
        self._kacheln.aktualisiere(
            kritisch=self._zaehler.get("CRITICAL", 0),
            hoch=self._zaehler.get("HIGH", 0),
            kev=self._zaehler.get("kev", 0),
        )

    # ------------------------------------------------------------------
    # Warnungen-Filter
    # ------------------------------------------------------------------

    def _filter_anwenden(self) -> None:
        """Filtert die Meldungsliste nach aktiven Filtereinstellungen."""
        while self._meldungen_layout.count():
            item = self._meldungen_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        quelle: QuelleTyp | None = self._combo_quelle.currentData()
        schwere: Schweregrad | None = self._combo_schwere.currentData()
        suche = self._suche.text().strip().lower()

        gefiltert = [
            m
            for m in self._meldungen
            if (quelle is None or m.quelle == quelle)
            and (schwere is None or m.schweregrad == schwere)
            and (
                not suche or suche in m.titel.lower() or suche in m.beschreibung.lower()
            )
        ]

        for m in gefiltert[:100]:
            self._meldungen_layout.addWidget(_MeldungsKarte(m))

        if not gefiltert:
            lbl = QLabel("Keine Meldungen für diesen Filter.")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet(f"color: {theme.get().TEXT_DIM}; padding: 20px;")
            self._meldungen_layout.addWidget(lbl)

    # ------------------------------------------------------------------
    # CVE-Tab
    # ------------------------------------------------------------------

    def _cve_tab_laden(self) -> None:
        """Befüllt den CVE-Tab mit gecachten Einträgen.

        Die Quelle-Combobox bestimmt den Pool (Alle/KEV/CRITICAL/Stack),
        die Schweregrad-Combobox verfeinert das Ergebnis. Stack-Match
        und KEV-Filter sind kombinierbar mit der Schweregrad-Wahl.
        """
        scope: str = self._combo_quelle_cve.currentData() or "alle"
        sg_user: str | None = self._combo_schwere_cve.currentData()

        nur_kev = scope == "kev"
        nur_stack = scope == "stack"
        # "critical"-Scope erzwingt CRITICAL, lässt sich aber durch die
        # Schweregrad-Combobox nicht weiter einschränken (UX-Konsistenz).
        schweregrad = "CRITICAL" if scope == "critical" else sg_user

        # DEBUG-Level: _cve_tab_laden feuert bei jedem Combobox-
        # Wechsel und nach jedem _LadeThread-Lauf. Für Diagnose das
        # Log-Level temporär hochziehen.
        log.debug(
            "CVE-Tab laden: scope=%s schweregrad=%r counter_kev=%d "
            "counter_high=%d counter_critical=%d",
            scope,
            schweregrad,
            self._zaehler.get("kev", 0),
            self._zaehler.get("HIGH", 0),
            self._zaehler.get("CRITICAL", 0),
        )
        cves = self._service.lade_cves_gefiltert(
            schweregrad=schweregrad,
            nur_kev=nur_kev,
            nur_stack=nur_stack,
            limit=50,
        )
        log.debug("CVE-Tab laden: lade_cves_gefiltert ergab %d Einträge", len(cves))
        self._cve_tabelle_befuellen(cves)
        # Status-Label zeigt den vom Service gelieferten User-Hinweis
        # (Rate-Limit / Offline / fehlender API-Key) statt nur "Keine CVEs".
        hint = self._service.nvd_status_hint()
        if cves:
            base = f"{len(cves)} CVEs"
            if scope == "stack":
                base = f"{len(cves)} CVEs für deinen Tech-Stack"
            elif scope == "kev":
                base = f"{len(cves)} aktiv ausgenutzte CVEs (KEV)"
            elif scope == "critical":
                base = f"{len(cves)} CRITICAL-CVEs"
            else:
                base = f"{len(cves)} CVEs im Cache"
            self._lbl_cve_status.setText(f"{base} — {hint}" if hint else base)
        else:
            # Scope-spezifischer Empty-Hinweis: Stack-Filter ohne Match ist
            # häufig ein leerer Tech-Stack, nicht ein Cache-Problem.
            if scope == "stack":
                empty_text = (
                    "Keine CVEs für deinen Tech-Stack — Stack leer oder kein "
                    "Match in den letzten Einträgen"
                )
            else:
                empty_text = "Keine CVEs im Cache"
            self._lbl_cve_status.setText(
                f"{empty_text} — {hint}" if hint else empty_text
            )

    def _cve_filter_anwenden(self) -> None:
        """Filtert den CVE-Tab nach gewähltem Schweregrad."""
        self._cve_tab_laden()

    def _cve_suchen(self) -> None:
        """Startet eine NVD-Produktsuche im Hintergrund-Thread."""
        produkt = self._cve_suche.text().strip()
        if not produkt:
            self._cve_tab_laden()
            return

        if not self._service.nvd_aktiv():
            self._lbl_cve_status.setText("Kein NVD API Key — Suche nicht möglich")
            return

        if self._cve_search_thread and self._cve_search_thread.isRunning():
            return

        tage = self._combo_zeitraum.currentData() or 7
        self._lbl_cve_status.setText("Suche läuft …")
        self._btn_cve_suchen.setEnabled(False)

        self._cve_search_thread = _CveSearchThread(self._service, produkt, tage)
        self._cve_search_thread.ergebnis.connect(self._cve_suchergebnis_empfangen)
        self._cve_search_thread.start()

    @Slot(list)
    def _cve_suchergebnis_empfangen(self, cves: list[CveEintrag]) -> None:
        """Zeigt das Ergebnis einer CVE-Produktsuche in der Tabelle.

        Args:
            cves: Gefundene CVE-Einträge.
        """
        self._btn_cve_suchen.setEnabled(True)
        self._cve_tabelle_befuellen(cves)
        produkt = self._cve_suche.text().strip()
        self._lbl_cve_status.setText(f'{len(cves)} Ergebnisse f\u00fcr "{produkt}"')

    def _cve_tabelle_befuellen(self, cves: list[CveEintrag]) -> None:
        """Befüllt die CVE-Tabelle mit den übergebenen Einträgen.

        Args:
            cves: Liste der anzuzeigenden CVE-Einträge.
        """
        self._cve_tabelle.setSortingEnabled(False)
        self._cve_tabelle.setRowCount(len(cves))

        fett = QFont()
        fett.setBold(True)

        for row, cve in enumerate(cves):
            # CVE-ID (mit KEV-Markierung)
            id_text = f"[KEV] {cve.cve_id}" if cve.cisa_kev else cve.cve_id
            item_id = QTableWidgetItem(id_text)
            if cve.cisa_kev:
                item_id.setFont(fett)
            self._cve_tabelle.setItem(row, 0, item_id)

            # CVSS-Score
            item_cvss = QTableWidgetItem(f"{cve.cvss_score:.1f}")
            item_cvss.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._cve_tabelle.setItem(row, 1, item_cvss)

            # Schweregrad
            item_sg = QTableWidgetItem(cve.schweregrad)
            item_sg.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._cve_tabelle.setItem(row, 2, item_sg)

            # Beschreibung
            self._cve_tabelle.setItem(row, 3, QTableWidgetItem(cve.beschreibung[:120]))

            # KEV
            item_kev = QTableWidgetItem("Ja" if cve.cisa_kev else "")
            item_kev.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._cve_tabelle.setItem(row, 4, item_kev)

            # Zeilenfarbe je Schweregrad (theme-abhängig)
            bg_hex, text_hex = _cve_farben().get(cve.schweregrad.upper(), ("", ""))
            for col in range(5):
                it = self._cve_tabelle.item(row, col)
                if it:
                    if bg_hex:
                        it.setBackground(QColor(bg_hex))
                    if text_hex:
                        it.setForeground(QColor(text_hex))
            # Severity-Badge in Spalte 2 ueberschreibt den dezenten
            # Zeilen-Tint mit vivider Markierung — macht LOW/INFO
            # ueberhaupt erst erkennbar.
            _apply_severity_badge(item_sg)

            # Details-Button
            url = cve.url
            btn = QPushButton()
            btn.setIcon(get_icon(Icons.LINK))
            btn.setMinimumSize(36, 28)
            btn.setToolTip(f"NVD: {cve.cve_id}")
            btn.clicked.connect(lambda _, u=url: _open_external_url(u))
            self._cve_tabelle.setCellWidget(row, 5, btn)

        self._cve_tabelle.setSortingEnabled(True)

    # ------------------------------------------------------------------
    # YouTube
    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"QWidget {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
            f"QScrollArea {{ border: none; }}"
            f"QTabWidget::pane {{ border: 1px solid {c.BORDER}; border-radius: 4px; }}"
            f"QTabBar::tab {{ background: {c.CARD_BG}; color: {c.TEXT_DIM};"
            f" padding: 8px 16px; border: none;"
            f" border-bottom: 2px solid transparent; font-size: 12px; }}"
            f"QTabBar::tab:selected {{ background: {c.BG_MAIN}; color: {c.ACCENT};"
            f" border-bottom: 2px solid {c.ACCENT}; font-weight: 600; }}"
            f"QTabBar::tab:hover:!selected {{ background: {c.ACCENT_DIM};"
            f" color: {c.TEXT_MAIN}; border-bottom: 2px solid {c.BORDER}; }}"
            f"QPushButton {{ background-color: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 5px 14px; }}"
            f"QPushButton:hover {{ background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; padding-top: 6px; padding-bottom: 4px; }}"
            f"QPushButton:disabled {{ background-color: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
            f"QListWidget {{ background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; }}"
            f"QListWidget::item:selected {{ background-color: {c.ACCENT};"
            f" color: {c.BG_DARK}; }}"
            f"QTableWidget {{ background-color: {c.CARD_BG}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; gridline-color: {c.BORDER}; }}"
            f"QHeaderView::section {{ background-color: {c.BG_MAIN};"
            f" color: {c.TEXT_MAIN}; border: 1px solid {c.BORDER}; padding: 4px; }}"
            f"QComboBox {{ background-color: {c.CARD_BG}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px; }}"
            f"QLineEdit {{ background-color: {c.CARD_BG}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px; }}"
        )
        self.refresh_severity_colors()

    def refresh_severity_colors(self) -> None:
        """Aktualisiert Severity-Hintergründe aller CVE-Tabellenzeilen.

        Wird beim Theme-Wechsel automatisch aufgerufen (via _force_repolish_recursive).
        Die Schweregrad-Spalte (col 2) wird ueber den Zeilen-Tint hinaus
        zusaetzlich als vivides Badge eingefaerbt.
        """
        farben = _cve_farben()
        for row in range(self._cve_tabelle.rowCount()):
            sg_item = self._cve_tabelle.item(row, 2)
            if sg_item is None:
                continue
            bg_hex, text_hex = farben.get(sg_item.text().upper(), ("", ""))
            for col in range(5):
                it = self._cve_tabelle.item(row, col)
                if it:
                    if bg_hex:
                        it.setBackground(QColor(bg_hex))
                    else:
                        it.setData(Qt.ItemDataRole.BackgroundRole, None)
                    if text_hex:
                        it.setForeground(QColor(text_hex))
                    else:
                        it.setData(Qt.ItemDataRole.ForegroundRole, None)
            # Badge-Override fuer Spalte 2 — nach dem Zeilen-Tint.
            _apply_severity_badge(sg_item)
