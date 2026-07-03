"""
status_tiles_section — Cockpit-Status-Kachel-Reihe (Cockpit Increment-2).

Vier At-a-glance-Kacheln (Patch-Status / Netzwerk / Supply-Chain / Passwörter)
mit Klick-Deeplink ins jeweilige Tool. Die Metriken kommen aus
``status_tile_metrics`` (lazy, fail-soft) — eine fehlende Tool-DB lässt die Reihe
neutral, nie leer/kaputt. Die Audit-Dimension fehlt bewusst: sie ist bereits als
``CustomerAuditCard`` im Cockpit (keine Doppelung).

Schichtzugehörigkeit: gui/ — nur Darstellung + Deeplink-Signale.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from core import theme
from tools.norisk_dashboard.application.status_tile_metrics import (
    netzwerk_letzter_scan,
    passwort_letzter_check,
    patch_offene_und_eol,
    supply_offene_punkte,
)


def _vor_tagen(dt: datetime | None) -> str:
    """Formatiert einen Zeitpunkt als „heute" / „vor N T" / „—"."""
    if dt is None:
        return "—"
    tage = (datetime.now(UTC) - dt).days
    return "heute" if tage <= 0 else f"vor {tage} T"


def _frische_zone(dt: datetime | None) -> str:
    """Farb-Zone aus der Frische: nie/>30 T -> warn, sonst ok."""
    if dt is None:
        return "warn"
    return "warn" if (datetime.now(UTC) - dt).days > 30 else "ok"


class _InsightTile(QFrame):
    """Kleiner Quick-Insight-Tile mit Titel + grosser Zahl + Subtitle.

    Klick-Signal ``clicked`` ist immer vorhanden — der Konsument entscheidet pro
    Tile, ob er es weiterleitet oder ignoriert.

    Bis lebte diese Klasse in ``hero_section.py`` und wurde von der
    HeroSection mitbenutzt. Mit dem Wegfall des Hero-Gauges Phase 4,
    ersetzt durch das ``SecurityCockpitBand``) ist die ``StatusTilesSection`` der
    einzige Konsument — die Klasse zog hierher um (kein totes Modul, kein
    cross-modul Privat-Import mehr).
    """

    clicked = Signal()

    def __init__(self, title: str, default_subtitle: str) -> None:
        super().__init__()
        self.setObjectName("insightTile")
        self.setFixedSize(150, 110)
        # Klickbar (mousePressEvent → clicked) → Hand-Cursor als Affordanz.
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._zone = "neutral"

        c = theme.get()
        self.setStyleSheet(self._stylesheet(c, "neutral"))

        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(2)

        self._title = QLabel(title.upper(), self)
        self._title.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; "
            f"font-weight: bold; letter-spacing: 1px; background: transparent;"
        )
        lay.addWidget(self._title)

        self._value = QLabel("—", self)
        self._value.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_HERO}px; "
            f"font-weight: bold; background: transparent;"
        )
        lay.addWidget(self._value)

        self._subtitle = QLabel(default_subtitle, self)
        self._subtitle.setWordWrap(True)
        self._subtitle.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; "
            f"background: transparent;"
        )
        lay.addWidget(self._subtitle)

    def set_value(self, text: str, zone: str) -> None:
        """Setzt den grossen Wert + die Farb-Zone (warn/danger/info/neutral)."""
        self._value.setText(text)
        self._zone = zone
        c = theme.get()
        color_map = {
            "danger": c.DANGER,
            "warn": theme.WARNING_ORANGE,
            "ok": c.SUCCESS,
            "info": c.STATUS_INFO,
            "neutral": c.TEXT_MAIN,
        }
        value_color = color_map.get(zone, c.TEXT_MAIN)
        self._value.setStyleSheet(
            f"color: {value_color}; font-size: {theme.FONT_SIZE_HERO}px; "
            f"font-weight: bold; background: transparent;"
        )
        self.setStyleSheet(self._stylesheet(c, zone))

    def set_subtitle(self, text: str) -> None:
        """Aktualisiert die Subtitle-Zeile unter dem Wert."""
        self._subtitle.setText(text)

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    @staticmethod
    def _stylesheet(c, zone: str) -> str:  # noqa: ANN001
        accent_map = {
            "danger": c.DANGER,
            "warn": theme.WARNING_ORANGE,
            "ok": c.SUCCESS,
            "info": c.STATUS_INFO,
            "neutral": c.BORDER,
        }
        accent = accent_map.get(zone, c.BORDER)
        return (
            f"#insightTile {{ background: {c.BG_INPUT}; "
            f"border: 1px solid {c.BORDER}; "
            f"border-left: 3px solid {accent}; "
            f"border-radius: 4px; }}"
        )


class StatusTilesSection(QWidget):
    """Vier At-a-glance-Status-Kacheln mit Klick-Deeplink ins jeweilige Tool."""

    #: Tool nur öffnen (kein Filter).
    navigate = Signal(str)
    #: Tool öffnen MIT einem ``focus``-Payload.
    open_with_filter = Signal(str, object)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Baut die Kachel-Reihe neutral; Metriken werden post-paint geladen.

        Perf Stage 1a: Die vier Metriken öffnen 4–5 SQLCipher-DBs. Im ctor lief
        das synchron auf dem GUI-Thread VOR dem ersten Paint (~400 ms Freeze beim
        Cockpit-Öffnen). Stattdessen bauen wir die Kacheln neutral („—") und holen
        die Metriken im nächsten Event-Loop-Tick (Kind-QTimer, single-shot, 0 ms) —
        nach dem ersten Paint. Gleiches Muster wie ``_initial_refresh_timer`` im
        ``DashboardWidget``.
        """
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # 1 — Patch-Status: N Updates offen (· M EOL)
        self._patch = _InsightTile("Patch-Status", "Updates offen")
        self._patch.set_value("—", "ok")
        self._patch.clicked.connect(
            lambda: self.open_with_filter.emit("patch_monitor", "outdated")
        )
        layout.addWidget(self._patch)

        # 2 — Netzwerk: Frische des letzten network_scanner-Laufs
        self._netz = _InsightTile("Netzwerk", "zuletzt gescannt")
        self._netz.set_value("—", "ok")
        self._netz.clicked.connect(lambda: self.navigate.emit("network_scanner"))
        layout.addWidget(self._netz)

        # 3 — Supply-Chain: offene Vendor/AVV-Punkte
        self._supply = _InsightTile("Supply-Chain", "Vendor/AVV offen")
        self._supply.set_value("—", "ok")
        self._supply.clicked.connect(
            lambda: self.open_with_filter.emit("supply_chain_monitor", "open")
        )
        layout.addWidget(self._supply)

        # 4 — Passwörter: Frische der letzten Prüfung
        self._pw = _InsightTile("Passwörter", "zuletzt geprüft")
        self._pw.set_value("—", "ok")
        self._pw.clicked.connect(
            lambda: self.open_with_filter.emit("password_checker", "check")
        )
        layout.addWidget(self._pw)

        layout.addStretch(1)

        # Perf Stage 1a: Metriken (4–5 DB-Öffnungen) erst NACH dem ersten Paint
        # laden. Kind-QTimer (single-shot) — stirbt mit dem Widget und feuert
        # nicht auf ein totes C++-Objekt (schnelles Erstellen/Zerstören,
        # Dock-Wechsel, Tests). Vorbild: ``DashboardWidget._initial_refresh_timer``.
        # Hinweis: die Kacheln laden post-paint synchron (4–5 Reads, warm
        # ~10 ms). Der grosse Cold-Start-Freeze lag im Cockpit-Aggregator (~16-25
        # DBs) — DER laeuft jetzt off-thread (s. dashboard_widget). Ein eigener
        # Tile-Worker brachte Teardown-Races (un-injizierte DB-Reads im Thread)
        # bei kleinem Nutzen und wurde bewusst nicht eingebaut.
        self._load_timer = QTimer(self)
        self._load_timer.setSingleShot(True)
        self._load_timer.timeout.connect(self._load_metrics)
        self._load_timer.start(0)

    def _load_metrics(self) -> None:
        """Befüllt die Kacheln fail-soft aus den Metriken (post-paint)."""
        offen, eol = patch_offene_und_eol()
        self._patch.set_value(str(offen), "warn" if offen else "ok")
        self._patch.set_subtitle(f"{eol} EOL" if eol else "Updates offen")

        scan = netzwerk_letzter_scan()
        self._netz.set_value(_vor_tagen(scan), _frische_zone(scan))
        self._netz.set_subtitle("zuletzt gescannt")

        offene_punkte = supply_offene_punkte()
        self._supply.set_value(str(offene_punkte), "warn" if offene_punkte else "ok")
        self._supply.set_subtitle("Vendor/AVV offen")

        chk = passwort_letzter_check()
        self._pw.set_value(_vor_tagen(chk), _frische_zone(chk))
        self._pw.set_subtitle("zuletzt geprüft")
