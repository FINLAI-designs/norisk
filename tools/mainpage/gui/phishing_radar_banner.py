"""
phishing_radar_banner — Phishing-Radar-Karte fuer den Homescreen.

 AP3: Vom 120px-Vollbreiten-Band zur vertikal
expandierenden Spalten-Karte (rechte Homescreen-Spalte) umgebaut.

Loest die alte 3-Spalten-``PhishingHelpSection`` ab. Zeigt:
  * Header mit Tooltip (Glossar Phishing)
  * Schutz-Framing-Pill ("Du wurdest heute vor X Tricks geschuetzt")
  * bis zu 6 frischeste High-Severity-Items aus PHISHING_CONSUMER
  * Primaer-Button "Alle X Warnungen oeffnen ->" → oeffnet
    ``PhishingInboxDialog``
  * Dezenter Notfall-Link "Schon reingefallen?" → oeffnet Tab 3 im
    Modal

UX-Norm: Schutz-Framing statt Pflicht-Framing, Du-Form, konkrete
Zahlen, Tooltip <= 20 Woerter (NN/g) — siehe interne UX-Doku.

Author: Patrick Riederich
Version: 1.0 (2026-05-28 Phishing-Radar-Refactor)
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from core.url_guard import open_external_url
from tools.mainpage.gui.phishing_inbox_list import (
    severity_signal_color,
    severity_text_color,
)
from tools.mainpage.gui.phishing_radar_data import (
    BannerDaten,
    PhishingRadarViewModel,
    relativ_zeit,
    severity_kuerzel,
    severity_tooltip,
)

log = get_logger(__name__)

# Mindesthoehe der Karte — nach oben waechst sie mit der Spalte
# AP3: expandierende Karte statt fixem 120px-Band).
_BANNER_HOEHE = 120

# Maximal gleichzeitig gerenderte Meldungen in der Karte.
_MAX_ITEMS = 6

# Tooltip-Text Glossar (siehe UX_TOOLTIP_STRATEGY §3) — exakt
# uebernommen, NN/g <= 20 Woerter.
_TOOLTIP_HEADER = (
    "Betrugs-Mails, SMS oder Webseiten, die Passwörter oder "
    "Zahlungsdaten abgreifen wollen — oft täuschend echt."
)


class PhishingRadarBanner(QWidget):
    """Kompakte Phishing-Banner-Sektion auf dem Homescreen.

    Args:
        view_model: Reine Datenquelle (ViewModel) — kann ``None`` sein
            (Test-/Stripped-Tier-Pfad).
        parent: Eltern-Widget.
    """

    def __init__(
        self,
        view_model: PhishingRadarViewModel | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._view_model = view_model or PhishingRadarViewModel(None)
        self._daten: BannerDaten | None = None
        # Expandierende Karte: Mindesthoehe statt Fixhoehe AP3)
        self.setMinimumHeight(_BANNER_HOEHE)
        self._build_ui()
        self.refresh()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 4, 8, 4)
        outer.setSpacing(4)

        # Card-Hauptcontainer.
        self._card = QFrame(self)
        self._card.setObjectName("phishing_radar_card")
        card_lyt = QVBoxLayout(self._card)
        card_lyt.setContentsMargins(12, 8, 12, 8)
        card_lyt.setSpacing(4)

        # Header-Zeile: Titel + Pill + Notfall-Link rechts.
        header_row = QWidget(self._card)
        header_row.setStyleSheet("background: transparent;")
        hr_lyt = QHBoxLayout(header_row)
        hr_lyt.setContentsMargins(0, 0, 0, 0)
        hr_lyt.setSpacing(8)

        self._header = QLabel("Phishing-Radar")
        self._header.setToolTip(_TOOLTIP_HEADER)
        self._header.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY_LG}px;"
            " font-weight: bold;"
        )
        hr_lyt.addWidget(self._header)

        self._pill = QLabel("")
        self._pill.setObjectName("phishing_radar_pill")
        self._pill.setVisible(False)
        hr_lyt.addWidget(self._pill)

        hr_lyt.addStretch(1)

        self._notfall_btn = QPushButton("Schon reingefallen?")
        self._notfall_btn.setFlat(True)
        self._notfall_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._notfall_btn.setObjectName("phishing_radar_notfall")
        self._notfall_btn.clicked.connect(self._oeffne_modal_notfall)
        hr_lyt.addWidget(self._notfall_btn)

        card_lyt.addWidget(header_row)

        # Items gestapelt — die Karte lebt jetzt in der rechten Homescreen-
        # Spalte und waechst vertikal AP3); der CTA wandert in eine
        # Fusszeile.
        self._items_container = QWidget(self._card)
        self._items_container.setStyleSheet("background: transparent;")
        self._items_layout = QVBoxLayout(self._items_container)
        self._items_layout.setContentsMargins(0, 0, 0, 0)
        self._items_layout.setSpacing(3)
        self._items_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        card_lyt.addWidget(self._items_container, stretch=1)

        # Fusszeile: Call-to-Action + Ungelesen-Counter.
        footer = QWidget(self._card)
        footer.setStyleSheet("background: transparent;")
        footer_lyt = QHBoxLayout(footer)
        footer_lyt.setContentsMargins(0, 0, 0, 0)
        footer_lyt.setSpacing(8)

        self._oeffnen_btn = QPushButton("Alle Warnungen öffnen →")
        self._oeffnen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._oeffnen_btn.setObjectName("phishing_radar_oeffnen")
        self._oeffnen_btn.clicked.connect(self._oeffne_modal_inbox)
        # Natürliche Breite — kein Full-Width-CTA (Review-F-2)
        footer_lyt.addWidget(self._oeffnen_btn)
        footer_lyt.addStretch(1)

        self._ungelesen_lbl = QLabel("")
        self._ungelesen_lbl.setObjectName("phishing_radar_ungelesen")
        footer_lyt.addWidget(self._ungelesen_lbl)

        card_lyt.addWidget(footer)
        outer.addWidget(self._card)

    # ------------------------------------------------------------------
    # Public-API
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Aktualisiert die Banner-Inhalte aus dem ViewModel."""

        try:
            self._daten = self._view_model.banner_daten()
            self._populate(self._daten)
        except Exception as exc:  # noqa: BLE001 -- Refresh darf nie crashen
            log.warning(
                "PhishingRadarBanner.refresh fehlgeschlagen: %s",
                type(exc).__name__,
            )

    def set_view_model(self, view_model: PhishingRadarViewModel) -> None:
        """Tauscht das ViewModel aus (z.B. bei Modus-Wechsel)."""

        self._view_model = view_model
        self.refresh()

    # ------------------------------------------------------------------
    # Rendering-Helpers
    # ------------------------------------------------------------------

    def _populate(self, daten: BannerDaten) -> None:
        # Items-Liste neu rendern.
        while self._items_layout.count():
            item = self._items_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not daten.bereit:
            placeholder = QLabel(
                "Phishing-Cache wird geladen — öffne das Risikobriefing "
                "einmal, danach erscheinen hier aktuelle Warnungen."
            )
            placeholder.setWordWrap(True)
            placeholder.setStyleSheet(
                f"font-size: {theme.FONT_SIZE_CAPTION}px;"
                f" color: {theme.get().TEXT_DIM};"
            )
            self._items_layout.addWidget(placeholder)
        elif not daten.items:
            placeholder = QLabel(
                "Keine aktuellen Phishing-Warnungen in den letzten 24 Stunden — "
                "weiter wachsam bleiben."
            )
            placeholder.setWordWrap(True)
            placeholder.setStyleSheet(
                f"font-size: {theme.FONT_SIZE_CAPTION}px;"
                f" color: {theme.get().TEXT_DIM};"
            )
            self._items_layout.addWidget(placeholder)
        else:
            for meldung in daten.items[:_MAX_ITEMS]:
                self._items_layout.addWidget(self._build_item_row(meldung))

        # Pill: Schutz-Framing mit konkretem Counter.
        if daten.bereit and daten.neue_24h > 0:
            self._pill.setText(
                f"Du wurdest heute vor {daten.neue_24h} neuen Tricks geschützt"
            )
            self._pill.setVisible(True)
        else:
            self._pill.setVisible(False)

        # CTA-Button + Ungelesen-Counter.
        if daten.gesamt > 0:
            self._oeffnen_btn.setText(f"Alle {daten.gesamt} Warnungen öffnen →")
        else:
            self._oeffnen_btn.setText("Phishing-Inbox öffnen →")
        if daten.ungelesen > 0:
            self._ungelesen_lbl.setText(f"{daten.ungelesen} ungelesen")
            self._ungelesen_lbl.setVisible(True)
        else:
            self._ungelesen_lbl.setVisible(False)

    def _build_item_row(self, meldung) -> QWidget:  # noqa: ANN001
        row = QFrame()
        row.setObjectName("phishing_radar_item")
        row.setCursor(Qt.CursorShape.PointingHandCursor)
        row_lyt = QHBoxLayout(row)
        row_lyt.setContentsMargins(4, 2, 4, 2)
        row_lyt.setSpacing(6)

        # Severity-Badge (kompakt) — Tooltip-Volltext fuer Barrierefreiheit.
        sev_value = getattr(meldung.schweregrad, "value", "info")
        badge = QLabel(severity_kuerzel(sev_value))
        badge.setObjectName("phishing_radar_badge")
        badge.setFixedWidth(48)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setProperty("severity", sev_value)
        badge.setToolTip(severity_tooltip(sev_value))
        # Severity-Farben direkt am Badge-Widget (nicht über die Vorfahren-
        # Kaskade) — nur so füllt Qt den Signal-Hintergrund des QLabel. Die
        # Signalfarben sind theme-unabhängige Konstanten → kein Re-Style nötig.
        badge.setStyleSheet(
            f"background-color: {severity_signal_color(sev_value)};"
            f" color: {severity_text_color(sev_value)};"
            " border-radius: 3px; padding: 1px 4px;"
            f" font-size: {theme.FONT_SIZE_CAPTION}px; font-weight: bold;"
        )
        row_lyt.addWidget(badge)

        # Titel mit Quelle/Datum-Sub.
        text_col = QWidget()
        text_col.setStyleSheet("background: transparent;")
        text_lyt = QVBoxLayout(text_col)
        text_lyt.setContentsMargins(0, 0, 0, 0)
        text_lyt.setSpacing(0)

        title = QLabel(_kuerze(meldung.titel, 90))
        # Feed-Titel ist untrusted — als PlainText rendern (kein Tracking-Pixel
        # via <img>-Markup im Titel).
        title.setTextFormat(Qt.TextFormat.PlainText)
        title.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_CAPTION}px; font-weight: bold;"
        )
        text_lyt.addWidget(title)

        sub = QLabel(
            f"{meldung.quelle.value} · {relativ_zeit(meldung.veroeffentlicht)}"
        )
        sub.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_CAPTION}px; color: {theme.get().TEXT_DIM};"
        )
        text_lyt.addWidget(sub)

        row_lyt.addWidget(text_col, stretch=1)

        # Click: oeffne URL (Scheme-Whitelist) + markiere als gelesen.
        def handler(_evt=None, m=meldung):  # noqa: ANN001, ANN202
            if m.url:
                open_external_url(m.url)
            self._view_model.markiere_gelesen([m.guid])
            self.refresh()

        row.mousePressEvent = handler  # type: ignore[assignment]
        return row

    # ------------------------------------------------------------------
    # Aktionen
    # ------------------------------------------------------------------

    def _oeffne_modal_inbox(self) -> None:
        self._oeffne_modal(initial_tab=0)

    def _oeffne_modal_notfall(self) -> None:
        self._oeffne_modal(initial_tab=2)

    def _oeffne_modal(self, initial_tab: int) -> None:
        try:
            from tools.mainpage.gui.phishing_inbox_dialog import (  # noqa: PLC0415
                PhishingInboxDialog,
            )

            dialog = PhishingInboxDialog(
                view_model=self._view_model,
                initial_tab=initial_tab,
                modus=self._view_model.modus,
                parent=self,
            )
            dialog.exec()
            self.refresh()
        except Exception as exc:  # noqa: BLE001 -- Modal-Open darf Banner nicht crashen
            log.warning(
                "PhishingInboxDialog-Open fehlgeschlagen: %s",
                type(exc).__name__,
            )

    # ------------------------------------------------------------------
    # Theming
    # ------------------------------------------------------------------

    def apply_theme(self) -> None:
        c = theme.get()
        self._header.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY_LG}px;"
            f" font-weight: bold; color: {c.TEXT_MAIN};"
        )
        # Pill direkt am Widget stylen (nicht über die self-Kaskade) — sonst füllt
        # Qt den Teal-Hintergrund des QLabel nicht und die dunkle Schrift landet
        # ohne Fill auf der dunklen Card (schwarz-auf-schwarz).
        self._pill.setStyleSheet(
            f"background-color: {c.ACCENT};"
            f" color: {c.BG_DARK if hasattr(c, 'BG_DARK') else c.BG_MAIN};"
            " border-radius: 8px; padding: 2px 8px;"
            f" font-size: {theme.FONT_SIZE_CAPTION}px; font-weight: bold;"
        )
        self.setStyleSheet(
            "QFrame#phishing_radar_card {"
            f" background: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER};"
            " border-radius: 6px;"
            "}"
            "QFrame#phishing_radar_item {"
            f" background: transparent; border: 1px solid transparent;"
            f" border-radius: 4px;"
            "}"
            "QFrame#phishing_radar_item:hover {"
            f" background: {c.BG_MAIN};"
            f" border: 1px solid {c.BORDER};"
            "}"
            "QLabel#phishing_radar_ungelesen {"
            f" color: {c.TEXT_DIM};"
            f" font-size: {theme.FONT_SIZE_CAPTION}px;"
            "}"
            "QPushButton#phishing_radar_notfall {"
            f" color: {c.ACCENT};"
            " background: transparent; border: none;"
            f" font-size: {theme.FONT_SIZE_CAPTION}px;"
            "}"
            "QPushButton#phishing_radar_notfall:hover {"
            f" color: {c.ACCENT_DIM};"
            " text-decoration: underline;"
            "}"
        )
        # CTA-Button ebenfalls direkt am Widget stylen — selber Grund wie bei der
        # Pill: der gefüllte Teal-Hintergrund wird nur über das eigene
        # Widget-Stylesheet gemalt, nicht über die App-/Vorfahren-Kaskade.
        self._oeffnen_btn.setStyleSheet(
            "QPushButton {"
            f" background-color: {c.ACCENT};"
            f" color: {c.BG_MAIN};"
            " border: none; border-radius: 4px; padding: 6px 10px;"
            f" font-size: {theme.FONT_SIZE_BODY_SM}px;"
            " font-weight: bold;"
            "}"
            "QPushButton:hover {"
            f" background-color: {c.ACCENT_DIM};"
            "}"
        )


# ----------------------------------------------------------------------
# Modul-Helpers
# ----------------------------------------------------------------------

def _kuerze(text: str, maxlen: int) -> str:
    if not text:
        return ""
    if len(text) <= maxlen:
        return text
    return text[: maxlen - 1].rstrip() + "…"
