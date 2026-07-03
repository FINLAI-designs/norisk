"""
phishing_inbox_dialog — Modal-Fenster fuer den Phishing-Radar mit
Master-Detail-Liste, Filter-Sidebar und 2 statischen Hilfe-Tabs.

Author: Patrick Riederich
Version: 1.0 (2026-05-28 Phishing-Radar-Refactor)
"""

from __future__ import annotations

import html

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from core.url_guard import open_external_url
from core.widgets.secure_markdown_browser import SecureMarkdownBrowser
from tools.mainpage.gui.phishing_inbox_list import (
    PhishingInboxListView,
    PhishingItemModel,
    snooze_bis_morgen,
)
from tools.mainpage.gui.phishing_radar_data import PhishingRadarViewModel
from tools.mainpage.gui.phishing_static_content import (
    EMERGENCY_STEPS,
    RECOGNITION_HINTS,
)

log = get_logger(__name__)


_ZEITRAUM_OPTIONEN: list[tuple[str, int]] = [
    ("Letzte 24 Stunden", 24),
    ("Letzte 7 Tage", 168),
    ("Letzte 14 Tage", 336),
    ("Letzte 30 Tage", 720),
]


_SCHWEREGRAD_OPTIONEN: list[tuple[str, str]] = [
    ("Alle", "niedrig"),
    ("Mittel und höher", "mittel"),
    ("Hoch und kritisch", "hoch"),
    ("Nur kritisch", "kritisch"),
]


class PhishingInboxDialog(QDialog):
    """Modal-Dialog fuer den Phishing-Radar.

    Args:
        view_model: Reine Datenquelle.
        initial_tab: 0=Aktuelle Warnungen, 1=Erkennen, 2=Notfall.
        modus: ``easy`` / ``expert`` — bestimmt Default-Filter und
            Sichtbarkeit der Filter-Sidebar.
        parent: Eltern-Widget.
    """

    def __init__(
        self,
        view_model: PhishingRadarViewModel,
        initial_tab: int = 0,
        modus: str = "easy",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._view_model = view_model
        self._modus = modus
        self._model = PhishingItemModel(self)
        self._aktuelle_meldung = None

        self.setWindowTitle("Phishing-Radar")
        self.setMinimumSize(900, 600)
        self.resize(1000, 700)
        self.setModal(True)

        self._build_ui(initial_tab)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(30_000)
        self._refresh_timer.timeout.connect(self._refresh_inbox)
        self._refresh_timer.start()

        theme.register_listener(self.apply_theme)
        self.apply_theme()
        self._refresh_inbox()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self, initial_tab: int) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(6)

        # Header.
        header = QWidget(self)
        header.setStyleSheet("background: transparent;")
        h_lyt = QHBoxLayout(header)
        h_lyt.setContentsMargins(0, 0, 0, 0)
        title = QLabel("Phishing-Radar")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY_LG}px;"
            " font-weight: bold;"
        )
        h_lyt.addWidget(title)
        h_lyt.addStretch(1)
        self._alle_gelesen_btn = QPushButton("Alle als gelesen markieren")
        self._alle_gelesen_btn.clicked.connect(self._alle_gelesen)
        h_lyt.addWidget(self._alle_gelesen_btn)
        outer.addWidget(header)

        # Tabs.
        self._tabs = QTabWidget(self)
        self._tabs.addTab(self._build_inbox_tab(), "Aktuelle Warnungen")
        self._tabs.addTab(self._build_static_tab(RECOGNITION_HINTS), "So erkennst du Phishing")
        self._tabs.addTab(self._build_static_tab(EMERGENCY_STEPS), "Schon reingefallen?")
        self._tabs.setCurrentIndex(max(0, min(initial_tab, 2)))
        outer.addWidget(self._tabs, stretch=1)

    def _build_inbox_tab(self) -> QWidget:
        wrap = QWidget()
        lyt = QHBoxLayout(wrap)
        lyt.setContentsMargins(0, 0, 0, 0)
        lyt.setSpacing(6)

        # Filter-Sidebar (Easy-Modus: hidden hinter Toggle).
        self._filter_sidebar = self._build_filter_sidebar()
        lyt.addWidget(self._filter_sidebar)
        # setVisible erst NACH dem Parenting (parentlos + True
        # mappt ein natives Top-Level-Fenster — Blitz beim Dialog-Öffnen).
        self._filter_sidebar.setVisible(self._modus == "expert")

        splitter = QSplitter(Qt.Orientation.Horizontal, wrap)

        self._list_view = PhishingInboxListView(splitter)
        self._list_view.setModel(self._model)
        self._list_view.selectionModel().selectionChanged.connect(
            self._on_selection
        )
        self._list_view.doubleClicked.connect(self._open_aktuelle_url)
        splitter.addWidget(self._list_view)

        self._detail = self._build_detail_panel()
        splitter.addWidget(self._detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        lyt.addWidget(splitter, stretch=1)

        # Toggle-Button fuer Filter (Easy/Expert-Modus-Wechsel).
        self._filter_toggle = QPushButton("☰ Filter")
        self._filter_toggle.setObjectName("phishing_inbox_filter_toggle")
        self._filter_toggle.setCheckable(True)
        self._filter_toggle.setChecked(self._modus == "expert")
        self._filter_toggle.toggled.connect(self._filter_sidebar.setVisible)
        # Toggle-Button vertikal links neben Sidebar einbauen.
        toggle_wrap = QWidget()
        tw_lyt = QVBoxLayout(toggle_wrap)
        tw_lyt.setContentsMargins(0, 0, 0, 0)
        tw_lyt.addWidget(self._filter_toggle)
        tw_lyt.addStretch(1)
        lyt.insertWidget(0, toggle_wrap)
        return wrap

    def _build_filter_sidebar(self) -> QWidget:
        side = QFrame()
        side.setObjectName("phishing_inbox_filter")
        side.setFixedWidth(220)
        s_lyt = QVBoxLayout(side)
        s_lyt.setContentsMargins(8, 8, 8, 8)
        s_lyt.setSpacing(6)

        s_lyt.addWidget(QLabel("Quellen"))
        self._quellen_list = QListWidget()
        self._quellen_list.itemChanged.connect(self._refresh_inbox)
        self._fill_quellen_list()
        s_lyt.addWidget(self._quellen_list, stretch=1)

        s_lyt.addWidget(QLabel("Schweregrad"))
        self._sg_combo = QComboBox()
        for label, value in _SCHWEREGRAD_OPTIONEN:
            self._sg_combo.addItem(label, value)
        # Default: Mittel und hoeher.
        self._sg_combo.setCurrentIndex(1)
        self._sg_combo.currentIndexChanged.connect(self._refresh_inbox)
        s_lyt.addWidget(self._sg_combo)

        s_lyt.addWidget(QLabel("Zeitraum"))
        self._zeit_combo = QComboBox()
        for label, hours in _ZEITRAUM_OPTIONEN:
            self._zeit_combo.addItem(label, hours)
        self._zeit_combo.setCurrentIndex(1)
        self._zeit_combo.currentIndexChanged.connect(self._refresh_inbox)
        s_lyt.addWidget(self._zeit_combo)

        self._nur_ungelesen = QCheckBox("Nur ungelesen")
        self._nur_ungelesen.toggled.connect(self._refresh_inbox)
        s_lyt.addWidget(self._nur_ungelesen)

        reset = QPushButton("Filter zurücksetzen")
        reset.clicked.connect(self._reset_filter)
        s_lyt.addWidget(reset)
        return side

    def _fill_quellen_list(self) -> None:
        """Befuellt die Quellen-Checkboxliste passend zum Modus."""

        from tools.cyber_dashboard.domain.models import (  # noqa: PLC0415
            QUELLE_KATEGORIE,
        )

        # Erlaubte Kategorien zentral aus dem ViewModel ableiten — der
        # ViewModel-Modus ist die Single Source of Truth.
        self._view_model.set_modus(self._modus)
        erlaubt = set(self._view_model.kategorien_fuer_modus())
        self._quellen_list.blockSignals(True)
        self._quellen_list.clear()
        for quelle, kategorie in QUELLE_KATEGORIE.items():
            if kategorie not in erlaubt:
                continue
            item = QListWidgetItem(quelle.value)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            item.setData(Qt.ItemDataRole.UserRole, quelle)
            self._quellen_list.addItem(item)
        self._quellen_list.blockSignals(False)

    def _build_detail_panel(self) -> QWidget:
        wrap = QFrame()
        wrap.setObjectName("phishing_inbox_detail")
        lyt = QVBoxLayout(wrap)
        lyt.setContentsMargins(8, 8, 8, 8)
        lyt.setSpacing(6)

        self._detail_title = QLabel("Wähle eine Warnung aus")
        # Feed-Titel ist untrusted — nie als Rich-Text rendern: ein
        # <img src="http://..."> im Titel wuerde sonst ein Tracking-Pixel
        # laden und die SecureMarkdownBrowser-Haertung des Body umgehen.
        self._detail_title.setTextFormat(Qt.TextFormat.PlainText)
        self._detail_title.setWordWrap(True)
        self._detail_title.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_BODY_LG}px; font-weight: bold;"
        )
        lyt.addWidget(self._detail_title)

        self._detail_meta = QLabel("")
        self._detail_meta.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" color: {theme.get().TEXT_DIM};"
        )
        lyt.addWidget(self._detail_meta)

        # SecureMarkdownBrowser: sanitisiert setHtml, blockt externe
        # Resource-Loads (Tracking-Pixel) und oeffnet nur https-Anchors.
        self._detail_text = SecureMarkdownBrowser()
        lyt.addWidget(self._detail_text, stretch=1)

        button_row = QWidget()
        br_lyt = QHBoxLayout(button_row)
        br_lyt.setContentsMargins(0, 0, 0, 0)
        br_lyt.setSpacing(6)

        self._open_btn = QPushButton("Im Browser öffnen")
        self._open_btn.clicked.connect(self._open_aktuelle_url)
        br_lyt.addWidget(self._open_btn)

        self._toggle_read_btn = QPushButton("Als gelesen markieren")
        self._toggle_read_btn.clicked.connect(self._toggle_read)
        br_lyt.addWidget(self._toggle_read_btn)

        self._snooze_btn = QPushButton("Bis morgen verstecken")
        self._snooze_btn.clicked.connect(self._snooze_aktuelle)
        br_lyt.addWidget(self._snooze_btn)

        # Reserviert fuer KI-Chat-Trigger.
        self._chat_btn = QPushButton("Erkläre mir das")
        self._chat_btn.setEnabled(False)
        self._chat_btn.setToolTip(
            "KI-Erklärung wird in einem späteren Sprint angeschlossen "
            "(WP T-262)."
        )
        br_lyt.addWidget(self._chat_btn)

        br_lyt.addStretch(1)
        lyt.addWidget(button_row)
        return wrap

    def _build_static_tab(
        self, eintraege: list[tuple[str, str]]
    ) -> QWidget:
        wrap = QWidget()
        wrap_lyt = QVBoxLayout(wrap)
        wrap_lyt.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea(wrap)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")
        content = QWidget()
        content.setStyleSheet("background: transparent;")
        c_lyt = QVBoxLayout(content)
        c_lyt.setContentsMargins(12, 12, 12, 12)
        c_lyt.setSpacing(8)

        for headline, detail in eintraege:
            frame = QFrame()
            frame.setObjectName("phishing_static_card")
            f_lyt = QVBoxLayout(frame)
            f_lyt.setContentsMargins(10, 8, 10, 8)
            f_lyt.setSpacing(3)
            hl = QLabel(headline)
            hl.setStyleSheet(
                f"font-size: {theme.FONT_SIZE_BODY_SM}px; font-weight: bold;"
            )
            hl.setWordWrap(True)
            f_lyt.addWidget(hl)
            dt = QLabel(detail)
            dt.setStyleSheet(f"font-size: {theme.FONT_SIZE_BODY_SM}px;")
            dt.setWordWrap(True)
            f_lyt.addWidget(dt)
            c_lyt.addWidget(frame)
        c_lyt.addStretch(1)
        scroll.setWidget(content)
        wrap_lyt.addWidget(scroll)
        return wrap

    # ------------------------------------------------------------------
    # Datenfluss
    # ------------------------------------------------------------------

    def _aktuelle_quellen_filter(self) -> list:
        if not hasattr(self, "_quellen_list"):
            return []
        ausgewaehlt = []
        for i in range(self._quellen_list.count()):
            item = self._quellen_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                ausgewaehlt.append(item.data(Qt.ItemDataRole.UserRole))
        return ausgewaehlt

    def _refresh_inbox(self) -> None:
        try:
            sg_value = (
                self._sg_combo.currentData()
                if hasattr(self, "_sg_combo")
                else "mittel"
            )
            hours = (
                self._zeit_combo.currentData()
                if hasattr(self, "_zeit_combo")
                else 168
            )
            nur_ungelesen = (
                self._nur_ungelesen.isChecked()
                if hasattr(self, "_nur_ungelesen")
                else False
            )
            meldungen = self._view_model.inbox_items(
                quellen_filter=self._aktuelle_quellen_filter() or None,
                min_schweregrad_value=sg_value,
                seit_stunden=int(hours),
                nur_ungelesen=nur_ungelesen,
                limit=200,
            )
            # Read-State fuer Delegate-Rendering ueber die oeffentliche
            # ViewModel-API (kein Durchgriff auf das Repository).
            gelesene = self._view_model.gelesene_guids(
                [m.guid for m in meldungen]
            )
            self._model.setze_meldungen(meldungen, gelesene)
            self._on_selection()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "PhishingInboxDialog._refresh_inbox fehlgeschlagen: %s",
                type(exc).__name__,
            )

    def _on_selection(self, *_args) -> None:  # noqa: ANN001
        idx = self._list_view.currentIndex()
        if not idx.isValid():
            self._aktuelle_meldung = None
            self._detail_title.setText("Wähle eine Warnung aus")
            self._detail_meta.setText("")
            self._detail_text.setHtml("")
            self._open_btn.setEnabled(False)
            self._toggle_read_btn.setEnabled(False)
            self._snooze_btn.setEnabled(False)
            return
        m = self._model.meldung_an(idx.row())
        self._aktuelle_meldung = m
        if m is None:
            return
        self._detail_title.setText(m.titel)
        self._detail_meta.setText(
            f"{m.quelle.value} · {m.schweregrad.value.upper()} · "
            f"{m.veroeffentlicht.strftime('%d.%m.%Y %H:%M')}"
        )
        # Feed-Inhalt ist nicht vertrauenswuerdig — vor dem Rendern
        # HTML-escapen (kein Markup aus dem Feed uebernehmen).
        beschreibung_html = html.escape(m.beschreibung or "").replace(
            "\n", "<br>"
        )
        if m.url:
            safe_url = html.escape(m.url, quote=True)
            link_html = f'<p><a href="{safe_url}">{safe_url}</a></p>'
        else:
            link_html = ""
        self._detail_text.setHtml(f"<p>{beschreibung_html}</p>{link_html}")
        gelesen = bool(idx.data(Qt.ItemDataRole.UserRole + 1))
        self._toggle_read_btn.setText(
            "Als ungelesen markieren" if gelesen else "Als gelesen markieren"
        )
        self._open_btn.setEnabled(bool(m.url))
        self._toggle_read_btn.setEnabled(True)
        self._snooze_btn.setEnabled(True)

    # ------------------------------------------------------------------
    # Aktionen
    # ------------------------------------------------------------------

    def _open_aktuelle_url(self, *_args) -> None:  # noqa: ANN001
        if self._aktuelle_meldung and self._aktuelle_meldung.url:
            # Scheme-Whitelist (http/https) gegen file://-/javascript:-Feeds.
            open_external_url(self._aktuelle_meldung.url)
            self._view_model.markiere_gelesen([self._aktuelle_meldung.guid])
            self._model.setze_gelesen([self._aktuelle_meldung.guid])
            self._on_selection()

    def _toggle_read(self) -> None:
        if self._aktuelle_meldung is None:
            return
        idx = self._list_view.currentIndex()
        gelesen = bool(idx.data(Qt.ItemDataRole.UserRole + 1))
        guid = self._aktuelle_meldung.guid
        if gelesen:
            self._view_model.markiere_ungelesen([guid])
            self._model.setze_ungelesen([guid])
        else:
            self._view_model.markiere_gelesen([guid])
            self._model.setze_gelesen([guid])
        self._on_selection()

    def _snooze_aktuelle(self) -> None:
        if self._aktuelle_meldung is None:
            return
        bis = snooze_bis_morgen()
        # Quelle mitgeben — die Meldung liegt hier vor, spart den Cache-Scan.
        self._view_model.schiebe_auf(
            self._aktuelle_meldung.guid,
            bis,
            self._aktuelle_meldung.quelle,
        )
        self._model.entferne(self._aktuelle_meldung.guid)
        self._aktuelle_meldung = None
        self._on_selection()

    def _alle_gelesen(self) -> None:
        if not self._model.rowCount():
            return
        guids = [
            self._model.meldung_an(i).guid
            for i in range(self._model.rowCount())
        ]
        self._view_model.markiere_gelesen(guids)
        self._model.setze_gelesen(guids)
        self._on_selection()

    def _reset_filter(self) -> None:
        self._sg_combo.setCurrentIndex(1)
        self._zeit_combo.setCurrentIndex(1)
        self._nur_ungelesen.setChecked(False)
        for i in range(self._quellen_list.count()):
            self._quellen_list.item(i).setCheckState(Qt.CheckState.Checked)

    # ------------------------------------------------------------------
    # Modus / Lifecycle
    # ------------------------------------------------------------------

    def setze_modus(self, modus: str) -> None:
        self._modus = modus
        self._filter_sidebar.setVisible(modus == "expert")
        self._filter_toggle.blockSignals(True)
        self._filter_toggle.setChecked(modus == "expert")
        self._filter_toggle.blockSignals(False)
        self._fill_quellen_list()
        self._refresh_inbox()

    def closeEvent(self, event) -> None:  # noqa: D401
        try:
            self._refresh_timer.stop()
        except Exception:  # noqa: BLE001
            pass
        super().closeEvent(event)

    # ------------------------------------------------------------------
    # Theming
    # ------------------------------------------------------------------

    def apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            "QDialog {"
            f" background: {c.BG_MAIN};"
            "}"
            "QFrame#phishing_inbox_filter {"
            f" background: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER};"
            " border-radius: 6px;"
            "}"
            "QFrame#phishing_inbox_detail {"
            f" background: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER};"
            " border-radius: 6px;"
            "}"
            "QFrame#phishing_static_card {"
            f" background: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER};"
            " border-radius: 6px;"
            "}"
            "QPushButton#phishing_inbox_filter_toggle {"
            f" background: {c.CARD_BG};"
            f" color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER};"
            " border-radius: 4px;"
            " padding: 4px 6px;"
            "}"
        )

        # Aktions-Buttons direkt am Widget stylen. Der globale QPushButton:hover
        # (background-color: ACCENT) malt auf einem Button INNERHALB des
        # stylesheet-behafteten Dialogs NICHT (App-/Vorfahren-Kaskade, fehlendes
        # WA_StyledBackground) — nur color: BG_DARK greift, sodass auf Hover die
        # dunkle Schrift ohne den Teal-Fill auf dem dunklen Grund landet =
        # unsichtbar. Ein EIGENES Widget-Stylesheet malt den Hover-Fill zuverlässig.
        action_btn_qss = (
            "QPushButton {"
            f" background-color: transparent; color: {c.ACCENT};"
            f" border: 1px solid {c.ACCENT}; border-radius: 4px;"
            " padding: 6px 12px; font-weight: 500;"
            "}"
            "QPushButton:hover {"
            f" background-color: {c.ACCENT}; color: {c.BG_DARK};"
            "}"
            "QPushButton:disabled {"
            f" background-color: transparent; color: {c.TEXT_DIM};"
            f" border-color: {c.BORDER};"
            "}"
        )
        for btn in (
            self._alle_gelesen_btn,
            self._open_btn,
            self._toggle_read_btn,
            self._snooze_btn,
            self._chat_btn,
        ):
            btn.setStyleSheet(action_btn_qss)
