"""
help_dialog — Zentrales NoRisk-Handbuch-Fenster mit zwei Tabs.

Tab 1 "Handbuch" — statisch:
    Links: QListWidget mit allen Tools, gruppiert nach Sidebar-Gruppen.
            Oben eine Volltextsuche (debounced, 300 ms) filtert die Liste.
    Rechts: QTextBrowser mit formatiertem HTML aus:class:`HelpContent`.

Tab 2 "FINLAI-Assistent" — inline:
    Schlankes:class:`core.help.tabs.assistant_tab.AssistantTab` — Eingabe,
    gestreamte Antwort und nach Domäne gruppierte Quellen. Spricht den am
    Composition-Root verdrahteten ``UnifiedAssistantService`` an (Bedienung
    **und** IT-Sicherheit hinter EINER gehärteten Pipeline) und ersetzt den
    früheren Launcher des Separat-Dialogs.

Der Dialog ist **nicht-modal** (``setModal(False)`` + ``show``) — der
User kann mit dem Hauptfenster weiterarbeiten, während das Handbuch
offen ist. Die Scroll-Position wird pro Tool via ``QSettings`` gemerkt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QSettings, Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.assistant.provider import get_assistant_service
from core.help import handbook_source
from core.help.display_mode import DisplayMode
from core.help.display_mode_state import DisplayModeState
from core.help.help_content import HelpContent
from core.help.help_registry import HelpRegistry
from core.help.tabs.assistant_tab import AssistantTab
from core.icons import Icons, get_icon
from core.logger import get_logger

log = get_logger(__name__)

_SEARCH_DEBOUNCE_MS = 300
_MIN_WIDTH = 700
_MIN_HEIGHT = 500
_DEFAULT_WIDTH = 900
_DEFAULT_HEIGHT = 650

_SCROLL_SETTINGS_PREFIX = "help_dialog_scroll_"


# Gruppierung der Einträge im Nav-List (passt zu den NoRisk-Sidebar-Gruppen).
_NAV_GROUPS: list[tuple[str, list[str]]] = [
    ("Cybersecurity", ["norisk:dashboard", "cyber_dashboard"]),
    (
        "Audits",
        ["customer_audit", "csaf_advisor", "dependency_auditor", "security_scoring"],
    ),
    (
        "Scanner & Tools",
        [
            "system_scanner",
            "techstack",
            "network_scanner",
            "network_monitor",
            "api_security",
            "cert_monitor",
            "password_checker",
            "email_scanner",
            "pdf_risk_scanner",
        ],
    ),
    ("FINLAI-Assistent", ["ki:ollama"]),
]


#: Alt-Tool-Nav-Keys → Handbuch-Abschnittsnummer. Erhält die kontextuellen
#: Deeplinks (Tool-Hilfe springt zum passenden Kapitel), obwohl die Navigation nun
#: aus den.md-Überschriften statt aus ``help_content``-Keys aufgebaut wird.
_NAV_KEY_TO_SECTION: dict[str, str] = {
    "norisk:dashboard": "7", "home": "7", "dashboard": "7",
    "cyber_dashboard": "8.1",
    "csaf_advisor": "8.2", "techstack": "8.2",
    "system_scanner": "9.1",
    "network_scanner": "9.2", "network_monitor": "9.2",
    "cert_monitor": "9.3",
    "api_security": "9.4",
    "file_scanner": "9.5", "email_scanner": "9.5", "pdf_risk_scanner": "9.5",
    "dependency_auditor": "9.6",
    "patch_monitor": "10.1",
    "password_checker": "10.2",  # nosec B105 — Abschnittsnummer, kein Secret
    "supply_chain_monitor": "10.3",
    "customer_audit": "11.1", "security_assessment": "11.1",
    "security_scoring": "11.2",
    "awareness_tracker": "11.3",
    "nis2_incidents": "11.4",
    "system_tuner": "11.5",
    "einstellungen": "12",
    "ki:ollama": "13",
}


#: Fallback-Bildbreite, falls die Viewport-Breite (noch) nicht bekannt ist.
_IMG_FALLBACK_WIDTH = 620
#: Ober-/Untergrenze der skalierten Screenshot-Breite (px).
_IMG_MIN_WIDTH = 320
_IMG_MAX_WIDTH = 900


def _resolve_app_name() -> str:
    """App-ID der aktiven Konfiguration (für die Handbuch-Dateiwahl), Default „norisk"."""
    try:
        from apps.app_config import get_active_config  # noqa: PLC0415

        config = get_active_config()
        return config.app_id if config is not None else "norisk"
    except Exception:  # noqa: BLE001 — außerhalb des App-Kontexts (Tests) fail-soft
        return "norisk"


class HelpDialog(QDialog):
    """Zentrales Handbuch-Fenster mit Navigation, Suche und KI-Tab.

    Args:
        initial_nav_key: Optionaler Tool-Nav-Key — der Dialog springt
            direkt zum entsprechenden Kapitel. ``None`` zeigt die
            Willkommensseite. Der Sentinel:attr:`ASSISTANT_KEY` öffnet
            stattdessen direkt den FINLAI-Assistent-Reiter.
        parent: Optionales Eltern-Widget.
    """

    WELCOME_KEY = "__welcome__"
    #: Sentinel-Nav-Key: öffnet den Dialog direkt auf dem FINLAI-Assistent-Reiter
    #: — genutzt von umgeleiteten ``ki:ollama``-Alt-Deeplinks.
    ASSISTANT_KEY = "__assistant__"
    #: Reiter-Index des FINLAI-Assistenten (Tab 1, nach „Handbuch").
    _ASSISTANT_TAB_INDEX = 1

    def __init__(
        self,
        initial_nav_key: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._initial_key = initial_nav_key
        self._current_key: str | None = None
        # Singleton-Referenz auf den RAG-Assistenten — pro Klick
        # entstand vorher eine NEUE Dialog-Instanz (Parent hielt alle am
        # Leben → Zombie-Akkumulation).
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self._apply_search)

        # Der Handbuch-Reiter rendert die.md-Datei direkt (Single Source of
        # Truth mit Screenshots). ``help_content`` bleibt nur Fallback, falls die
        # Datei fehlt (z. B. unvollständiger Build).
        self._app_name = _resolve_app_name()
        self._sections = handbook_source.load_sections(self._app_name)
        self._section_by_num = {s.number: s for s in self._sections if s.number}
        self._img_base = handbook_source.images_base_uri(self._app_name)

        self.setWindowTitle("NoRisk Handbuch")
        self.setWindowIcon(get_icon(Icons.HELP_CENTER))
        self.setModal(False)
        self.setWindowFlags(
            Qt.WindowType.Window
            | Qt.WindowType.WindowCloseButtonHint
            | Qt.WindowType.WindowMinMaxButtonsHint
        )
        self.setMinimumSize(_MIN_WIDTH, _MIN_HEIGHT)
        self.resize(_DEFAULT_WIDTH, _DEFAULT_HEIGHT)

        self._build_ui()
        self._populate_nav_list()
        self._apply_theme()
        theme.register_listener(self._apply_theme)

        # Einfach/Profi-Zustand: Checkbox spiegelt + steuert den globalen
        # DisplayMode; bei jedem Wechsel wird das offene Kapitel neu gerendert.
        self._display_state = DisplayModeState.instance()
        self._mode_check.setChecked(self._display_state.is_easy())
        self._mode_check.toggled.connect(self._on_mode_check_toggled)
        self._display_state.mode_changed.connect(self._on_display_mode_changed)

        # Initial-Kapitel auswählen — oder direkt den Assistenz-Reiter öffnen.
        if self._initial_key == self.ASSISTANT_KEY:
            self._render_welcome()  # Handbuch-Reiter bleibt auf Willkommen
            self.show_assistant()
        elif self._initial_key:
            self._select_nav_key(self._initial_key)
        else:
            self._render_welcome()

    def show_assistant(self) -> None:
        """Bringt den FINLAI-Assistent-Reiter nach vorn + fokussiert die Eingabe.

        Wird beim Direkt-Öffnen (``ASSISTANT_KEY``) UND beim Wiederverwenden eines
        bereits offenen Dialogs (umgeleiteter ``ki:ollama``-Deeplink) aufgerufen —
        so landet jeder Alt-Einstieg verlässlich auf dem Assistenten, nicht nur
        beim ersten Öffnen Review-P2).
        """
        self._tabs.setCurrentIndex(self._ASSISTANT_TAB_INDEX)
        self._assistant_tab.focus_input()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._tabs = QTabWidget(self)
        self._tabs.setDocumentMode(True)
        root.addWidget(self._tabs)

        self._tabs.addTab(
            self._build_handbook_tab(), get_icon(Icons.BOOK), "Handbuch"
        )
        self._tabs.addTab(
            self._build_assistant_tab(), get_icon(Icons.CHAT), "FINLAI-Assistent"
        )

    def _build_handbook_tab(self) -> QWidget:
        """Tab 1 — Handbuch mit Navigation + Suche + Textansicht."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Suche
        search_row = QHBoxLayout()
        search_icon = QLabel()
        search_icon.setPixmap(get_icon(Icons.SEARCH).pixmap(16, 16))
        search_row.addWidget(search_icon)
        self._search_edit = QLineEdit()
        self._search_edit.setObjectName("help_dialog_search")
        self._search_edit.setPlaceholderText(
            "Suche — z.B. CVE, Passwort, Firewall, Scanner …"
        )
        self._search_edit.textChanged.connect(self._on_search_changed)
        search_row.addWidget(self._search_edit, stretch=1)
        self._search_hits_lbl = QLabel("")
        self._search_hits_lbl.setObjectName("help_dialog_hits")
        search_row.addWidget(self._search_hits_lbl)

        # Einfach/Profi-Umschalter — schaltet handbuch-weit zwischen
        # laienverständlichem und Profi-Text um.
        self._mode_check = QCheckBox("Einfach erklärt")
        self._mode_check.setObjectName("help_dialog_mode")
        self._mode_check.setToolTip(
            "An: einfache, laienverständliche Erklärungen — Aus: Profi-Details."
        )
        # Beim.md-Handbuch (einheitliche Stimme, kein Einfach/Profi-Text)
        # ist der Umschalter bedeutungslos → ausblenden. Der globale Anzeige-Modus
        # bleibt über das Glühbirnen-Symbol in der Titelleiste steuerbar.
        if self._sections:
            self._mode_check.setVisible(False)
        search_row.addWidget(self._mode_check)
        layout.addLayout(search_row)

        # Splitter mit Nav-Liste links, Content rechts
        splitter = QSplitter(Qt.Orientation.Horizontal, container)
        splitter.setChildrenCollapsible(False)

        self._nav_list = QListWidget()
        self._nav_list.setObjectName("help_dialog_nav")
        self._nav_list.setMinimumWidth(200)
        self._nav_list.setMaximumWidth(280)
        self._nav_list.currentItemChanged.connect(self._on_nav_changed)
        splitter.addWidget(self._nav_list)

        self._content_view = QTextBrowser()
        self._content_view.setObjectName("help_dialog_content")
        self._content_view.setOpenExternalLinks(True)
        if self._sections:
            # Bild-Suchpfad für die ``images/…``-Screenshots des Handbuchs (Backup;
            # die Bild-Links werden zusätzlich auf absolute file://-URIs umgeschrieben).
            self._content_view.setSearchPaths(
                [str(handbook_source.handbook_path(self._app_name).parent)]
            )
        splitter.addWidget(self._content_view)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([240, _DEFAULT_WIDTH - 240])

        layout.addWidget(splitter, stretch=1)
        return container

    def _build_assistant_tab(self) -> QWidget:
        """Tab 2 — schlanker, inline eingebetteter FINLAI-Assistent.

        Übergibt das Provider-Callable (kein Service-Aufbau hier — der Service
        wird LAZY beim ersten Senden im Worker-Thread gebaut). Außerhalb des
        App-Kontexts liefert der Provider ``None``, was das Widget abfängt.
        """
        self._assistant_tab = AssistantTab(service_provider=get_assistant_service)
        return self._assistant_tab

    # ------------------------------------------------------------------
    # Nav-Liste
    # ------------------------------------------------------------------

    def _populate_nav_list(self) -> None:
        """Befüllt die Nav-Liste — aus dem.md-Handbuch oder Legacy-Fallback."""
        self._nav_list.clear()
        if not self._sections:
            self._populate_nav_list_legacy()
            return

        welcome = QListWidgetItem(get_icon(Icons.HOME), "Willkommen")
        welcome.setData(Qt.ItemDataRole.UserRole, self.WELCOME_KEY)
        self._nav_list.addItem(welcome)

        for sec in self._sections:
            # Kapitel (##) fett + bündig, Unterkapitel (###) eingerückt.
            label = ("   " + sec.title) if sec.level >= 3 else sec.title
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, sec.number or f"t:{sec.title}")
            if sec.level == 2:
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            self._nav_list.addItem(item)

    def _populate_nav_list_legacy(self) -> None:
        """Fallback-Navigation aus ``help_content`` (nur wenn die.md fehlt)."""
        welcome = QListWidgetItem(get_icon(Icons.HOME), "Willkommen")
        welcome.setData(Qt.ItemDataRole.UserRole, self.WELCOME_KEY)
        self._nav_list.addItem(welcome)

        for group_label, nav_keys in _NAV_GROUPS:
            # Separator-Gruppen-Titel (nicht auswählbar)
            separator = QListWidgetItem(group_label)
            separator.setFlags(Qt.ItemFlag.NoItemFlags)
            separator.setData(Qt.ItemDataRole.UserRole, None)
            self._nav_list.addItem(separator)

            for key in nav_keys:
                content = HelpRegistry.get(key)
                if content is None:
                    continue
                item = QListWidgetItem("   " + content.tool_name)
                item.setData(Qt.ItemDataRole.UserRole, key)
                self._nav_list.addItem(item)

    def _select_nav_key(self, nav_key: str) -> None:
        """Springt zum passenden Kapitel (Tool-Deeplink → Handbuch-Abschnitt)."""
        target = (
            _NAV_KEY_TO_SECTION.get(nav_key, nav_key) if self._sections else nav_key
        )
        for i in range(self._nav_list.count()):
            item = self._nav_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == target:
                self._nav_list.setCurrentItem(item)
                return
        # Unbekannter Deeplink → Willkommen statt leerer Ansicht.
        self._render_welcome()

    def _on_nav_changed(
        self, current: QListWidgetItem | None, previous: QListWidgetItem | None
    ) -> None:
        """Zeigt das Kapitel im Content-Bereich an."""
        if current is None:
            return
        key = current.data(Qt.ItemDataRole.UserRole)
        if key is None:
            return  # Separator
        # Scroll-Position des vorherigen Kapitels merken
        if previous is not None:
            prev_key = previous.data(Qt.ItemDataRole.UserRole)
            if prev_key and prev_key != self.WELCOME_KEY:
                self._save_scroll_pos(prev_key)
        if key == self.WELCOME_KEY:
            self._render_welcome()
        elif self._sections:
            self._render_section(key)
        else:
            self._render_tool(key)
        self._current_key = key

    # ------------------------------------------------------------------
    # Content-Rendering
    # ------------------------------------------------------------------

    def _render_welcome(self) -> None:
        #.md-Handbuch: Einstieg = Kapitel „1. Was ist NoRisk?"; sonst HTML-Willkommen.
        first = self._section_by_num.get("1") if self._sections else None
        if first is not None:
            self._content_view.setMarkdown(self._section_markdown(first))
            self._clamp_images()
        else:
            self._content_view.setHtml(self._build_welcome_html())
        self._current_key = self.WELCOME_KEY

    def _section_markdown(self, section: handbook_source.HandbookSection) -> str:
        """Abschnitts-Markdown mit auf absolute file://-URIs umgeschriebenen Bildern.

        Die Bilder bleiben Markdown-Syntax (``![alt](file://…)``) — nur diese wird von
        ``setMarkdown`` als echtes Bild gerendert; die Breite wird nach dem Rendern
        über:meth:`_clamp_images` an die Content-Breite geklemmt.
        """
        return section.body.replace("](images/", f"]({self._img_base}/images/")

    def _clamp_images(self) -> None:
        """Skaliert zu breite Screenshots auf die Content-Breite (nach setMarkdown)."""
        from PySide6.QtCore import QUrl  # noqa: PLC0415
        from PySide6.QtGui import QImage, QTextCursor  # noqa: PLC0415

        max_w = self._image_width()
        doc = self._content_view.document()
        cursor = QTextCursor(doc)
        block = doc.begin()
        while block.isValid():
            frag_it = block.begin()
            while not frag_it.atEnd():
                frag = frag_it.fragment()
                char_fmt = frag.charFormat()
                if char_fmt.isImageFormat():
                    img_fmt = char_fmt.toImageFormat()
                    local = QUrl(img_fmt.name()).toLocalFile()
                    natural = QImage(local).size() if local else None
                    nat_w = natural.width() if natural else 0
                    nat_h = natural.height() if natural else 0
                    if nat_w > max_w:
                        img_fmt.setWidth(max_w)
                        img_fmt.setHeight(round(nat_h * max_w / nat_w))
                        cursor.setPosition(frag.position())
                        cursor.setPosition(
                            frag.position() + frag.length(),
                            QTextCursor.MoveMode.KeepAnchor,
                        )
                        cursor.setCharFormat(img_fmt)
                frag_it += 1
            block = block.next()

    def _image_width(self) -> int:
        """Ziel-Screenshot-Breite (px), an die aktuelle Content-Breite geklemmt."""
        available = self._content_view.viewport().width() - 44
        if available <= 0:
            available = _IMG_FALLBACK_WIDTH
        return max(_IMG_MIN_WIDTH, min(_IMG_MAX_WIDTH, available))

    def _content_stylesheet(self) -> str:
        """Theme-konformes Dokument-Stylesheet für das gerenderte Handbuch-Markdown."""
        c = theme.get()
        return (
            f"h1 {{ color:{c.ACCENT}; font-family:'Raleway'; font-size:20px;"
            f" font-weight:700; }}"
            f"h2 {{ color:{c.ACCENT}; font-family:'Raleway'; font-size:16px;"
            f" font-weight:700; }}"
            f"h3 {{ color:{theme.DARK_ACCENT_SUBTLE}; font-family:'Raleway';"
            f" font-size:14px; font-weight:600; }}"
            f"h4 {{ color:{c.TEXT_MAIN}; font-family:'Raleway'; font-size:13px; }}"
            f"p, li, td {{ color:{c.TEXT_MAIN}; font-family:'Inter','Raleway';"
            f" font-size:13px; }}"
            f"a {{ color:{theme.DARK_ACCENT_SUBTLE}; text-decoration:none; }}"
            f"strong {{ color:{c.TEXT_MAIN}; }}"
            f"em {{ color:{c.TEXT_DIM}; font-style:italic; }}"
            f"code {{ font-family:'JetBrains Mono'; color:{theme.DARK_ACCENT_SUBTLE};"
            f" background-color:{c.BG_INPUT}; }}"
            f"pre {{ font-family:'JetBrains Mono'; color:{c.TEXT_MAIN};"
            f" background-color:{c.BG_DARK}; }}"
            f"th {{ color:{c.ACCENT}; font-family:'Raleway';"
            f" background-color:{c.CARD_BG}; }}"
            f"td, th {{ border:1px solid {c.BORDER}; padding:4px 8px; }}"
            f"blockquote {{ background-color:{c.CARD_BG}; color:{c.TEXT_MAIN};"
            f" border-left:3px solid {c.ACCENT}; }}"
        )

    def _apply_content_style(self) -> None:
        """Setzt das Dokument-Stylesheet + Rand für das Handbuch-Markdown (theme-reaktiv)."""
        if not self._sections:
            return
        doc = self._content_view.document()
        doc.setDefaultStyleSheet(self._content_stylesheet())
        doc.setDocumentMargin(14)

    def _render_section(self, number: str) -> None:
        """Rendert einen Handbuch-Abschnitt (.md → Markdown mit Screenshots)."""
        section = self._section_by_num.get(number)
        if section is None:
            self._content_view.setMarkdown(f"*Abschnitt {number} nicht gefunden.*")
            return
        self._content_view.setMarkdown(self._section_markdown(section))
        self._clamp_images()
        QTimer.singleShot(0, lambda: self._restore_scroll_pos(number))

    def _on_mode_check_toggled(self, checked: bool) -> None:
        """Checkbox -> globaler DisplayMode (löst mode_changed + Re-Render aus)."""
        self._display_state.set_mode(
            DisplayMode.EASY if checked else DisplayMode.EXPERT
        )

    def _on_display_mode_changed(self, mode: DisplayMode) -> None:
        """Hält die Checkbox synchron und rendert das offene Kapitel neu."""
        self._mode_check.setChecked(mode is DisplayMode.EASY)
        if self._current_key and self._current_key != self.WELCOME_KEY:
            if self._sections:
                self._render_section(self._current_key)
            else:
                self._render_tool(self._current_key)

    def _render_tool(self, nav_key: str) -> None:
        content = HelpRegistry.get(nav_key)
        if content is None:
            self._content_view.setHtml(
                f"<p><i>Kein Hilfetext für '{nav_key}' hinterlegt.</i></p>"
            )
            return
        mode = DisplayModeState.instance().mode()
        self._content_view.setHtml(self._build_tool_html(content, mode))
        QTimer.singleShot(0, lambda: self._restore_scroll_pos(nav_key))

    def _build_welcome_html(self) -> str:
        c = theme.get()
        # Inline-CSS damit QTextBrowser die Farben direkt übernimmt.
        return (
            f"<style>h1 {{ color: {c.ACCENT}; }} h2 {{ color: {c.ACCENT}; "
            f"font-size: 14px; margin-top: 18px; }} p, li {{ color: {c.TEXT_MAIN}; "
            f"font-size: 13px; line-height: 1.5; }}</style>"
            "<h1>NoRisk Handbuch</h1>"
            "<p>Willkommen. Dieses Handbuch erklärt jede Funktion von "
            "NoRisk — laienverständlich und ohne Vorkenntnisse.</p>"
            "<h2>So findest du, was du brauchst</h2>"
            "<ul>"
            "<li>Links in der Liste das Tool auswählen, zu dem du Hilfe suchst.</li>"
            "<li>Oben die Suche nutzen, wenn du nur einen Begriff kennst "
            "(z.B. <i>CVE</i>, <i>Firewall</i>, <i>Scanner</i>).</li>"
            "<li>Fragen in Alltagssprache — zur Bedienung oder zu IT-Sicherheit? "
            "Wechsle in den Tab <b>FINLAI-Assistent</b>.</li>"
            "</ul>"
            "<h2>Jedes Tool-Kapitel ist gleich aufgebaut</h2>"
            "<ul>"
            "<li><b>Wozu dient es?</b> — Der Nutzen in Alltagssprache</li>"
            "<li><b>Wann nutzen?</b> — Typische Situationen</li>"
            "<li><b>So geht es</b> — Schritt-für-Schritt-Anleitung</li>"
            "<li><b>So liest du das Ergebnis</b> — Bedeutung der Farben/Zahlen</li>"
            "<li><b>Was tun danach?</b> — Konkrete nächste Schritte</li>"
            "</ul>"
        )

    @staticmethod
    def _build_tool_html(content: HelpContent, mode: DisplayMode) -> str:
        steps_html = "".join(
            f"<li>{step}</li>" for step in content.steps_for(mode)
        )
        tooltips_html = ""
        if content.tooltips:
            rows = "".join(
                f"<tr><td style='color:{theme.DARK_TEXT_SECONDARY};"
                f" padding-right:12px; vertical-align:top;'>"
                f"<code>{key}</code></td><td>{content.tooltip_for(key, mode)}</td></tr>"
                for key in content.tooltips
            )
            tooltips_html = (
                "<h2>Tooltip-Referenz</h2>"
                "<table style='font-size:12px; line-height:1.4;'>" + rows + "</table>"
            )
        return (
            "<style>"
            f"h1 {{ color: {theme.DARK_ACCENT}; }} "
            f"h2 {{ color: {theme.DARK_ACCENT}; font-size: 14px; margin-top: 18px; }}"
            f"p, li, td {{ color: {theme.DARK_TEXT_PRIMARY};"
            f" font-size: 13px; line-height: 1.5; }}"
            f"code {{ background: {theme.BG_PANEL_DARK};"
            f" padding: 1px 4px; border-radius: 3px; }}"
            "</style>"
            f"<h1>{content.tool_name}</h1>"
            f"<p><i>{content.short_description_for(mode)}</i></p>"
            "<h2>Wozu dient es?</h2>"
            f"<p>{content.purpose_for(mode)}</p>"
            "<h2>Wann nutzen?</h2>"
            f"<p>{content.when_to_use_for(mode)}</p>"
            "<h2>So geht es</h2>"
            f"<ol>{steps_html}</ol>"
            "<h2>So liest du das Ergebnis</h2>"
            f"<p>{content.result_explanation_for(mode)}</p>"
            "<h2>Was tun danach?</h2>"
            f"<p>{content.next_steps_for(mode)}</p>"
            + tooltips_html
        )

    # ------------------------------------------------------------------
    # Suche
    # ------------------------------------------------------------------

    def _on_search_changed(self, _: str) -> None:
        """Debounced-Trigger der Volltextsuche."""
        self._search_timer.start(_SEARCH_DEBOUNCE_MS)

    def _apply_search(self) -> None:
        """Filtert die Nav-Liste anhand der Suchanfrage."""
        query = self._search_edit.text().strip().lower()
        if not query:
            self._show_all_items()
            self._search_hits_lbl.setText("")
            return

        hits = 0
        for i in range(self._nav_list.count()):
            item = self._nav_list.item(i)
            key = item.data(Qt.ItemDataRole.UserRole)
            if key is None or key == self.WELCOME_KEY:
                item.setHidden(bool(query))  # Separator/Welcome weg bei Suche
                continue
            if self._sections:
                sec = self._section_by_num.get(key)
                match = sec is not None and query in f"{sec.title}\n{sec.body}".lower()
            else:
                content = HelpRegistry.get(key)
                match = content is not None and self._matches_query(content, query)
            item.setHidden(not match)
            if match:
                hits += 1
        self._search_hits_lbl.setText(f"{hits} Treffer" if hits else "keine Treffer")

    def _show_all_items(self) -> None:
        for i in range(self._nav_list.count()):
            self._nav_list.item(i).setHidden(False)

    @staticmethod
    def _matches_query(content: HelpContent, query: str) -> bool:
        haystack_parts = [
            content.tool_name,
            content.nav_key,
            content.short_description,
            content.purpose,
            content.when_to_use,
            " ".join(content.steps),
            content.result_explanation,
            content.next_steps,
            " ".join(content.tooltips.values()),
        ]
        haystack = " ".join(haystack_parts).lower()
        return query in haystack

    # ------------------------------------------------------------------
    # Scroll-Position
    # ------------------------------------------------------------------

    def _save_scroll_pos(self, nav_key: str) -> None:
        pos = self._content_view.verticalScrollBar().value()
        QSettings("finLai", "HelpDialog").setValue(
            f"{_SCROLL_SETTINGS_PREFIX}{nav_key}", pos
        )

    def _restore_scroll_pos(self, nav_key: str) -> None:
        pos = QSettings("finLai", "HelpDialog").value(
            f"{_SCROLL_SETTINGS_PREFIX}{nav_key}", 0, type=int
        )
        self._content_view.verticalScrollBar().setValue(int(pos))

    # ------------------------------------------------------------------
    # KI-Assistent-Launcher (Tab 2)
    # ------------------------------------------------------------------
    # Close / Theme
    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:  # noqa: D401 — Qt-Override
        """Persistiert die Scroll-Position und räumt den Assistenz-Reiter auf.

        Der Assistenz-Reiter bricht laufende Ollama-Streams kontrolliert ab und
        meldet seinen Theme-Listener ab; zusätzlich wird der Theme-Listener des
        Dialogs entfernt. Beides gegen den bekannten Qt-Teardown-Segfault
        (Exit 134) auf Linux — der Dialog wird je Öffnen neu erzeugt.
        """
        if self._current_key and self._current_key != self.WELCOME_KEY:
            self._save_scroll_pos(self._current_key)
        assistant_tab = getattr(self, "_assistant_tab", None)
        if assistant_tab is not None:
            assistant_tab.cleanup()
        try:
            theme.unregister_listener(self._apply_theme)
        except (ValueError, RuntimeError):
            pass
        # mode_changed-Verbindung trennen, sonst akkumulieren geschlossene
        # Dialoge am globalen Singleton + rendern bei jedem Modus-Wechsel mit.
        try:
            self._display_state.mode_changed.disconnect(self._on_display_mode_changed)
        except (TypeError, RuntimeError):
            pass
        super().closeEvent(event)

    def _apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
            f"QTabWidget::pane {{ border: 1px solid {c.BORDER}; top: -1px; }}"
            f"QTabBar::tab {{"
            f" background: {c.CARD_BG}; color: {c.TEXT_DIM};"
            f" padding: 8px 16px; border: 1px solid {c.BORDER};"
            f" border-bottom: none; font-size: 12px;"
            f" }}"
            f"QTabBar::tab:selected {{"
            f" background: {c.BG_MAIN}; color: {c.ACCENT}; font-weight: 600;"
            f" border-bottom: 2px solid {c.ACCENT};"
            f" }}"
            f"QLineEdit#help_dialog_search {{"
            f" background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 6px 10px; font-size: 12px;"
            f" }}"
            f"QLineEdit#help_dialog_search:focus {{"
            f" border-color: {c.ACCENT};"
            f" }}"
            f"QLabel#help_dialog_hits {{ color: {c.TEXT_DIM}; font-size: 11px; }}"
            f"QListWidget#help_dialog_nav {{"
            f" background: {c.CARD_BG}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" font-size: 12px;"
            f" }}"
            f"QListWidget#help_dialog_nav::item {{ padding: 6px 8px; }}"
            f"QListWidget#help_dialog_nav::item:selected {{"
            f" background: {c.ACCENT}; color: {c.BG_DARK};"
            f" }}"
            f"QTextBrowser#help_dialog_content {{"
            f" background: {c.BG_MAIN}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 12px;"
            f" }}"
            f"QLabel#assistant_title {{"
            f" color: {c.ACCENT}; font-size: 16px; font-weight: 700;"
            f" background: transparent; border: none;"
            f" }}"
            f"QLabel#assistant_body {{"
            f" color: {c.TEXT_MAIN}; font-size: 13px; line-height: 1.5;"
            f" background: transparent; border: none;"
            f" }}"
            f"QLabel#assistant_hint {{"
            f" color: {c.TEXT_DIM}; font-size: 11px; font-style: italic;"
            f" background: transparent; border: none;"
            f" }}"
            f"QPushButton#assistant_launch_btn {{"
            f" background: {c.ACCENT}; color: {c.BG_DARK}; border: none;"
            f" border-radius: 4px; padding: 10px 20px; font-size: 13px;"
            f" font-weight: 600;"
            f" }}"
            f"QPushButton#assistant_launch_btn:hover {{"
            f" background: {c.ACCENT_DIM}; color: {c.BG_DARK}; border: none;"
            f" }}"
            f"QPushButton#assistant_launch_btn:pressed {{"
            f" background: {c.ACCENT_DARK}; color: {c.BG_DARK}; border: none;"
            f" }}"
        )
        # Theme-konformes Styling des gerenderten Handbuch-Markdowns Design):
        # muss vor dem ersten setMarkdown gesetzt sein und bei Theme-Wechsel neu greifen.
        self._apply_content_style()
        if self._sections and self._current_key:
            if self._current_key == self.WELCOME_KEY:
                self._render_welcome()
            else:
                self._render_section(self._current_key)
