"""
tool_page — Standard-Scaffold für Tool-Seiten AP7, Muster R6).

Ersetzt den bisher pro Tool duplizierten Kopf-Boilerplate
(Titel + Trennlinie + HelpPanel) und gibt dem Seiten-Layout eine
gemeinsame Struktur. Design-Sprache gemäß: Titel in ACCENT,
darunter eine gedimmte 1px-Akzentlinie (ACCENT_LINE, AP2) statt eines
vollen Teal-Balkens.

Verwendung::

    page = ToolPage("Zertifikats-Monitor", help_key="cert_monitor")
    page.body.addWidget(eingabe_zeile)
    page.body.addWidget(tabelle, stretch=1) # genau EINE Primärfläche

Die Primärflächen-Regel AP5, R1): pro Seite bekommt genau EIN
wachstumsfähiges Element ``stretch=1``; ``addStretch`` als
Resteverwerter im Body ist verboten.

WICHTIG: ToolPage registriert KEINEN theme-Listener — mehrere Tools
bauen ihre UI bei ``apply_theme`` komplett neu auf; pro Instanz
registrierte Listener würden anwachsen (Lehre aus Review-P2-3).

Author: Patrick Riederich
Version: 1.0 AP7)
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from core import theme
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry


class ToolPage(QWidget):
    """Seiten-Scaffold: Titel + Akzentlinie + optionales HelpPanel + Body.

    Args:
        title: Seitentitel (erscheint in ACCENT, Raleway, 18px).
        help_key: Nav-Key in der:class:`HelpRegistry`; leer = kein
            HelpPanel.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        title: str,
        help_key: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._help_key = help_key

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(0)

        self._title_lbl = QLabel(title)
        # Titel heute Literale — trotzdem nie als Auto-RichText interpretieren,
        # falls künftig dynamische Titel durchlaufen (R22).
        self._title_lbl.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self._title_lbl)

        self._sep = QFrame()
        self._sep.setFrameShape(QFrame.Shape.HLine)
        self._sep.setFixedHeight(1)
        root.addWidget(self._sep)

        self.help_panel: HelpPanel | None = None
        if help_key:
            help_content = HelpRegistry.get(help_key)
            if help_content is not None:
                self.help_panel = HelpPanel(help_content)
                self.help_panel.open_full_help.connect(self._open_help_dialog)
                root.addWidget(self.help_panel)

        #: Body-Layout der Seite — Tools fügen hier ihre Zeilen hinzu;
        #: die Primärfläche bekommt ``stretch=1`` (Muster R1 AP5).
        self.body = QVBoxLayout()
        self.body.setSpacing(8)
        root.addLayout(self.body, stretch=1)

        self.apply_theme()

    def apply_theme(self) -> None:
        """Aktualisiert Titel- und Linienfarben auf den aktiven Look.

        Explizit aufzurufen (kein eigener Listener — siehe Modul-Docstring):
        Tools, die bei ``apply_theme`` neu bauen, brauchen nichts weiter;
        Tools, die in-place restylen (z.B. techstack), rufen diese Methode
        aus ihrem Theme-Pfad.
        """
        c = theme.get()
        self._title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 18px; font-weight: bold;"
            f" color: {c.ACCENT}; margin-bottom: 4px;"
        )
        # Struktur-Linie gedimmt — Teal voll nur als Zustands-Signal (AP2)
        self._sep.setStyleSheet(
            f"background-color: {c.ACCENT_LINE}; margin: 8px 0 16px 0;"
        )

    def _open_help_dialog(self, nav_key: str = "") -> None:
        """Öffnet den vollständigen Hilfe-Dialog des Tools.

        Args:
            nav_key: Nav-Key aus dem HelpPanel-Signal (Fallback:
                ``help_key`` der Seite).
        """
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or self._help_key, parent=self.window()
        )
        dlg.show()
