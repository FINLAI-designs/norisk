"""explainable_label — QLabel mit Erklär-Layer-Reaktion (Sprint S1c).

Eine schmale Wrapper-Komponente um ``QLabel``: Sieht im Default exakt
wie ein normales Label aus, schaltet aber bei aktiver
:class:`core.help.explain_mode.ExplainMode` einen visuellen Hinweis
(Akzent-Border + Tooltip + Hilfe-Cursor) zu.

Designziel
----------
Konsumenten bekommen ein drop-in-replacement für ``QLabel(text)``::

    from core.help.explainable_label import ExplainableLabel

    title = ExplainableLabel("Netzwerkmonitor",
                             "Live-Bild deines Netzwerk-Verkehrs...")
    layout.addWidget(title)

Sobald der globale Erklär-Mode an ist (TitleBar-Toggle), zeigt das
Label seinen Erklär-Text als Tooltip und gibt sich durch eine 1-px
Akzent-Border zu erkennen.

Schichtzugehörigkeit: core/ — gewollt PySide6-abhängig.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QWidget

from core import theme
from core.help.explain_mode import ExplainMode


class ExplainableLabel(QLabel):
    """Wrapper um ``QLabel``, der auf ``ExplainMode`` reagiert.

    Args:
        text: Text, der immer angezeigt wird (Mode an/aus identisch).
        explanation: 1–3-Satz-Erklär-Text. Wird im Erklär-Mode als
            Tooltip eingeblendet. Im Default-Mode bleibt der Tooltip leer.
        parent: Optionales Eltern-Widget.

    Verhalten:
        - Default (Mode aus): wie ``QLabel(text)`` — kein Tooltip,
          kein Border, Standard-Cursor.
        - Mode an: Tooltip = ``explanation``, 1-px-Border in
:data:`core.theme.DARK_ACCENT`, ``WhatsThisCursor`` zum
          klaren Affordance-Signal.
        - Mode-Wechsel ohne Re-Layout — nur Tooltip/Stylesheet/Cursor
          werden neu gesetzt.
    """

    def __init__(
        self,
        text: str,
        explanation: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        self._explanation = explanation
        # Initialer Push: aktuellen Mode-Stand sofort anwenden, dann
        # Subscription für künftige Wechsel.
        mode = ExplainMode.instance()
        self._apply_mode(mode.is_enabled())
        mode.mode_changed.connect(self._apply_mode)

    @property
    def explanation(self) -> str:
        """Der Erklär-Text — schreibgeschützt (:meth:`set_explanation`)."""
        return self._explanation

    def set_explanation(self, explanation: str) -> None:
        """Tauscht den Erklär-Text und aktualisiert den Tooltip live."""
        self._explanation = explanation
        if ExplainMode.instance().is_enabled():
            self.setToolTip(self._explanation)

    def _apply_mode(self, enabled: bool) -> None:
        """Schaltet die visuelle Reaktion auf den Mode-Stand."""
        if enabled:
            self.setToolTip(self._explanation)
            self.setStyleSheet(
                f"border: 1px solid {theme.DARK_ACCENT};"
                f" border-radius: 3px;"
                f" padding: 2px 6px;"
            )
            self.setCursor(Qt.CursorShape.WhatsThisCursor)
        else:
            self.setToolTip("")
            self.setStyleSheet("")
            self.unsetCursor()
