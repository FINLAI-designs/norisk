"""
section — Klappbare Karten-Sektion (Titel + Chevron + Inhalt).

 AP7: aus ``tools/norisk_dashboard/gui/_section.py`` nach
``core/widgets`` gehoben (dort bleibt ein Re-Export-Alias) — die
Komponente ist tool-unabhängig und wird u.a. vom NoRisk-Dashboard
(Kanban/Notizen/Light-SIEM) genutzt; weitere Tools können sie für
Sektions-Layouts wiederverwenden.

Author: Patrick Riederich
Version: 1.1 (Cockpit-Perf A — Lazy-Content-Factory beim ersten Expand)
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon


class Section(QFrame):
    """Klappbare Sektion mit Titel + Inhalt.

    Der Inhalt wird per ``set_content`` gesetzt. Der Initial-Zustand
    (offen/zu) steuert das Default-Verhalten beim ersten Öffnen.

    Signals:
        toggled(bool): Emittiert wenn Nutzer die Sektion auf/zuklappt.
    """

    toggled = Signal(bool)

    def __init__(
        self,
        title: str,
        expanded: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._title = title
        self._expanded = expanded
        self._content: QWidget | None = None
        # Cockpit-Perf A: Lazy-on-expand. Wird ein Content-Factory gesetzt
        # (``set_content_factory``), baut die Sektion ihr Inhalts-Widget erst
        # beim ERSTEN Aufklappen — danach ist es gecacht (``_content``) und der
        # Factory wird nie erneut aufgerufen. So laufen teure Sektions-
        # Konstruktoren (DB-Reads im ctor) nicht schon beim App-Start.
        self._content_factory: Callable[[], QWidget] | None = None

        # objectName "dashboardSection" stammt aus dem Dashboard-Original und
        # adressiert nur das EIGENE lokale Stylesheet (self-contained Selektor;
        # externe Verweise gibt es nicht — grep-verifiziert AP7).
        self.setObjectName("dashboardSection")
        c = theme.get()
        self.setStyleSheet(
            f"#dashboardSection {{ background: {c.CARD_BG}; "
            f"border: 1px solid {c.BORDER}; border-radius: 6px; }}"
        )
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        self._root = QVBoxLayout(self)
        self._root.setContentsMargins(0, 0, 0, 0)
        self._root.setSpacing(0)

        self._root.addWidget(self._build_header())

        self._content_host = QWidget(self)
        self._content_layout = QVBoxLayout(self._content_host)
        self._content_layout.setContentsMargins(16, 8, 16, 16)
        self._content_layout.setSpacing(8)
        self._root.addWidget(self._content_host)

        self._content_host.setVisible(self._expanded)
        self._update_chevron()

    def _build_header(self) -> QWidget:
        c = theme.get()
        header = QWidget()
        header.setObjectName("dashboardSectionHeader")
        header.setCursor(Qt.CursorShape.PointingHandCursor)
        header.setFixedHeight(40)
        header.setStyleSheet(
            f"#dashboardSectionHeader {{ background: transparent; "
            f"border-bottom: 1px solid {c.BORDER}; }}"
        )
        lay = QHBoxLayout(header)
        lay.setContentsMargins(16, 0, 8, 0)
        lay.setSpacing(8)

        self._title_label = QLabel(self._title)
        # set_title ist öffentlicher Mutator — Titel nie als Auto-RichText
        # interpretieren (R22; einzige Abweichung vom 1:1-Lift).
        self._title_label.setTextFormat(Qt.TextFormat.PlainText)
        self._title_label.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 13px; font-weight: bold;"
        )
        lay.addWidget(self._title_label)
        lay.addStretch()

        self._chevron_btn = QToolButton(header)
        self._chevron_btn.setAutoRaise(True)
        self._chevron_btn.setFixedSize(28, 28)
        self._chevron_btn.setIconSize(self._chevron_btn.size())
        self._chevron_btn.clicked.connect(self._on_toggle)
        lay.addWidget(self._chevron_btn)

        header.mousePressEvent = self._on_header_click  # type: ignore[assignment]
        return header

    def _on_header_click(self, event) -> None:  # noqa: ANN001
        if event.button() == Qt.MouseButton.LeftButton:
            self._on_toggle()

    def _on_toggle(self) -> None:
        self._expanded = not self._expanded
        if self._expanded:
            self._ensure_lazy_content()
        self._content_host.setVisible(self._expanded)
        self._update_chevron()
        self.toggled.emit(self._expanded)

    def _ensure_lazy_content(self) -> None:
        """Materialisiert den Factory-Inhalt beim ersten Aufklappen (Cockpit-Perf A).

        No-op, wenn kein Factory gesetzt ist oder der Inhalt schon gebaut
        wurde. Nach dem ersten Lauf ist der Factory verbraucht (``None``),
        sodass das teure Inhalts-Widget nur EINMAL entsteht (gecacht).
        """
        if self._content_factory is None:
            return
        factory = self._content_factory
        self._content_factory = None
        self.set_content(factory())

    def _update_chevron(self) -> None:
        name = Icons.EXPAND_LESS if self._expanded else Icons.EXPAND_MORE
        self._chevron_btn.setIcon(get_icon(name))

    def set_content(self, widget: QWidget) -> None:
        """Ersetzt das Inhalts-Widget (eager)."""
        if self._content is not None:
            self._content_layout.removeWidget(self._content)
            self._content.deleteLater()
        self._content = widget
        self._content_layout.addWidget(widget)

    def set_content_factory(self, factory: Callable[[], QWidget]) -> None:
        """Setzt eine Lazy-Content-Factory (Cockpit-Perf A).

        Statt das Inhalts-Widget sofort zu bauen, ruft die Sektion ``factory``
        erst beim ERSTEN Aufklappen genau einmal auf und cacht das Ergebnis.
        Ist die Sektion bereits aufgeklappt (``expanded=True``), wird der
        Inhalt sofort gebaut — der Lazy-Vorteil greift also nur für zugeklappte
        Sektionen, was beabsichtigt ist.

        Args:
            factory: Parameterloser Builder, der das Inhalts-Widget liefert.
        """
        self._content_factory = factory
        if self._expanded:
            self._ensure_lazy_content()

    def has_content(self) -> bool:
        """Gibt zurück, ob das Inhalts-Widget bereits gebaut wurde.

        ``False`` solange eine Lazy-Factory gesetzt, aber noch nicht ausgelöst
        wurde (Sektion nie aufgeklappt). Erlaubt Aufrufern (z.B. dem Dashboard-
        ``_apply``), das Befüllen noch nicht gebauter Sektionen zu überspringen.
        """
        return self._content is not None

    def is_expanded(self) -> bool:
        """Gibt den aktuellen Expand-Zustand zurück."""
        return self._expanded

    def set_expanded(self, expanded: bool) -> None:
        """Setzt den Expand-Zustand programmatisch (z.B. Deeplink).

        Args:
            expanded: True klappt die Sektion auf, False zu.
        """
        if expanded == self._expanded:
            return
        self._on_toggle()

    def set_title(self, title: str) -> None:
        """Aktualisiert den Titel in der Kopfzeile."""
        self._title = title
        self._title_label.setText(title)
