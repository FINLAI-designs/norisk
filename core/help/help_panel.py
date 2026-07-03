"""
help_panel — Zusammenfaltbares Info-Panel für jedes Tool-Widget.

Das Panel erscheint oben in einem Tool-Widget und zeigt im eingeklappten
Zustand nur eine einzeilige Zusammenfassung. Per Klick auf die rechte
Pfeil-Schaltfläche klappt es weich auf (QPropertyAnimation) und zeigt
die vier strukturierten Abschnitte aus dem:class:`HelpContent`:
``WOZU DIENT ES?``, ``WANN NUTZEN?``, ``SO GEHT ES`` und einen Button
der das vollständige:class:`HelpDialog` auf dem Kapitel des Tools öffnet.

Der Zustand (ein-/ausgeklappt) wird pro ``nav_key`` über:class:`QSettings`
persistiert; beim nächsten Öffnen desselben Tools ist der letzte Zustand
wiederhergestellt. Standard beim Erstkontakt: eingeklappt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    QSettings,
    Qt,
    Signal,
)
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.help.display_mode_state import DisplayModeState
from core.help.help_content import HelpContent
from core.icons import Icons, get_icon

_COLLAPSED_HEIGHT = 36
_EXPANDED_MAX_HEIGHT = 320
_ANIMATION_MS = 180
_SETTINGS_KEY_PREFIX = "help_panel_expanded_"


class HelpPanel(QWidget):
    """Zusammenfaltbares Hilfe-Panel mit persistenem Zustand.

    Signals:
        open_full_help: Emittiert wenn der Button "Vollständige Hilfe öffnen"
            geklickt wird — der Parameter ist der ``nav_key`` des Tools.
            Der MainWindow-Slot öffnet dann das:class:`HelpDialog` mit
            initial_nav_key.

    Args:
        help_content: Der:class:`HelpContent` dieses Tools (aus Registry).
        parent: Optionales Eltern-Widget.
    """

    open_full_help: Signal = Signal(str)

    def __init__(
        self,
        help_content: HelpContent,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._content = help_content
        self._expanded = self._load_expanded_state()

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._build_ui()
        self._apply_theme()
        theme.register_listener(self._apply_theme)
        # Initial-Höhe entsprechend persistiertem Zustand
        self.setMaximumHeight(
            _EXPANDED_MAX_HEIGHT if self._expanded else _COLLAPSED_HEIGHT
        )
        self._sync_expanded_ui()

        # Animation einmalig erstellen — self als Parent, damit Qt die
        # Lebensdauer managed und die Instanz nicht zwischen Klicks vom
        # C++-GC eingesammelt wird. Kein DeletionPolicy, kein Neu-Erstellen
        # pro Toggle (Shiboken "already deleted"-Crash).
        self._animation = QPropertyAnimation(self, b"maximumHeight", self)
        self._animation.setDuration(_ANIMATION_MS)
        self._animation.setEasingCurve(QEasingCurve.Type.InOutQuad)

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        # Inline-Hilfe folgt dem globalen Einfach/Profi-Modus (gelesen beim
        # Aufbau; umgeschaltet wird zentral im Handbuch-Dialog).
        mode = DisplayModeState.instance().mode()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._frame = QFrame(self)
        self._frame.setObjectName("help_panel_frame")
        outer.addWidget(self._frame)

        frame_layout = QVBoxLayout(self._frame)
        frame_layout.setContentsMargins(12, 8, 12, 8)
        frame_layout.setSpacing(6)

        # --- Kopfzeile (immer sichtbar) -----------------------------------
        header = QHBoxLayout()
        header.setSpacing(8)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_icon(Icons.INFO).pixmap(18, 18))
        icon_lbl.setObjectName("help_panel_icon")
        header.addWidget(icon_lbl)

        summary = QLabel(
            f"<b>{self._content.tool_name}</b> — "
            f"{self._content.short_description_for(mode)}"
        )
        summary.setObjectName("help_panel_summary")
        summary.setWordWrap(True)
        summary.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        header.addWidget(summary, stretch=1)

        self._toggle_btn = QPushButton()
        self._toggle_btn.setObjectName("help_panel_toggle")
        self._toggle_btn.setFixedSize(24, 24)
        self._toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._toggle_btn.setToolTip("Hilfe ein-/ausklappen")
        self._toggle_btn.clicked.connect(self._on_toggle_clicked)
        header.addWidget(self._toggle_btn)

        frame_layout.addLayout(header)

        # --- Detail-Bereich (nur bei Expanded sichtbar) -------------------
        self._detail = QWidget(self._frame)
        self._detail.setObjectName("help_panel_detail")
        detail_layout = QVBoxLayout(self._detail)
        detail_layout.setContentsMargins(26, 4, 4, 4)
        detail_layout.setSpacing(6)

        detail_layout.addLayout(
            self._build_section("WOZU DIENT ES?", self._content.purpose_for(mode))
        )
        detail_layout.addLayout(
            self._build_section("WANN NUTZEN?", self._content.when_to_use_for(mode))
        )
        detail_layout.addLayout(
            self._build_section(
                "SO GEHT ES", self._format_steps(self._content.steps_for(mode))
            )
        )

        self._btn_open_dialog = QPushButton("Vollständige Hilfe öffnen")
        self._btn_open_dialog.setObjectName("help_panel_open_btn")
        self._btn_open_dialog.setIcon(get_icon(Icons.OPEN_IN_NEW))
        self._btn_open_dialog.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_open_dialog.clicked.connect(self._on_open_full_help)
        open_row = QHBoxLayout()
        open_row.addStretch()
        open_row.addWidget(self._btn_open_dialog)
        detail_layout.addLayout(open_row)

        frame_layout.addWidget(self._detail)

    def _build_section(self, title: str, body: str) -> QVBoxLayout:
        """Baut eine beschriftete Text-Sektion für den Detail-Bereich."""
        layout = QVBoxLayout()
        layout.setSpacing(2)
        title_lbl = QLabel(title)
        title_lbl.setObjectName("help_panel_section_title")
        layout.addWidget(title_lbl)
        body_lbl = QLabel(body)
        body_lbl.setObjectName("help_panel_section_body")
        body_lbl.setWordWrap(True)
        body_lbl.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(body_lbl)
        return layout

    @staticmethod
    def _format_steps(steps: list[str]) -> str:
        """Formatiert Schritte als HTML-Liste."""
        items = "".join(f"<li>{step}</li>" for step in steps)
        return f"<ol style='margin-left:0; padding-left:16px;'>{items}</ol>"

    # ------------------------------------------------------------------
    # Toggle + Animation + Persistenz
    # ------------------------------------------------------------------

    def _on_toggle_clicked(self) -> None:
        self._expanded = not self._expanded
        self._save_expanded_state()
        self._animate_toggle()
        self._sync_expanded_ui()

    def _animate_toggle(self) -> None:
        """Weiche Animation zwischen collapsed- und expanded-Höhe.

        Nutzt die einmalig im ``__init__`` erzeugte QPropertyAnimation —
        kein Neu-Erstellen pro Klick, keine DeletionPolicy. Damit kann
        Qt-Shiboken das C++-Objekt nicht unter dem Python-Zeiger weg
        einsammeln.
        """
        if self._animation.state() == QPropertyAnimation.State.Running:
            self._animation.stop()
        self._animation.setStartValue(self.maximumHeight())
        self._animation.setEndValue(
            _EXPANDED_MAX_HEIGHT if self._expanded else _COLLAPSED_HEIGHT
        )
        self._animation.start()

    def _sync_expanded_ui(self) -> None:
        """Aktualisiert Detail-Sichtbarkeit und Toggle-Icon."""
        self._detail.setVisible(self._expanded)
        icon = Icons.EXPAND_LESS if self._expanded else Icons.EXPAND_MORE
        self._toggle_btn.setIcon(get_icon(icon))

    def _settings_key(self) -> str:
        return f"{_SETTINGS_KEY_PREFIX}{self._content.nav_key}"

    def _load_expanded_state(self) -> bool:
        settings = QSettings("finLai", "HelpPanel")
        return bool(settings.value(self._settings_key(), False, type=bool))

    def _save_expanded_state(self) -> None:
        settings = QSettings("finLai", "HelpPanel")
        settings.setValue(self._settings_key(), self._expanded)

    # ------------------------------------------------------------------
    # Signal-Handler
    # ------------------------------------------------------------------

    def _on_open_full_help(self) -> None:
        """Emittiert ``open_full_help`` mit dem Nav-Key des Tools."""
        self.open_full_help.emit(self._content.nav_key)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self) -> None:
        c = theme.get()
        # Panel-Hintergrund: leicht heller als CARD_BG (+ Teal-Border-Left).
        self.setStyleSheet(
            f"QFrame#help_panel_frame {{"
            f" background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER};"
            f" border-left: 3px solid {theme.DARK_ACCENT};"
            f" border-radius: 4px;"
            f" }}"
            f"QLabel#help_panel_summary {{"
            f" color: {c.TEXT_MAIN}; font-size: 12px; background: transparent;"
            f" border: none;"
            f" }}"
            f"QLabel#help_panel_section_title {{"
            f" color: {c.ACCENT}; font-size: 10px; font-weight: 700;"
            f" letter-spacing: 0.6px; background: transparent; border: none;"
            f" }}"
            f"QLabel#help_panel_section_body {{"
            f" color: {c.TEXT_MAIN}; font-size: 12px; background: transparent;"
            f" border: none;"
            f" }}"
            f"QPushButton#help_panel_toggle {{"
            f" background: transparent; border: none; padding: 0;"
            f" }}"
            f"QPushButton#help_panel_toggle:hover {{"
            f" background: {c.BG_INPUT}; border-radius: 4px;"
            f" }}"
            f"QPushButton#help_panel_open_btn {{"
            f" background: transparent; color: {c.ACCENT};"
            f" border: 1px solid {c.ACCENT}; border-radius: 4px;"
            f" padding: 4px 10px; font-size: 11px;"
            f" }}"
            f"QPushButton#help_panel_open_btn:hover {{"
            f" background: {c.ACCENT}; color: {c.BG_DARK};"
            f" }}"
        )
