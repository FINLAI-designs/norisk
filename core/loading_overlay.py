"""loading_overlay — App-Ladebildschirm (Re-Login nach Logout).

``AppLoadingOverlay`` überdeckt den Aufbau des MainWindow nach einem Re-Login,
sodass Initialisierungs-Aufblitzer (Dock-Widgets, Sidebar) nicht sichtbar sind.
Der initiale App-Start nutzt dagegen das ``StartupWindow`` (eigener Ladescreen).

Verwendung als Kind des MainWindow — deckt nur das Fenster ab, nie den
ganzen Bildschirm) in ``apps/__init__.py``::

    window = MainWindow
    overlay = AppLoadingOverlay(config, parent=window)
    window.show
    overlay.resize(window.size); overlay.raise_; overlay.show
    overlay.run_sequence(on_done=lambda: overlay.hide)

Der Standalone-Modus (``parent=None``) bleibt als Fallback erhalten, dann jedoch
ohne ``WindowStaysOnTopHint`` und nicht maximiert.

Author: Patrick Riederich
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.widgets.finlai_progress import FinlaiProgressBar

if TYPE_CHECKING:
    from apps.app_config import AppConfig

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

_MIN_SICHTBAR_MS = 500  # Mindest-Anzeigezeit — verhindert Flackern bei schnellem Start
_SCHRITT_DELAY_MS = 100  # Pause zwischen Schritten (6 × 100ms = 600ms > MIN_SICHTBAR)
_TIMEOUT_MS = 30_000  # Sicherheits-Timeout — Overlay verschwindet immer

_SCHRITTE: list[tuple[int, str]] = [
    (80, "Benutzeroberfläche wird aufgebaut …"),
    (85, "Tools werden registriert …"),
    (90, "Einstellungen werden geladen …"),
    (100, "Bereit."),
]


# ---------------------------------------------------------------------------
# Overlay-Widget
# ---------------------------------------------------------------------------


class AppLoadingOverlay(QWidget):
    """Ladebildschirm nach Login.

    Liegt als Kind-Widget mit ``raise_`` über dem MainWindow und verdeckt
    sämtliche Initialisierungs-Aufblitzer (Dock-Widgets, Sidebar-Aufbau).

    Nach ``run_sequence`` animiert der Overlay selbstständig durch die
    Lade-Schritte. Nach Abschluss + Mindest-Anzeigezeit wird ``on_done``
    aufgerufen (typischerweise ``overlay.hide``).

    Args:
        config: ``AppConfig`` der laufenden App (für Logo und App-Namen).
        parent: Das zu überdeckende MainWindow.
    """

    def __init__(self, config: AppConfig, parent: QWidget | None = None) -> None:
        """Initialisiert den Ladebildschirm.

        Args:
            config: ``AppConfig`` der laufenden App (für Logo und App-Namen).
            parent: Eltern-Widget. ``None`` → eigenständiges, rahmenloses Fenster
                    mit Taskbar-Eintrag (``Qt.Window | FramelessWindowHint``,
                    KEIN StaysOnTop). Der aktive Re-Login-Pfad nutzt jedoch die
                    Kind-Variante (parent=MainWindow), sodass das Overlay nur das
                    Fenster und nie den ganzen Bildschirm abdeckt.
        """
        super().__init__(parent)
        self._config = config
        self._step_idx = 0
        self._start_time: float = 0.0
        self._on_done: Callable[[], None] | None = None

        # Standalone-Modus ohne WindowStaysOnTopHint — der Nutzer muss zu
        # anderen Apps wechseln koennen. ``Qt.Window`` sichert einen Taskbar-
        # Eintrag. (Aktiver Pfad nutzt die Kind-Variante, siehe Docstring.)
        if parent is None:
            self.setWindowFlags(
                Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint
            )

        # Schritt-Timer (wiederverwendbar, single-shot)
        self._step_timer = QTimer(self)
        self._step_timer.setSingleShot(True)
        self._step_timer.timeout.connect(self._advance)

        # Sicherheits-Timeout: Overlay verschwindet spätestens nach 30 Sekunden
        self._safety_timer = QTimer(self)
        self._safety_timer.setSingleShot(True)
        self._safety_timer.setInterval(_TIMEOUT_MS)
        self._safety_timer.timeout.connect(self._finish)

        # Eltern-Widget beobachten um Größe zu synchronisieren (nur Kind-Modus)
        if parent is not None:
            parent.installEventFilter(self)

        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt die zentrierte Karte mit Logo, Name, Fortschrittsbalken."""
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Karte
        self._card = QFrame()
        self._card.setObjectName("app_lade_card")
        self._card.setFixedWidth(420)

        card_layout = QVBoxLayout(self._card)
        card_layout.setContentsMargins(40, 36, 40, 36)
        card_layout.setSpacing(0)
        card_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # App-Logo
        self._lbl_icon = QLabel()
        self._lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_icon.setFixedHeight(64)
        self._lbl_icon.setStyleSheet("background: transparent; border: none;")
        self._load_logo()
        card_layout.addWidget(self._lbl_icon)

        # App-Name
        lbl_name = QLabel(self._config.app_name)
        lbl_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_name.setStyleSheet(
            "font-family: 'Raleway'; font-size: 16px; font-weight: 700;"
            " background: transparent; border: none; margin-top: 8px;"
        )
        card_layout.addWidget(lbl_name)

        # Untertitel
        lbl_sub = QLabel("wird gestartet …")
        lbl_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_sub.setObjectName("app_lade_sub")
        lbl_sub.setStyleSheet(
            "font-family: 'Raleway'; font-size: 13px;"
            " background: transparent; border: none; margin-bottom: 20px;"
        )
        card_layout.addWidget(lbl_sub)

        # kanonischer FinlaiProgressBar (8 px aus core/theme.py)
        self._progress = FinlaiProgressBar(total=100)
        card_layout.addWidget(self._progress)
        card_layout.addSpacing(10)

        # Schritt-Text
        self._lbl_schritt = QLabel("Initialisierung …")
        self._lbl_schritt.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_schritt.setObjectName("app_lade_schritt")
        self._lbl_schritt.setWordWrap(True)
        self._lbl_schritt.setFixedHeight(36)
        card_layout.addWidget(self._lbl_schritt)

        outer.addWidget(self._card)

    def _load_logo(self) -> None:
        """Lädt das App-Logo aus ``config.icon_path``."""
        icon_path = Path(self._config.icon_path)
        if not icon_path.is_absolute():
            icon_path = Path(__file__).parent.parent / icon_path
        if icon_path.exists():
            pixmap = QPixmap(str(icon_path)).scaled(
                56,
                56,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self._lbl_icon.setPixmap(pixmap)

    # ------------------------------------------------------------------
    # Öffentliche API
    # ------------------------------------------------------------------

    def set_progress(self, percent: int, schritt: str) -> None:
        """Aktualisiert Fortschrittsbalken und Schritt-Text.

        Args:
            percent: Fortschritt in Prozent (0–100); sinkt nie ab.
            schritt: Beschreibung des aktuellen Schritts.
        """
        self._progress.setValue(max(self._progress.value(), percent))
        self._lbl_schritt.setText(schritt)

    def run_sequence(self, on_done: Callable[[], None] | None = None) -> None:
        """Startet die Lade-Animation.

        Die Animation läuft im Qt-Event-Loop (via QTimer). ``on_done`` wird
        nach Abschluss aller Schritte + Mindest-Anzeigezeit aufgerufen.

        Args:
            on_done: Callback nach Abschluss — typischerweise ``overlay.hide``.
        """
        self._on_done = on_done
        self._start_time = time.monotonic()
        self._step_idx = 0
        self._safety_timer.start()
        self._advance()

    # ------------------------------------------------------------------
    # Interne Logik
    # ------------------------------------------------------------------

    def _advance(self) -> None:
        """Zeigt den nächsten Lade-Schritt oder wartet auf Mindest-Anzeigezeit."""
        if self._step_idx >= len(_SCHRITTE):
            elapsed_ms = int((time.monotonic() - self._start_time) * 1000)
            remaining = max(0, _MIN_SICHTBAR_MS - elapsed_ms)
            QTimer.singleShot(remaining, self._finish)
            return
        percent, text = _SCHRITTE[self._step_idx]
        self.set_progress(percent, text)
        self._step_idx += 1
        self._step_timer.start(_SCHRITT_DELAY_MS)

    def _finish(self) -> None:
        """Beendet die Animation und ruft on_done auf."""
        self._step_timer.stop()
        self._safety_timer.stop()
        if self._on_done:
            self._on_done()

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        """Synchronisiert die Overlay-Größe mit dem Eltern-Widget."""
        if obj is self.parent() and event.type() == QEvent.Type.Resize:
            parent = self.parent()
            if parent is not None:
                self.resize(parent.size())  # type: ignore[union-attr]
        return super().eventFilter(obj, event)

    def apply_theme(self) -> None:
        """Aktualisiert Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(f"QWidget {{ background-color: {c.BG_MAIN}; }}")
        self._card.setStyleSheet(
            f"QFrame#app_lade_card {{"
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
