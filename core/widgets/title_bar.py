"""
title_bar — Custom-Titlebar fuer das rahmenlose MainWindow.

Sprint 7 Phase 1: Aus core/main_window.py extrahiert.

Zeigt App-Logo, App-Name, optionalen Slogan, optionales Beta-Banner,
zentrierte Such-Leiste und vier Fenster-Buttons (Help/Min/Max/Close).
Drag-Bewegung des rahmenlosen MainWindow ist hier verkabelt.

Signals:
    search_changed(str): Bei jeder Eingabe in die Such-Leiste.
    help_requested: Klick auf den Help-Button (oder F1 im MainWindow).

Tonale Schale — border-bottom von 2px ACCENT auf
neutrale 1px-Hairline (BORDER_SIDEBAR) umgestellt.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import os

from PySide6.QtCore import QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QPalette, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QWidget,
)

from core import theme
from core.help.explain_mode import ExplainMode
from core.icons import Icons, get_icon


def _resolve_logo_path(config, base_dir: str) -> str:
    """Ermittelt den Logo-Pfad fuer die TitleBar.

    Bevorzugt ``config.icon_path`` wenn es eine PNG- oder SVG-Datei ist und
    auf der Festplatte existiert. Faellt andernfalls auf das FINLAI-Standard-
    Logo (assets/logo/finlai_logo.png) zurueck.

    ICO-Dateien werden bewusst ignoriert -- sie sind fuer Taskleiste/Dock
    gedacht, nicht als TitleBar-Logo geeignet.

    Args:
        config: AppConfig-Instanz oder None.
        base_dir: Absoluter Projektroot-Pfad.

    Returns:
        Absoluter Pfad zur Logo-Datei (Existenz liegt beim Caller).
    """
    default_logo = os.path.join(base_dir, "assets", "logo", "finlai_logo.png")
    icon_path = getattr(config, "icon_path", "") or ""
    if not icon_path:
        return default_logo
    if not os.path.isabs(icon_path):
        icon_path = os.path.normpath(os.path.join(base_dir, icon_path))
    if icon_path.lower().endswith((".png", ".svg")) and os.path.isfile(icon_path):
        return icon_path
    return default_logo


class TitleBar(QWidget):
    """Eigener Titelbalken mit Drag-Unterstuetzung und Fenster-Buttons.

    Logout-Funktionalitaet liegt ausschliesslich in der Sidebar (unten).
    Der Titelbalken zeigt nur den Benutzernamen als reinen Text an.

    Signals:
        search_changed(str): Wird bei jeder Eingabe in das Suchfeld emittiert.
        help_requested: Klick auf den Help-Button (oder F1).
    """

    search_changed = Signal(str)
    help_requested = Signal()

    def __init__(self, window: QMainWindow, config=None) -> None:
        """Initialisiert den Titelbalken.

        Args:
            window: Das uebergeordnete rahmenlose Hauptfenster.
            config: AppConfig-Instanz fuer App-Name und Slogan.
        """
        super().__init__(window)
        self._window = window
        self._config = config
        self._drag_pos: QPoint | None = None
        self.setObjectName("titlebar")

        self.setFixedHeight(42)
        self.setAutoFillBackground(True)
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(theme.get().BG_TITLEBAR))
        self.setPalette(pal)
        self.setStyleSheet(f"""
            QWidget#titlebar {{
                background-color: {theme.get().BG_TITLEBAR};
                border-bottom: 1px solid {theme.get().BORDER_SIDEBAR};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 8, 0)
        layout.setSpacing(4)

        # Links: Logo-Bild + App-Name + Trennstrich + Slogan
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # widgets/ ist eine Ebene tiefer als das alte main_window.py — fuer
        # die Logo-Aufloesung muessen wir noch eine Ebene weiter hoch.
        base = os.path.dirname(base)
        logo_path = _resolve_logo_path(config, base)

        self._logo_label = QLabel()
        if os.path.isfile(logo_path):
            logo_pixmap = QPixmap(logo_path).scaled(
                28,
                28,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self._logo_label.setPixmap(logo_pixmap)
        else:
            self._logo_label.setText("💰")
            self._logo_label.setStyleSheet("font-size: 18px;")
        self._logo_label.setStyleSheet("border: none;")

        app_name = config.app_name if config else "FINLAI"
        app_slogan = config.app_slogan if config else ""
        _version = getattr(config, "version", "") if config else ""
        if _version:
            self._logo_label.setToolTip(f"{app_name}  v{_version}")

        self._title_label = QLabel(app_name)
        self._title_label.setStyleSheet(
            f"border: none; color: {theme.get().ACCENT}; "
            f"font-family: '{theme.TITLE_FONT}', '{theme.TITLE_FONT_FALLBACK}', 'Segoe UI', sans-serif; "
            f"font-size: 14px; font-weight: bold;"
        )

        self._separator_lbl = QLabel("|")
        self._separator_lbl.setStyleSheet(
            f"border: none; color: {theme.get().TEXT_DIM}; "
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 14px; margin: 0 6px;"
        )

        self._slogan = QLabel(app_slogan)
        self._slogan.setStyleSheet(
            f"border: none; color: {theme.get().ACCENT}; "
            f"font-family: '{theme.TITLE_FONT}', '{theme.TITLE_FONT_FALLBACK}', 'Segoe UI', sans-serif; "
            f"font-size: 13px; font-style: normal;"
        )

        layout.addWidget(self._logo_label)
        layout.addWidget(self._title_label)
        if app_slogan:
            layout.addWidget(self._separator_lbl)
            layout.addWidget(self._slogan)
        else:
            self._separator_lbl.hide()
            self._slogan.hide()

        # Zentrierte Suchleiste
        layout.addStretch(1)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Tool suchen...")
        self._search.setFixedWidth(280)
        self._search.setFixedHeight(28)
        _search_icon_action = QAction(get_icon(Icons.SEARCH), "", self._search)
        self._search.addAction(
            _search_icon_action, QLineEdit.ActionPosition.LeadingPosition
        )
        self._search.setStyleSheet(f"""
            QLineEdit {{
                background: rgba(255,255,255,0.08);
                color: {theme.get().TEXT_MAIN};
                border: 1px solid {theme.get().BORDER};
                border-radius: 4px;
                padding: 0px 14px;
                font-family: 'Raleway';
                font-size: 12px;
            }}
            QLineEdit:focus {{
                border: 1px solid {theme.get().ACCENT};
                background: rgba(255,255,255,0.12);
            }}
            QLineEdit::placeholder {{
                color: {theme.get().TEXT_DIM};
            }}
        """)
        self._search.textChanged.connect(self.search_changed)
        self._search.keyPressEvent = self._on_search_key  # type: ignore[method-assign]

        layout.addWidget(self._search)
        layout.addStretch(1)

        layout.addSpacing(8)

        # Fenster-Buttons -- Minimieren / Verkleinern / Schliessen
        _btn_base = """
            QPushButton {
                background: transparent;
                border: none;
                font-size: 15px;
                font-family: 'Segoe UI Symbol', 'Segoe UI', sans-serif;
                min-width: 32px; max-width: 32px;
                min-height: 28px; max-height: 28px;
                border-radius: 4px;
                padding: 0px;
            }
        """

        self._btn_help = QPushButton()
        self._btn_help.setIcon(get_icon(Icons.HELP_CENTER))
        self._btn_help.setToolTip("Handbuch öffnen (F1)")
        self._btn_help.setStyleSheet(
            _btn_base
            + f"""
            QPushButton {{
                color: {theme.get().ACCENT};
            }}
            QPushButton:hover {{
                background: rgba(0, 212, 255, 0.25);
                color: {theme.get().ACCENT};
            }}
        """
        )
        self._btn_help.clicked.connect(self._emit_help_requested)

        # Sprint S1c: Erklär-Mode-Toggle ("Was bedeutet das?"). Checkable,
        # damit der Aktiv-Zustand visuell sichtbar ist.
        # Sichtbarkeits-Fix. Vorher unsichtbar weil
        # transparenter Hintergrund + ACCENT-Icon auf akzent-cyan-Header
        # untergeht. Jetzt: ``LIGHTBULB``-Icon (klar als "Erklaer-Modus"
        # lesbar) + 1px-Akzent-Border + leicht eingefaerbter Hintergrund.
        self._btn_explain = QPushButton()
        self._btn_explain.setIcon(get_icon(Icons.LIGHTBULB))
        self._btn_explain.setCheckable(True)
        self._btn_explain.setChecked(ExplainMode.instance().is_enabled())
        self._btn_explain.setToolTip(
            "Anzeige-Modus: An = Einfach (mehr Erklärungen, 'Was bedeutet "
            "das?'), Aus = Profi (knappe Fachsprache)."
        )
        self._btn_explain.setStyleSheet(
            _btn_base
            + f"""
            QPushButton {{
                color: {theme.get().ACCENT};
                background: rgba(0, 212, 255, 0.08);
                border: 1px solid {theme.get().ACCENT};
            }}
            QPushButton:hover {{
                background: rgba(0, 212, 255, 0.25);
                color: {theme.get().ACCENT};
            }}
            QPushButton:checked {{
                background: {theme.DARK_ACCENT};
                color: #ffffff;
                border: 1px solid {theme.get().ACCENT};
            }}
        """  # noqa: hex-color-pending — pures Weiss auf Akzent bewusst
        )
        self._btn_explain.toggled.connect(self._on_explain_toggled)
        ExplainMode.instance().mode_changed.connect(
            self._sync_explain_button
        )

        self._btn_min = QPushButton("−")  # − (Minus-Zeichen)
        self._btn_min.setToolTip("Minimieren")
        self._btn_min.setStyleSheet(
            _btn_base
            + f"""
            QPushButton {{
                color: {theme.get().ACCENT};
            }}
            QPushButton:hover {{
                background: rgba(0, 212, 255, 0.25);
                color: {theme.get().ACCENT};
            }}
        """
        )
        self._btn_min.clicked.connect(window.showMinimized)

        self._btn_max = QPushButton("□")  # □ (Quadrat)
        self._btn_max.setToolTip("Verkleinern")
        self._btn_max.setStyleSheet(
            _btn_base
            + f"""
            QPushButton {{
                color: {theme.get().ACCENT};
            }}
            QPushButton:hover {{
                background: rgba(0, 212, 255, 0.25);
                color: {theme.get().ACCENT};
            }}
        """
        )
        self._btn_max.clicked.connect(self._toggle_maximize)

        self._btn_close = QPushButton("⏻")  # ⏻ (Power-Symbol)
        self._btn_close.setToolTip("Schließen")
        self._btn_close.setStyleSheet(
            _btn_base
            + f"""
            QPushButton {{
                color: {theme.get().DANGER};
            }}
            QPushButton:hover {{
                background: {theme.get().DANGER};
                color: #ffffff;
            }}
        """  # noqa: hex-color-pending — pures Weiss auf Danger-Rot bewusst (Material-Standard)
        )
        self._btn_close.clicked.connect(window.close)

        for btn in (
            self._btn_explain,
            self._btn_help,
            self._btn_min,
            self._btn_max,
            self._btn_close,
        ):
            # kein setVisible(True) vor addWidget — die Buttons sind
            # hier noch parentlos und wuerden als Top-Level-Fenster
            # aufblitzen; nach dem Parenting sind sie default-sichtbar.
            btn.setAutoFillBackground(False)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)

        layout.addWidget(self._btn_explain)
        layout.addWidget(self._btn_help)
        layout.addWidget(self._btn_min)
        layout.addWidget(self._btn_max)
        layout.addWidget(self._btn_close)

        theme.register_listener(self.apply_theme)

    # ------------------------------------------------------------------
    def apply_theme(self) -> None:
        """Aktualisiert alle TitleBar-Styles auf den aktuellen Look."""
        c = theme.get()
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(c.BG_TITLEBAR))
        self.setPalette(pal)
        self.setStyleSheet(f"""
            QWidget#titlebar {{
                background-color: {c.BG_TITLEBAR};
                border-bottom: 1px solid {c.BORDER_SIDEBAR};
            }}
            QWidget#titlebar QLabel {{
                color: {c.TEXT_TITLEBAR};
                background: transparent;
            }}
        """)
        self._logo_label.setStyleSheet("border: none;")
        self._title_label.setStyleSheet(
            f"border: none; color: {c.ACCENT}; "
            f"font-family: '{theme.TITLE_FONT}', '{theme.TITLE_FONT_FALLBACK}', 'Segoe UI', sans-serif; "
            f"font-size: 14px; font-weight: bold;"
        )
        self._separator_lbl.setStyleSheet(
            f"border: none; color: {c.TEXT_DIM}; "
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 14px; margin: 0 6px;"
        )
        self._slogan.setStyleSheet(
            f"border: none; color: {c.ACCENT}; "
            f"font-family: '{theme.TITLE_FONT}', '{theme.TITLE_FONT_FALLBACK}', 'Segoe UI', sans-serif; "
            f"font-size: 13px; font-style: normal;"
        )
        # Suchfeld: Hintergrundtoenung -- Light-Theme wurde 12.04.2026 entfernt.
        search_bg = "rgba(255,255,255,0.08)"
        search_bg_focus = "rgba(255,255,255,0.12)"
        self._search.setStyleSheet(f"""
            QLineEdit {{
                background: {search_bg};
                color: {c.TEXT_TITLEBAR};
                border: 1px solid {c.BORDER};
                border-radius: 4px;
                padding: 0px 14px;
                font-family: 'Raleway';
                font-size: 12px;
            }}
            QLineEdit:focus {{
                border: 1px solid {c.ACCENT};
                background: {search_bg_focus};
            }}
            QLineEdit::placeholder {{
                color: {c.TEXT_DIM};
            }}
        """)
        _btn_base = f"""
            QPushButton {{
                background: transparent;
                border: none;
                font-size: 15px;
                font-family: 'Segoe UI Symbol', 'Segoe UI', sans-serif;
                min-width: 32px; max-width: 32px;
                min-height: 28px; max-height: 28px;
                border-radius: 4px;
                padding: 0px;
                color: {c.TEXT_TITLEBAR};
            }}
        """
        self._btn_min.setStyleSheet(
            _btn_base
            + f"""
            QPushButton {{
                color: {c.ACCENT};
            }}
            QPushButton:hover {{
                background: {c.ACCENT_DIM};
                color: {c.ACCENT};
            }}
        """
        )
        self._btn_max.setStyleSheet(
            _btn_base
            + f"""
            QPushButton {{
                color: {c.ACCENT};
            }}
            QPushButton:hover {{
                background: {c.ACCENT_DIM};
                color: {c.ACCENT};
            }}
        """
        )
        self._btn_close.setStyleSheet(
            _btn_base
            + f"""
            QPushButton {{
                color: {c.DANGER};
            }}
            QPushButton:hover {{
                background: {c.DANGER};
                color: {c.TEXT_ON_DARK};
            }}
        """
        )

    def _emit_help_requested(self) -> None:
        """Emittiert das help_requested-Signal, MainWindow oeffnet das HelpDialog."""
        self.help_requested.emit()

    def _on_explain_toggled(self, checked: bool) -> None:
        """User-Klick auf den Erklär-Mode-Button → Singleton aktualisieren."""
        ExplainMode.instance().set_enabled(checked)

    def _sync_explain_button(self, enabled: bool) -> None:
        """Singleton-Mode hat sich geändert (z.B. von einer anderen UI) →
        Button-Zustand anpassen, ohne erneut ``set_enabled`` zu triggern.
        """
        if self._btn_explain.isChecked() == enabled:
            return
        # ``blockSignals`` verhindert, dass der Sync ein weiteres
        # ``toggled``-Signal auslöst und damit eine Endlos-Schleife.
        self._btn_explain.blockSignals(True)
        self._btn_explain.setChecked(enabled)
        self._btn_explain.blockSignals(False)

    def _toggle_maximize(self) -> None:
        """Wechselt zwischen maximiert und halber Bildschirmgroesse (50%)."""
        if self._window.isMaximized():
            # T-GUI-060: Den Screen des Fensters nutzen, nicht den Primaer-
            # Screen — sonst springt das Fenster beim Verkleinern vom Zweit-/
            # Dritt-Monitor zurueck auf den Primaer-Monitor.
            screen = self._window.screen() or QApplication.primaryScreen()
            if screen:
                geo = screen.availableGeometry()
                half_w = geo.width() // 2
                half_h = geo.height() // 2
                x = geo.x() + (geo.width() - half_w) // 2
                y = geo.y() + (geo.height() - half_h) // 2
                self._window.showNormal()
                # Verzoegert setzen: showNormal muss abgeschlossen sein,
                # bevor der Window-Manager setGeometry akzeptiert.
                QTimer.singleShot(
                    0, lambda: self._window.setGeometry(x, y, half_w, half_h)
                )
            else:
                self._window.showNormal()
            self._btn_max.setText("□")  # □
            self._btn_max.setToolTip("Verkleinern")
        else:
            self._window.showMaximized()
            self._btn_max.setText("❐")  # ❐
            self._btn_max.setToolTip("Wiederherstellen")

    def mousePressEvent(self, event) -> None:
        """Speichert die Startposition fuer Drag.

        Args:
            event: MousePressEvent mit globaler Mausposition.
        """
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event) -> None:
        """Verschiebt das Fenster entsprechend der Mausbewegung.

        Args:
            event: MouseMoveEvent mit aktueller Mausposition.
        """
        if self._drag_pos is not None and event.buttons() == Qt.MouseButton.LeftButton:
            delta = event.globalPosition().toPoint() - self._drag_pos
            self._window.move(self._window.pos() + delta)
            self._drag_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, _event) -> None:
        """Beendet den Drag-Vorgang."""
        self._drag_pos = None

    def _on_search_key(self, event) -> None:
        """Leert das Suchfeld bei Escape, leitet sonst an QLineEdit weiter."""
        if event.key() == Qt.Key.Key_Escape:
            self._search.clear()
            self._search.clearFocus()
        else:
            QLineEdit.keyPressEvent(self._search, event)
