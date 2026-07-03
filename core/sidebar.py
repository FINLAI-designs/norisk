"""
sidebar — Professionelles SidebarWidget für FINLAI.

Implementiert eine mehrstufige, animierte Sidebar mit:

  - Aufklappbaren Gruppen (Cybersecurity, TaxTech, Robotic, KI-Helfer, SFTP, Finance, Links)
  - Icon-Modus (52 px) und Textmodus (220 px Standard)
  - Sanfter Animation beim Ein-/Ausklappen (QPropertyAnimation, 200 ms)
  - Sanfter Expand-Animation für Gruppen (QPropertyAnimation, 150 ms)
  - Neonblau-Hover auf ALLEN klickbaren Elementen via enterEvent/leaveEvent
  - XMind-Stil Baum-Linien (├─ / └─) für Sub-Sub-Items
  - Persistenter Breite und Zustand via UISettings

Signals:
    navigate(str): Schlüssel des aktivierten Items.
    open_url(str): URL die im Standardbrowser geöffnet werden soll.
    logout_requested: Logout-Button wurde geklickt.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QObject,
    QPropertyAnimation,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor, QCursor, QIcon, QPainter, QPen
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .icons import Icons, get_icon, get_sidebar_icon
from .links_repository import LinksRepository, on_links_changed
from .logger import get_logger
from .security_subject.resolver import create_subject_store
from .security_subject.w1_profil import GATING_KEYS
from .sidebar_config import ALL_NORISK_GROUP_CONFIGS, SidebarGroupConfig
from .sidebar_links import load_sidebar_links
from .ui_settings import UISettings

_log = get_logger(__name__)

# Status-Schlüssel für Coming-Soon-Sidebar-Items
_STATUS_COMING_SOON = "coming_soon"


# ---------------------------------------------------------------------------
# Hilfsfunktion: Tool-Key → lesbarer Label
# ---------------------------------------------------------------------------
def _humanize_key(key: str) -> str:
    """Leitet einen lesbaren Anzeigenamen aus einem Tool-Schlüssel ab.

    Beispiele: ``"finance:dashboard"`` → ``"Dashboard"``,
    ``"xml_reader:camt"`` → ``"Camt"``.

    Args:
        key: Interner Tool-Schlüssel (mit oder ohne Namespace-Präfix).

    Returns:
        Anzeigename mit großem Anfangsbuchstaben.
    """
    part = key.split(":")[-1] if ":" in key else key
    return part.replace("_", " ").title()


# ---------------------------------------------------------------------------
# _ComingSoonDialog — Info-Dialog für Module in Entwicklung
# ---------------------------------------------------------------------------
class _ComingSoonDialog(QDialog):
    """Modaler Info-Dialog für Sidebar-Items mit Status ``coming_soon``.

    Zeigt eine kurze Hinweismeldung und einen OK-Button. Styled im
    aktuellen Theme (Dark/Light).
    """

    def __init__(self, tool_name: str, parent: QWidget | None = None) -> None:
        """Initialisiert den Coming-Soon-Dialog.

        Args:
            tool_name: Name des Moduls / Werkzeugs — erscheint im Titel.
            parent: Optionaler Eltern-Widget.
        """
        super().__init__(parent)
        c = theme.get()
        self.setWindowTitle(tool_name)
        self.setModal(True)
        self.setFixedWidth(340)

        lyt = QVBoxLayout(self)
        lyt.setSpacing(16)
        lyt.setContentsMargins(24, 24, 24, 16)

        # Icon (Sanduhr)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_icon(Icons.HOURGLASS, color=c.ACCENT).pixmap(36, 36))
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lyt.addWidget(icon_lbl)

        # Meldung
        msg_lbl = QLabel(
            "Dieses Modul ist in Entwicklung und wird\n"
            "mit einem zukünftigen Update verfügbar."
        )
        msg_lbl.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 13px; color: {c.TEXT_MAIN}; "
            f"border: none; background: transparent;"
        )
        msg_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lyt.addWidget(msg_lbl)

        # OK-Button
        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        # Label explizit deutsch setzen (locale-unabhaengig statt Qt-Default)
        btn_box.button(QDialogButtonBox.StandardButton.Ok).setText("OK")
        btn_box.accepted.connect(self.accept)
        btn_box.setStyleSheet(
            f"QPushButton {{"
            f"  background-color: {c.ACCENT}; color: {c.TEXT_ON_DARK}; "
            f"  font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"  font-size: 13px; font-weight: bold; "
            f"  border: none; border-radius: 4px; padding: 6px 24px;"
            f"}}"
            f"QPushButton:hover {{"
            f"  background-color: {c.ACCENT_DIM};"
            f"}}"
        )
        lyt.addWidget(btn_box, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setStyleSheet(
            f"QDialog {{"
            f"  background-color: {c.CARD_BG}; "
            f"  border: 1px solid {c.BORDER}; border-radius: 8px;"
            f"}}"
        )


# ---------------------------------------------------------------------------
# _ComingSoonItemWidget — Sidebar-Item für Module in Entwicklung
# ---------------------------------------------------------------------------
class _ComingSoonItemWidget(QWidget):
    """Nicht-navigierbares Sidebar-Item das ein Modul in Entwicklung anzeigt.

    Visuell:
    - Icon mit 40 % Deckkraft (QGraphicsOpacityEffect)
    - Text in gedimmter Schrift (theme.TEXT_DIM)
    - Kleines farbiges "BALD"-Badge neben dem Namen

    Bei Klick wird ``_ComingSoonDialog`` geöffnet, **kein** ``navigate``-Signal.
    """

    def __init__(
        self,
        label: str,
        badge: str = "BALD",
        indent_px: int | None = None,
        show_tree: bool = False,
        is_last: bool = False,
        key: str = "",
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Coming-Soon-Item.

        Args:
            label: Anzeigetext.
            badge: Badge-Text neben dem Label (Standard: ``"BALD"``).
            indent_px: Linke Einrückung in Pixeln. None → ``_INDENT_L1``.
            show_tree: True → Baum-Linie vor dem Icon anzeigen.
            is_last: True → └─ statt ├─.
            key: Navigations-Schlüssel (z.B. ``"finance:dashboard"``)
                       für Suchindex und ``set_active_key``-Iteration.
                       Default leer für Rückwärtskompatibilität.
            parent: Optionaler Eltern-Widget.
        """
        super().__init__(parent)
        self._key = key
        self._label = label
        self._badge = badge
        self._tree: _TreeLine | None = None
        _indent = indent_px if indent_px is not None else _INDENT_L1

        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setFixedHeight(_ITEM_H)
        self.setToolTip(f"{label} — demnächst verfügbar")

        lyt = QHBoxLayout(self)
        lyt.setSpacing(0)

        if show_tree:
            lyt.setContentsMargins(8, 0, 8, 0)
            self._tree = _TreeLine(is_last=is_last)
            lyt.addWidget(self._tree)
            lyt.addSpacing(4)
        else:
            lyt.setContentsMargins(_indent, 6, 8, 6)

        # Icon (Sanduhr) mit Opacity-Effekt
        icon_lbl = _make_icon_label(get_icon(Icons.HOURGLASS), size=16)
        effect = QGraphicsOpacityEffect(icon_lbl)
        effect.setOpacity(0.4)
        icon_lbl.setGraphicsEffect(effect)
        lyt.addWidget(icon_lbl)
        lyt.addSpacing(_ICON_GAP)

        # Text — gedimmt
        lbl_text = QLabel(label)
        lbl_text.setStyleSheet(_text_qss(theme.get().TEXT_DIM, 12))
        lbl_text.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        lyt.addWidget(lbl_text)

        # "BALD"-Badge
        lbl_badge = QLabel(badge)
        c = theme.get()
        lbl_badge.setStyleSheet(
            f"color: {c.ACCENT}; font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 9px; font-weight: bold; "
            f"background-color: transparent; "
            f"border: 1px solid {c.ACCENT}; "
            f"border-radius: 3px; padding: 1px 4px;"
        )
        lbl_badge.setFixedHeight(16)
        lyt.addWidget(lbl_badge)
        lyt.addSpacing(4)

    def mousePressEvent(self, event) -> None:
        """Öffnet den Info-Dialog bei Linksklick — keine Navigation."""
        if event.button() == Qt.MouseButton.LeftButton:
            dlg = _ComingSoonDialog(self._label, self)
            dlg.exec()
        super().mousePressEvent(event)

    def set_collapsed(self, collapsed: bool) -> None:
        """Sidebar-Collapse-Kompatibilität (keine-op für Badge/Text hier)."""
        pass

    def set_active(self, active: bool) -> None:
        """API-Kompatibilität zu ``_NavItemWidget`` — Coming-Soon ist nie aktiv."""
        pass

    def _apply_style(self) -> None:
        """Theme-Listener-Kompatibilität (kein aktiver Zustand nötig)."""
        pass


# Hinweis: ``_apply_license_lock`` wurde mit entfernt. NoRisk ist
# Single-Tenant-Open-Source — es gibt kein Lizenz-Nav-Gating mehr (``has_feature``
# liefert bedingungslos True). Damit entfällt der frühere Sidebar-Lock samt seines
# fail-closed-Pfades; das schließt das Residualrisiko R-1 (Sidebar Fail-Open)
# strukturell. Das deklarative ``license_feature``-Metadatum in ``sidebar_config``
# bleibt als inertes (ungelesenes) Feld erhalten. Profil-Gating
# (``_apply_profile_gating``, W1/) ist davon unberührt und bleibt aktiv.


def _apply_profile_gating(
    widget: QWidget,
    gating_key: str,
    flags: dict[str, int | None],
) -> None:
    """Graut ein Nav-Item aus, wenn das W1-Profil das Modul als irrelevant markiert.

    Profil-Gating Phase 3d): Module wie API-Security sind nur
    relevant, wenn das eigene System die zugehörige Eigenschaft hat. Das tri-state
    Flag am eigenen Subjekt steuert die Sichtbarkeit:

    - ``1`` → Eigenschaft vorhanden → relevant → keine Wirkung.
    - ``None`` → nicht erfasst → keine Aussage → keine Wirkung (kein Gating).
    - ``0`` → Eigenschaft fehlt → irrelevant → Item wird ausgegraut.

    Bewusst **ausgegraut statt versteckt**: das Modul bleibt sichtbar und
    auffindbar (Discovery), der Tooltip erklärt die Ursache und den Weg zum
    Override. Das Gating ist rein visuell — Scans/Scoring bleiben unberührt
    (Plan §4: „Gating darf coverage nicht mindern"). Reversibel über
    ``UISettings.profile_gating_enabled`` (der Aufrufer ruft hier dann nicht an).

    Wird nur auf bereits aktive Widgets angewandt — ein bereits per Lizenz
    gesperrtes Item behält seine Lizenz-Meldung (kein Tooltip-Überschreiben).

    Args:
        widget: Das ``_NavItemWidget``.
        gating_key: W1-Flag-Schlüssel (Attributname am Subjekt; aus
:data:`core.security_subject.w1_profil.GATING_KEYS`).
        flags: Mapping Flag-Schlüssel → tri-state-Wert des eigenen Subjekts.
    """
    if not gating_key or not widget.isEnabled():
        return
    if flags.get(gating_key) == 0:
        widget.setEnabled(False)
        widget.setToolTip(
            "[Für dein Profil ausgeblendet] Laut deinen Angaben nicht relevant. "
            "Wieder einblenden über Einstellungen → Alle Module anzeigen."
        )


# ---------------------------------------------------------------------------
# Dimensionskonstanten
# ---------------------------------------------------------------------------
SIDEBAR_COLLAPSED_W: int = 52
SIDEBAR_DEFAULT_W: int = 220
SIDEBAR_MAX_W: int = 320
SIDEBAR_MIN_W: int = 52
SIDEBAR_ANIM_MS: int = 200

# Item-Dimensionen
_ITEM_H: int = 34  # Gesamthöhe aller Nav-Items
_INDENT_L1: int = 24  # Einrückung Sub-Items (px)
_INDENT_L2_SPACE: int = 20  # Linker Leerraum vor Baum-Linie bei Sub-Sub-Items
_ICON_GAP: int = 10  # Abstand Icon → Text
_ACTIVE_BAR_W: int = 3  # Breite Aktiv-Indikator links; Platzhalter identisch (kein Textsprung)

# Programmier-Sprachen-IDs die in Customer-Builds NIEMALS in der Sidebar erscheinen dürfen.
# Wird beim Aufbau der Cheatsheets-Gruppe als Filter verwendet, damit stale Daten
# aus einem früheren Bug-Zustand (skip_defaults fehlte) nicht sichtbar werden.
# Muss synchron gehalten werden mit _PROGRAMMIER_SPRACHEN in
# tools/cheatsheet/gui/buchhalter_cheatsheet_widget.py.
_CHEATSHEET_PROGRAMMIER_IDS: frozenset[str] = frozenset(
    {"python", "javascript", "css", "php", "html", "mysql", "vba"}
)


# ---------------------------------------------------------------------------
# Farb-Hilfsfunktionen (alle Werte aus theme.py, keine Hardcodierung)
# ---------------------------------------------------------------------------
def _accent_rgba(alpha_0_255: int) -> str:
    """Gibt einen rgba-String aus theme.get.ACCENT mit gegebenem Alpha zurück.

    Args:
        alpha_0_255: Alpha-Wert 0–255.

    Returns:
        CSS-kompatibler rgba-String.
    """
    c = QColor(theme.get().ACCENT)
    return f"rgba({c.red()}, {c.green()}, {c.blue()}, {alpha_0_255})"


# Vorberechnete Farbstrings (einmal beim Modulimport)
_HOVER_BG: str = _accent_rgba(30)  # 12 % Deckkraft
_ACTIVE_BG: str = _accent_rgba(51)  # 20 % Deckkraft


def _make_icon_label(icon: str | QIcon, size: int = 16) -> QLabel:
    """Erstellt ein Icon-QLabel aus einem Emoji-String oder QIcon.

    Args:
        icon: Emoji-String ODER QIcon (Material Symbol).
        size: Pixelbreite/-höhe für QIcon-Pixmap.

    Returns:
        Konfiguriertes QLabel.
    """
    lbl = QLabel()
    lbl.setFixedWidth(size + 2)
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    if isinstance(icon, QIcon):
        lbl.setPixmap(icon.pixmap(size, size))
    else:
        lbl.setText(icon)
        lbl.setStyleSheet(
            f"font-size: {size - 3}px; border: none; background: transparent;"
        )
    return lbl


def _text_qss(color: str, size: int = 12, bold: bool = False) -> str:
    """Gibt ein kompaktes QSS-Stylesheet für QLabel-Text zurück.

    Args:
        color: CSS-Farbwert.
        size: Schriftgröße in Pixeln.
        bold: True für fetten Text.

    Returns:
        QSS-String.
    """
    weight = "bold" if bold else "normal"
    return (
        f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
        f"font-size: {size}px; font-weight: {weight}; "
        f"color: {color}; border: none; background: transparent;"
    )


# ---------------------------------------------------------------------------
# _TreeLine — QPainter-basierte Baum-Verbindungslinie
# ---------------------------------------------------------------------------
class _TreeLine(QWidget):
    """Zeichnet eine ├─ oder └─ Verbindungslinie für Sub-Sub-Items.

    Verwendet QPainter für eine pixelgenaue 1 px Linie.
    Farbe: theme.get.BORDER im Normalzustand, theme.get.ACCENT bei Hover.
    Das Widget ist transparent für Maus-Events (Eltern-Widget empfängt sie).
    """

    def __init__(self, is_last: bool, parent: QWidget | None = None) -> None:
        """Initialisiert die Baum-Linie.

        Args:
            is_last: True → └─ (letztes Item), False → ├─ (mittleres Item).
            parent: Optionaler Eltern-Widget.
        """
        super().__init__(parent)
        self._is_last = is_last
        self._hovered = False
        self.setFixedSize(16, _ITEM_H)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def set_hovered(self, hovered: bool) -> None:
        """Setzt den Hover-Zustand und löst Neuzeichnung aus.

        Args:
            hovered: True → Linie in theme.get.ACCENT zeichnen.
        """
        if self._hovered != hovered:
            self._hovered = hovered
            self.update()

    def paintEvent(self, _event) -> None:
        """Zeichnet die ├─ oder └─ Linie mit QPainter."""
        painter = QPainter(self)
        color = QColor(theme.get().ACCENT if self._hovered else theme.get().BORDER)
        pen = QPen(color, 1)
        painter.setPen(pen)

        cx = self.width() // 2
        mid_y = self.height() // 2
        # Vertikale Linie: oben bis Mitte (└) oder ganz durch (├)
        bottom_y = mid_y if self._is_last else self.height()
        painter.drawLine(cx, 0, cx, bottom_y)
        # Horizontale Linie: von Mitte nach rechts
        painter.drawLine(cx, mid_y, self.width() - 1, mid_y)
        painter.end()


# ---------------------------------------------------------------------------
# _NavItemWidget — Sub-Menü-Item
# ---------------------------------------------------------------------------
class _NavItemWidget(QWidget):
    """Klickbares Sub-Menü-Navigations-Item.

    Verwendet enterEvent/leaveEvent für zuverlässige Hover-Effekte
    (theme.get.ACCENT Text + halbtransparenter Hintergrund) unabhängig
    von QSS-Kaskadierungsproblemen.

    Signals:
        clicked(str): Wird mit dem Navigationsschlüssel emittiert.
    """

    clicked = Signal(str)
    open_in_bottom = Signal(str)

    def __init__(
        self,
        key: str,
        label: str,
        icon: str | QIcon,
        indent_px: int = _INDENT_L1,
        tooltip: str = "",
        font_size: int = 12,
        show_tree: bool = False,
        is_last: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Nav-Item.

        Args:
            key: Navigationsschlüssel.
            label: Anzeigetext.
            icon: Emoji-Icon.
            indent_px: Linke Einrückung in Pixeln.
            tooltip: Tooltip-Text.
            font_size: Schriftgröße in Pixeln.
            show_tree: True → L-Verbindungslinie vor dem Icon anzeigen.
            is_last: True → └─ statt ├─ (letztes Item der Gruppe).
            parent: Optionaler Eltern-Widget.
        """
        super().__init__(parent)
        self._key = key
        self._active = False
        self._indent_px = indent_px
        self._font_size = font_size
        self._tree: _TreeLine | None = None

        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setFixedHeight(_ITEM_H)
        self.setToolTip(tooltip if tooltip else label)

        self._lyt = QHBoxLayout(self)
        self._lyt.setSpacing(0)

        if show_tree:
            self._lyt.setContentsMargins(8, 0, 8, 0)
            self._tree = _TreeLine(is_last=is_last)
            self._lyt.addWidget(self._tree)
            self._lyt.addSpacing(4)
        else:
            self._lyt.setContentsMargins(indent_px, 6, 8, 6)

        self._lbl_icon = _make_icon_label(icon, size=16)

        self._lbl_text = QLabel(label)
        self._lbl_text.setStyleSheet(_text_qss(theme.get().TEXT_SIDEBAR, font_size))
        self._lbl_text.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )

        self._lyt.addWidget(self._lbl_icon)
        self._lyt.addSpacing(_ICON_GAP)
        self._lyt.addWidget(self._lbl_text)
        self._lyt.addStretch()

        self._apply_style()

    # ------------------------------------------------------------------
    def _apply_style(self) -> None:
        """Wendet das korrekte Stylesheet für den Aktiv-Zustand an."""
        if self._active:
            self.setStyleSheet(
                f"border-left: {_ACTIVE_BAR_W}px solid {theme.get().ACCENT}; "
                f"background-color: {_accent_rgba(51)};"
            )
            self._lbl_text.setStyleSheet(
                _text_qss(theme.get().ACCENT, self._font_size, bold=True)
            )
            if self._tree:
                self._tree.set_hovered(True)
        else:
            # Platzhalter synchron zur Indikator-Breite, sonst springt der Text
            self.setStyleSheet(
                f"border-left: {_ACTIVE_BAR_W}px solid transparent; "
                f"background-color: transparent;"
            )
            self._lbl_text.setStyleSheet(
                _text_qss(theme.get().TEXT_SIDEBAR, self._font_size)
            )
            if self._tree:
                self._tree.set_hovered(False)

    def set_active(self, active: bool) -> None:
        """Setzt den visuellen Aktiv-Zustand.

        Args:
            active: True hebt das Item als aktuell ausgewählt hervor.
        """
        if self._active != active:
            self._active = active
            self._apply_style()

    def set_collapsed(self, collapsed: bool) -> None:
        """Wechselt zwischen Icon-Modus (collapsed) und Textmodus.

        Args:
            collapsed: True → nur Icon; False → Icon + Text.
        """
        self._lbl_text.setVisible(not collapsed)
        if self._tree:
            self._tree.setVisible(not collapsed)
        if collapsed:
            self._lyt.setContentsMargins(0, 6, 8, 6)
        elif self._tree:
            self._lyt.setContentsMargins(8, 0, 8, 0)
        else:
            self._lyt.setContentsMargins(self._indent_px, 6, 8, 6)

    # ------------------------------------------------------------------
    def enterEvent(self, event) -> None:
        """Hover: nur Schrift wird Teal, kein Hintergrund-Rechteck."""
        if not self._active:
            self.setStyleSheet(
                f"border-left: {_ACTIVE_BAR_W}px solid transparent; "
                f"background-color: transparent;"
            )
            self._lbl_text.setStyleSheet(_text_qss(theme.get().ACCENT, self._font_size))
        if self._tree:
            self._tree.set_hovered(True)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        """Hover-Ende: Schrift zurück auf weiß."""
        if not self._active:
            self.setStyleSheet(
                f"border-left: {_ACTIVE_BAR_W}px solid transparent; "
                f"background-color: transparent;"
            )
            self._lbl_text.setStyleSheet(
                _text_qss(theme.get().TEXT_SIDEBAR, self._font_size)
            )
        if self._tree:
            self._tree.set_hovered(False)
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:
        """Emittiert ``clicked`` bei Linksklick."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._key)
        super().mousePressEvent(event)

    def contextMenuEvent(self, event) -> None:
        """Kontextmenü mit 'Im unteren Panel öffnen'."""
        menu = QMenu(self)
        act = menu.addAction("Im unteren Panel öffnen")
        chosen = menu.exec(event.globalPos())
        if chosen is act:
            self.open_in_bottom.emit(self._key)


# ---------------------------------------------------------------------------
# _SubNavItemWidget — Sub-Sub-Menü-Item mit Baum-Linie
# ---------------------------------------------------------------------------
class _SubNavItemWidget(QWidget):
    """Klickbares Sub-Sub-Menü-Item im XMind-Stil (├─ / └─).

    Zeigt eine Verbindungslinie (_TreeLine) die bei Hover von
    theme.get.BORDER zu theme.get.ACCENT wechselt.

    Signals:
        clicked(str): Wird mit dem Navigationsschlüssel emittiert.
    """

    clicked = Signal(str)
    open_in_bottom = Signal(str)

    def __init__(
        self,
        key: str,
        label: str,
        icon: str | QIcon,
        is_last: bool = False,
        tooltip: str = "",
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Sub-Sub-Item.

        Args:
            key: Navigationsschlüssel.
            label: Anzeigetext.
            icon: Emoji-Icon.
            is_last: True → └─ Linie (letztes Item der Gruppe).
            tooltip: Tooltip-Text.
            parent: Optionaler Eltern-Widget.
        """
        super().__init__(parent)
        self._key = key
        self._active = False

        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setFixedHeight(_ITEM_H)
        self.setToolTip(tooltip if tooltip else label)

        lyt = QHBoxLayout(self)
        lyt.setContentsMargins(_INDENT_L2_SPACE, 0, 8, 0)
        lyt.setSpacing(0)

        # Baum-Linie
        self._tree = _TreeLine(is_last=is_last)
        lyt.addWidget(self._tree)
        lyt.addSpacing(4)

        # Icon
        self._lbl_icon = _make_icon_label(icon, size=14)
        lyt.addWidget(self._lbl_icon)
        lyt.addSpacing(_ICON_GAP)

        # Text — weiß als Standard
        self._lbl_text = QLabel(label)
        self._lbl_text.setStyleSheet(_text_qss(theme.get().TEXT_SIDEBAR, 11))
        self._lbl_text.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        lyt.addWidget(self._lbl_text)
        lyt.addStretch()

        self._apply_style()

    # ------------------------------------------------------------------
    def _apply_style(self) -> None:
        """Wendet das korrekte Stylesheet für den Aktiv-Zustand an."""
        if self._active:
            self.setStyleSheet(
                f"border-left: {_ACTIVE_BAR_W}px solid {theme.get().ACCENT}; "
                f"background-color: {_accent_rgba(51)};"
            )
            self._lbl_text.setStyleSheet(_text_qss(theme.get().ACCENT, 11, bold=True))
            self._tree.set_hovered(True)
        else:
            # Platzhalter synchron zur Indikator-Breite, sonst springt der Text
            self.setStyleSheet(
                f"border-left: {_ACTIVE_BAR_W}px solid transparent; "
                f"background-color: transparent;"
            )
            self._lbl_text.setStyleSheet(_text_qss(theme.get().TEXT_SIDEBAR, 11))
            self._tree.set_hovered(False)

    def set_active(self, active: bool) -> None:
        """Setzt den visuellen Aktiv-Zustand.

        Args:
            active: True → hervorgehoben.
        """
        if self._active != active:
            self._active = active
            self._apply_style()

    def set_collapsed(self, collapsed: bool) -> None:
        """Wechselt zwischen Icon-Modus und Textmodus.

        Args:
            collapsed: True → nur Icon; False → Icon + Text + Baum.
        """
        self._lbl_text.setVisible(not collapsed)
        self._tree.setVisible(not collapsed)

    # ------------------------------------------------------------------
    def enterEvent(self, event) -> None:
        """Hover: nur Schrift wird Teal, kein Hintergrund-Rechteck."""
        if not self._active:
            self.setStyleSheet(
                f"border-left: {_ACTIVE_BAR_W}px solid transparent; "
                f"background-color: transparent;"
            )
            self._lbl_text.setStyleSheet(_text_qss(theme.get().ACCENT, 11))
            self._tree.set_hovered(True)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        """Hover-Ende: Schrift zurück auf weiß."""
        if not self._active:
            self.setStyleSheet(
                f"border-left: {_ACTIVE_BAR_W}px solid transparent; "
                f"background-color: transparent;"
            )
            self._lbl_text.setStyleSheet(_text_qss(theme.get().TEXT_SIDEBAR, 11))
            self._tree.set_hovered(False)
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:
        """Emittiert ``clicked`` bei Linksklick."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._key)
        super().mousePressEvent(event)

    def contextMenuEvent(self, event) -> None:
        """Kontextmenü mit 'Im unteren Panel öffnen'."""
        menu = QMenu(self)
        act = menu.addAction("Im unteren Panel öffnen")
        chosen = menu.exec(event.globalPos())
        if chosen is act:
            self.open_in_bottom.emit(self._key)


# ---------------------------------------------------------------------------
# _GroupWidget — aufklappbare Gruppe mit Kategorie-Header
# ---------------------------------------------------------------------------
class _GroupWidget(QWidget):
    """Aufklappbare Navigationsgruppe mit Kategorie-Label-Stil.

    Der Header wirkt als diskrete Kategoriebeschriftung (Großbuchstaben,
    gedimmter Text, kein Hintergrund-Rechteck). Kinder-Widgets werden
    mit einer QPropertyAnimation (150 ms) ein-/ausgeblendet.

    Signals:
        item_clicked(str): Weitergeleitet vom angeklickten Kind-Item.
    """

    item_clicked = Signal(str)
    item_open_bottom = Signal(str)

    def __init__(
        self,
        key: str,
        label: str,
        icon: str | QIcon,
        expanded: bool = False,
        show_tree: bool = False,
        is_last: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert die Gruppe.

        Args:
            key: Eindeutiger Schlüssel der Gruppe.
            label: Gruppenname (wird in Großbuchstaben angezeigt).
            icon: Emoji-Icon.
            expanded: True wenn die Gruppe beim Start ausgeklappt ist.
            show_tree: True → L-Verbindungslinie im Header anzeigen.
            is_last: True → └─ statt ├─ (letztes Item im Eltern-Container).
            parent: Optionaler Eltern-Widget.
        """
        super().__init__(parent)
        self._key = key
        self._label = label
        self._expanded = expanded
        self._collapsed_mode = False
        self._children: list = []  # _NavItemWidget | _SubNavItemWidget
        self._subheaders: list = []  # reine Deko-Labels hotfix)
        self._anim_h: QPropertyAnimation | None = None
        self._natural_height: int = 0
        self._expanding: bool = False
        self._header_tree: _TreeLine | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ------------------------------------------------------------------
        # Header — Kategorie-Label-Stil
        # ------------------------------------------------------------------
        self._header = QWidget()
        self._header.setFixedHeight(38)
        self._header.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._header.setToolTip(label)
        self._header.setStyleSheet("background-color: transparent; border: none;")

        # Monkey-patch enterEvent/leaveEvent/mousePressEvent auf Header
        self._header.enterEvent = self._header_enter  # type: ignore[method-assign]
        self._header.leaveEvent = self._header_leave  # type: ignore[method-assign]
        self._header.mousePressEvent = self._header_click  # type: ignore[method-assign]

        hlyt = QHBoxLayout(self._header)
        hlyt.setSpacing(0)

        if show_tree:
            hlyt.setContentsMargins(8, 0, 10, 0)
            self._header_tree = _TreeLine(is_last=is_last)
            hlyt.addWidget(self._header_tree)
            hlyt.addSpacing(4)
        else:
            hlyt.setContentsMargins(12, 0, 10, 0)

        hlyt.addSpacing(8)

        self._lbl_icon = _make_icon_label(icon, size=18)
        if isinstance(icon, str):
            self._lbl_icon.setStyleSheet(
                f"font-size: 13px; color: {theme.get().ACCENT}; "
                f"border: none; background: transparent;"
            )

        # Label in Großbuchstaben als Kategorie-Markierung — Neonblau
        self._lbl_text = QLabel(label.upper())
        self._lbl_text.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 11px; font-weight: bold; "
            f"color: {theme.get().ACCENT}; border: none; background: transparent;"
        )
        self._lbl_text.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )

        # Aufklapp-Pfeil (▾ / ▸)
        self._lbl_arrow = QLabel("▾" if expanded else "▸")
        self._lbl_arrow.setStyleSheet(
            f"font-size: 9px; color: {theme.get().ACCENT}; "
            f"border: none; background: transparent;"
        )

        hlyt.addWidget(self._lbl_icon)
        hlyt.addWidget(self._lbl_text)
        hlyt.addStretch()
        hlyt.addWidget(self._lbl_arrow)

        outer.addWidget(self._header)

        # ------------------------------------------------------------------
        # Kinder-Container (animierbar)
        # ------------------------------------------------------------------
        self._children_widget = QWidget()
        if not expanded:
            self._children_widget.setMaximumHeight(0)
        self._children_layout = QVBoxLayout(self._children_widget)
        self._children_layout.setContentsMargins(0, 0, 0, 0)
        self._children_layout.setSpacing(0)

        outer.addWidget(self._children_widget)
        # setVisible erst NACH dem Parenting — auf dem parentlosen
        # Widget mappt setVisible(True) ein natives Top-Level-Fenster
        # (sichtbarer Blitz beim Sidebar-Bau).
        self._children_widget.setVisible(expanded)

    # ------------------------------------------------------------------
    # Header-Event-Handler
    # ------------------------------------------------------------------
    def apply_theme(self) -> None:
        """Aktualisiert alle Label-Farben des Group-Headers auf den aktuellen Look."""
        c = theme.get()
        self._lbl_icon.setStyleSheet(
            f"font-size: 13px; color: {c.ACCENT}; "
            f"border: none; background: transparent;"
        )
        self._lbl_text.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 11px; font-weight: bold; "
            f"color: {c.ACCENT}; border: none; background: transparent;"
        )
        self._lbl_arrow.setStyleSheet(
            f"font-size: 9px; color: {c.ACCENT}; border: none; background: transparent;"
        )
        for child in self._children:
            child._apply_style()

    def _header_enter(self, event) -> None:
        """Hover: ganzes Rechteck in hellem Neonblau, Text bleibt ACCENT."""
        self._header.setStyleSheet(
            f"background-color: {_accent_rgba(50)}; border: none; border-radius: 4px;"
        )
        self._lbl_icon.setStyleSheet(
            f"font-size: 13px; color: {theme.get().ACCENT}; "
            f"border: none; background: transparent;"
        )
        self._lbl_text.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 11px; font-weight: bold; "
            f"color: {theme.get().ACCENT}; border: none; background: transparent;"
        )
        self._lbl_arrow.setStyleSheet(
            f"font-size: 9px; color: {theme.get().ACCENT}; "
            f"border: none; background: transparent;"
        )

    def _header_leave(self, event) -> None:
        """Hover-Ende: Hintergrund zurücksetzen, Text bleibt Neonblau."""
        self._header.setStyleSheet("background-color: transparent; border: none;")
        self._lbl_icon.setStyleSheet(
            f"font-size: 13px; color: {theme.get().ACCENT}; "
            f"border: none; background: transparent;"
        )
        self._lbl_text.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 11px; font-weight: bold; "
            f"color: {theme.get().ACCENT}; border: none; background: transparent;"
        )
        self._lbl_arrow.setStyleSheet(
            f"font-size: 9px; color: {theme.get().ACCENT}; "
            f"border: none; background: transparent;"
        )

    def _header_click(self, event) -> None:
        """Klappt die Gruppe auf/zu bei Linksklick (nur im Textmodus)."""
        if event.button() == Qt.MouseButton.LeftButton and not self._collapsed_mode:
            self._expanded = not self._expanded
            self._lbl_arrow.setText("▾" if self._expanded else "▸")
            self._animate_expand(self._expanded)

    # ------------------------------------------------------------------
    # Expand-Animation
    # ------------------------------------------------------------------
    def _animate_expand(self, expand: bool) -> None:
        """Animiert das Auf-/Zuklappen der Kinder-Widgets (150 ms).

        Args:
            expand: True → ausklappen; False → einklappen.
        """
        if self._anim_h:
            self._anim_h.stop()
            try:
                self._anim_h.finished.disconnect(self._on_expand_done)
            except RuntimeError:
                pass

        self._expanding = expand

        if expand:
            target_h = self._get_natural_height()
            self._children_widget.setMaximumHeight(0)
            self._children_widget.setVisible(True)
            start_h = 0
        else:
            target_h = 0
            start_h = self._children_widget.height()

        self._anim_h = QPropertyAnimation(self._children_widget, b"maximumHeight")
        self._anim_h.setDuration(150)
        self._anim_h.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self._anim_h.setStartValue(start_h)
        self._anim_h.setEndValue(target_h)
        self._anim_h.finished.connect(self._on_expand_done)
        self._anim_h.start()

    def _on_expand_done(self) -> None:
        """Bereinigt nach Ende der Expand-Animation."""
        if self._expanding:
            # Maximale Höhe entfernen damit Widget frei skaliert
            self._children_widget.setMaximumHeight(16_777_215)
        else:
            self._children_widget.setVisible(False)

    def _get_natural_height(self) -> int:
        """Berechnet die natürliche Höhe des Kinder-Containers.

        Verwendet das sizeHint der Layout-Items da der Container
        möglicherweise versteckt ist.

        Returns:
            Natürliche Höhe in Pixeln (mindestens _ITEM_H).
        """
        if self._natural_height > 0:
            return self._natural_height
        total = 0
        for i in range(self._children_layout.count()):
            item = self._children_layout.itemAt(i)
            if item and item.widget():
                h = item.widget().sizeHint().height()
                total += max(h, _ITEM_H)
        self._natural_height = max(total, _ITEM_H)
        return self._natural_height

    # ------------------------------------------------------------------
    # Öffentliche API
    # ------------------------------------------------------------------
    @property
    def title(self) -> str:
        """Gruppenname in Originalschreibweise."""
        return self._label

    def expand(self) -> None:
        """Klappt die Gruppe auf (programmatisch, ohne Benutzerklick)."""
        if not self._expanded:
            self._expanded = True
            self._lbl_arrow.setText("▾")
            self._animate_expand(True)

    def collapse(self) -> None:
        """Klappt die Gruppe zu (programmatisch, ohne Benutzerklick)."""
        if self._expanded:
            self._expanded = False
            self._lbl_arrow.setText("▸")
            self._animate_expand(False)

    def add_item(self, item_widget) -> None:
        """Fügt ein Navigations-Item zur Gruppe hinzu.

        Verbindet das ``clicked``-Signal des Items mit dem eigenen
        ``item_clicked``-Signal.

        Args:
            item_widget: _NavItemWidget oder _SubNavItemWidget Instanz.
        """
        self._children_layout.addWidget(item_widget)
        self._children.append(item_widget)
        if hasattr(item_widget, "clicked"):
            item_widget.clicked.connect(self.item_clicked)
        if hasattr(item_widget, "open_in_bottom"):
            item_widget.open_in_bottom.connect(self.item_open_bottom)
        # Gecachte Höhe zurücksetzen
        self._natural_height = 0

    def add_subheader(self, text: str) -> QLabel:
        """Fuegt eine Sub-Kategorie-Beschriftung in die Gruppe ein.

        Wird genutzt um die kuratierten Links nach Kategorie (BSI,
        Oesterreich,...) optisch zu trennen.
        Anders als ``add_item`` wird kein Click-Signal verdrahtet; das
        Label ist rein visueller Trenner und landet bewusst NICHT in
        ``self._children``, weil Sidebar-Code an mehreren Stellen ueber
        ``_children`` iteriert und ``_key`` / ``_apply_style`` erwartet
        (Hotfix nach-Crash am Start).

        Args:
            text: Kategoriename (wird in Grossbuchstaben gerendert).

        Returns:
            Das erstellte QLabel — der Aufrufer kann es z. B. zum
            Theme-Refresh in einer Liste halten.
        """
        c = theme.get()
        lbl = QLabel(text.upper())
        lbl.setObjectName("SidebarSubheader")
        lbl.setStyleSheet(
            f"QLabel#SidebarSubheader {{"
            f" font-family: 'Raleway', 'Segoe UI', sans-serif;"
            f" font-size: 10px; font-weight: bold; color: {c.TEXT_DIM};"
            f" padding: 6px 0 2px 32px; background: transparent; border: none;"
            f"}}"
        )
        self._children_layout.addWidget(lbl)
        self._subheaders.append(lbl)
        self._natural_height = 0
        return lbl

    def set_collapsed(self, collapsed: bool) -> None:
        """Wechselt den Sidebar-weiten Collapse-Zustand.

        Im Icon-Modus sind Label, Pfeil und alle Kinder-Container verborgen.

        Args:
            collapsed: True → Icon-Modus; False → Textmodus.
        """
        self._collapsed_mode = collapsed
        self._lbl_text.setVisible(not collapsed)
        self._lbl_arrow.setVisible(not collapsed)
        if self._header_tree:
            self._header_tree.setVisible(not collapsed)
        if collapsed:
            self._children_widget.setVisible(False)
        else:
            self._children_widget.setVisible(self._expanded)
        for child in self._children:
            if hasattr(child, "set_collapsed"):
                child.set_collapsed(collapsed)


# ---------------------------------------------------------------------------
# Trennlinie-Hilfsfunktion
# ---------------------------------------------------------------------------
def _make_separator(accent: bool = False) -> QFrame:
    """Erstellt eine horizontale Trennlinie.

    Args:
        accent: True → Farbe theme.get.ACCENT; False → theme.get.BORDER.

    Returns:
        Konfigurierter QFrame.
    """
    sep = QFrame()
    sep.setFrameShape(QFrame.Shape.HLine)
    sep.setFixedHeight(1)
    color = theme.get().ACCENT if accent else theme.get().BORDER
    sep.setStyleSheet(
        f"background-color: {color}; border: none; margin-top: 6px; margin-bottom: 6px;"
    )
    return sep


# ---------------------------------------------------------------------------
# _WidthAnimator — QPropertyAnimation-Helper für Sidebar-Breite
# ---------------------------------------------------------------------------
class _WidthAnimator(QObject):
    """Animiert die Sidebar-Breite über eine Qt-Property.

    Der Setter ruft ``setFixedWidth`` auf dem Ziel-Widget auf,
    was vom QSplitter respektiert wird.
    """

    def __init__(self, target: QWidget, parent: QObject | None = None) -> None:
        """Initialisiert den Animator.

        Args:
            target: Das Widget dessen Breite animiert wird.
            parent: Optionaler QObject-Elternteil.
        """
        super().__init__(parent)
        self._target = target
        self._w = target.width()

    def _get_w(self) -> int:
        return self._w

    def _set_w(self, value: int) -> None:
        self._w = value
        self._target.setFixedWidth(value)

    anim_width = Property(int, _get_w, _set_w)


# ---------------------------------------------------------------------------
# SidebarWidget — Haupt-Sidebar
# ---------------------------------------------------------------------------
class SidebarWidget(QWidget):
    """Professionelles mehrstufiges Sidebar-Widget für FINLAI.

    Enthält aufklappbare Navigationsgruppen, fixierten Boden-Bereich
    (Debug-Konsole, Einstellungen, Benutzer/Logout) und Toggle-Button.
    Der frühere Logo-Header entfiel mit (Dublette der Titelbar);
    der Home-Pfad ist das "home"-Nav-Item in der Cockpit-Gruppe.

    Signals:
        navigate(str): Navigationsschlüssel des ausgewählten Items.
        open_url(str): URL die im Browser geöffnet werden soll.
        logout_requested: Logout-Button wurde geklickt.
    """

    navigate = Signal(str)
    open_url = Signal(str)
    logout_requested = Signal()
    tool_open_bottom = Signal(str)

    def __init__(
        self,
        tools: list,
        session,
        settings: UISettings,
        groups: list[dict] | None = None,
        parent: QWidget | None = None,
        app_name: str = "FINLAI",
    ) -> None:
        """Initialisiert die Sidebar.

        Args:
            tools: Liste der zugänglichen BaseTool-Instanzen.
            session: Aktive Session-Instanz.
            settings: Geladene UISettings für Breite und Collapse-Zustand.
            groups: Optionale Sidebar-Gruppen-Konfiguration aus ``AppConfig``.
                     Wenn angegeben, werden nur die dort definierten Gruppen
                     in der angegebenen Reihenfolge gebaut. Wenn ``None``,
                     werden alle Gruppen in der Standard-Reihenfolge gebaut
                     (Rückwärtskompatibilität).
            parent: Optionaler Eltern-Widget.
            app_name: App-Name (aus ``AppConfig.app_name``). Seit
                     ohne eigene Anzeige (Logo-Header entfernt) — Parameter
                     bleibt für API-Kompatibilität der Aufrufer erhalten.
        """
        super().__init__(parent)
        self._settings = settings
        self._collapsed = settings.sidebar_collapsed
        self._active_key: str = ""
        self._all_nav_items: list = []
        self._all_groups: list[_GroupWidget] = []
        self._bottom_items: list[_NavItemWidget] = []
        self._animator: _WidthAnimator | None = None
        self._app_name = app_name
        # Phase 3d: einmal pro Nav-Aufbau aufgelöste W1-Gating-Flags des
        # eigenen Subjekts (None = noch nicht aufgelöst; in _build_nav genullt).
        self._profile_gating_flags_cache: dict[str, int | None] | None = None
        # Geordnete Gruppen-Config aus AppConfig (leer = alle Gruppen in Standardreihenfolge)
        self._groups: list[dict] = groups or []

        self._tool_names: set[str] = {t.name for t in tools}

        self.setObjectName("sidebar")
        # Kein eigener border-right — QSplitter-Handle übernimmt die Linie
        self.setStyleSheet(
            f"#sidebar {{ background-color: {theme.get().BG_SIDEBAR}; border: none; }}"
        )

        if self._collapsed:
            self.setFixedWidth(SIDEBAR_COLLAPSED_W)
        else:
            self.setFixedWidth(settings.sidebar_width)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Toggle-Button
        self._btn_toggle = self._build_toggle_btn()
        main_layout.addWidget(self._btn_toggle)

        # 2. Maskottchen-Logo (Live-Test 2026-06-27, Patrick: wieder oben in
        # die Sidebar). hatte den damaligen Logo-Header (finlai_logo +
        # App-Name) als Titelbar-Dublette entfernt; hier kommt NUR das
        # Maskottchen-Badge zurueck (kein Namens-Label -> keine Dublette).
        self._logo_header = self._build_logo_header()
        if self._logo_header is not None:
            main_layout.addWidget(self._logo_header)

        # 2. Scrollbarer Navigationsbereich
        # LinksRepository vor _build_nav initialisieren (wird in _build_links_group gebraucht)
        self._links_repo = LinksRepository()
        on_links_changed(self._rebuild_links_group)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; } "
            "QScrollBar:vertical { width: 4px; } "
        )
        nav = self._build_nav()
        scroll.setWidget(nav)
        main_layout.addWidget(scroll)

        # 3. Fixierter Boden
        main_layout.addWidget(self._build_bottom(session))

        # Suchindex aufbauen (nach Aufbau aller Navigation)
        self._search_index: list[dict] = []
        for _grp in self._all_groups:
            self._search_index.append(
                {"text": _grp.title.lower(), "type": "group", "ref": _grp}
            )
            for _child in _grp._children:
                self._search_index.append(
                    {
                        "text": _child.toolTip().lower() + " " + _child._key.lower(),
                        "type": "item",
                        "ref": _child,
                        "parent": _grp,
                    }
                )
        for _item in self._bottom_items:
            self._search_index.append(
                {
                    "text": _item.toolTip().lower() + " " + _item._key.lower(),
                    "type": "bottom",
                    "ref": _item,
                }
            )

        # Animator initialisieren
        self._animator = _WidthAnimator(self)
        self._anim = QPropertyAnimation(self._animator, b"anim_width")
        self._anim.setDuration(SIDEBAR_ANIM_MS)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self._anim.finished.connect(self._on_anim_finished)

        if self._collapsed:
            self._apply_collapsed_ui(animate=False)

        theme.register_listener(self.apply_theme)
        _log.debug("SidebarWidget initialisiert (collapsed=%s)", self._collapsed)

    def _build_logo_header(self) -> QWidget | None:
        """Baut den Maskottchen-Kopf der Sidebar (Live-Test 2026-06-27).

        Zeigt das FINLAI-Maskottchen als zentriertes Badge oben in der Sidebar.
        Nutzt den geteilten Branding-Helfer ``robot_badge_label``; fehlt das
        Asset, entfaellt der Header ganz (Rueckgabe ``None``). Das 40px-Badge
        bleibt auch im eingeklappten Zustand (Breite ``SIDEBAR_COLLAPSED_W`` =
        52) zentriert sichtbar — kein Sonderfall noetig.

        Returns:
            Transparenter Container mit dem Maskottchen-Badge, oder ``None``,
            wenn das Maskottchen-Asset fehlt.
        """
        from core.branding import robot_badge_label  # noqa: PLC0415

        badge = robot_badge_label(40)
        if badge is None:
            return None
        container = QWidget()
        container.setObjectName("sidebar_logo")
        container.setStyleSheet("background: transparent; border: none;")
        lyt = QVBoxLayout(container)
        lyt.setContentsMargins(0, 8, 0, 8)
        lyt.addWidget(badge, alignment=Qt.AlignmentFlag.AlignCenter)
        return container

    # ==================================================================
    # Theme-Listener
    # ==================================================================

    def apply_theme(self) -> None:
        """Aktualisiert alle Sidebar-Styles auf den aktuellen Look.

        Wird automatisch aufgerufen wenn theme.apply den Look wechselt.
        """
        c = theme.get()
        # Kein eigener border-right — QSplitter-Handle übernimmt die Linie
        # (synchron zum __init__-Styling)
        self.setStyleSheet(
            f"#sidebar {{ background-color: {c.BG_SIDEBAR}; border: none; }}"
        )
        for item in self._all_nav_items:
            item._apply_style()
        for grp in self._all_groups:
            grp.apply_theme()
        for item in self._bottom_items:
            item._apply_style()

        if hasattr(self, "_nav_widget"):
            self._nav_widget.setStyleSheet(
                f"background-color: {c.BG_SIDEBAR}; border: none;"
            )
        if hasattr(self, "_bottom_container"):
            self._bottom_container.setStyleSheet(
                f"background-color: {c.BG_SIDEBAR}; border: none;"
                f" border-top: 1px solid {c.BORDER};"
            )
        if hasattr(self, "_bottom_sep"):
            self._bottom_sep.setStyleSheet(
                f"background-color: {c.ACCENT}; border: none; margin: 0;"
            )
        if hasattr(self, "_user_widget"):
            self._user_widget.setStyleSheet(
                f"background-color: {c.BG_SIDEBAR_HEADER}; border: none;"
            )
        if hasattr(self, "_lbl_username"):
            self._lbl_username.setStyleSheet(_text_qss(c.TEXT_DIM, 11))
        if hasattr(self, "_btn_logout"):
            self._btn_logout.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    border: 1px solid {c.BORDER};
                    color: {c.TEXT_DIM};
                    font-size: 11px;
                    border-radius: 3px;
                    padding: 0 6px;
                }}
                QPushButton:hover {{
                    background-color: {c.DANGER};
                    border-color: {c.DANGER};
                    color: {c.TEXT_ON_DARK};
                }}
            """)

    # ==================================================================
    # Bau-Methoden
    # ==================================================================

    def _build_toggle_btn(self) -> QPushButton:
        """Erstellt den Toggle-Button « / ».

        Returns:
            Konfigurierter QPushButton.
        """
        icon = "»" if self._collapsed else "«"
        btn = QPushButton(icon)
        btn.setFixedHeight(26)
        btn.setToolTip("Sidebar ein-/ausklappen")
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {theme.get().TEXT_DIM};
                border: none;
                border-bottom: 1px solid {theme.get().BORDER};
                font-size: 12px;
                font-family: 'Raleway', 'Segoe UI', sans-serif;
                padding: 0 4px;
                text-align: right;
            }}
            QPushButton:hover {{
                color: {theme.get().ACCENT};
                background-color: {_HOVER_BG};
            }}
        """)
        btn.clicked.connect(self.toggle_collapse)
        return btn

    def _build_nav(self) -> QWidget:
        """Erstellt den scrollbaren Navigationsbereich.

        Wenn ``self._groups`` (aus ``AppConfig.sidebar_groups``) gesetzt ist,
        werden nur die dort definierten Gruppen in der angegebenen Reihenfolge
        gebaut. Andernfalls werden alle Gruppen in der Standard-Reihenfolge
        gebaut (Rückwärtskompatibilität mit ``main.py``).

        Returns:
            QWidget das in die QScrollArea eingebettet wird.
        """
        nav = QWidget()
        self._nav_widget = nav
        # W1-Gating-Flags pro Nav-Aufbau frisch auflösen (spiegelt Profil-/
        # Override-Änderungen bei einem Rebuild wider).
        self._profile_gating_flags_cache = None
        self._nav_widget.setStyleSheet(
            f"background-color: {theme.get().BG_SIDEBAR}; border: none;"
        )
        lyt = QVBoxLayout(nav)
        lyt.setContentsMargins(0, 4, 0, 4)
        lyt.setSpacing(0)

        # Sprint 5 Phase 3: Statische Gruppen kommen aus
        # ALL_NORISK_GROUP_CONFIGS (zentrale Single-Source-of-Truth in
        # sidebar_config.py). Sonderfaelle: "links" ist dynamisch
        # (LinksRepository + Live-Rebuild), Coming-Soon kommt direkt aus
        # AppConfig.sidebar_groups.
        _config_by_key: dict[str, SidebarGroupConfig] = {
            cfg.key: cfg for cfg in ALL_NORISK_GROUP_CONFIGS
        }

        def _build_static(key: str) -> _GroupWidget:
            """Baut entweder eine Config-Gruppe oder die dynamische Links-Gruppe."""
            if key == "links":
                return self._build_links_group()
            return self._build_group_from_config(_config_by_key[key])

        if self._groups:
            # Config-driven: nur Gruppen aus AppConfig, in der definierten Reihenfolge.
            # Gruppen mit status=="coming_soon" werden separat behandelt.
            active_groups = [
                g
                for g in self._groups
                if g.get("status") == _STATUS_COMING_SOON
                or g["key"] in _config_by_key
                or g["key"] == "links"
            ]
            for i, g_cfg in enumerate(active_groups):
                key = g_cfg["key"]
                if g_cfg.get("status") == _STATUS_COMING_SOON:
                    grp = self._build_coming_soon_group(g_cfg)
                else:
                    grp = _build_static(key)
                    self._all_groups.append(grp)
                lyt.addWidget(grp)
                if i < len(active_groups) - 1:
                    lyt.addWidget(_make_separator())
        else:
            # Default: alle statischen Gruppen aus der Config-Liste, dann links.
            default_keys = [cfg.key for cfg in ALL_NORISK_GROUP_CONFIGS] + ["links"]
            for i, key in enumerate(default_keys):
                grp = _build_static(key)
                self._all_groups.append(grp)
                lyt.addWidget(grp)
                if i < len(default_keys) - 1:
                    lyt.addWidget(_make_separator())

        lyt.addStretch()
        return nav

    # ------------------------------------------------------------------
    # Coming-Soon-Gruppen-Builder
    # ------------------------------------------------------------------

    def _build_coming_soon_group(self, group_cfg: dict) -> _GroupWidget:
        """Erstellt eine Coming-Soon-Navigationsgruppe aus der Sidebar-Config.

        Wird aufgerufen wenn ``group_cfg["status"] == "coming_soon"``.
        Alle Items in ``tool_keys`` werden als ``_ComingSoonItemWidget``
        dargestellt — geklickt öffnen sie einen Info-Dialog statt zu navigieren.

        Args:
            group_cfg: Sidebar-Gruppen-Dict aus ``AppConfig.sidebar_groups``
                       mit den Schlüsseln ``key``, ``name``, ``icon``,
                       ``tool_keys``, optional ``status_label``.

        Returns:
            _GroupWidget mit Coming-Soon-Items.
        """
        name = group_cfg.get("name", group_cfg.get("key", "Demnächst"))
        icon_name = group_cfg.get("icon", Icons.HOURGLASS)
        tool_keys: list[str] = group_cfg.get("tool_keys", [])
        badge = group_cfg.get("status_label", "BALD")

        grp = _GroupWidget(
            key=group_cfg.get("key", "coming_soon"),
            label=name,
            icon=get_icon(icon_name, color=theme.get().ACCENT),
            expanded=False,
        )
        # Item-Liste: ein Eintrag pro tool_key, oder ein Platzhalter
        labels = (
            [_humanize_key(k) for k in tool_keys]
            if tool_keys
            else ["Demnächst verfügbar"]
        )
        group_key = group_cfg.get("key", "coming_soon")
        for i, label in enumerate(labels):
            item_key = tool_keys[i] if tool_keys else f"{group_key}_placeholder"
            w = _ComingSoonItemWidget(
                label=label,
                badge=badge,
                indent_px=_INDENT_L1,
                show_tree=True,
                is_last=(i == len(labels) - 1),
                key=item_key,
            )
            grp._children_layout.addWidget(w)
            grp._children.append(w)
            self._all_nav_items.append(w)

        self._all_groups.append(grp)
        _log.debug("Coming-Soon-Gruppe gebaut: %s (%d Items)", name, len(labels))
        return grp

    # ------------------------------------------------------------------
    # Gruppen-Builder
    # ------------------------------------------------------------------

    def _build_group_from_config(self, cfg: SidebarGroupConfig) -> _GroupWidget:
        """Generic Builder: erzeugt _GroupWidget aus deklarativer Config.

        Sprint 5 Phase 1: zentraler Ersatz für die hardcodierten
        ``_build_*_group``-Methoden. Wiederverwendet das existierende
        ``_GroupWidget`` + ``_NavItemWidget`` + License-Lock-Pattern.

        Wendet den ``AppConfig.sidebar_groups[i]["tool_keys"]``-Filter an,
        falls für ``cfg.key`` ein Eintrag existiert. Setzt ``is_last`` korrekt
        für die XMind-Baumlinien.

        Args:
            cfg: Deklarative Gruppen-Config aus:mod:`core.sidebar_config`.

        Returns:
            Konfiguriertes ``_GroupWidget`` mit allen aktiven Items.
        """
        grp = _GroupWidget(
            cfg.key,
            cfg.label,
            get_sidebar_icon(cfg.icon),
            expanded=cfg.expanded,
        )
        grp.item_clicked.connect(self._on_item_clicked)
        grp.item_open_bottom.connect(self._on_item_open_bottom)

        # Filter aus AppConfig.sidebar_groups (falls vorhanden)
        _allowed: set[str] | None = None
        for g in self._groups:
            if g.get("key") == cfg.key:
                _allowed = set(g.get("tool_keys", []))
                break

        active = [
            item for item in cfg.items if _allowed is None or item.key in _allowed
        ]
        for i, item_cfg in enumerate(active):
            is_last = i == len(active) - 1
            w = _NavItemWidget(
                key=item_cfg.key,
                label=item_cfg.label,
                icon=get_sidebar_icon(item_cfg.icon),
                indent_px=_INDENT_L1,
                tooltip=item_cfg.tooltip or item_cfg.label,
                show_tree=True,
                is_last=is_last,
            )
            # Lizenz-Nav-Gating entfällt seit — kein
            # _apply_license_lock mehr. ``item_cfg.license_feature`` bleibt als
            # inertes Metadatum bestehen. Profil-Gating (W1) wirkt weiter:
            if item_cfg.profile_gating_key:
                _apply_profile_gating(
                    w, item_cfg.profile_gating_key, self._get_profile_gating_flags()
                )
            grp.add_item(w)
            self._all_nav_items.append(w)
        return grp

    def _get_profile_gating_flags(self) -> dict[str, int | None]:
        """Löst die W1-Gating-Flags des eigenen Subjekts auf (fail-soft, gecacht).

        Liefert ein Mapping {Flag-Schlüssel → tri-state-Wert} für die in
:data:`core.security_subject.w1_profil.GATING_KEYS` definierten Flags. Bei
        deaktiviertem Gating (``UISettings.profile_gating_enabled is False``),
        fehlendem ``SubjectStore`` oder fehlendem eigenem Subjekt ein leeres Dict
        → kein Gating (``_apply_profile_gating`` greift dann für keinen Schlüssel).

        Wird pro Nav-Aufbau einmal aufgelöst und gecacht (vermeidet N DB-Lesungen
        über alle Items hinweg).

        Returns:
            Mapping der Gating-Flags (leer = kein Gating).
        """
        if self._profile_gating_flags_cache is not None:
            return self._profile_gating_flags_cache
        flags: dict[str, int | None] = {}
        if getattr(self._settings, "profile_gating_enabled", True):
            try:
                store = create_subject_store()
                subject = store.get_self() if store is not None else None
                if subject is not None:
                    flags = {key: getattr(subject, key, None) for key in GATING_KEYS}
            except Exception:  # noqa: BLE001 — fail-soft: ohne Profil kein Gating
                # warning statt debug: der Pfad steuert die Sichtbarkeit
                # sicherheitsrelevanter Module — ein degradiertes Gating soll
                # sichtbar sein (PII-frei, kein Wert geloggt).
                _log.warning("Profil-Gating: Subjekt nicht auflösbar — kein Gating.")
                flags = {}
        self._profile_gating_flags_cache = flags
        return flags

    def _build_links_group(self) -> _GroupWidget:
        """Erstellt die „Wichtige Links"-Gruppe dynamisch aus LinksRepository.

        Returns:
            _GroupWidget mit benutzerspezifischen URL-Links.
        """
        grp = _GroupWidget(
            "links", "Wichtige Links", get_sidebar_icon(Icons.LINK), expanded=False
        )
        grp.item_clicked.connect(self._on_item_clicked)
        grp.item_open_bottom.connect(self._on_item_open_bottom)
        self._populate_links_group(grp)
        return grp

    def _populate_links_group(self, grp: _GroupWidget) -> None:
        """Befüllt eine Links-_GroupWidget mit kuratierten und benutzereigenen Links.

        Sprint 5 Phase 4: Lade-Logik (Session, AppConfig,
        Curated-Profil, User-Repository) lebt jetzt in
:func:`core.sidebar_links.load_sidebar_links`. Diese Methode
        ist nur noch der Widget-Builder ueber das Resultat.

        Vor jedem Wechsel von ``spec.category`` wird
        ein Subheader-Label eingefuegt, damit z. B. "BSI & Deutschland",
        "Oesterreich" und "Eigene Links" optisch getrennt sind. Leere
        Kategorien (Backwards-Compat fuer Profile ohne ``category``)
        erzeugen keinen Subheader.

        Args:
            grp: Ziel-_GroupWidget das befüllt werden soll.
        """
        specs = load_sidebar_links(self._groups, self._links_repo)
        last_category = ""
        for idx, spec in enumerate(specs):
            if spec.category and spec.category != last_category:
                grp.add_subheader(spec.category)
                last_category = spec.category
            icon_val: Any = spec.icon
            # Material Symbol names are lowercase ASCII + underscores (no emoji)
            if (
                spec.icon
                and spec.icon.isascii()
                and spec.icon.replace("_", "").isalpha()
            ):
                icon_val = get_icon(spec.icon)
            w = _NavItemWidget(
                key=spec.key,
                label=spec.label,
                icon=icon_val,
                indent_px=_INDENT_L1,
                tooltip=spec.label,
                show_tree=True,
                is_last=(idx == len(specs) - 1),
            )
            # URL direkt am Widget hinterlegen — wird in _on_item_clicked ausgelesen
            w._link_url = spec.url  # type: ignore[attr-defined]
            grp.add_item(w)
            self._all_nav_items.append(w)

    def _rebuild_links_group(self) -> None:
        """Ersetzt die Links-Gruppe live bei Änderungen aus den Einstellungen."""
        # Alte Gruppe in _all_groups suchen und Referenz merken
        old_grp: _GroupWidget | None = None
        old_idx: int = -1
        for i, grp in enumerate(self._all_groups):
            if getattr(grp, "_key", None) == "links":
                old_grp = grp
                old_idx = i
                break

        if old_grp is None:
            return

        # Alte Nav-Items aus _all_nav_items entfernen
        for child in old_grp._children:
            if child in self._all_nav_items:
                self._all_nav_items.remove(child)

        # Neue Gruppe bauen
        new_grp = self._build_links_group()

        # Im Layout tauschen
        lyt = self._nav_widget.layout()
        if lyt is not None:
            lyt.replaceWidget(old_grp, new_grp)
        old_grp.deleteLater()

        self._all_groups[old_idx] = new_grp
        _log.debug("Links-Gruppe neu aufgebaut")

    def _build_bottom(self, session) -> QWidget:
        """Erstellt den fixierten Boden-Bereich.

        Enthält Debug-Konsole, Einstellungen, eine ACCENT-Trennlinie
        und den Benutzer/Logout-Bereich.

        Args:
            session: Aktive Session für Benutzernamen.

        Returns:
            QWidget mit Bottom-Navigation.
        """
        container = QWidget()
        self._bottom_container = container
        self._bottom_container.setStyleSheet(
            f"background-color: {theme.get().BG_SIDEBAR}; border: none;"
        )
        lyt = QVBoxLayout(container)
        lyt.setContentsMargins(0, 2, 0, 0)
        lyt.setSpacing(0)

        # Einstellungen
        settings_item = _NavItemWidget(
            "einstellungen",
            "Einstellungen",
            get_sidebar_icon(Icons.SETTINGS),
            indent_px=12,
            tooltip="Einstellungen",
        )
        settings_item.clicked.connect(self._on_item_clicked)
        self._all_nav_items.append(settings_item)
        self._bottom_items.append(settings_item)
        lyt.addWidget(settings_item)

        # ACCENT-Trennlinie vor Benutzer-Bereich
        self._bottom_sep = QFrame()
        self._bottom_sep.setFrameShape(QFrame.Shape.HLine)
        self._bottom_sep.setFixedHeight(1)
        self._bottom_sep.setStyleSheet(
            f"background-color: {theme.get().ACCENT}; border: none; margin: 0;"
        )
        lyt.addWidget(self._bottom_sep)

        # Benutzer + Logout
        self._user_widget = self._build_user_widget(session)
        lyt.addWidget(self._user_widget)

        return container

    def _build_user_widget(self, session) -> QWidget:
        """Erstellt das Benutzer/Logout-Widget am Sidebar-Boden.

        Hintergrund: theme.get.BG_SIDEBAR_HEADER.
        Logout-Button-Hover: theme.get.DANGER (rot).

        Args:
            session: Aktive Session für Benutzernamen.

        Returns:
            QWidget mit Benutzername und Logout-Button.
        """
        w = QWidget()
        w.setFixedHeight(38)
        w.setStyleSheet(
            f"background-color: {theme.get().BG_SIDEBAR_HEADER}; border: none;"
        )

        lyt = QHBoxLayout(w)
        lyt.setContentsMargins(12, 0, 8, 0)
        lyt.setSpacing(8)

        self._lbl_user_icon = QLabel("👤")
        self._lbl_user_icon.setFixedWidth(16)
        self._lbl_user_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_user_icon.setStyleSheet(
            "font-size: 13px; border: none; background: transparent;"
        )

        full_name = ""
        if session.is_logged_in():
            full_name = session.current_user.full_name

        self._lbl_username = QLabel(full_name or "Benutzer")
        self._lbl_username.setStyleSheet(_text_qss(theme.get().TEXT_DIM, 11))
        self._lbl_username.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )

        self._btn_logout = QPushButton("⏻  Abmelden")
        self._btn_logout.setFixedHeight(22)
        self._btn_logout.setToolTip("Abmelden")
        self._btn_logout.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {theme.get().BORDER};
                color: {theme.get().TEXT_DIM};
                font-size: 11px;
                border-radius: 3px;
                padding: 0 6px;
            }}
            QPushButton:hover {{
                background-color: {theme.get().DANGER};
                border-color: {theme.get().DANGER};
                color: {theme.get().TEXT_ON_DARK};
            }}
        """)
        self._btn_logout.clicked.connect(self.logout_requested)

        lyt.addWidget(self._lbl_user_icon)
        lyt.addWidget(self._lbl_username)
        lyt.addWidget(self._btn_logout)

        return w

    # ==================================================================
    # Öffentliche API
    # ==================================================================

    def set_active_key(self, key: str) -> None:
        """Setzt das aktive (hervorgehobene) Navigationselement.

        Args:
            key: Schlüssel des aktiv zu setzenden Items.
        """
        self._active_key = key
        for item in self._all_nav_items:
            item.set_active(item._key == key)

    def set_user(self, full_name: str) -> None:
        """Aktualisiert den angezeigten Benutzernamen.

        Args:
            full_name: Vollständiger Name des angemeldeten Benutzers.
        """
        self._lbl_username.setText(full_name)

    def toggle_collapse(self) -> None:
        """Wechselt zwischen Icon-Modus und Textmodus mit Animation (200 ms)."""
        self._collapsed = not self._collapsed
        self._settings.sidebar_collapsed = self._collapsed

        start_w = self.width()
        end_w = SIDEBAR_COLLAPSED_W if self._collapsed else self._settings.sidebar_width

        if self._collapsed:
            self._apply_collapsed_ui(animate=True)
        else:
            self._apply_expanded_ui(animate=True)

        if self._anim:
            self._anim.stop()
            self._animator._w = start_w
            self._anim.setStartValue(start_w)
            self._anim.setEndValue(end_w)
            self._anim.start()

    def save_width(self, width: int) -> None:
        """Speichert die neue Sidebar-Breite nach Splitter-Drag.

        Args:
            width: Neue Breite in Pixeln.
        """
        if not self._collapsed:
            self._settings.sidebar_width = max(SIDEBAR_MIN_W, min(SIDEBAR_MAX_W, width))

    def filter_items(self, query: str) -> None:
        """Filtert Sidebar-Einträge nach dem Suchbegriff.

        Bei aktivem Query werden Gruppen mit Treffern aufgeklappt und
        nicht-passende Items ausgeblendet. Der Gruppenname selbst wird
        ebenfalls als Suchtext berücksichtigt.

        Bei leerem Query werden alle Items wieder eingeblendet und
        alle Gruppen in den Ausgangszustand (zugeklappt) zurückversetzt.

        Args:
            query: Suchbegriff aus der Titelbalken-Suchleiste.
        """
        query = query.strip().lower()

        if not query:
            # Ausgangszustand: alle Gruppen sichtbar + zugeklappt,
            # alle Items sichtbar
            for grp in self._all_groups:
                grp.setVisible(True)
                grp.collapse()
                for child in grp._children:
                    child.setVisible(True)
            for item in self._bottom_items:
                item.setVisible(True)
            return

        # Mit Query: Gruppen und ihre Kinder filtern
        for grp in self._all_groups:
            group_name = grp.title.lower()
            group_has_match = False

            for child in grp._children:
                item_text = child.toolTip().lower() + " " + child._key.lower()
                item_matches = query in item_text or query in group_name
                child.setVisible(item_matches)
                if item_matches:
                    group_has_match = True

            grp.setVisible(group_has_match)
            if group_has_match:
                grp.expand()

        # Bottom-Items (Einstellungen etc.) separat filtern
        for item in self._bottom_items:
            item_text = item.toolTip().lower() + " " + item._key.lower()
            item.setVisible(query in item_text)

    # ==================================================================
    # Interne Methoden
    # ==================================================================

    def _apply_collapsed_ui(self, animate: bool = False) -> None:
        """Versteckt alle Texte und klappt alle Gruppen ein (Icon-Modus).

        Args:
            animate: Wenn False wird die Breite sofort gesetzt.
        """
        self._btn_toggle.setText("»")
        for grp in self._all_groups:
            grp.set_collapsed(True)
        for item in self._bottom_items:
            item.set_collapsed(True)
        self._lbl_username.setVisible(False)
        self._btn_logout.setVisible(False)
        if not animate:
            self.setFixedWidth(SIDEBAR_COLLAPSED_W)

    def _apply_expanded_ui(self, animate: bool = False) -> None:
        """Zeigt alle Texte wieder an (Textmodus).

        Args:
            animate: Wenn False wird die Breite sofort gesetzt.
        """
        self._btn_toggle.setText("«")
        for grp in self._all_groups:
            grp.set_collapsed(False)
        for item in self._bottom_items:
            item.set_collapsed(False)
        self._lbl_username.setVisible(True)
        self._btn_logout.setVisible(True)
        if not animate:
            self.setFixedWidth(self._settings.sidebar_width)

    def _on_anim_finished(self) -> None:
        """Bereinigt nach Ende der Sidebar-Collapse-Animation."""
        if self._collapsed:
            self.setFixedWidth(SIDEBAR_COLLAPSED_W)
        else:
            self.setMinimumWidth(SIDEBAR_MIN_W)
            self.setMaximumWidth(SIDEBAR_MAX_W)
            self.resize(self._settings.sidebar_width, self.height())

    def _on_item_clicked(self, key: str) -> None:
        """Verarbeitet Klick auf ein Navigationselement.

        URL-Links öffnen den Browser; alle anderen Schlüssel navigieren
        den Stack.

        Args:
            key: Navigationsschlüssel des angeklickten Items.
        """
        if key.startswith("link:"):
            # URL direkt vom Nav-Item-Widget lesen (dynamisch aus LinksRepository)
            url = ""
            for item in self._all_nav_items:
                if getattr(item, "_key", None) == key:
                    url = getattr(item, "_link_url", "")
                    break
            if url:
                self.open_url.emit(url)
            return

        self.set_active_key(key)
        self.navigate.emit(key)

    def _on_item_open_bottom(self, key: str) -> None:
        """Emittiert ``tool_open_bottom`` für den angegebenen Schlüssel.

        Args:
            key: Navigationsschlüssel des Items das im unteren Panel geöffnet werden soll.
        """
        if key.startswith("link:"):
            return
        if key == "home":
            # Home ist das Welcome-Dock — im unteren Panel gäbe
            # es nur einen nutzlosen Platzhalter-Tab.
            return
        self.tool_open_bottom.emit(key)
