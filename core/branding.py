"""
branding — Zentrale Lade-Stelle für das FINLAI-Maskottchen.

Der FINLAI-Roboter erscheint an persönlichen Kontaktpunkten der App
(Begrüßungs-Header, Login, KI-Chat-Avatar, KI-Todo-Sektion). Das runde
Firmen-Emblem (``finlai_logo.png``) bleibt für formale Flächen
(Titelbar, PDF-Exporte) bestehen.

Asset-Tausch: Dieses Modul ist die EINZIGE Integrationsstelle für das
Roboter-Bild. Liefert Patrick später ein transparentes Hi-Res-Asset,
genügt es, ``assets/logo/finlai_robot.png`` auszutauschen — kein
Code-Anfasser nötig. Die Kreismaske sorgt dafür, dass der dunkle
Navy-Hintergrund des aktuellen PNGs als runder Badge-Grund liest
(gleiche Optik wie das heutige runde Emblem).

WICHTIG::func:`robot_pixmap` darf nur aus GUI-Code NACH dem
QApplication-Start aufgerufen werden (QPixmap braucht eine laufende
GUI-Session). Bewusst KEIN ``functools.lru_cache`` — der Modul-Dict-
Cache hält keine Funktions-Closures über den QApplication-Teardown
hinaus und bleibt explizit inspizier-/leerbar.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

from core import theme

_ROBOT_PATH = Path(__file__).parent.parent / "assets" / "logo" / "finlai_robot.png"

# Cache pro Zielgröße — QPixmap-Skalierung + Maskierung nur einmal.
_cache: dict[int, QPixmap] = {}


def robot_pixmap(size: int) -> QPixmap:
    """Liefert das FINLAI-Roboter-Maskottchen als rundes Badge-Pixmap.

    Lädt ``assets/logo/finlai_robot.png``, skaliert smooth auf
    ``size``×``size`` (KeepAspectRatioByExpanding) und maskiert das
    Ergebnis per:class:`QPainterPath` auf einen Kreis — Badge-Look
    analog zum runden Firmen-Emblem.

    Args:
        size: Kantenlänge des quadratischen Ziel-Pixmaps in Pixeln.

    Returns:
        Rundes Roboter-Pixmap in ``size``×``size``. Wenn das Asset
        fehlt oder nicht ladbar ist: leeres ``QPixmap`` — Aufrufer
        prüfen ``isNull`` und behalten dann ihr bisheriges Bild/Icon.
        WICHTIG: Das Resultat ist ein GETEILTES Cache-Objekt — nur via
        ``setPixmap`` verwenden, nie direkt darauf malen.
    """
    if size <= 0:
        return QPixmap()
    cached = _cache.get(size)
    if cached is not None:
        return cached

    source = QPixmap(str(_ROBOT_PATH))
    if source.isNull():
        return QPixmap()

    scaled = source.scaled(
        size,
        size,
        Qt.AspectRatioMode.KeepAspectRatioByExpanding,
        Qt.TransformationMode.SmoothTransformation,
    )

    result = QPixmap(size, size)
    result.fill(Qt.GlobalColor.transparent)
    painter = QPainter(result)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    clip = QPainterPath()
    clip.addEllipse(0, 0, size, size)
    painter.setClipPath(clip)
    # Zentrierter Ausschnitt — bei nicht-quadratischen Assets schneidet
    # KeepAspectRatioByExpanding den Überstand symmetrisch ab.
    painter.drawPixmap(
        (size - scaled.width()) // 2,
        (size - scaled.height()) // 2,
        scaled,
    )
    painter.end()

    _cache[size] = result
    return result


def robot_badge_label(size: int) -> QLabel | None:
    """Liefert ein fertiges QLabel mit dem Maskottchen-Badge.

    Bündelt das wiederkehrende Muster QLabel + ``setPixmap`` +
    transparentem Hintergrund-Style, damit der Boilerplate nicht
    weiter kopiert wird (Review-Finding).

    Args:
        size: Kantenlänge des Badges in Pixeln.

    Returns:
        Zentriertes, transparentes QLabel mit dem Badge — oder ``None``,
        wenn das Asset fehlt (Aufrufer lassen das Label dann einfach weg).
    """
    robot = robot_pixmap(size)
    if robot.isNull():
        return None
    label = QLabel()
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setFixedHeight(size)
    label.setPixmap(robot)
    label.setStyleSheet("background: transparent; border: none;")
    return label


# ObjectName des Namens-Labels in der Avatar-Kopfzeile — wird von
# restyle_avatar_header fuer den Theme-Wechsel wiedergefunden.
_AVATAR_NAME_OBJECT = "FinlaiAvatarHeaderName"


def _avatar_name_qss() -> str:
    """Liefert das QSS des Avatar-Namens-Labels im aktiven Look."""
    return (
        f"QLabel#{_AVATAR_NAME_OBJECT} {{"
        f" color: {theme.get().ACCENT};"
        f" font-size: {theme.FONT_SIZE_CAPTION}px;"
        " font-weight: bold;"
        " background: transparent; border: none; }"
    )


def finlai_avatar_header(name: str = "FINLAI", size: int = 22) -> QWidget:
    """Liefert die Avatar-Kopfzeile einer Assistenten-Chat-Bubble.

    Bündelt das wiederkehrende Muster „rundes Maskottchen-Badge + Name in
    Akzentfarbe" über Assistenten-Antworten (bisheriges Vorbild:
    ``tools/ki_integration/gui/chat/message_bubble.py``). Rule of Three:
    Dieses Modul ist die einzige Maskottchen-Integrationsstelle —
    Konsumenten kopieren das Muster nicht mehr, sie rufen diese Factory.

    Args:
        name: Anzeigename neben dem Badge (Default ``"FINLAI"``).
        size: Kantenlänge des Avatar-Badges in Pixeln.

    Returns:
        Transparentes ``QWidget`` mit HBox (Badge + Name + Stretch).
        Fehlt das Maskottchen-Asset (``robot_pixmap.isNull``), entfällt
        nur das Badge — der Name bleibt sichtbar (White-Label-/Headless-Pfad).
    """
    header = QWidget()
    header.setStyleSheet("background: transparent; border: none;")
    row = QHBoxLayout(header)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(4)

    avatar = robot_pixmap(size)
    if not avatar.isNull():
        lbl_avatar = QLabel()
        lbl_avatar.setFixedSize(size, size)
        lbl_avatar.setPixmap(avatar)
        lbl_avatar.setStyleSheet("background: transparent; border: none;")
        row.addWidget(lbl_avatar)

    lbl_name = QLabel(name)
    lbl_name.setObjectName(_AVATAR_NAME_OBJECT)
    lbl_name.setStyleSheet(_avatar_name_qss())
    row.addWidget(lbl_name)
    row.addStretch()
    return header


def restyle_avatar_header(header: QWidget) -> None:
    """Wendet den aktiven Theme-Look auf eine Avatar-Kopfzeile neu an.

    Für die ``apply_theme``-Pfade der Konsumenten (Theme-Wechsel zur
    Laufzeit) — das Badge-Pixmap ist theme-unabhängig, nur das
    Namens-Label trägt eine Akzentfarbe.

    Args:
        header: Rückgabewert von:func:`finlai_avatar_header`.
    """
    lbl_name = header.findChild(QLabel, _AVATAR_NAME_OBJECT)
    if lbl_name is not None:
        lbl_name.setStyleSheet(_avatar_name_qss())
