"""
phishing_inbox_list — ListView + Item-Delegate fuer die Phishing-
Inbox-Liste im ``PhishingInboxDialog``.

Author: Patrick Riederich
Version: 1.0 (2026-05-28 Phishing-Radar-Refactor)
"""

from __future__ import annotations

import html
from datetime import UTC, datetime, timedelta

from PySide6.QtCore import (
    QAbstractListModel,
    QModelIndex,
    QSize,
    Qt,
)
from PySide6.QtGui import QColor, QFont, QFontMetrics
from PySide6.QtWidgets import (
    QListView,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QWidget,
)

from core import theme
from tools.mainpage.gui.phishing_radar_data import (
    relativ_zeit,
    severity_kuerzel,
    severity_tooltip,
)

_ROW_HOEHE = 56

# Severity-Signalfarben zentral aus dem Theme — keine hartcodierten Hex.
_SEVERITY_SIGNAL: dict[str, str] = {
    "kritisch": theme.SEVERITY_SIGNAL_CRITICAL,
    "hoch": theme.SEVERITY_SIGNAL_HIGH,
    "mittel": theme.SEVERITY_SIGNAL_MEDIUM,
    "niedrig": theme.SEVERITY_SIGNAL_LOW,
    "info": theme.SEVERITY_SIGNAL_INFO,
}

# Auf den helleren Signalfarben (orange/gelb/hellblau) ist schwarzer Text
# kontraststaerker, auf rot/grau weisser (WCAG 2.2 AA, SC 1.4.3).
_SEVERITY_DARK_TEXT: frozenset[str] = frozenset({"hoch", "mittel", "niedrig"})


def severity_signal_color(value: str) -> str:
    """Theme-Signalfarbe (Hex-String) zu einem Schweregrad-Value."""

    return _SEVERITY_SIGNAL.get(value, theme.SEVERITY_SIGNAL_INFO)


def severity_text_color(value: str) -> str:
    """Kontraststarke Badge-Textfarbe zu einem Schweregrad-Value."""

    return "black" if value in _SEVERITY_DARK_TEXT else "white"


def _farbe(value: str) -> QColor:
    return QColor(severity_signal_color(value))


def _badge_text_farbe(value: str) -> QColor:
    return QColor(severity_text_color(value))


class PhishingItemModel(QAbstractListModel):
    """Model fuer die Inbox-Liste — haelt CyberMeldung-Objekte +
    Read/Snooze-Marker."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._meldungen: list = []
        self._read_guids: set[str] = set()

    def setze_meldungen(self, meldungen: list, gelesene: set[str]) -> None:
        self.beginResetModel()
        self._meldungen = list(meldungen)
        self._read_guids = set(gelesene)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008, D401
        if parent.isValid():
            return 0
        return len(self._meldungen)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: ANN201
        if not index.isValid() or index.row() >= len(self._meldungen):
            return None
        meldung = self._meldungen[index.row()]
        if role == Qt.ItemDataRole.UserRole:
            return meldung
        if role == Qt.ItemDataRole.UserRole + 1:
            return meldung.guid in self._read_guids
        if role == Qt.ItemDataRole.DisplayRole:
            return meldung.titel
        if role == Qt.ItemDataRole.ToolTipRole:
            sev = getattr(meldung.schweregrad, "value", "info")
            # Feed-Titel ist untrusted — escapen, sonst interpretiert Qt den
            # Tooltip als Rich-Text (Tracking-Pixel via <img> im Titel).
            return f"{severity_tooltip(sev)}\n{html.escape(meldung.titel)}"
        return None

    def meldung_an(self, row: int):  # noqa: ANN201
        if 0 <= row < len(self._meldungen):
            return self._meldungen[row]
        return None

    def setze_gelesen(self, guids: list[str]) -> None:
        self._read_guids.update(g for g in guids if g)
        if self._meldungen:
            top = self.index(0)
            bot = self.index(len(self._meldungen) - 1)
            self.dataChanged.emit(top, bot, [Qt.ItemDataRole.UserRole + 1])

    def setze_ungelesen(self, guids: list[str]) -> None:
        for g in guids:
            self._read_guids.discard(g)
        if self._meldungen:
            top = self.index(0)
            bot = self.index(len(self._meldungen) - 1)
            self.dataChanged.emit(top, bot, [Qt.ItemDataRole.UserRole + 1])

    def entferne(self, guid: str) -> None:
        for i, m in enumerate(self._meldungen):
            if m.guid == guid:
                self.beginRemoveRows(QModelIndex(), i, i)
                self._meldungen.pop(i)
                self.endRemoveRows()
                return


class PhishingItemDelegate(QStyledItemDelegate):
    """Card-artige Darstellung pro Inbox-Eintrag."""

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:  # noqa: ARG002
        return QSize(0, _ROW_HOEHE)

    def paint(self, painter, option, index):  # noqa: ANN001, D401
        painter.save()
        meldung = index.data(Qt.ItemDataRole.UserRole)
        gelesen = bool(index.data(Qt.ItemDataRole.UserRole + 1))
        c = theme.get()

        rect = option.rect.adjusted(4, 2, -4, -2)

        # Hintergrund (Selected / Hover). PySide6/Qt6: QStyle.StateFlag ist strikt
        # typisiert — ``& int`` wirft ``TypeError: unsupported operand... 'StateFlag'
        # and 'int'`` und liess das Oeffnen der Inbox crashen. Daher die echten
        # Enum-Flags (die alten Magic-Numbers 0x0008/0x0010 waren ausserdem
        # State_Off/State_NoChange — nicht Selected/MouseOver).
        if option.state & (
            QStyle.StateFlag.State_Selected | QStyle.StateFlag.State_MouseOver
        ):
            painter.fillRect(rect, QColor(c.BG_TABLE_ALT))

        # Severity-Badge links.
        sev_value = getattr(meldung.schweregrad, "value", "info")
        badge_rect = rect.adjusted(4, 10, 0, -10)
        badge_rect.setWidth(56)
        painter.fillRect(badge_rect, _farbe(sev_value))
        painter.setPen(_badge_text_farbe(sev_value))
        font = QFont(painter.font())
        font.setBold(True)
        font.setPointSize(8)
        painter.setFont(font)
        painter.drawText(
            badge_rect, Qt.AlignmentFlag.AlignCenter, severity_kuerzel(sev_value)
        )

        # Read-Dot rechts vom Badge.
        if not gelesen:
            dot_rect = rect.adjusted(66, 22, 0, 0)
            dot_rect.setSize(QSize(6, 6))
            painter.setBrush(QColor(c.ACCENT))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(dot_rect)

        # Text-Spalte.
        text_x = rect.left() + 80
        text_w = rect.width() - 90
        # Titel.
        painter.setPen(QColor(c.TEXT_MAIN))
        title_font = QFont(painter.font())
        title_font.setBold(not gelesen)
        title_font.setPointSize(9)
        painter.setFont(title_font)
        fm = QFontMetrics(title_font)
        title = fm.elidedText(meldung.titel, Qt.TextElideMode.ElideRight, text_w)
        painter.drawText(text_x, rect.top() + 22, title)

        # Sub: Quelle + Datum.
        sub_font = QFont(painter.font())
        sub_font.setBold(False)
        sub_font.setPointSize(8)
        painter.setFont(sub_font)
        painter.setPen(QColor(c.TEXT_DIM))
        sub_text = f"{meldung.quelle.value} · {relativ_zeit(meldung.veroeffentlicht)}"
        painter.drawText(text_x, rect.top() + 40, sub_text)

        painter.restore()


class PhishingInboxListView(QListView):
    """``QListView`` mit angepasstem Item-Delegate."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setUniformItemSizes(True)
        self.setMouseTracking(True)
        self.setSelectionMode(QListView.SelectionMode.SingleSelection)
        self.setStyleSheet("background: transparent; border: none;")
        self.setItemDelegate(PhishingItemDelegate(self))


def snooze_bis_morgen() -> datetime:
    """Liefert den Zeitpunkt 'morgen 06:00 lokale Zeit' als UTC.

    Berechnet 06:00 in der **lokalen** Zeitzone des Nutzers (DACH-Markt)
    und konvertiert nach UTC fuer die Persistenz. Ein reiner UTC-Wert
    waere in MEZ/MESZ um 1-2 Stunden verschoben.
    """

    jetzt_lokal = datetime.now().astimezone()
    morgen_lokal = (jetzt_lokal + timedelta(days=1)).replace(
        hour=6, minute=0, second=0, microsecond=0
    )
    return morgen_lokal.astimezone(UTC)
