"""cert_burndown_tile — Quick-Win W2 (Sprint S3c).

Zeigt das TLS-Zertifikat mit der niedrigsten Restlaufzeit als kompakte
KPI-Kachel mit Ampel-Logik:

  - ``<= 7 Tage`` -> rot (kritisch — Patrick-typische Erneuerungsfrist)
  - ``<= 30 Tage`` -> orange (warnung)
  - ``> 30 Tage`` -> gruen (entspannt)
  - ``None`` -> grau ("Keine Zertifikate ueberwacht")

Datenquelle::class:`CertBurndown` aus dem
:class:`DashboardAggregator` (Loader liest ``CertRepository``).

Schichtzugehoerigkeit: gui/ — keine Domain-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QLabel, QSizePolicy, QVBoxLayout, QWidget

from core import theme
from tools.norisk_dashboard.domain.models import CertBurndown


class CertBurndownTile(QFrame):
    """Kompakte KPI-Kachel mit Min-Restlaufzeit + Ampelfarbe.

    Signals:
        clicked: Linksklick — fuehrt zum Cert-Monitor (vom Dashboard
            geroutet).
    """

    clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data: CertBurndown | None = None
        self.setObjectName("certBurndownTile")
        self.setFixedSize(180, 140)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(2)

        c = theme.get()
        self._title = QLabel("ZERTIFIKATE", self)
        self._title.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 10px; "
            f"font-weight: bold; letter-spacing: 1px; background: transparent;"
        )
        lay.addWidget(self._title)

        self._value = QLabel("—", self)
        self._value.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 36px; font-weight: bold; "
            f"background: transparent;"
        )
        lay.addWidget(self._value)

        self._unit = QLabel("Keine Zertifikate", self)
        self._unit.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; background: transparent;"
        )
        lay.addWidget(self._unit)

        self._sub = QLabel("", self)
        self._sub.setWordWrap(True)
        self._sub.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 10px; background: transparent;"
        )
        lay.addWidget(self._sub)

        self._apply_zone(None)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_data(self, data: CertBurndown | None) -> None:
        """Aktualisiert den dargestellten Zustand."""
        self._data = data
        if data is None or data.min_days is None:
            self._value.setText("—")
            self._unit.setText("Keine Zertifikate")
            self._sub.setText("")
            self._apply_zone(None)
            self.setToolTip(
                "Cert-Monitor hat noch keine Zertifikate erfasst.\n"
                "Im Cert-Monitor eine Domain hinzufuegen, um die "
                "Restlaufzeit zu sehen."
            )
            return

        self._value.setText(f"{data.min_days}")
        unit = "Tag" if abs(data.min_days) == 1 else "Tage"
        suffix = "abgelaufen" if data.min_days < 0 else "verbleibend"
        self._unit.setText(f"{unit} {suffix}")
        sub_parts: list[str] = []
        if data.domain:
            sub_parts.append(data.domain)
        sub_parts.append(f"{data.count_total} Zertifikate ueberwacht")
        if data.count_critical:
            sub_parts.append(f"{data.count_critical} kritisch")
        elif data.count_warning:
            sub_parts.append(f"{data.count_warning} bald faellig")
        self._sub.setText(" · ".join(sub_parts))
        self._apply_zone(data.min_days)
        self._refresh_tooltip(data)

    # ------------------------------------------------------------------
    # Interna
    # ------------------------------------------------------------------

    def _apply_zone(self, days: int | None) -> None:
        c = theme.get()
        if days is None:
            border = c.BORDER
            value_color = c.TEXT_DIM
        elif days <= 7:
            border = c.DANGER
            value_color = c.DANGER
        elif days <= 30:
            border = theme.WARNING_ORANGE
            value_color = theme.WARNING_ORANGE
        else:
            border = c.SUCCESS
            value_color = c.SUCCESS
        self.setStyleSheet(
            f"#certBurndownTile {{ background: {c.BG_MAIN}; "
            f"border: 1px solid {c.BORDER}; "
            f"border-left: 4px solid {border}; "
            f"border-radius: 6px; }} "
            f"#certBurndownTile:hover {{ border-color: {theme.DARK_ACCENT}; "
            f"border-left-color: {border}; }}"
        )
        self._value.setStyleSheet(
            f"color: {value_color}; font-size: 36px; font-weight: bold; "
            f"background: transparent;"
        )

    def _refresh_tooltip(self, data: CertBurndown) -> None:
        lines = [
            "Cert-Burndown — naechstes Zertifikat:",
            f"  Restlaufzeit: {data.min_days} Tage",
        ]
        if data.domain:
            lines.append(f"  Domain: {data.domain}")
        lines.extend(
            [
                f"  Ueberwacht: {data.count_total}",
                f"  Kritisch (<= 7 d): {data.count_critical}",
                f"  Warnung (<= 30 d): {data.count_warning}",
            ]
        )
        self.setToolTip("\n".join(lines))

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)
