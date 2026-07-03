"""
renewal_banner — Status-Banner-Card fuer auslaufende/abgelaufene Schulungen.

Iteration 3b: Inspiriert vom EOL-Banner im Patch-
Monitor, ``patch_console_widget._build_eol_banner``). Sichtbar
nur wenn mindestens eine Schulung im Status EXPIRED oder EXPIRING_SOON
ist; zwei Buttons "Anzeigen" (filtert die Tabelle) und "Renewals als
.ics exportieren".

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import QSize, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from core import theme
from core.icons import ICON_SIZE_LG, Icons, get_icon
from tools.awareness_tracker.domain.models import (
    Training,
    ValidityStatus,
)

# Pixel-Groesse der Banner-Severity-Indikatoren (Material-Symbol).
_BANNER_ICON_PX: int = ICON_SIZE_LG


class RenewalBanner(QFrame):
    """Card mit Renewal-Status-Zusammenfassung.

    Signals:
        show_renewals_clicked: User hat "Anzeigen" gedrueckt -- der
            ``awareness_widget`` filtert die Tabelle auf renewal-pflichtige
            Schulungen.
        export_ics_clicked: User hat den Export-Button gedrueckt -- der
            ``awareness_widget`` oeffnet einen Save-Dialog und ruft den
            ``ics_exporter`` auf.
    """

    show_renewals_clicked = Signal()
    export_ics_clicked = Signal()

    def __init__(self, parent=None) -> None:  # noqa: ANN001 — QWidget-Subklasse
        super().__init__(parent)
        self.setObjectName("AwarenessRenewalBanner")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._build_ui()
        self._set_visible_if_needed(expired=0, expiring=0)

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        text_box = QVBoxLayout()
        text_box.setSpacing(2)

        self._icon_label = QLabel()
        self._icon_label.setObjectName("AwarenessRenewalBannerIcon")
        layout.addWidget(self._icon_label)

        self._title_label = QLabel("Renewal-Status")
        self._title_label.setObjectName("AwarenessRenewalBannerTitle")
        text_box.addWidget(self._title_label)

        self._detail_label = QLabel("")
        self._detail_label.setObjectName("AwarenessRenewalBannerDetail")
        self._detail_label.setWordWrap(True)
        text_box.addWidget(self._detail_label)

        layout.addLayout(text_box, stretch=1)

        self._show_button = QPushButton("Renewal-Liste anzeigen")
        self._show_button.setObjectName("AwarenessRenewalBannerShowButton")
        self._show_button.clicked.connect(self.show_renewals_clicked.emit)
        layout.addWidget(self._show_button)

        self._export_button = QPushButton("Renewals als .ics exportieren")
        self._export_button.setObjectName("AwarenessRenewalBannerExportButton")
        self._export_button.clicked.connect(self.export_ics_clicked.emit)
        layout.addWidget(self._export_button)

    def update_from(
        self,
        trainings: list[Training],
        now: datetime | None = None,
    ) -> None:
        """Aktualisiert den Banner-Text + die Sichtbarkeit.

        Args:
            trainings: ALLE Schulungen (nicht vorgefiltert) — der Banner
                       berechnet den Status selbst. Permanent-Schulungen
                       werden in der Zaehlung ignoriert.
            now: Referenz-Zeitpunkt (testbar). Default: jetzt UTC.
        """
        reference = now or datetime.now(UTC)
        expired = 0
        expiring = 0
        for training in trainings:
            status = training.validity_status(now=reference)
            if status is ValidityStatus.EXPIRED:
                expired += 1
            elif status is ValidityStatus.EXPIRING_SOON:
                expiring += 1

        self._title_label.setText(_build_title(expired, expiring))
        self._detail_label.setText(_build_detail(expired, expiring))
        self._show_button.setEnabled(expired + expiring > 0)
        self._export_button.setEnabled(expired + expiring > 0)
        self._set_visible_if_needed(expired=expired, expiring=expiring)

    def _set_visible_if_needed(self, *, expired: int, expiring: int) -> None:
        # Card ist immer sichtbar — aber Icon + Style aendern sich.
        self.setVisible(True)
        severity = _severity(expired=expired, expiring=expiring)
        # ObjectName-Suffix erlaubt theme.qss Stil-Selektoren wie
        # ``#AwarenessRenewalBanner[severity="critical"]``.
        self.setProperty("severity", severity)
        icon_name, icon_color = _severity_icon(severity)
        self._icon_label.setPixmap(
            get_icon(icon_name, color=icon_color).pixmap(
                QSize(_BANNER_ICON_PX, _BANNER_ICON_PX)
            )
        )
        # Style-Re-Polish, damit setProperty in QSS greift.
        self.style().unpolish(self)
        self.style().polish(self)


# ---------------------------------------------------------------------------
# Reine Berechnungs-Funktionen (testbar ohne Qt-Widget-Instanz).
# ---------------------------------------------------------------------------


def _severity(*, expired: int, expiring: int) -> str:
    if expired > 0:
        return "critical"
    if expiring > 0:
        return "warning"
    return "ok"


def _severity_icon(severity: str) -> tuple[str, str]:
    """Material-Symbol-Name + Theme-Farbe pro Severity-Stufe.

    Returns:
        ``(icon_name, hex_color)`` — direkt fuer
:func:`core.icons.get_icon` verwendbar.
    """
    mapping: dict[str, tuple[str, str]] = {
        "critical": (Icons.ERROR, theme.DANGER),
        "warning": (Icons.WARNING, theme.WARNING),
        "ok": (Icons.CHECK_CIRCLE, theme.SUCCESS),
    }
    return mapping.get(severity, mapping["ok"])


def _build_title(expired: int, expiring: int) -> str:
    if expired == 0 and expiring == 0:
        return "Renewal-Status: alle Schulungen aktuell"
    if expired > 0 and expiring == 0:
        return "Renewal-Status: Schulungen abgelaufen"
    if expired == 0 and expiring > 0:
        return "Renewal-Status: Schulungen laufen aus"
    return "Renewal-Status: Schulungen abgelaufen + auslaufend"


def _build_detail(expired: int, expiring: int) -> str:
    if expired == 0 and expiring == 0:
        return "Alle befristeten Schulungen sind innerhalb des Warn-Fensters."
    parts: list[str] = []
    if expired > 0:
        parts.append(
            f"{expired} {_pl(expired, 'Schulung', 'Schulungen')} abgelaufen"
        )
    if expiring > 0:
        parts.append(
            f"{expiring} {_pl(expiring, 'Schulung', 'Schulungen')} "
            f"laufen in den naechsten 60 Tagen aus"
        )
    return " · ".join(parts) + "."


def _pl(n: int, sg: str, pl: str) -> str:
    return sg if n == 1 else pl


__all__ = ["RenewalBanner"]
