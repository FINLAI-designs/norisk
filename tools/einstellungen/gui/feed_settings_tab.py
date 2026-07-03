"""
feed_settings_tab — Master-Schalter „Externe Abrufe" + Consumer-Feed-Auswahl.

Oben ein Master-Schalter für ALLE automatischen externen Sicherheits-Abrufe
(Offline-Modus), darunter die einzelnen Consumer-Feeds (BSI / MSRC /
Chrome / Mozilla / Watchlist). Persistiert via:mod:`core.feed_settings`.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QGroupBox,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiConfirmDialog
from core.feed_settings import FeedSettings, load_feed_settings, save_feed_settings
from core.logger import get_logger

_log = get_logger(__name__)


_FEED_BESCHREIBUNGEN: list[tuple[str, str, str]] = [
    (
        "bsi",
        "BSI / CERT-Bund WID",
        "Deutschsprachige Schwachstellen-Warnungen zu verbreiteten Produkten.",
    ),
    (
        "msrc",
        "Microsoft Security Update Guide",
        "Patch-Tuesday-Advisories für Windows, Office, Edge, .NET, Teams.",
    ),
    (
        "chrome",
        "Chrome Releases",
        "Stable/Beta-Channel-Updates für Chrome Desktop, Android, ChromeOS.",
    ),
    (
        "mozilla",
        "Mozilla Security Blog",
        "Firefox/Thunderbird-Advisories und Security-Policy-Posts.",
    ),
    # Watchlist Internet (OIAT) ergaenzt — seit
    # als RSS-Quelle im Cyber-Dashboard, deckt Phishing/Smishing/
    # Vishing/Online-Betrug ab (Schwerpunkt Oesterreich).
    (
        "watchlist_at",
        "Watchlist Internet (Österreich)",
        "Tagesaktuelle Phishing-, Betrugs- und Online-Scam-Warnungen vom OIAT.",
    ),
]


class FeedSettingsTab(QWidget):
    """Tab zur Konfiguration der Consumer-Feeds für das Cyber-Briefing."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings: FeedSettings = load_feed_settings()
        self._checkboxes: dict[str, QCheckBox] = {}
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QLabel#intro {{ color: {c.TEXT_DIM}; font-size: 12px; }}"
            f"QGroupBox {{ color: {c.TEXT_MAIN}; font-weight: bold;"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" margin-top: 8px; padding-top: 12px; }}"
            f"QGroupBox::title {{ left: 8px; padding: 0 4px; }}"
            f"QLabel.feed_hint {{ color: {c.TEXT_DIM}; font-size: 11px;"
            f" margin-left: 22px; }}"
        )

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        intro = QLabel(
            "Steuere die externen Sicherheits-Abrufe von NoRisk. Der obere "
            "Schalter deaktiviert ALLE automatischen Abrufe (Offline-Modus); "
            "darunter wählst du, welche Consumer-Feeds das KI-Briefing auswertet."
        )
        intro.setObjectName("intro")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        # Master-Schalter: alle automatischen externen Abrufe.
        master_grp = QGroupBox("Externe Sicherheits-Abrufe")
        master_layout = QVBoxLayout(master_grp)
        master_layout.setSpacing(6)
        self._chk_master = QCheckBox("Externe Abrufe erlauben (Online-Modus)")
        self._chk_master.setChecked(self._settings.external_fetches_enabled)
        self._chk_master.stateChanged.connect(self._on_master_toggle)
        master_layout.addWidget(self._chk_master)
        master_hint = QLabel(
            "Aktiv: NoRisk ruft automatisch aktuelle Bedrohungs-Feeds "
            "(Cyber-Lagebild), CVE-/Schwachstellen-Quellen und den Passwort-Leak-"
            "Abgleich ab — übertragen wird dabei nur Ihre IP-Adresse bzw. ein "
            "Hash, keine Inhalte. Aus (Offline-Modus): keine automatischen "
            "Abrufe — die Schutzwirkung von NoRisk sinkt erheblich."
        )
        master_hint.setProperty("class", "feed_hint")
        master_hint.setObjectName("feed_hint")
        master_hint.setWordWrap(True)
        master_hint.setStyleSheet("margin-left: 22px;")
        master_layout.addWidget(master_hint)
        layout.addWidget(master_grp)

        self._grp_consumer = QGroupBox("Consumer-Feeds (KI-Briefing)")
        grp_layout = QVBoxLayout(self._grp_consumer)
        grp_layout.setSpacing(10)

        for key, label, hint in _FEED_BESCHREIBUNGEN:
            cb = QCheckBox(label)
            cb.setChecked(self._settings.consumer_feeds.get(key, True))
            cb.stateChanged.connect(
                lambda _state, k=key: self._on_toggle(k)
            )
            grp_layout.addWidget(cb)
            hint_lbl = QLabel(hint)
            hint_lbl.setProperty("class", "feed_hint")
            hint_lbl.setObjectName("feed_hint")
            hint_lbl.setWordWrap(True)
            hint_lbl.setStyleSheet("margin-left: 22px;")
            grp_layout.addWidget(hint_lbl)
            self._checkboxes[key] = cb

        layout.addWidget(self._grp_consumer)
        layout.addStretch()

        # Consumer-Feeds sind im Offline-Modus gegenstandslos -> ausgrauen.
        self._grp_consumer.setEnabled(self._settings.external_fetches_enabled)

    def _on_master_toggle(self, _state: int) -> None:
        """Master-Schalter: beim Ausschalten warnen, dann persistieren."""
        enabled = self._chk_master.isChecked()
        if not enabled:
            dlg = FinlaiConfirmDialog(
                title="Externe Abrufe deaktivieren?",
                message=(
                    "Ohne externe Sicherheits-Abrufe kann NoRisk keine aktuellen "
                    "Bedrohungen, CVEs/Schwachstellen und Datenleck-Abgleiche mehr "
                    "abrufen. Die Schutzwirkung von NoRisk wird dadurch erheblich "
                    "reduziert.\n\nWirklich in den Offline-Modus wechseln?"
                ),
                confirm_text="In Offline-Modus wechseln",
                parent=self,
            )
            if dlg.exec() != QDialog.DialogCode.Accepted:
                # Abbruch -> Haken ohne erneutes Signal wiederherstellen.
                self._chk_master.blockSignals(True)
                self._chk_master.setChecked(True)
                self._chk_master.blockSignals(False)
                return
        self._settings.external_fetches_enabled = enabled
        self._grp_consumer.setEnabled(enabled)
        self._save()

    def _on_toggle(self, key: str) -> None:
        """Persistiert den Toggle-Zustand einer Feed-Checkbox."""
        cb = self._checkboxes.get(key)
        if cb is None:
            return
        self._settings.consumer_feeds[key] = cb.isChecked()
        self._save()

    def _save(self) -> None:
        """Schreibt die Feed-Settings; Schreibfehler werden nur geloggt."""
        try:
            save_feed_settings(self._settings)
        except OSError as exc:
            _log.warning("feed_settings.json konnte nicht gespeichert werden: %s", exc)
