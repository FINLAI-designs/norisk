"""
einstellungen.gui.patch_monitor_setup_tab — Settings-Tab fuer Patch-Monitor.

Bug-Fix-Sprint C-5 (Option D ergaenzt). Permanenter Zugang zur Modul-
Installation und Diagnose, ausserhalb des Onboarding-Dialogs:

* Status-Anzeige (``Microsoft.WinGet.Client``: verfuegbar / nicht installiert /
  blockiert) — klassen-basiert, niemals stderr-Excerpts.
* **Modul installieren** — oeffnet:class:`WingetModuleOnboardingDialog`
  (gleiche Logik wie aus dem Patch-Monitor-Onboarding).
* **Status neu pruefen** — invalidiert den Detection-Cache (``force_refresh``).
* **Onboarding-Marker zuruecksetzen** — entfernt das Marker-File, sodass der
  Onboarding-Dialog beim naechsten Patch-Monitor-Open wieder erscheint.
* **Diagnose anzeigen** — Opt-in fuer Admin (zeigt ``reason_detail`` mit
  ggf. stderr-Excerpts; standardmaessig versteckt).

Schicht: ``gui/`` — keine Business-Logik. Subprocess-Aufruf liegt im
:mod:`tools.patch_monitor.onboarding_orchestrator`, Marker-IO im
:mod:`tools.patch_monitor.onboarding_marker`. Status-Polling via
:func:`core.patch_collector.get_winget_module_status`.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.icons import Icons, get_icon
from core.logger import get_logger
from core.patch_collector import ModuleStatus, get_winget_module_status
from core.patch_policy import PolicyDB
from tools.patch_monitor.gui.onboarding_dialog import (
    WingetModuleOnboardingDialog,
)
from tools.patch_monitor.onboarding_marker import wipe_marker

log = get_logger(__name__)

# Labels fuer den globalen Standard-Update-Kanal (Sie-Form, deutsch).
# Reihenfolge = Anzeige-Reihenfolge im QComboBox. Schluessel =
# core.patch_policy.USER_OVERRIDE_CHANNELS. Bewusst lokal (kein Cross-Tool-Import
# der Patch-Console-Labels — import-linter/); 5 Eintraege, Drift unkritisch.
_DEFAULT_CHANNEL_LABELS: dict[str, str] = {
    "notify_only": "Nur melden (Standard)",
    "patch_only": "Nur Patches",
    "stable": "Stabil",
    "latest": "Neueste",
    "pinned": "Eingefroren",
}


# ---------------------------------------------------------------------------
# Status-Mapping (modul-funktion, testbar ohne QApplication)
# ---------------------------------------------------------------------------


_STATUS_LABEL: dict[ModuleStatus, str] = {
    ModuleStatus.AVAILABLE: "Verfügbar",
    ModuleStatus.NEEDS_INSTALL: "Nicht installiert",
    ModuleStatus.BLOCKED: "Blockiert",
}

# FE-1 (Code-Review 2026-05-19): Unicode-Glyphs ('✓'/'○'/'⚠') durch
# Material-Symbol-Keys ersetzt (User-Direktive 2026-05-20). Gerendert
# wird ueber get_icon im UI-Setup, nicht mehr per QLabel.setText.
_STATUS_ICON: dict[ModuleStatus, str] = {
    ModuleStatus.AVAILABLE: Icons.CHECK_CIRCLE,
    ModuleStatus.NEEDS_INSTALL: Icons.PENDING,
    ModuleStatus.BLOCKED: Icons.WARNING,
}

_STATUS_COLOR: dict[ModuleStatus, str] = {
    ModuleStatus.AVAILABLE: "#27AE60",
    ModuleStatus.NEEDS_INSTALL: "#7F8C8D",
    ModuleStatus.BLOCKED: "#E67E22",
}


def status_label(status: ModuleStatus) -> str:
    """User-lesbarer Status-Label."""
    return _STATUS_LABEL.get(status, status.value)


def status_icon(status: ModuleStatus) -> str:
    """Material-Symbol-Key fuer den Status (zum Rendern via ``get_icon``).

    FE-1 (Code-Review 2026-05-19): Returnt jetzt einen Material-Symbol-
    Namen statt eines Unicode-Glyphs. Caller muss ``get_icon.pixmap``
    nutzen, nicht ``QLabel.setText``.
    """
    return _STATUS_ICON.get(status, Icons.HELP)


def status_color(status: ModuleStatus) -> str:
    """Status-Farbe (Hex)."""
    return _STATUS_COLOR.get(status, "#7F8C8D")


# ---------------------------------------------------------------------------
# Tab-Widget
# ---------------------------------------------------------------------------


class PatchMonitorSetupTab(QWidget):
    """Settings-Tab: Status, Install, Refresh, Marker-Reset, Diagnose-Opt-in.

    Nutzt:class:`WingetModuleOnboardingDialog` fuer den Install-Pfad —
    selbe Logik wie im Patch-Monitor-Onboarding (Lokalitaetsprinzip).
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._policy_db: PolicyDB | None = None
        self._build_ui()
        self._refresh()
        self._load_default_channel()

    # -- UI ------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        header = QLabel("Patch-Monitor — Voraussetzungen")
        header.setStyleSheet(
            "font-family: 'Raleway'; font-size: 14px; font-weight: bold;"
        )
        layout.addWidget(header)

        intro = QLabel(
            "Der Patch-Monitor nutzt das PowerShell-Modul "
            "<b>Microsoft.WinGet.Client</b> fuer zuverlaessige Update-"
            "Erkennung. Ohne dieses Modul laeuft der Patch-Monitor in einem "
            "eingeschraenkten Fallback-Modus."
        )
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(intro)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        layout.addWidget(sep)

        # Status-Zeile. FE-1: Material-Pixmap statt Unicode-Glyph.
        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self._status_icon_label = QLabel()
        self._status_icon_label.setPixmap(get_icon(Icons.HELP).pixmap(24, 24))
        self._status_icon_label.setMinimumWidth(24)
        status_row.addWidget(self._status_icon_label)

        self._status_text_label = QLabel("Status wird geprüft …")
        self._status_text_label.setStyleSheet(
            "font-family: 'Raleway'; font-size: 13px;"
        )
        status_row.addWidget(self._status_text_label, stretch=1)
        layout.addLayout(status_row)

        # Reason-Klasse (immer sichtbar, kein stderr-Excerpt)
        self._reason_label = QLabel("")
        self._reason_label.setStyleSheet(
            "font-family: 'Raleway'; font-size: 12px; color: #7F8C8D;"
        )
        layout.addWidget(self._reason_label)

        # Action-Buttons
        button_row = QHBoxLayout()
        button_row.setSpacing(8)
        self._install_btn = QPushButton("Modul installieren …")
        self._install_btn.clicked.connect(self._on_install_clicked)
        button_row.addWidget(self._install_btn)

        self._refresh_btn = QPushButton("Status neu prüfen")
        self._refresh_btn.clicked.connect(self._on_refresh_clicked)
        button_row.addWidget(self._refresh_btn)

        self._wipe_btn = QPushButton("Onboarding zurücksetzen")
        self._wipe_btn.clicked.connect(self._on_wipe_clicked)
        button_row.addWidget(self._wipe_btn)
        button_row.addStretch()
        layout.addLayout(button_row)

        # Diagnose-Section (Opt-in für Admin)
        self._diagnose_btn = QPushButton("Diagnose anzeigen")
        self._diagnose_btn.setCheckable(True)
        self._diagnose_btn.toggled.connect(self._on_diagnose_toggled)
        layout.addWidget(self._diagnose_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        self._diagnose_label = QLabel("")
        self._diagnose_label.setWordWrap(True)
        self._diagnose_label.setVisible(False)
        self._diagnose_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._diagnose_label.setStyleSheet(
            "font-family: monospace; padding: 8px;"
            "background: #FAFAFA; border: 1px solid #DDD; border-radius: 3px;"
        )
        layout.addWidget(self._diagnose_label)

        # globaler Standard-Update-Kanal fuer unbekannte Software.
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setFixedHeight(1)
        layout.addWidget(sep2)

        ch_header = QLabel("Standard-Update-Kanal")
        ch_header.setStyleSheet(
            "font-family: 'Raleway'; font-size: 14px; font-weight: bold;"
        )
        layout.addWidget(ch_header)

        ch_intro = QLabel(
            "Update-Kanal für Programme OHNE eigene Regel (unbekannte Software). "
            "<b>Nur melden</b> = nicht automatisch patchen (Werks-Standard). "
            "Stellen Sie ihn z. B. auf <b>Stabil</b>, damit unbekannte Programme "
            "über den Patch-Monitor aktualisierbar werden. Pro App lässt sich der "
            "Kanal in der Patch-Konsole überschreiben."
        )
        ch_intro.setWordWrap(True)
        ch_intro.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(ch_intro)

        ch_row = QHBoxLayout()
        ch_row.setSpacing(8)
        ch_label = QLabel("Standard-Kanal:")
        ch_label.setStyleSheet("font-family: 'Raleway'; font-size: 13px;")
        ch_row.addWidget(ch_label)
        self._channel_combo = QComboBox()
        for ch, label in _DEFAULT_CHANNEL_LABELS.items():
            self._channel_combo.addItem(label, ch)
        self._channel_combo.activated.connect(self._on_default_channel_changed)
        ch_row.addWidget(self._channel_combo)
        ch_row.addStretch()
        layout.addLayout(ch_row)

        layout.addStretch()

    # -- Globaler Default-Kanal -------------------------------

    def _get_policy_db(self) -> PolicyDB | None:
        """Lazily konstruierte, gecachte PolicyDB — fail-soft (None bei Fehler)."""
        if self._policy_db is None:
            try:
                self._policy_db = PolicyDB()
            except Exception as exc:  # noqa: BLE001 — Settings-Tab darf nie crashen
                log.exception("PolicyDB-Init im Settings-Tab fehlgeschlagen: %s", exc)
                return None
        return self._policy_db

    def _load_default_channel(self) -> None:
        """Setzt den Combo auf den aktuell gespeicherten Default-Kanal."""
        db = self._get_policy_db()
        if db is None:
            return
        try:
            current = db.get_default_channel()
        except Exception as exc:  # noqa: BLE001
            log.exception("get_default_channel fehlgeschlagen: %s", exc)
            return
        idx = self._channel_combo.findData(current)
        if idx >= 0:
            self._channel_combo.setCurrentIndex(idx)

    @Slot(int)
    def _on_default_channel_changed(self, _idx: int) -> None:
        """Persistiert den gewaehlten globalen Default-Kanal."""
        db = self._get_policy_db()
        if db is None:
            return
        channel = self._channel_combo.currentData()
        try:
            db.set_default_channel(channel)
        except Exception as exc:  # noqa: BLE001 — Persistenz darf UI nicht crashen
            log.exception("set_default_channel(%s) fehlgeschlagen: %s", channel, exc)

    # -- Status-Refresh -----------------------------------------------

    def _refresh(self, *, force: bool = False) -> None:
        """Liest aktuellen Modul-Status und aktualisiert die Anzeige.

        Args:
            force: Wenn ``True``, Detection-Cache invalidieren
                (``force_refresh=True``). Default ``False`` — nutzt
                gecachten Status.
        """
        try:
            detail = get_winget_module_status(force_refresh=force)
        except Exception as exc:  # noqa: BLE001
            log.exception("setup-tab status refresh crash: %s", exc)
            self._status_text_label.setText("Status nicht abrufbar (siehe Logs)")
            return
        # FE-1: Material-Pixmap statt setText-Glyph.
        self._status_icon_label.setPixmap(
            get_icon(status_icon(detail.status)).pixmap(24, 24)
        )
        self._status_text_label.setText(
            f"Microsoft.WinGet.Client: {status_label(detail.status)}"
        )
        self._reason_label.setText(f"Klasse: {detail.reason}")
        self._install_btn.setEnabled(detail.can_attempt_install)
        # Diagnose-Inhalt aktualisieren (auch wenn Section gerade versteckt).
        if detail.reason_detail:
            self._diagnose_label.setText(detail.reason_detail)
            self._diagnose_btn.setEnabled(True)
        else:
            self._diagnose_label.setText(
                f"Kein zusätzlicher Diagnose-Text. Klasse: {detail.reason}"
            )
            self._diagnose_btn.setEnabled(True)

    # -- Slots ---------------------------------------------------------

    @Slot()
    def _on_install_clicked(self) -> None:
        dialog = WingetModuleOnboardingDialog(parent=self)
        dialog.exec()
        self._refresh(force=True)

    @Slot()
    def _on_refresh_clicked(self) -> None:
        self._refresh(force=True)

    @Slot()
    def _on_wipe_clicked(self) -> None:
        try:
            wipe_marker()
        except Exception as exc:  # noqa: BLE001
            log.exception("wipe_marker crash: %s", exc)

    @Slot(bool)
    def _on_diagnose_toggled(self, checked: bool) -> None:
        self._diagnose_label.setVisible(checked)
        self._diagnose_btn.setText(
            "Diagnose ausblenden" if checked else "Diagnose anzeigen"
        )
