"""einstellungen.gui.network_collector_setup_tab — Settings-Tab fuer den
Netzwerk-Hintergrund-Collector Phase C).

Aktiviert/deaktiviert die Windows-Geplante-Aufgabe, die den ETW-Netzwerk-
Collector bei jeder Anmeldung elevated startet — ohne Kommandozeile:

* **Status-Anzeige** — Aufgabe registriert (aktiv) / nicht aktiv.
* **Aktivieren** — loest via:func:`core.elevation.relaunch_elevated` genau eine
  UAC-Abfrage aus; der elevated Prozess registriert die Aufgabe und beendet sich.
  Danach laeuft der Collector autonom bei jeder Anmeldung (kein weiterer Prompt).
* **Deaktivieren** — entfernt die Aufgabe (faellt bei fehlenden Rechten auf einen
  elevated Lauf zurueck).
* **Status aktualisieren** — liest den Aufgaben-Status neu.

Schicht: ``gui/`` — keine Business-Logik. Task-Registrierung/-Abfrage liegt in
:mod:`tools.network_monitor.data.collector_task_manager`, die UAC-Erhoehung in
:mod:`core.elevation`.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Slot
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog
from core.elevation import relaunch_elevated
from core.finlai_paths import finlai_home_override
from core.icons import Icons, get_icon
from core.logger import get_logger
from tools.network_monitor.application.collector_control import (
    collector_needs_migration,
    deactivate_collector,
    get_collector_action_path,
    get_collector_status,
    take_install_reject,
)
from tools.network_monitor.domain.collector_status import CollectorStatus

log = get_logger(__name__)

#: CLI-Flags des Entry-Points (apps/norisk_app.py) fuer den elevated Lauf.
_INSTALL_FLAG = "--install-collector-task"
_UNINSTALL_FLAG = "--uninstall-collector-task"

#: Verzoegerung (ms) bis zum Status-Refresh nach dem elevated Neustart — der
#: separate Prozess braucht einen Moment, um die Aufgabe zu registrieren.
_REFRESH_DELAY_MS = 2500

#: Groesse der Status-Icons (px).
_STATUS_ICON_PX = 24


class NetworkCollectorSetupTab(QWidget):
    """Settings-Tab: Hintergrund-Collector aktivieren/deaktivieren."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()
        self._refresh()

    # -- UI ------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        header = QLabel("Netzwerk-Erfassung — Hintergrund-Collector")
        header.setStyleSheet(
            "font-family: 'Raleway'; font-size: 14px; font-weight: bold;"
        )
        layout.addWidget(header)

        intro = QLabel(
            "Aktiviere die dauerhafte Netzwerk-Erfassung im Hintergrund. "
            "Dabei wird eine geplante Windows-Aufgabe eingerichtet, die den "
            "Collector bei jeder Anmeldung automatisch startet. Die Einrichtung "
            "erfordert einmalig eine Bestätigung der Windows-"
            "Benutzerkontensteuerung."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("font-family: 'Raleway'; font-size: 13px;")
        layout.addWidget(intro)

        dsgvo = QLabel(
            "Datenschutz: Erfasst werden ausschließlich lokale Verbindungs-"
            "Metadaten (Prozess, Ziel-Host, Datenmenge) für maximal 48 Stunden. "
            "Es werden keine Inhalte gespeichert und keine Daten an Dritte "
            "übertragen."
        )
        dsgvo.setWordWrap(True)
        dsgvo.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {theme.get().TEXT_DIM};"
        )
        layout.addWidget(dsgvo)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        layout.addWidget(sep)

        # Status-Zeile (Material-Pixmap statt Unicode-Glyph).
        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self._status_icon = QLabel()
        self._status_icon.setPixmap(
            get_icon(Icons.HELP).pixmap(_STATUS_ICON_PX, _STATUS_ICON_PX)
        )
        self._status_icon.setMinimumWidth(_STATUS_ICON_PX)
        status_row.addWidget(self._status_icon)

        self._status_text = QLabel("Status wird geprüft …")
        self._status_text.setStyleSheet("font-family: 'Raleway'; font-size: 13px;")
        status_row.addWidget(self._status_text, stretch=1)
        layout.addLayout(status_row)

        # Installationspfad (Action.Path) — Anzeige, wohin die Aufgabe startet
        # (relevant für den „nach %ProgramFiles% installieren"-Hinweis, F-C-5).
        # PlainText: ein Pfad ist kein RichText (R22).
        self._path_label = QLabel()
        self._path_label.setWordWrap(True)
        self._path_label.setTextFormat(Qt.TextFormat.PlainText)
        self._path_label.setStyleSheet(
            f"font-family: 'JetBrains Mono'; font-size: 12px; "
            f"color: {theme.get().TEXT_DIM};"
        )
        layout.addWidget(self._path_label)
        self._update_path_label()

        # Action-Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self._activate_btn = QPushButton("Hintergrund-Erfassung aktivieren")
        self._activate_btn.clicked.connect(self._on_activate_clicked)
        btn_row.addWidget(self._activate_btn)

        self._deactivate_btn = QPushButton("Deaktivieren")
        self._deactivate_btn.clicked.connect(self._on_deactivate_clicked)
        btn_row.addWidget(self._deactivate_btn)

        self._refresh_btn = QPushButton("Status aktualisieren")
        self._refresh_btn.clicked.connect(self._on_refresh_clicked)
        btn_row.addWidget(self._refresh_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        layout.addStretch()

    # -- Status-Refresh -----------------------------------------------

    def _set_status(self, icon_name: str, color: str | None, text: str) -> None:
        self._status_icon.setPixmap(
            get_icon(icon_name, color=color).pixmap(_STATUS_ICON_PX, _STATUS_ICON_PX)
        )
        self._status_text.setText(text)

    def _update_path_label(self) -> None:
        """Zeigt den Exe-/Skript-Pfad an, den die Aufgabe startet (Action.Path)."""
        try:
            path = get_collector_action_path()
        except Exception:  # noqa: BLE001 — Anzeige-Helfer darf die GUI nicht crashen
            log.exception("Collector-Action-Pfad nicht ermittelbar.")
            path = "(unbekannt)"
        # „Zielpfad bei (Neu-)Installation" — das ist der Pfad, den ein Install JETZT
        # verwenden würde (default_collector_action), nicht zwingend das aktuell
        # eingebrannte Action-Ziel einer evtl. veralteten Aufgabe (Migrations-Drift).
        self._path_label.setText(f"Zielpfad bei (Neu-)Installation: {path}")

    def _refresh(self) -> None:
        """Liest den Aufgaben-Status und aktualisiert Anzeige + Buttons."""
        try:
            status = get_collector_status()
        except Exception:  # noqa: BLE001 — COM-Status darf die GUI nicht crashen
            log.exception("Collector-Status nicht abrufbar.")
            self._set_status(
                Icons.WARNING,
                theme.get().WARNING,
                "Status nicht abrufbar (siehe Logs).",
            )
            self._activate_btn.setText("Hintergrund-Erfassung aktivieren")
            self._activate_btn.setEnabled(True)
            self._deactivate_btn.setEnabled(False)
            return

        if status is CollectorStatus.ACTIVE:
            if self._needs_migration():
                # Aufgabe läuft, zeigt aber auf einen alten Build-Pfad (nach Update).
                self._set_status(
                    Icons.WARNING,
                    theme.get().WARNING,
                    "Hintergrund-Erfassung ist aktiv, zeigt aber auf einen "
                    "veralteten Build-Pfad. Aktualisiere sie.",
                )
                self._activate_btn.setText("Erfassung aktualisieren")
                self._activate_btn.setEnabled(True)
            else:
                self._set_status(
                    Icons.CHECK_CIRCLE,
                    theme.get().SUCCESS,
                    "Hintergrund-Erfassung ist aktiv.",
                )
                self._activate_btn.setText("Hintergrund-Erfassung aktivieren")
                self._activate_btn.setEnabled(False)
            self._deactivate_btn.setEnabled(True)
        elif status is CollectorStatus.BROKEN:
            self._set_status(
                Icons.WARNING,
                theme.get().WARNING,
                "Hintergrund-Erfassung ist eingerichtet, läuft aber nicht. "
                "Aktiviere sie erneut, um sie zu reparieren.",
            )
            self._activate_btn.setText("Erfassung reparieren")
            self._activate_btn.setEnabled(True)
            self._deactivate_btn.setEnabled(True)
        else:  # NOT_INSTALLED
            self._set_status(
                Icons.PENDING,
                theme.get().TEXT_DIM,
                "Hintergrund-Erfassung ist nicht aktiv.",
            )
            self._activate_btn.setText("Hintergrund-Erfassung aktivieren")
            self._activate_btn.setEnabled(True)
            self._deactivate_btn.setEnabled(False)

    def _needs_migration(self) -> bool:
        """True, wenn die Aufgabe auf ein veraltetes Exe-Ziel zeigt (fail-soft)."""
        try:
            return collector_needs_migration()
        except Exception:  # noqa: BLE001 — Status-Helfer darf die GUI nicht crashen
            log.exception("Collector-Migrations-Status nicht abrufbar.")
            return False

    def _refresh_after_install(self) -> None:
        """Status-Refresh nach dem elevated Install-Lauf.

        Zeigt zusätzlich einen Security-Reject (Gate F-C-3) an, den der
        elevated Prozess per Marker-Datei zurückmeldet — der Exit-Code erreicht
        die GUI über ``relaunch_elevated`` nicht.
        """
        self._refresh()
        try:
            reason = take_install_reject()
        except Exception:  # noqa: BLE001 — Marker-Lesefehler darf die GUI nicht crashen
            log.exception("Install-Ergebnis-Marker nicht lesbar.")
            return
        if not reason:
            return
        self._set_status(
            Icons.WARNING,
            theme.get().WARNING,
            "Aktivierung aus Sicherheitsgründen abgelehnt.",
        )
        FinlaiInfoDialog(
            title="Installation aus Sicherheitsgründen abgelehnt",
            message=reason,
            parent=self,
        ).exec()

    # -- Slots ---------------------------------------------------------

    @Slot()
    def _on_activate_clicked(self) -> None:
        dlg = FinlaiConfirmDialog(
            title="Hintergrund-Erfassung aktivieren",
            message=(
                "Windows fragt gleich nach Administrator-Rechten, um die geplante "
                "Aufgabe einzurichten. Danach startet der Collector bei jeder "
                "Anmeldung automatisch."
            ),
            confirm_text="Aktivieren",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        # Aktives FINLAI_HOME-Profil durch die UAC-Elevation an den elevated
        # Install-Prozess weiterreichen (runas vererbt das Env nicht zuverlaessig).
        # Ohne Override (Produktion) bleibt die Action FINLAI_HOME-frei -> ~/.finlai.
        override = finlai_home_override()
        extra = ("--finlai-home", str(override)) if override is not None else ()
        if relaunch_elevated(_INSTALL_FLAG, *extra):
            self._status_text.setText(
                "Aktivierung läuft — Status aktualisiert sich gleich …"
            )
            QTimer.singleShot(_REFRESH_DELAY_MS, self._refresh_after_install)
        else:
            FinlaiInfoDialog(
                title="Aktivierung abgebrochen",
                message="Die Aktivierung wurde abgebrochen oder nicht bestätigt.",
                parent=self,
            ).exec()

    @Slot()
    def _on_deactivate_clicked(self) -> None:
        dlg = FinlaiConfirmDialog(
            title="Hintergrund-Erfassung deaktivieren",
            message=(
                "Die geplante Aufgabe wird entfernt. Der Collector startet dann "
                "nicht mehr automatisch."
            ),
            confirm_text="Deaktivieren",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            deactivate_collector()
        except PermissionError:
            # Erwartet: die HIGHEST-Aufgabe ist nur elevated loeschbar.
            # Kein Fehler, sondern das Signal "Admin-Rechte noetig" — ruhig auf
            # einen elevierten Lauf umschalten, ohne ERROR-Traceback zu loggen.
            log.info("Deaktivierung erfordert Administrator-Rechte — elevierter Neustart.")
            if relaunch_elevated(_UNINSTALL_FLAG):
                self._status_text.setText(
                    "Deaktivierung läuft — Status aktualisiert sich gleich …"
                )
                QTimer.singleShot(_REFRESH_DELAY_MS, self._refresh)
            else:
                FinlaiInfoDialog(
                    title="Deaktivierung abgebrochen",
                    message="Die Deaktivierung wurde abgebrochen oder nicht bestätigt.",
                    parent=self,
                ).exec()
            return
        except Exception:  # noqa: BLE001 — unerwarteter Fehler → elevated Fallback + Log
            log.exception("Direktes Entfernen fehlgeschlagen — versuche elevated.")
            if relaunch_elevated(_UNINSTALL_FLAG):
                self._status_text.setText(
                    "Deaktivierung läuft — Status aktualisiert sich gleich …"
                )
                QTimer.singleShot(_REFRESH_DELAY_MS, self._refresh)
            return
        self._refresh()

    @Slot()
    def _on_refresh_clicked(self) -> None:
        self._refresh()
