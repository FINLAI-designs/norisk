"""core/updater_dialog.py — Update-Dialog und Hintergrund-Worker für FINLAI.

Ablauf:
  1. ``start_background_check(parent, config)`` wird nach App-Start aufgerufen.
  2. Ein QTimer verzögert den Check um ``UPDATE_CHECK_DELAY_MS`` (3 s) damit
     das MainWindow vollständig geladen ist.
  3. ``_UpdateCheckWorker`` (QThread) ruft ``check_for_update`` auf.
  4. Ist ein Update verfügbar → ``UpdateDialog`` (modaler QDialog) öffnet sich.
  5. "Jetzt aktualisieren" → ``_DownloadWorker`` (QThread) lädt herunter.
  6. Nach erfolgreichem Download → ``apply_update`` mit ``QApplication.quit``.
  7. "Später" → Dialog schließen, App läuft normal weiter.

Schichtzugehörigkeit: core/ (PySide6-Dialog, darf PySide6 importieren).

Author: Patrick Riederich
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.config import UPDATE_BASE_URL, UPDATE_CHECK_DELAY_MS
from core.logger import get_logger
from core.updater import UpdateInfo, apply_update, check_for_update, download_update
from core.widgets.finlai_progress import FinlaiProgressBar

if TYPE_CHECKING:
    from pathlib import Path

    from apps.app_config import AppConfig

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Hintergrund-Thread: Update-Prüfung
# ---------------------------------------------------------------------------


class _UpdateCheckWorker(QThread):
    """Prüft im Hintergrund ob ein Update verfügbar ist.

    Signale:
        update_found: Wird emittiert wenn eine neuere Version existiert.
        check_done: Wird immer emittiert (auch wenn kein Update vorhanden).
    """

    update_found: Signal = Signal(object)  # UpdateInfo
    check_done: Signal = Signal()

    def __init__(
        self,
        current_version: str,
        app_id: str,
        override_url: str = "",
    ) -> None:
        """Initialisiert den Worker.

        Args:
            current_version: Lokal installierte App-Version.
            app_id: App-Bezeichner für den Update-Kanal.
            override_url: Optionale Override-URL (White-Label).
        """
        super().__init__()
        self._current_version = current_version
        self._app_id = app_id
        self._override_url = override_url

    def run(self) -> None:
        """Führt die Update-Prüfung durch (läuft im Worker-Thread)."""
        info = check_for_update(
            self._current_version,
            self._app_id,
            override_url=self._override_url,
        )
        if info is not None:
            self.update_found.emit(info)
        self.check_done.emit()


# ---------------------------------------------------------------------------
# Hintergrund-Thread: Download
# ---------------------------------------------------------------------------


class _DownloadWorker(QThread):
    """Lädt das Update-Paket im Hintergrund herunter.

    Signale:
        progress: Fortschritt in Prozent (0–100).
        download_success: Wird mit dem Pfad zur EXE emittiert.
        download_failed: Wird emittiert wenn der Download scheitert.
    """

    progress: Signal = Signal(int)
    download_success: Signal = Signal(object)  # Path
    download_failed: Signal = Signal()

    def __init__(self, update_info: UpdateInfo) -> None:
        """Initialisiert den Worker.

        Args:
            update_info: Metadaten des herunterzuladenden Updates.
        """
        super().__init__()
        self._update_info = update_info

    def run(self) -> None:
        """Führt den Download durch (läuft im Worker-Thread)."""
        result: Path | None = download_update(
            self._update_info,
            progress_callback=lambda pct: self.progress.emit(pct),
        )
        if result is not None:
            self.download_success.emit(result)
        else:
            self.download_failed.emit()


# ---------------------------------------------------------------------------
# Update-Dialog
# ---------------------------------------------------------------------------


class UpdateDialog(QDialog):
    """Modaler Dialog der über ein verfügbares Update informiert.

    Zeigt Versionsnummer und Release-Notes an und bietet zwei Aktionen:
    - "Jetzt aktualisieren" — startet Download + SHA-256-Check + apply
    - "Später" — schließt den Dialog, App läuft weiter

    Args:
        update_info: Metadaten des verfügbaren Updates.
        current_version: Lokal installierte Version (für Anzeige).
        parent: Optionales Eltern-Widget (typisch: MainWindow).
    """

    def __init__(
        self,
        update_info: UpdateInfo,
        current_version: str,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den UpdateDialog."""
        super().__init__(parent)
        self._update_info = update_info
        self._current_version = current_version
        self._worker: _DownloadWorker | None = None

        self.setWindowTitle("Update verfügbar")
        self.setMinimumWidth(480)
        self.setMinimumHeight(320)

        # Kein [X]-Schließen während Download läuft
        from PySide6.QtCore import Qt  # noqa: PLC0415

        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.WindowTitleHint)

        self._build_ui()
        theme.register_listener(self._apply_theme)
        self._apply_theme()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt die Dialog-Oberfläche."""
        c = theme.get()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Titel
        title = QLabel("Update verfügbar")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 16px; font-weight: bold;"
            f" color: {c.ACCENT};"
        )
        layout.addWidget(title)

        sep_top = QFrame()
        sep_top.setFrameShape(QFrame.Shape.HLine)
        sep_top.setFixedHeight(1)
        sep_top.setStyleSheet(f"background-color: {c.ACCENT};")
        layout.addWidget(sep_top)

        # Versionsinformation
        version_row = QWidget()
        version_layout = QHBoxLayout(version_row)
        version_layout.setContentsMargins(0, 0, 0, 0)
        version_layout.setSpacing(8)

        lbl_old = QLabel(f"Aktuell: {self._current_version}")
        lbl_old.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {c.TEXT_DIM};"
        )
        version_layout.addWidget(lbl_old)

        lbl_arrow = QLabel("→")
        lbl_arrow.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
        version_layout.addWidget(lbl_arrow)

        lbl_new = QLabel(f"Neu: {self._update_info.version}")
        lbl_new.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {c.ACCENT};"
        )
        version_layout.addWidget(lbl_new)
        version_layout.addStretch()
        layout.addWidget(version_row)

        # Release Notes
        if self._update_info.release_notes:
            notes_label = QLabel("Änderungen:")
            notes_label.setStyleSheet(
                f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_DIM};"
            )
            layout.addWidget(notes_label)

            notes = QTextEdit()
            notes.setReadOnly(True)
            notes.setFixedHeight(100)
            notes.setPlainText(self._update_info.release_notes)
            notes.setStyleSheet(
                f"background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
                f" border: 1px solid {c.BORDER}; border-radius: 4px;"
                f" font-family: 'Inter'; font-size: 13px;"
            )
            layout.addWidget(notes)

        # Status-Label (Fehler / Infos während Download)
        self._lbl_status = QLabel("")
        self._lbl_status.setWordWrap(True)
        self._lbl_status.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_DIM};"
        )
        self._lbl_status.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        layout.addWidget(self._lbl_status)

        # Progress-Bar: kanonischer FinlaiProgressBar).
        # P2: 16 px statt Default 8 px — visuelles Gewicht
        # fuer "groesserer Vorgang" (Update-Download), analog Wizard-Pattern.
        self._progress = FinlaiProgressBar(total=100)
        self._progress.setFixedHeight(16)
        self._progress.hide()
        layout.addWidget(self._progress)

        layout.addStretch()

        sep_bot = QFrame()
        sep_bot.setFrameShape(QFrame.Shape.HLine)
        sep_bot.setFixedHeight(1)
        sep_bot.setStyleSheet(f"background-color: {c.BORDER};")
        layout.addWidget(sep_bot)

        # Aktions-Buttons
        btn_row = QWidget()
        btn_layout = QHBoxLayout(btn_row)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(10)
        btn_layout.addStretch()

        self._btn_later = QPushButton("Später")
        self._btn_later.setFixedHeight(36)
        self._btn_later.clicked.connect(self.reject)
        btn_layout.addWidget(self._btn_later)

        self._btn_update = QPushButton("Jetzt aktualisieren")
        self._btn_update.setFixedHeight(36)
        self._btn_update.setDefault(True)
        self._btn_update.clicked.connect(self._start_download)
        btn_layout.addWidget(self._btn_update)

        layout.addWidget(btn_row)
        self._style_buttons()

    def _style_buttons(self) -> None:
        """Wendet Theme-Farben auf die Aktions-Buttons an."""
        c = theme.get()
        self._btn_update.setStyleSheet(
            f"QPushButton {{ background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f" border: none; border-radius: 4px; font-weight: bold;"
            f" font-family: 'Raleway'; }}"
            f"QPushButton:hover {{ background-color: {c.BG_SIDEBAR_HOVER}; }}"
            f"QPushButton:disabled {{ background-color: {c.BORDER}; color: {c.TEXT_DIM}; }}"
        )
        self._btn_later.setStyleSheet(
            f"QPushButton {{ background-color: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" font-family: 'Raleway'; }}"
            f"QPushButton:hover {{ background-color: {c.BG_SIDEBAR_HOVER}; }}"
        )

    def _apply_theme(self) -> None:
        """Aktualisiert Hintergrundfarbe bei Theme-Wechsel."""
        c = theme.get()
        self.setStyleSheet(f"background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN};")
        self._style_buttons()

    # ------------------------------------------------------------------
    # Download-Flow
    # ------------------------------------------------------------------

    def _start_download(self) -> None:
        """Startet den Download-Worker und sperrt die UI."""
        self._btn_update.setEnabled(False)
        self._btn_later.setEnabled(False)
        self._progress.setValue(0)
        self._progress.show()
        self._set_status("Lade Update herunter …", dim=True)

        self._worker = _DownloadWorker(self._update_info)
        self._worker.progress.connect(self._on_progress)
        self._worker.download_success.connect(self._on_download_success)
        self._worker.download_failed.connect(self._on_download_failed)
        self._worker.start()

    def _on_progress(self, pct: int) -> None:
        """Aktualisiert die Progress-Bar.

        Args:
            pct: Fortschritt in Prozent (0–100).
        """
        self._progress.setValue(pct)
        self._set_status(f"Herunterladen … {pct} %", dim=True)

    def _on_download_success(self, exe_path: object) -> None:
        """Startet die neue EXE und beendet die App.

        Args:
            exe_path: Pfad zur verifizierten Installer-EXE (als ``Path``).
        """
        from pathlib import Path  # noqa: PLC0415

        from PySide6.QtWidgets import QApplication  # noqa: PLC0415

        _log.info("Download erfolgreich — starte Update-EXE.")
        self._set_status("Update wird angewendet …", dim=True)
        self._progress.setValue(100)

        apply_update(
            Path(str(exe_path)),
            old_version=self._current_version,
            quit_callback=QApplication.quit,
            expected_sha256=self._update_info.sha256,
        )

    def _on_download_failed(self) -> None:
        """Zeigt Fehlermeldung und reaktiviert die Buttons."""
        _log.warning("Download fehlgeschlagen — User kann es erneut versuchen.")
        self._progress.hide()
        self._set_status(
            "Download fehlgeschlagen. Bitte Internetverbindung prüfen und erneut versuchen.",
            error=True,
        )
        self._btn_update.setEnabled(True)
        self._btn_later.setEnabled(True)

    def _set_status(
        self,
        text: str,
        *,
        error: bool = False,
        dim: bool = False,
    ) -> None:
        """Zeigt eine Status-Meldung unter der Progress-Bar.

        Args:
            text: Anzuzeigende Meldung.
            error: Wenn True → rote Fehlerfarbe.
            dim: Wenn True → gedimmte Textfarbe.
        """
        c = theme.get()
        if error:
            color = "#f44336"
        elif dim:
            color = c.TEXT_DIM
        else:
            color = c.TEXT_MAIN
        self._lbl_status.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {color};"
        )
        self._lbl_status.setText(text)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        """Verhindert Schließen während des Downloads."""
        if self._worker is not None and self._worker.isRunning():
            event.ignore()
            return
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# Öffentliche API
# ---------------------------------------------------------------------------


def start_background_check(parent: QWidget, config: AppConfig) -> None:
    """Startet die Update-Prüfung verzögert im Hintergrund.

    Wird von ``apps/__init__._AppController._show_main`` aufgerufen,
    nachdem das MainWindow sichtbar ist. Der QTimer-Delay gibt dem
    UI-Thread Zeit, die Oberfläche vollständig aufzubauen.

    Im Dev-Modus (``FINLAI_DEV=1``) wird diese Funktion vom Aufrufer
    übersprungen und gar nicht aufgerufen.

    Args:
        parent: Eltern-Widget für den modalen Dialog (typisch: MainWindow).
        config: AppConfig der laufenden App.
    """
    from PySide6.QtCore import QTimer  # noqa: PLC0415

    version = getattr(config, "version", "0.0.0")
    app_id = getattr(config, "app_id", "finlai")
    override_url = getattr(config, "update_url", "")

    # Open-Source-Build ohne Update-Endpunkt: kein Worker, kein QTimer, kein
    # Netzwerk-Zugriff. Kommerzielle/White-Label-Builds setzen update_url oder
    # FINLAI_UPDATE_BASE_URL (-> UPDATE_BASE_URL) und laufen wie bisher.
    if not override_url and not UPDATE_BASE_URL:
        _log.debug(
            "Update-Check übersprungen: kein Update-Endpunkt konfiguriert "
            "(Open-Source-Build ohne update_url/FINLAI_UPDATE_BASE_URL)"
        )
        return

    def _do_check() -> None:
        worker = _UpdateCheckWorker(version, app_id, override_url)
        # Referenz halten damit der Thread nicht vom GC gesammelt wird
        parent._update_check_worker = worker  # type: ignore[attr-defined]

        def _on_update_found(info: UpdateInfo) -> None:
            dlg = UpdateDialog(info, version, parent=parent)
            dlg.exec()

        worker.update_found.connect(_on_update_found)
        worker.start()

    QTimer.singleShot(UPDATE_CHECK_DELAY_MS, _do_check)
    _log.debug(
        "Update-Check geplant in %d ms (app_id=%s, version=%s)",
        UPDATE_CHECK_DELAY_MS,
        app_id,
        version,
    )
