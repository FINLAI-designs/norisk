"""
patch_monitor.gui.onboarding_dialog — Modal fuer das WinGet-Modul-Onboarding.

Bug-Fix-Sprint C-3 (Option D). Dialog mit drei Buttons:

* **Installieren**: ruft ``Install-Module`` (asynchron via Worker-Thread,
  damit die UI nicht 1-3 Minuten einfriert), prueft den Detection-Cache neu,
  speichert bei Erfolg ``decision=installed``.
* **Diesmal ueberspringen**: speichert ``decision=skip_session`` und
  schliesst den Dialog. Beim naechsten Patch-Monitor-Open wird der Dialog
  erneut gezeigt.
* **Nie wieder fragen**: speichert ``decision=never``. Patch-Monitor laeuft
  ab jetzt im Fallback-Pfad ohne Onboarding-Hinweis.

Schicht: ``gui/`` — keine Business-Logik. Subprocess-Aufruf, Cache-Reset und
Marker-Persistierung delegieren an:mod:`tools.patch_monitor.onboarding_orchestrator`
und:mod:`tools.patch_monitor.onboarding_marker` (per Dependency-Injection,
damit Tests nicht echten ``Install-Module``-Aufruf brauchen).

Privacy-Filter (C-5-Direktive): ``InstallResult.reason_class`` ist klassen-
basiert (``ok``/``install-failed``/``subprocess-error``), niemals roher
stderr-Excerpt im UI.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.logger import get_logger
from core.patch_collector import ModuleStatus
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.patch_monitor.onboarding_marker import (
    OnboardingDecision,
    OnboardingMarker,
    save_marker,
)
from tools.patch_monitor.onboarding_orchestrator import (
    InstallResult,
    create_scan_reminder_task,
    install_winget_module,
    refresh_module_status,
)

log = get_logger(__name__)

#: Type-Aliase fuer Dependency-Injection (Tests).
Installer = Callable[[], InstallResult]
Refresher = Callable[[], ModuleStatus]
MarkerSaver = Callable[[OnboardingDecision], OnboardingMarker]
#: Callable fuer das Anlegen des kritischen Homescreen-Tasks.
ScanReminderCreator = Callable[[], bool]


# ---------------------------------------------------------------------------
# Status-Text-Mapping (Privacy-Filter-konform — keine stderr-Excerpts)
# ---------------------------------------------------------------------------


_REASON_TEXT: Final[dict[str, str]] = {
    "ok": "Installation erfolgreich.",
    "non-windows-platform": (
        "Auf dieser Plattform ist Microsoft.WinGet.Client nicht verfügbar."
    ),
    "subprocess-error": (
        "PowerShell konnte nicht ausgeführt werden. Bitte prüfen, ob "
        "PowerShell installiert ist und vom Pfad aus erreichbar."
    ),
    "install-failed": (
        "Install-Module ist fehlgeschlagen. Mögliche Ursachen: "
        "fehlende Internet-Verbindung, restriktive Execution-Policy, "
        "PowerShell-Gallery nicht erreichbar."
    ),
}


def _format_install_message(result: InstallResult) -> str:
    """Mapped:class:`InstallResult` → User-lesbare Status-Zeile.

    Niemals ``stderr``-Inhalte einfliessen lassen — Privacy-Filter-Direktive.
    """
    return _REASON_TEXT.get(
        result.reason_class, "Unbekannter Status — bitte App-Logs prüfen."
    )


# ---------------------------------------------------------------------------
# Worker — Install-Module asynchron damit UI nicht einfriert
# ---------------------------------------------------------------------------


class _InstallWorker(QObject):
    """QObject-Worker, der den Install-Aufruf in einem QThread macht.

    Emittiert:attr:`finished` mit dem:class:`InstallResult` (ggf.
    erfolgreich gefolgt von einem refreshter ModuleStatus).
    """

    #: ``finished(InstallResult, ModuleStatus)`` — emittiert nach Subprocess.
    #: Bei ``InstallResult.success=False`` ist der Status der pre-existierende
    #: Cached-Status (kein force_refresh — der Subprocess hat ja gar nichts
    #: installiert).
    finished = Signal(object, object)

    def __init__(
        self, installer: Installer, refresher: Refresher
    ) -> None:
        super().__init__()
        self._installer = installer
        self._refresher = refresher

    @Slot()
    def run(self) -> None:
        """Subprocess-Aufruf + Cache-Refresh, fail-open."""
        try:
            result = self._installer()
        except Exception as exc:  # noqa: BLE001 — Worker darf nie crashen
            log.exception("install worker crash: %s", exc)
            result = InstallResult(success=False, reason_class="subprocess-error")
        try:
            status = self._refresher() if result.success else ModuleStatus.BLOCKED
        except Exception as exc:  # noqa: BLE001
            log.exception("module status refresh crash: %s", exc)
            status = ModuleStatus.BLOCKED
        self.finished.emit(result, status)


# ---------------------------------------------------------------------------
# Dialog
# ---------------------------------------------------------------------------


class WingetModuleOnboardingDialog(QDialog):
    """Modal fuer das einmalige WinGet-Modul-Onboarding.

    Args:
        parent: Eltern-Widget (typisch:class:`PatchConsoleWidget`).
        installer: Callable fuer ``Install-Module``-Aufruf (DI fuer Tests).
        refresher: Callable fuer Cache-Refresh (DI).
        marker_saver: Callable fuer ``save_marker(decision)`` (DI).
        task_creator: Callable, das beim Ueberspringen das kritische
            Homescreen-Task anlegt, DI fuer Tests). Default:
:func:`create_scan_reminder_task`.

    Public-API beschraenkt sich auf den Konstruktor und:meth:`exec` —
    Buttons triggern die User-Wahl, der Dialog persistiert den Marker
    und schliesst sich.:meth:`result_decision` liefert nach
    ``exec`` die Entscheidung als:class:`OnboardingDecision`. Seit
    ist auch der X-Abbruch eine Entscheidung (``SKIP_SESSION``) — der modale
    Dialog soll nach dem ersten Mal nicht erneut "nerven".
    """

    def __init__(
        self,
        *,
        parent: QWidget | None = None,
        installer: Installer = install_winget_module,
        refresher: Refresher = refresh_module_status,
        marker_saver: MarkerSaver = save_marker,
        task_creator: ScanReminderCreator = create_scan_reminder_task,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Patch-Monitor — Voraussetzung einrichten")
        self.setModal(True)
        self.setMinimumWidth(520)
        self._installer = installer
        self._refresher = refresher
        self._marker_saver = marker_saver
        self._task_creator = task_creator
        self._decision: OnboardingDecision | None = None
        self._final_status: ModuleStatus | None = None
        self._thread: QThread | None = None
        self._worker: _InstallWorker | None = None
        self._build_ui()

    # -- public --------------------------------------------------------

    def result_decision(self) -> OnboardingDecision | None:
        """Letzte gespeicherte Entscheidung, oder ``None`` bei Abbruch."""
        return self._decision

    def result_status(self) -> ModuleStatus | None:
        """Detection-Status nach Install-Versuch, oder ``None``."""
        return self._final_status

    # -- UI ------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        intro = QLabel(
            "Der Patch-Monitor benötigt das PowerShell-Modul "
            "<b>Microsoft.WinGet.Client</b>, um Updates zuverlässig "
            "zu erkennen.\n\n"
            "Möchtest du das Modul jetzt installieren?\n"
            "Die Installation läuft im Benutzerprofil und benötigt "
            "keine Administratorrechte."
        )
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(intro)

        self._status_label = QLabel("")
        self._status_label.setWordWrap(True)
        self._status_label.setVisible(False)
        layout.addWidget(self._status_label)

        # kanonischer FinlaiProgressBar (indeterminate)
        self._progress = FinlaiProgressBar()
        self._progress.setVisible(False)
        layout.addWidget(self._progress)

        button_row = QHBoxLayout()
        self._install_btn = QPushButton("Installieren")
        self._install_btn.setDefault(True)
        self._install_btn.clicked.connect(self._on_install_clicked)
        button_row.addWidget(self._install_btn)

        self._skip_btn = QPushButton("Diesmal überspringen")
        self._skip_btn.clicked.connect(self._on_skip_clicked)
        button_row.addWidget(self._skip_btn)

        self._never_btn = QPushButton("Nie wieder fragen")
        self._never_btn.clicked.connect(self._on_never_clicked)
        button_row.addWidget(self._never_btn)

        layout.addLayout(button_row)

    # -- Button-Slots --------------------------------------------------

    @Slot()
    def _on_install_clicked(self) -> None:
        self._set_buttons_enabled(False)
        self._status_label.setText("Installiere Microsoft.WinGet.Client …")
        self._status_label.setVisible(True)
        self._progress.setVisible(True)
        self._start_install_worker()

    @Slot()
    def _on_skip_clicked(self) -> None:
        self._skip_and_remind()

    @Slot()
    def _on_never_clicked(self) -> None:
        self._persist_decision(OnboardingDecision.NEVER)
        self.accept()

    def reject(self) -> None:
        """X-Abbruch behandeln wie „Diesmal ueberspringen".

        Verhindert, dass ein per X geschlossener Dialog beim naechsten Oeffnen
        erneut erscheint. Nur wenn noch keine Entscheidung gefallen ist UND
        kein Install-Worker laeuft — sonst Standard-Reject (der Install-Thread
        wird in:meth:`_on_install_finished` aufgeraeumt).
        """
        if self._decision is None and self._thread is None:
            self._skip_and_remind()
            return
        super().reject()

    # -- Install-Worker-Lifecycle --------------------------------------

    def _start_install_worker(self) -> None:
        thread = QThread(self)
        worker = _InstallWorker(self._installer, self._refresher)
        worker.moveToThread(thread)
        worker.finished.connect(self._on_install_finished)
        thread.started.connect(worker.run)
        thread.finished.connect(worker.deleteLater)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(object, object)
    def _on_install_finished(
        self, result: InstallResult, status: ModuleStatus
    ) -> None:
        self._progress.setVisible(False)
        self._final_status = status
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(2000)
            self._thread = None
            self._worker = None
        if result.success and status is ModuleStatus.AVAILABLE:
            self._persist_decision(OnboardingDecision.INSTALLED)
            self._status_label.setText(_format_install_message(result))
            self.accept()
            return
        # Install fehlgeschlagen ODER post-install-status nicht AVAILABLE.
        # Buttons wieder freischalten, User kann Skip/Never waehlen oder
        # nochmal probieren.
        self._set_buttons_enabled(True)
        if not result.success:
            msg = _format_install_message(result)
        else:
            msg = (
                "Installation lief durch, aber das Modul ist noch nicht "
                "verfügbar. Bitte App-Logs prüfen."
            )
        self._status_label.setText(msg)

    # -- Helpers -------------------------------------------------------

    def _set_buttons_enabled(self, enabled: bool) -> None:
        self._install_btn.setEnabled(enabled)
        self._skip_btn.setEnabled(enabled)
        self._never_btn.setEnabled(enabled)

    def _skip_and_remind(self) -> None:
        """Ueberspringen-Pfad: Marker setzen + kritisches Homescreen-Task anlegen.

        Gemeinsam genutzt vom „Diesmal ueberspringen"-Button und vom Dialog-
        Abbruch via X (:meth:`reject`). Die Task-Erzeugung ist fail-soft —
        schlaegt sie fehl, schliesst der Dialog trotzdem (der Reminder ist
        Best-effort und darf den Flow nie blockieren).
        """
        self._persist_decision(OnboardingDecision.SKIP_SESSION)
        try:
            # DI-Seam: der Default-Creator ist selbst fail-soft (gibt bool),
            # aber ein injizierter task_creator (Tests/Fremd) darf werfen —
            # der Dialog soll trotzdem sauber schliessen.
            self._task_creator()
        except Exception as exc:  # noqa: BLE001 — Reminder darf Dialog nie crashen
            log.warning(
                "scan reminder task creation failed: %s", type(exc).__name__
            )
        self.accept()

    def _persist_decision(self, decision: OnboardingDecision) -> None:
        try:
            self._marker_saver(decision)
        except OSError as exc:
            log.warning("could not persist onboarding decision: %s", exc)
        self._decision = decision
