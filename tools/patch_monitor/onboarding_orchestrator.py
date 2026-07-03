"""
patch_monitor.onboarding_orchestrator — Logik zwischen Marker, Detection und Install.

Bug-Fix-Sprint C-3 (Option D). Diese Schicht ist UI-frei (kein PySide6-Import)
und enthaelt die State-Machine fuer "Dialog zeigen oder nicht?", den
``Install-Module``-Subprocess-Aufruf, und die Cache-Invalidierung nach Install.

Verantwortungsgrenzen:

*:mod:`tools.patch_monitor.onboarding_marker` — Marker-File-IO.
*:mod:`tools.patch_monitor.gui.onboarding_dialog` — Modal-UI, ruft die
  Funktionen hier in Reaktion auf User-Klicks.
*:func:`core.patch_collector.get_winget_module_status` — Detection-Cache,
  wird hier mit ``force_refresh=True`` invalidiert.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from core.logger import get_logger
from core.patch_collector import (
    ModuleStatus,
    get_winget_module_status,
)
from core.proc import run_hidden
from tools.patch_monitor.onboarding_marker import OnboardingMarker

if TYPE_CHECKING:
    from tools.mainpage.application.task_service import TaskService

log = get_logger(__name__)

#: Timeout fuer ``Install-Module`` (sekunden). Repository-Sync + Module-Pull
#: kann auf langsamen Verbindungen 1-2 Minuten dauern; 180 s ist Puffer.
_INSTALL_TIMEOUT_S: Final[int] = 180

#: PowerShell-Kommando fuer den Install-Aufruf. ``-Force`` umgeht
#: interaktive Bestaetigung, ``-AcceptLicense`` umgeht den Lizenz-Prompt
#: bestimmter PowerShell-Module, ``-Scope CurrentUser`` vermeidet die
#: UAC-Elevation. Bei Admin-Sessions koennte AllUsers verwendet werden,
#: das uebernimmt aber das Installer-Post-Install-Script, C-4)
#: zentral fuer alle User; der Onboarding-Dialog macht den
#: User-Scope-Fallback fuer Workstations ohne Admin-Rechte.
_INSTALL_CMD: Final[str] = (
    "Install-Module -Name Microsoft.WinGet.Client "
    "-Scope CurrentUser -Force -AcceptLicense"
)


@dataclass(frozen=True)
class InstallResult:
    """Ergebnis eines ``Install-Module``-Aufrufs.

    Attributes:
        success: ``True`` wenn returncode 0 und kein Subprocess-Fehler.
        reason_class: Klassen-basiert (kein roher stderr) —:data:`INSTALL_REASON_CLASSES`. UI-sicher fuer Anzeige.
    """

    success: bool
    reason_class: str


#: Klassen-Vokabular fuer:attr:`InstallResult.reason_class`. Enge Liste
#: damit UI/Logs vorhersehbar bleiben (Privacy-Filter-Direktive aus C-5
#: schon hier angewandt: keine stderr-Excerpts).
INSTALL_REASON_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "ok",
        "non-windows-platform",
        "subprocess-error",
        "install-failed",
    }
)


def should_show_onboarding(
    module_status: ModuleStatus,
    marker: OnboardingMarker | None,
) -> bool:
    """Entscheidet, ob der Onboarding-Dialog gezeigt werden soll.

    State-Machine — "genau einmal fragen"):

    * ``AVAILABLE`` → niemals Dialog (Modul ist da, kein Onboarding noetig).
    * Modul fehlt + ``marker is None`` → Dialog (User wurde noch nie gefragt).
    * Modul fehlt + Marker existiert → **kein** Dialog. Egal welche
      Entscheidung (``SKIP_SESSION`` / ``NEVER`` / stale ``INSTALLED``): der
      modale Dialog erscheint nach der ersten Entscheidung nicht erneut — sonst
      "nervt" er bei jeder frischen ``PatchConsoleWidget``-Instanz.
      Die nicht-modalen Pfade bleiben erhalten: der In-Tool-Banner
      (``PatchConsoleWidget._refresh_module_banner``) bietet weiterhin den
      Re-Install-Weg, und ``SKIP_SESSION`` setzt zusaetzlich ein kritisches
      Homescreen-Task (:func:`create_scan_reminder_task`).

    Args:
        module_status: Aktueller Detection-Status.
        marker: Geladener Marker oder ``None`` falls keiner existiert.

    Returns:
        ``True`` wenn Dialog gezeigt werden soll.
    """
    if module_status is ModuleStatus.AVAILABLE:
        return False
    return marker is None


def install_winget_module() -> InstallResult:
    """Ruft ``Install-Module Microsoft.WinGet.Client -Scope CurrentUser``.

    Fail-open: Subprocess-Fehler werden in:class:`InstallResult` mit
    ``success=False`` gemappt, niemals Exception nach aussen.

    Returns:
:class:`InstallResult` mit klassen-basierter ``reason_class``.
        Niemals roher stderr — Privacy-Filter (C-5-Direktive in
        der internen Entscheidungs-Doku).
    """
    if sys.platform != "win32":
        return InstallResult(success=False, reason_class="non-windows-platform")
    try:
        result = run_hidden(
            ["powershell", "-NoProfile", "-Command", _INSTALL_CMD],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_INSTALL_TIMEOUT_S,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.warning("install_winget_module subprocess failed: %s", type(exc).__name__)
        return InstallResult(success=False, reason_class="subprocess-error")
    if result.returncode != 0:
        log.info(
            "install_winget_module returncode=%s (stderr-len=%s)",
            result.returncode,
            len(result.stderr or ""),
        )
        return InstallResult(success=False, reason_class="install-failed")
    return InstallResult(success=True, reason_class="ok")


def refresh_module_status() -> ModuleStatus:
    """Invalidiert den Detection-Cache und prueft das Modul neu.

    Wird nach erfolgreichem:func:`install_winget_module` aufgerufen, damit
    der naechste regulaere ``get_winget_module_status``-Call (z.B. in
    ``collect_winget_inventory``) den frischen State sieht.

    Returns:
:class:`ModuleStatus` aus der frischen Detection.
    """
    detail = get_winget_module_status(force_refresh=True)
    return detail.status


# ---------------------------------------------------------------------------
# Homescreen-Reminder — Scan-Hinweis statt Dauerprompt
# ---------------------------------------------------------------------------

#: Stabiler Dedup-Schluessel des Reminder-Tasks. ``find_task_by_dedup_key``
#: dedupt unabhaengig vom Task-Status (auch nach Erledigung) → derselbe Hinweis
#: landet nie doppelt im Kanban; mehrfaches Ueberspringen erzeugt kein Duplikat.
_SCAN_REMINDER_DEDUP_KEY: Final[str] = "patch_monitor:winget_module_onboarding"

#: Titel des kritischen Homescreen-Tasks (priority="high" → "kritisch" im Kanban).
_SCAN_REMINDER_TITLE: Final[str] = "Patch-Monitor einrichten"

#: Beschreibung (Du-Form, konsistent zum Onboarding-Dialog-Text).
_SCAN_REMINDER_DESCRIPTION: Final[str] = (
    "Der Patch-Monitor braucht das PowerShell-Modul Microsoft.WinGet.Client, "
    "um Updates zuverlässig zu erkennen. Öffne den Patch-Monitor und installiere "
    "das Modul über das Hinweis-Banner — die Installation läuft im Benutzerprofil "
    "und braucht keine Administratorrechte."
)


def _build_default_task_service() -> TaskService | None:
    """Baut lazy einen:class:`TaskService` auf der ``mainpage``-DB.

    Spiegelt das Cross-Tool-Lazy-Import-Pattern aus
:class:`core.storytelling.ki_todo_emitter.KiTodoEmitter`: Patch-Monitor darf
    ``tools.mainpage`` nicht hart importieren — der Lazy-Import vermeidet einen
    Import-Zirkel und haelt den App-Bootstrap frei. Best-effort: jeder
    Setup-Fehler (z. B. fehlende/gesperrte SQLCipher-DB) liefert ``None``, der
    Aufrufer behandelt das als No-op.

    Returns:
        Frische:class:`TaskService`-Instanz oder ``None`` bei Setup-Fehler.
    """
    try:
        from tools.mainpage.application.journal_service import (  # noqa: PLC0415
            JournalService,
        )
        from tools.mainpage.application.task_service import (  # noqa: PLC0415
            TaskService,
        )
        from tools.mainpage.data.mainpage_repository import (  # noqa: PLC0415
            MainpageRepository,
        )

        repo = MainpageRepository()
        return TaskService(repo, JournalService(repo))
    except Exception as exc:  # noqa: BLE001 — Setup-Fehler darf Onboarding nicht brechen
        log.warning(
            "scan-reminder task service init failed (%s) — reminder skipped",
            type(exc).__name__,
        )
        return None


def create_scan_reminder_task(task_service: TaskService | None = None) -> bool:
    """Legt den Patch-Monitor-Hinweis als kritisches Homescreen-Task an.

    Wird gerufen, wenn der User das Onboarding ueberspringt (Skip-Button oder
    Dialog-Abbruch via X). Statt den modalen Dialog erneut zu zeigen, landet die
    Erinnerung als ``priority="high"``-Task im Homescreen-Kanban. Idempotent ueber
:data:`_SCAN_REMINDER_DEDUP_KEY` — mehrfaches Ueberspringen erzeugt kein
    Duplikat.

    Best-effort/fail-soft: jeder Fehler (DB nicht erreichbar, Service-Bau scheitert,
    Schreibfehler) wird geloggt und als ``False`` zurueckgegeben — der
    Onboarding-Flow darf nie an einem fehlgeschlagenen Reminder scheitern.

    Args:
        task_service: Optional injizierter Service (Tests). ``None`` →
:func:`_build_default_task_service` baut lazy einen.

    Returns:
        ``True`` wenn das Task angelegt (oder via Dedup bereits vorhanden) ist,
        ``False`` bei Setup-/Schreibfehler.
    """
    service = (
        task_service if task_service is not None else _build_default_task_service()
    )
    if service is None:
        return False
    try:
        service.create_critical_task(
            title=_SCAN_REMINDER_TITLE,
            description=_SCAN_REMINDER_DESCRIPTION,
            source_tool="patch_monitor",
            dedup_key=_SCAN_REMINDER_DEDUP_KEY,
        )
    except Exception as exc:  # noqa: BLE001 — Reminder darf Onboarding nicht brechen
        log.warning(
            "scan-reminder task create failed (%s) — reminder skipped",
            type(exc).__name__,
        )
        return False
    return True
