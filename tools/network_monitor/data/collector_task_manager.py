"""network_monitor.data.collector_task_manager — geplante Aufgabe fuer den Collector B2.4).

Registriert/entfernt die Windows-Geplante-Aufgabe, die
:mod:`apps.collector_main` elevated im **User-Kontext** startet. Bewusst via
**pywin32 COM** (``Schedule.Service``) statt schtasks-CLI — nur darueber sind
``ExecutionTimeLimit="PT0S"`` (unbegrenzt, fuer einen Dauer-Collector noetig) und
``RestartCount`` (Crash-Resilienz) sauber setzbar (Patrick-Entscheid 2026-05-25).

Schluessel-Settings (Web-Recherche 2026-05-25, MS-Doku):
- ``Principal.LogonType = TASK_LOGON_INTERACTIVE_TOKEN (3)`` — laeuft mit dem
  interaktiven Token des angemeldeten Users → DPAPI-CurrentUser bleibt korrekt
  (Voraussetzung fuer den Zugriff auf die user-verschluesselte DB).
- ``Principal.RunLevel = TASK_RUNLEVEL_HIGHEST (1)`` — elevated genug fuer ETW.
- Logon-Trigger (Typ 9) + ``Enabled = True`` (pywin32-Quirk #1205: sonst evtl. disabled).

**Anlegen erfordert einmalig Admin** (RegisterTaskDefinition mit HIGHEST) → der
GUI-Aufrufer (Phase C) muss sich via ``ShellExecute "runas"`` elevaten. Danach
laeuft die Aufgabe selbst ohne weiteren UAC-Prompt.

pywin32 (``win32com``) ist nur unter Windows installiert → Lazy-Import in den
Funktionen, damit das Modul plattformunabhaengig importier- und testbar bleibt.
"""

from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any, Final

from core.finlai_paths import finlai_dir
from core.logger import get_logger
from core.win_security import assess_install_path_trust
from tools.network_monitor.data.etw_network_subscriber import is_admin
from tools.network_monitor.domain.collector_status import (
    CollectorStatus,
    CollectorTaskHealth,
)
from tools.network_monitor.domain.exceptions import UntrustedCollectorPathError

_log = get_logger(__name__)

#: Name der Aufgabe im Task-Scheduler-Root.
TASK_NAME: Final[str] = "NoRiskNetCollector"

#: Dateiname der gepackten, Qt-freien Collector-Exe (2. EXE-Target der
#: PyInstaller-Spec F-C). Liegt im selben dist-Ordner neben der
#: Haupt-Exe (``norisk.exe``).
COLLECTOR_EXE_NAME: Final[str] = "norisk-collector.exe"

# ── Task-Scheduler-2.0-COM-Konstanten (aus der MS-Doku) ──────────────────────
TASK_TRIGGER_LOGON: Final[int] = 9
TASK_ACTION_EXEC: Final[int] = 0
TASK_CREATE_OR_UPDATE: Final[int] = 6
TASK_LOGON_INTERACTIVE_TOKEN: Final[int] = 3
TASK_RUNLEVEL_HIGHEST: Final[int] = 1
TASK_INSTANCES_IGNORE_NEW: Final[int] = 2

_RESTART_COUNT: Final[int] = 3
_RESTART_INTERVAL: Final[str] = "PT1M"
_EXECUTION_TIME_LIMIT_UNLIMITED: Final[str] = "PT0S"

#: Datei (unter FINLAI_HOME), über die der elevated Install-Prozess das Ergebnis
#: an den nicht-elevated GUI-Prozess zurückmeldet F-C-5). Nötig, weil
#: ``relaunch_elevated`` (ShellExecute "runas") keinen Exit-Code an die GUI
#: durchreicht. Best-effort/fail-soft — kein Sicherheits-, sondern ein UX-Kanal.
_INSTALL_MARKER_NAME: Final[str] = "collector_install_status.json"
#: Marker-Ergebnis: Security-Gate hat einen benutzer-beschreibbaren Pfad abgelehnt.
INSTALL_RESULT_REJECTED: Final[str] = "rejected_untrusted_path"


def install_marker_path() -> Path:
    """Pfad der Install-Ergebnis-Marker-Datei unter dem aktiven FINLAI_HOME."""
    return finlai_dir() / _INSTALL_MARKER_NAME


def write_install_reject_marker(reason: str) -> None:
    """Schreibt den „Pfad abgelehnt"-Marker für den GUI-Prozess (fail-soft).

    Wird vom elevated Install-Prozess geschrieben, wenn das Security-Gate
    (:class:`UntrustedCollectorPathError`) die Installation fail-closed ablehnt.

    Args:
        reason: Kurze, benutzerlesbare Begründung (kein Override-Hinweis).
    """
    try:
        path = install_marker_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"result": INSTALL_RESULT_REJECTED, "reason": reason}
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    except OSError:
        _log.exception("Install-Reject-Marker konnte nicht geschrieben werden.")


def clear_install_marker() -> None:
    """Entfernt einen evtl. vorhandenen (alten) Install-Marker (fail-soft)."""
    try:
        install_marker_path().unlink(missing_ok=True)
    except OSError:
        _log.exception("Install-Marker konnte nicht entfernt werden.")


def read_install_marker() -> dict[str, Any] | None:
    """Liest den Install-Marker (oder ``None``, wenn keiner/unlesbar).

    Hinweis: Werte sind ``Any`` (nicht garantiert ``str``) — ``json.loads`` kann
    bei einer korrupten/manipulierten Datei beliebige JSON-Typen liefern. Aufrufer
    (z. B.:func:`collector_control.take_install_reject`) müssen die Feld-Typen
    selbst absichern, bevor sie in die GUI fließen (fail-soft).

    Returns:
        Das geparste Marker-Dict (``{"result":..., "reason":...}``) oder
        ``None``, wenn keine Datei existiert oder sie nicht lesbar/parsebar ist.
    """
    path = install_marker_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _log.warning("Install-Marker %s unlesbar — ignoriert.", path)
        return None
    return data if isinstance(data, dict) else None


def current_user_id() -> str:
    """Liefert ``DOMAIN\\user`` (bzw. nur ``user``, wenn keine Domain gesetzt)."""
    user = getpass.getuser()
    domain = os.environ.get("USERDOMAIN")
    return f"{domain}\\{user}" if domain else user


def _canonical_repo_root(start: Path) -> Path:
    """Loest den Haupt-Arbeitsbaum auf, falls ``start`` in einem linked Worktree liegt.

    In einem linked git-Worktree ist ``.git`` eine **Datei** mit Inhalt
    ``gitdir: <main>/.git/worktrees/<name>``; ``start`` zeigt dann auf einen
    transienten Worktree-Pfad, der jederzeit geloescht werden kann — genau die
    Wurzel der-Konstellation (geplante Aufgabe brennt einen Worktree-Pfad
    ein, Worktree verschwindet, Aufgabe laeuft ins Leere). Diese Funktion liefert
    in dem Fall den stabilen Haupt-Arbeitsbaum, sonst ``start`` unveraendert.

    Bewusst **ohne** git-Subprozess (git ist zur Laufzeit nicht garantiert auf
    dem PATH): liest nur die ``.git``-Datei und leitet den Pfad strukturell ab.

    Args:
        start: Der via ``Path(__file__).parents[...]`` ermittelte Repo-Root-
            Kandidat.

    Returns:
        Den Haupt-Arbeitsbaum (bei linked Worktree) oder ``start`` (Haupt-Repo,
        gepackte Exe oder unlesbares Layout — konservativ unveraendert).
    """
    git_path = start / ".git"
    try:
        if not git_path.is_file():
            return start  # Haupt-Repo (.git ist Ordner) oder kein git -> bereits stabil
        content = git_path.read_text(encoding="utf-8").strip()
    except OSError:
        return start
    prefix = "gitdir:"
    if not content.startswith(prefix):
        return start
    gitdir = Path(content[len(prefix) :].strip())
    if not gitdir.is_absolute():
        gitdir = (start / gitdir).resolve()
    # Standard-Layout: <main>/.git/worktrees/<name> -> Haupt-Arbeitsbaum ist die
    # Eltern des ``.git``-Ordners. Nur verwenden, wenn das Layout wirklich passt.
    if gitdir.parent.parent.name == ".git":
        return gitdir.parent.parent.parent
    return start


def default_collector_action() -> tuple[str, str, str]:
    """Ermittelt ``(exe, arguments, working_dir)`` fuer die Collector-Aufgabe.

    Zwei Modi F-C):

    - **Gepackt** (``getattr(sys, "frozen", False)``): die separate, Qt-freie
      Collector-Exe:data:`COLLECTOR_EXE_NAME` (2. EXE-Target der Spec) neben der
      Haupt-Exe. **Keine** Argumente — die Exe *ist* der Collector (kein
      Subcommand); ``WorkingDirectory`` ist der dist-Ordner.
    - **Dev**: ``pythonw.exe`` (kein Konsolenfenster) neben dem aktuellen
      Interpreter + ``apps/collector_main.py``. Der Repo-Root wird via
:func:`_canonical_repo_root` kanonisiert, damit ein Install aus einem
      linked git-Worktree den **stabilen** Haupt-Arbeitsbaum einbrennt statt
      eines transienten Worktree-Pfads-Wurzel).

    Die Action bleibt in:func:`install_collector_task` ueberschreibbar (Tests,
    Sonderdeployments).

    **check==burn (R-23 F-C-2 Teil 2):** Alle zurueckgegebenen Pfade sind
    ``os.path.realpath``-aufgeloest. Damit brennt:func:`install_collector_task`
    exakt den Pfad ein, den:func:`core.win_security.assess_install_path_trust`
    (das ebenfalls ueber ``realpath`` prueft) als vertrauenswuerdig bestaetigt hat
    — der frueher dokumentierte ``check != burn``-Spalt entfaellt. Da diese Funktion
    die **Single-Source** sowohl fuer den Install als auch fuer
:func:`collector_task_needs_migration` ist, bleibt der Migrations-Vergleich
    konsistent (kein Dauer-„Migration noetig" durch roh-vs-aufgeloest-Drift; gegen
    den Frozen-Build verifiziert, ``realpath == roh`` unter %ProgramFiles%).

    Returns:
        ``(exe, arguments, working_dir)`` — ``arguments`` enthaelt im Dev-Modus
        den gequoteten Skriptpfad, im gepackten Modus den Leerstring.
    """
    if getattr(sys, "frozen", False):
        collector = Path(os.path.realpath(Path(sys.executable).with_name(COLLECTOR_EXE_NAME)))
        return str(collector), "", str(collector.parent)
    repo_root = _canonical_repo_root(Path(__file__).resolve().parents[3])
    interpreter = Path(sys.executable)
    pythonw = interpreter.with_name("pythonw.exe")
    # check==burn: alle drei Pfade einheitlich via realpath (os.path.realpath
    # akzeptiert Path-like direkt und liefert stets str).
    exe = os.path.realpath(pythonw if pythonw.exists() else interpreter)
    script = os.path.realpath(repo_root / "apps" / "collector_main.py")
    return exe, f'"{script}"', os.path.realpath(repo_root)


def configure_task_definition(
    task_def: Any,
    *,
    exe: str,
    arguments: str,
    working_dir: str,
    user_id: str,
    description: str = "NoRisk ETW-Network-Collector (T-075)",
) -> Any:
    """Setzt alle Felder der Task-Definition (testbar mit gemocktem COM-Objekt).

    Args:
        task_def: ``ITaskDefinition``-COM-Objekt aus ``scheduler.NewTask(0)``.
        exe: Pfad zur ausfuehrbaren Datei.
        arguments: Kommandozeilen-Argumente.
        working_dir: Arbeitsverzeichnis.
        user_id: Principal-User (``DOMAIN\\user``).
        description: Beschreibung im Scheduler.

    Returns:
        Das (mutierte) ``task_def``.
    """
    task_def.RegistrationInfo.Description = description
    task_def.RegistrationInfo.Author = "FINLAI"

    principal = task_def.Principal
    principal.UserId = user_id
    principal.LogonType = TASK_LOGON_INTERACTIVE_TOKEN
    principal.RunLevel = TASK_RUNLEVEL_HIGHEST

    settings = task_def.Settings
    settings.Enabled = True
    settings.StartWhenAvailable = True
    settings.DisallowStartIfOnBatteries = False
    settings.StopIfGoingOnBatteries = False
    settings.ExecutionTimeLimit = _EXECUTION_TIME_LIMIT_UNLIMITED
    settings.MultipleInstances = TASK_INSTANCES_IGNORE_NEW
    settings.RestartCount = _RESTART_COUNT
    settings.RestartInterval = _RESTART_INTERVAL

    trigger = task_def.Triggers.Create(TASK_TRIGGER_LOGON)
    trigger.Id = "LogonTrigger"
    trigger.Enabled = True
    trigger.UserId = user_id

    action = task_def.Actions.Create(TASK_ACTION_EXEC)
    action.Path = exe
    action.Arguments = arguments
    action.WorkingDirectory = working_dir

    return task_def


def _connect_scheduler() -> Any:
    """Verbindet zum Task-Scheduler-Dienst (lazy pywin32-Import)."""
    import win32com.client

    scheduler = win32com.client.Dispatch("Schedule.Service")
    scheduler.Connect()
    return scheduler


def _assert_collector_path_trusted(
    exe: str, arguments: str, working_dir: str, *, allow_untrusted_path: bool
) -> None:
    """Lehnt ein benutzer-beschreibbares Action-Ziel ab, bevor es elevated eingebrannt wird.

    Prüft die Exe, das ``WorkingDirectory`` und — im Dev-Modus — das ``.py``-Skript
    via:func:`core.win_security.assess_install_path_trust` (Prefix-Vorfilter +
    DACL/Owner inkl. Ancestor-Walk). Ein nicht vertrauenswürdiger Pfad ließe einen
    Nicht-Admin die elevated Aufgabe kapern (EoP F-C-3).

    Args:
        exe: Pfad zur ausführbaren Datei (``action.Path``).
        arguments: Action-Argumente (zur ``.py``-Skript-Extraktion im Dev-Modus).
        working_dir: Arbeitsverzeichnis der Action (CWD des elevated Prozesses).
        allow_untrusted_path: Wenn True, wird ein nicht vertrauenswürdiges Ziel nur
            mit WARNING zugelassen statt abgelehnt (Dev/Smoke-Override).

    Raises:
        UntrustedCollectorPathError: Wenn ein geprüftes Ziel nicht vertrauenswürdig
            ist und ``allow_untrusted_path`` nicht gesetzt wurde, ODER wenn die
            Action gar kein prüfbares Ziel hat (leeres exe/working_dir — fail-closed).
    """
    candidates = [exe, working_dir]
    script = _script_from_arguments(arguments)
    if script is not None and script.lower().endswith(".py"):
        candidates.append(script)
    checkable = [c for c in candidates if c]
    if not checkable:
        # Fail-closed: ein leeres Action-Ziel ist nie ein legitimer Pfad und darf
        # nicht still durchgewunken werden (auch nicht per Override).
        raise UntrustedCollectorPathError(
            "Collector-Action hat kein prüfbares Ziel (leeres exe/working_dir) — "
            "Installation fail-closed abgelehnt."
        )
    untrusted = [
        verdict
        for verdict in (assess_install_path_trust(c) for c in checkable)
        if not verdict.trusted
    ]
    if not untrusted:
        return
    detail = "; ".join(f"{v.checked_path}: {v.reason}" for v in untrusted)
    if allow_untrusted_path:
        _log.warning(
            "Collector-Installationspfad NICHT vertrauenswürdig, per Override "
            "zugelassen (nur auf Entwickler-Maschinen vertretbar): %s",
            detail,
        )
        return
    raise UntrustedCollectorPathError(
        "Collector-Installationspfad ist durch Nicht-Admins manipulierbar "
        f"(EoP-Risiko): {detail}. Installieren Sie nach %ProgramFiles% oder setzen "
        "Sie allow_untrusted_path=True (nur Entwickler-Maschinen)."
    )


def install_collector_task(
    *,
    exe: str | None = None,
    arguments: str | None = None,
    working_dir: str | None = None,
    task_name: str = TASK_NAME,
    finlai_home: str | None = None,
    allow_untrusted_path: bool = False,
) -> None:
    """Registriert (oder aktualisiert) die Collector-Aufgabe.

    Erfordert Administrator-Rechte (RunLevel HIGHEST).

    Args:
        exe/arguments/working_dir: Optionale Override der Action; Default ist
:func:`default_collector_action`.
        task_name: Aufgaben-Name im Root-Ordner.
        finlai_home: Aktiver FINLAI_HOME-Override (oder ``None``). Ist er gesetzt,
            wird ``--finlai-home "<dir>"`` an die Action-Argumente **angehaengt**,
            damit der Logon-Collector im selben Profil schreibt statt still ins
            echte ``~/.finlai``. Wird hinten angehaengt, damit der
            Skript-/Subcommand-Token erster Token bleibt (Status-Check-Contract,
:func:`_script_from_arguments`). Der Wert wird vor dem Einbrennen
            validiert (absoluter, existierender Pfad ohne ``"``), da er in eine
            HIGHEST-Logon-Aufgabe persistiert wird (fail-closed gegen
            Quote-Injection / beliebiges Schreibziel).
        allow_untrusted_path: Übergeht das Security-Gate F-C-3), das das
            Einbrennen eines benutzer-beschreibbaren Ziels in eine HIGHEST-Aufgabe
            ablehnt (EoP). Default ``False`` (fail-closed). Nur auf
            Entwickler-Maschinen / im lokalen Frozen-Smoke bewusst auf ``True``
            setzen — der Dev-/Repo-Pfad ist immer benutzer-beschreibbar.

    Raises:
        PermissionError: Wenn der Prozess nicht elevated ist.
        ValueError: Wenn ``finlai_home`` gesetzt, aber kein gueltiger
            (absoluter, existierender, anfuehrungszeichen-freier) Pfad ist.
        UntrustedCollectorPathError: Wenn das Action-Ziel in einem
            benutzer-beschreibbaren Pfad läge und ``allow_untrusted_path`` nicht
            gesetzt ist (Security-Gate F-C-3).
    """
    if not is_admin():
        raise PermissionError(
            "Anlegen der geplanten Aufgabe erfordert Administrator-Rechte."
        )
    if exe is None or arguments is None or working_dir is None:
        d_exe, d_args, d_dir = default_collector_action()
        exe = exe or d_exe
        arguments = arguments or d_args
        working_dir = working_dir or d_dir
    if finlai_home:
        # Privileg-Grenze: der Pfad landet roh in den Argumenten einer HIGHEST-
        # Logon-Aufgabe. Fail-closed validieren statt still ins falsche Profil zu
        # schreiben oder einen aufgebrochenen Argument-String einzubrennen.
        home = Path(finlai_home)
        if '"' in finlai_home or not home.is_absolute() or not home.is_dir():
            raise ValueError(
                "Ungueltiger FINLAI_HOME-Pfad fuer die Collector-Aufgabe: "
                f"{finlai_home!r} — erwartet ein existierendes, absolutes "
                'Verzeichnis ohne Anfuehrungszeichen. Aufgabe NICHT installiert '
                "(fail-closed)."
            )
        arguments = f'{arguments} --finlai-home "{finlai_home}"'.strip()

    _assert_collector_path_trusted(
        exe, arguments, working_dir, allow_untrusted_path=allow_untrusted_path
    )

    scheduler = _connect_scheduler()
    root = scheduler.GetFolder("\\")
    task_def = configure_task_definition(
        scheduler.NewTask(0),
        exe=exe,
        arguments=arguments,
        working_dir=working_dir,
        user_id=current_user_id(),
    )
    root.RegisterTaskDefinition(
        task_name,
        task_def,
        TASK_CREATE_OR_UPDATE,
        "",  # user — leer bei interaktivem Token
        "",  # password — leer
        TASK_LOGON_INTERACTIVE_TOKEN,
    )
    _log.info("Geplante Aufgabe '%s' registriert.", task_name)


def uninstall_collector_task(task_name: str = TASK_NAME) -> bool:
    """Entfernt die Collector-Aufgabe.

    Erfordert Administrator-Rechte: die Aufgabe ist mit ``RunLevel HIGHEST`` im
    Root-Ordner registriert, ein unelevierter ``DeleteTask`` scheitert daher mit
    ``ACCESS_DENIED``. Wie:func:`install_collector_task` wird das hier als
    klarer:class:`PermissionError` signalisiert (statt eines rohen COM-Fehlers),
    damit der GUI-Aufrufer ruhig auf einen elevierten Lauf umschalten kann, ohne
    einen Traceback zu loggen.

    Args:
        task_name: Aufgaben-Name im Root-Ordner.

    Returns:
        True wenn entfernt, False wenn sie nicht existierte.

    Raises:
        PermissionError: Wenn der Prozess nicht elevated ist.
    """
    if not is_admin():
        raise PermissionError(
            "Entfernen der geplanten Aufgabe erfordert Administrator-Rechte."
        )
    scheduler = _connect_scheduler()
    root = scheduler.GetFolder("\\")
    if not is_task_installed(task_name):
        return False
    root.DeleteTask(task_name, 0)
    _log.info("Geplante Aufgabe '%s' entfernt.", task_name)
    return True


def is_task_installed(task_name: str = TASK_NAME) -> bool:
    """True wenn die Aufgabe im Root-Ordner existiert."""
    try:
        scheduler = _connect_scheduler()
        root = scheduler.GetFolder("\\")
        root.GetTask(task_name)
        return True
    except Exception:  # noqa: BLE001 — COM wirft bei „nicht gefunden"
        return False


def _script_from_arguments(arguments: str) -> str | None:
    """Extrahiert den (ggf. gequoteten) ersten Datei-Pfad aus den Action-Args.

    Die Dev-Action ruft ``pythonw.exe "<repo>/apps/collector_main.py"`` — der
    erste Token ist der Skriptpfad. Bei einer gepackten Exe ohne Skript-Argument
    (Release, ``--run-collector``) liefert die Funktion den ersten Token, der
    dann von:func:`_action_targets_exist` als Nicht-Datei erkannt wird.

    Args:
        arguments: Die ``action.Arguments``-Zeichenkette der Aufgabe.

    Returns:
        Den extrahierten Pfad/Token, oder ``None`` bei leeren Argumenten.
    """
    stripped = arguments.strip()
    if not stripped:
        return None
    if stripped.startswith('"'):
        end = stripped.find('"', 1)
        return stripped[1:end] if end != -1 else stripped[1:]
    return stripped.split()[0]


def _action_targets_exist(exe: str, arguments: str) -> bool:
    """Prueft, ob die ausfuehrbare Datei und (falls vorhanden) das Skript existieren.

    Erkennt die-Konstellation „Aufgabe zeigt auf geloeschten Worktree":
    ``pythonw.exe`` existiert, aber das Collector-Skript im Worktree fehlt. Nur
    ein ``.py``-Argument wird als Datei geprueft; ein Subcommand wie
    ``--run-collector`` (gepackte Exe) loest keinen False-Broken aus.

    Args:
        exe: Pfad zur ausfuehrbaren Datei (``action.Path``).
        arguments: Argumente der Action (``action.Arguments``).

    Returns:
        True, wenn alle pruefbaren Ziele existieren.
    """
    script = _script_from_arguments(arguments)
    if not exe and script is None:
        # Action war nicht lesbar (leeres exe + kein Argument) -> Ziel nicht
        # bestaetigbar; konservativ NICHT als vorhanden werten, sonst entstuende
        # genau der False-Positive-„aktiv", den beseitigen soll.
        return False
    if exe and not Path(exe).exists():
        return False
    if script is not None and script.lower().endswith(".py"):
        return Path(script).exists()
    return True


def _read_exec_action(task: Any) -> tuple[str, str]:
    """Liest Pfad + Argumente der ersten Exec-Action der Aufgabe.

    Args:
        task: ``IRegisteredTask``-COM-Objekt.

    Returns:
        ``(exe, arguments)``; ``("", "")`` bei Lesefehler/ohne Exec-Action.
    """
    try:
        actions = task.Definition.Actions
        for i in range(1, int(actions.Count) + 1):
            action = actions.Item(i)
            if int(getattr(action, "Type", TASK_ACTION_EXEC)) == TASK_ACTION_EXEC:
                return action.Path or "", action.Arguments or ""
    except Exception:  # noqa: BLE001 — COM-Property-Quirks duerfen nicht crashen
        _log.exception("Exec-Action der Collector-Aufgabe nicht lesbar.")
    return "", ""


def _read_last_task_result(task: Any) -> int | None:
    """Liest ``LastTaskResult`` der Aufgabe (``None`` bei Lesefehler)."""
    try:
        return int(task.LastTaskResult)
    except Exception:  # noqa: BLE001 — COM-Property evtl. nicht verfuegbar
        return None


def get_collector_status(task_name: str = TASK_NAME) -> CollectorStatus:
    """Ermittelt das Health-Verdikt der Collector-Aufgabe.

    Anders als:func:`is_task_installed` prueft diese Funktion nicht nur die
    Registrierung, sondern auch, ob das Action-Ziel (Collector-Skript/-Exe) auf
    der Platte existiert und ob der letzte Lauf nicht fehlschlug. Damit wird die
    Konstellation erkannt, bei der die Aufgabe registriert ist, aber auf
    einen geloeschten Worktree-Pfad zeigt (``LastTaskResult=2``) und nicht laeuft.

    Args:
        task_name: Aufgaben-Name im Root-Ordner.

    Returns:
        Das:class:`CollectorStatus`-Verdikt (NOT_INSTALLED/ACTIVE/BROKEN).
    """
    try:
        scheduler = _connect_scheduler()
        root = scheduler.GetFolder("\\")
        task = root.GetTask(task_name)
    except Exception:  # noqa: BLE001 — COM wirft bei „nicht gefunden"
        return CollectorTaskHealth(installed=False).status

    exe, arguments = _read_exec_action(task)
    target_exists = _action_targets_exist(exe, arguments)
    if not target_exists:
        _log.warning(
            "Collector-Aufgabe '%s' zeigt auf nicht vorhandenes Ziel "
            "(exe=%s, args=%s) — gilt als nicht aktiv.",
            task_name,
            exe,
            arguments,
        )
    return CollectorTaskHealth(
        installed=True,
        target_exists=target_exists,
        last_task_result=_read_last_task_result(task),
    ).status


def _exe_paths_equivalent(a: str, b: str) -> bool:
    """Vergleicht zwei Exe-Pfade case-/separator-normalisiert (Windows-Aufgaben).

    Args:
        a: Erster Pfad.
        b: Zweiter Pfad.

    Returns:
        True, wenn beide nicht-leer sind und denselben normalisierten Pfad
        bezeichnen (``os.path.normcase`` + ``normpath`` — case-insensitiv unter
        Windows); False sonst.
    """
    if not a or not b:
        return False
    return os.path.normcase(os.path.normpath(a)) == os.path.normcase(os.path.normpath(b))


def collector_task_needs_migration(task_name: str = TASK_NAME) -> bool:
    """True, wenn eine installierte Aufgabe auf ein anderes Exe-Ziel zeigt als der aktuelle Default.

    Erkennt den Update-Fall F-C): die Aufgabe wurde unter einer frueheren
    Action-Variante registriert (z. B. dev-``pythonw.exe`` + Skript ODER eine
    Collector-Exe in einem alten Installationspfad), der aktuelle Build liefert
    aber ein anderes:func:`default_collector_action`-Ziel. Dann muss die Aufgabe
    **elevated neu registriert** werden (``install_collector_task`` aktualisiert
    via ``CREATE_OR_UPDATE``), damit der Logon-Collector wieder das richtige Ziel
    startet — sonst zeigt ``LastTaskResult`` ins Leere und der Status faellt auf
    BROKEN-Mechanik).

    Bewusst nur ein **Detektor** (das Lesen der Aufgabe braucht keine
    Admin-Rechte): die eigentliche Migration ist der elevated Re-Install und wird
    vom GUI-Pfad (Einstellungen, F-C-5) ausgeloest.

    Verglichen wird nur der **Exe-Pfad** (case-/separator-normalisiert), nicht die
    Argumente: reiner Argument-Drift (z. B. anderes ``--finlai-home``) erzeugt
    keinen BROKEN-Status und ist daher bewusst KEIN Migrationsgrund. Ein
    8.3-Kurzname-vs-Langname-Unterschied kann theoretisch einen False-Positive
    geben — die einzige Folge waere ein idempotenter Re-Install (1 UAC-Prompt),
    kein Schaden.

    Args:
        task_name: Aufgaben-Name im Root-Ordner.

    Returns:
        True, wenn die Aufgabe existiert UND ihr Exec-Exe-Pfad vom aktuellen
        Default abweicht; False bei nicht installiert / bereits aktuell /
        unlesbarer Action.
    """
    try:
        scheduler = _connect_scheduler()
        root = scheduler.GetFolder("\\")
        task = root.GetTask(task_name)
    except Exception:  # noqa: BLE001 — COM wirft bei „nicht gefunden"
        return False
    installed_exe, _arguments = _read_exec_action(task)
    if not installed_exe:
        return False  # unlesbare Action -> nicht als migrationsbeduerftig werten
    return not _exe_paths_equivalent(installed_exe, default_collector_action()[0])
