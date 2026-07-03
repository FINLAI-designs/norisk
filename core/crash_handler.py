"""
crash_handler — End-User-Diagnose-Infrastruktur fuer NoRisk.

Patrick-Wunsch 2026-05-14: "wir brauchen generell noch logs für externe
user, die wir uns bei problemen ansehen können ohne tief in die
powershell gehen zu müssen."

Liefert drei Bausteine:

1.:func:`install_excepthook` — globaler ``sys.excepthook`` der
   unbehandelte Python-Exceptions ins finlai-Log schreibt und einen
   Diagnose-Dialog anzeigt (mit Klick "Logs oeffnen" /
   "Diagnose-Bundle exportieren").
2.:func:`install_qt_message_handler` — fuer ``qInstallMessageHandler``,
   damit Qt-Fatal-Logs (``QtMsgType.QtFatalMsg``) ebenfalls den
   Crash-Dialog triggern.
3.:func:`export_diagnose_bundle` — ZIP mit aktuellem Log + System-
   Info (Python-Version, OS-Build, installierte Pakete via
   ``pip list``). Keine PII.

Plus eine helper-API fuer das Hilfe-Menue:

*:func:`open_log_directory` — oeffnet ``logs/`` im Explorer/Finder.
*:func:`open_current_log_file` — oeffnet die heutige Log-Datei.

Schichtzugehoerigkeit: ``core/`` — kein Tool-Import, nur stdlib +
``core.logger``.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import faulthandler
import io
import os
import platform
import sys
import traceback
import zipfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TextIO

from core.logger import get_current_log_file, get_log_dir, get_logger

log = get_logger(__name__)

#: Offen gehaltene Datei fuer ``faulthandler`` — darf NICHT vom GC eingesammelt
#: werden, sonst schreibt faulthandler beim Crash in einen toten FD.
_FAULT_LOG_FILE: TextIO | None = None

#: Wird beim Crash-Dialog-Trigger gesetzt — verhindert dass eine
#: Exception-Kette im Excepthook selbst (z. B. Qt nicht mehr verfuegbar)
#: in unendlicher Rekursion endet.
_DIALOG_DISABLED: bool = False

#: Optional vom MainWindow gesetzt — wird vom Excepthook benutzt um
#: einen modalen Crash-Dialog zu zeigen. Wenn ``None``, log-only.
_DIALOG_TRIGGER: Callable[[str, str], None] | None = None


def install_excepthook() -> None:
    """Installiert ``sys.excepthook`` fuer Python-Exceptions.

    Idempotent — kann beim App-Start mehrfach aufgerufen werden, der
    Original-Hook wird nur beim ersten Aufruf gespeichert.
    """
    if getattr(sys, "_finlai_excepthook_installed", False):
        return
    sys._finlai_original_excepthook = sys.excepthook  # type: ignore[attr-defined]
    sys.excepthook = _excepthook
    sys._finlai_excepthook_installed = True  # type: ignore[attr-defined]
    log.debug("Crash-Handler: sys.excepthook installiert")


def install_faulthandler() -> None:
    """Aktiviert ``faulthandler`` — schreibt bei einem NATIVEN Absturz
    (Segfault/Abort auf C-Ebene, z. B. Qt-Thread-Race oder SQLCipher) einen
    C-Level-Stacktrace aller Threads in ``logs/crash_native.log``.

    Der reine ``sys.excepthook`` faengt NUR Python-Exceptions; ein nativer
    Crash hinterlaesst sonst keinerlei Spur — genau der Fall beim Live-Monitor
    (Patrick-Live-Test 2026-06-27: Absturz ohne Traceback). Idempotent.
    """
    global _FAULT_LOG_FILE
    if getattr(sys, "_finlai_faulthandler_installed", False):
        return
    try:
        crash_path = get_log_dir() / "crash_native.log"
        # Append, damit aufeinanderfolgende Laeufe nicht ueberschrieben werden.
        _FAULT_LOG_FILE = crash_path.open("a", encoding="utf-8")
        _FAULT_LOG_FILE.write(
            f"\n=== faulthandler aktiv {datetime.now().isoformat(timespec='seconds')} "
            f"(PID {os.getpid()}) ===\n"
        )
        _FAULT_LOG_FILE.flush()
        faulthandler.enable(file=_FAULT_LOG_FILE, all_threads=True)
        sys._finlai_faulthandler_installed = True  # type: ignore[attr-defined]
        log.debug("Crash-Handler: faulthandler aktiv -> %s", crash_path)
    except (OSError, RuntimeError, ValueError) as exc:
        # faulthandler braucht einen echten Datei-FD; in eingebetteten/headless
        # Kontexten kann das fehlschlagen — dann eben kein nativer Dump.
        log.warning("faulthandler nicht aktivierbar: %s", type(exc).__name__)


def arm_freeze_watchdog(seconds: float, label: str = "") -> None:
    """Bewaffnet einen Einmal-Watchdog: dumpt nach ``seconds`` die Stacks ALLER
    Threads nach ``logs/crash_native.log`` — fuer FREEZES (kein Crash-Signal).

    Ein eingefrorener UI-Thread (z. B. blockierende DB-I/O) loest KEIN
    Fatal-Signal aus -> weder ``sys.excepthook`` noch das normale
    ``faulthandler.enable`` greifen. ``faulthandler.dump_traceback_later``
    feuert dagegen aus einem eigenen Thread und zeigt, WO der UI-Thread haengt.

    Vor jedem Live-Tab-Aufbau bewaffnen, nach erfolgreichem Aufbau via
:func:`disarm_freeze_watchdog` entschaerfen. Feuert der Watchdog, steht im
    Crash-Log ein vollstaendiger Thread-Dump (Patrick-Live-Test 2026-06-27:
    Netzwerkmonitor-Live friert ohne Spur ein).

    Args:
        seconds: Frist bis zum Stack-Dump (eine Sekunde Minimum sinnvoll).
        label: Optionales Kontext-Label, wird vor den Dump geschrieben.
    """
    if not getattr(sys, "_finlai_faulthandler_installed", False):
        # Ohne aktiven faulthandler-File-Handle kein zuverlaessiges Ziel.
        install_faulthandler()
    try:
        if _FAULT_LOG_FILE is not None and label:
            _FAULT_LOG_FILE.write(
                f"\n--- freeze-watchdog bewaffnet ({label}, {seconds:.0f}s) "
                f"{datetime.now().isoformat(timespec='seconds')} ---\n"
            )
            _FAULT_LOG_FILE.flush()
        faulthandler.dump_traceback_later(
            seconds, repeat=False, file=_FAULT_LOG_FILE, exit=False
        )
    except (RuntimeError, ValueError, AttributeError) as exc:
        log.warning("freeze-watchdog nicht bewaffnet: %s", type(exc).__name__)


def disarm_freeze_watchdog() -> None:
    """Entschaerft den:func:`arm_freeze_watchdog` (Aufbau war schnell genug)."""
    try:
        faulthandler.cancel_dump_traceback_later()
    except (RuntimeError, ValueError):
        pass


def install_qt_message_handler() -> None:
    """Verbindet Qt-FatalMsg mit dem Crash-Dialog.

    Qt-Fatal-Logs landen sonst nur in ``stderr`` und werden vom Python-
    Logger nicht gefangen — das ist genau der Pfad, an dem End-User
    nichts sehen ausser einem Crash.
    """
    try:
        from PySide6.QtCore import QtMsgType, qInstallMessageHandler  # noqa: PLC0415
    except ImportError:
        log.debug("Qt nicht verfuegbar — Qt-Message-Handler nicht installiert")
        return

    def _handler(msg_type, context, message: str) -> None:  # noqa: ANN001
        if msg_type == QtMsgType.QtFatalMsg:
            log.error("Qt FATAL: %s", message)
            _trigger_dialog(
                "Qt-Fehler",
                f"Schwerwiegender Qt-Fehler:\n{message}",
            )
        elif msg_type == QtMsgType.QtCriticalMsg:
            log.warning("Qt CRITICAL: %s", message)

    qInstallMessageHandler(_handler)
    log.debug("Crash-Handler: Qt-Message-Handler installiert")


def set_dialog_trigger(trigger: Callable[[str, str], None] | None) -> None:
    """Setzt die Dialog-Funktion (von MainWindow waehrend des Setups).

    Args:
        trigger: Callable ``(title, message) -> None``. ``None`` zum
            Abmelden (z. B. beim App-Close vor Qt-Teardown).
    """
    global _DIALOG_TRIGGER
    _DIALOG_TRIGGER = trigger


def open_log_directory() -> bool:
    """Oeffnet das Log-Verzeichnis im Betriebssystem-Datei-Explorer.

    Returns:
        ``True`` wenn der Aufruf erfolgreich abgesetzt wurde, sonst
        ``False`` (Verzeichnis existiert nicht / Plattform-Tool fehlt).
    """
    log_dir = get_log_dir()
    if not log_dir.exists():
        log.warning("open_log_directory: Verzeichnis fehlt: %s", log_dir)
        return False
    try:
        if sys.platform == "win32":
            os.startfile(str(log_dir))  # noqa: S606 # nosec B606
        elif sys.platform == "darwin":
            import subprocess  # noqa: PLC0415

            subprocess.run(["open", str(log_dir)], check=False)  # noqa: S603, S607
        else:
            import subprocess  # noqa: PLC0415

            subprocess.run(["xdg-open", str(log_dir)], check=False)  # noqa: S603, S607
        return True
    except OSError as exc:
        log.warning("open_log_directory fehlgeschlagen: %s", exc)
        return False


def open_current_log_file() -> bool:
    """Oeffnet die heutige Log-Datei im Standard-Editor.

    Returns:
        ``True`` bei Erfolg.
    """
    log_file = get_current_log_file()
    if not log_file.exists():
        log.warning("open_current_log_file: Datei fehlt: %s", log_file)
        return False
    try:
        if sys.platform == "win32":
            os.startfile(str(log_file))  # noqa: S606 # nosec B606
        elif sys.platform == "darwin":
            import subprocess  # noqa: PLC0415

            subprocess.run(["open", str(log_file)], check=False)  # noqa: S603, S607
        else:
            import subprocess  # noqa: PLC0415

            subprocess.run(["xdg-open", str(log_file)], check=False)  # noqa: S603, S607
        return True
    except OSError as exc:
        log.warning("open_current_log_file fehlgeschlagen: %s", exc)
        return False


def export_diagnose_bundle(target_path: Path) -> Path:
    """Erstellt ein ZIP mit aktuellem Log + System-Info ohne PII.

    Was reinkommt:
      * Heutige finlai-Log-Datei.
      * ``system_info.txt`` — Python-Version, Platform, Architektur,
        installierte Pakete (``importlib.metadata`` / ``pkg_resources``-
        Best-Effort).

    Was **NICHT** reinkommt:
      * SecureStorage-Inhalt
      * SQLCipher-DBs
      * User-Konfiguration unter ``~/.finlai/``

    Args:
        target_path: Pfad fuer das ZIP (z. B. ``Path.home /
            'NoRisk_Diagnose.zip'``).

    Returns:
        Der ``target_path`` (zur Convenience).
    """
    log_file = get_current_log_file()
    sys_info = _build_system_info()

    with zipfile.ZipFile(target_path, "w", zipfile.ZIP_DEFLATED) as zf:
        if log_file.exists():
            zf.write(log_file, arcname=log_file.name)
        zf.writestr("system_info.txt", sys_info)

    log.info("Diagnose-Bundle erstellt: %s", target_path)
    return target_path


def _build_system_info() -> str:
    """Sammelt anonyme System-Informationen fuer das Diagnose-Bundle."""
    buf = io.StringIO()
    buf.write("# NoRisk Diagnose-Bundle\n")
    buf.write(f"Erstellt: {datetime.now().isoformat(timespec='seconds')}\n\n")
    buf.write("## Python\n")
    buf.write(f"Version: {sys.version.replace(chr(10), ' ')}\n")
    buf.write(f"Executable: {sys.executable}\n\n")
    buf.write("## Plattform\n")
    buf.write(f"System: {platform.system()} {platform.release()}\n")
    buf.write(f"Build: {platform.version()}\n")
    buf.write(f"Architektur: {platform.machine()}\n")
    buf.write(f"Prozessor: {platform.processor()}\n\n")
    buf.write("## Pakete (Best-Effort)\n")
    try:
        from importlib.metadata import distributions  # noqa: PLC0415

        names = sorted(
            f"{d.metadata['Name']}=={d.version}" for d in distributions()
        )
        buf.write("\n".join(names[:200]))
    except Exception as exc:  # noqa: BLE001
        buf.write(f"(Paket-Liste fehlgeschlagen: {type(exc).__name__})")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Intern
# ---------------------------------------------------------------------------


def _excepthook(exc_type, exc_value, exc_tb) -> None:  # noqa: ANN001
    """Globaler Excepthook fuer unbehandelte Python-Exceptions."""
    formatted = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    log.error("UNBEHANDELTE EXCEPTION:\n%s", formatted)
    _trigger_dialog(
        f"Unbehandelter Fehler: {exc_type.__name__}",
        f"{exc_type.__name__}: {exc_value}\n\nDetails in der Log-Datei.",
    )
    # Original-Hook ggf. weiter aufrufen (z. B. Pytest's eigener Hook).
    orig = getattr(sys, "_finlai_original_excepthook", None)
    if orig and orig is not _excepthook:
        try:
            orig(exc_type, exc_value, exc_tb)
        except Exception:  # noqa: BLE001
            pass


def _trigger_dialog(title: str, message: str) -> None:
    """Ruft den Dialog-Trigger auf — defensiv gegen Rekursion."""
    global _DIALOG_DISABLED
    if _DIALOG_DISABLED:
        return
    if _DIALOG_TRIGGER is None:
        return
    _DIALOG_DISABLED = True
    try:
        _DIALOG_TRIGGER(title, message)
    except Exception as exc:  # noqa: BLE001
        log.error("Crash-Dialog selbst fehlgeschlagen: %s", type(exc).__name__)
    finally:
        _DIALOG_DISABLED = False


__all__ = [
    "arm_freeze_watchdog",
    "disarm_freeze_watchdog",
    "export_diagnose_bundle",
    "install_excepthook",
    "install_faulthandler",
    "install_qt_message_handler",
    "open_current_log_file",
    "open_log_directory",
    "set_dialog_trigger",
]
