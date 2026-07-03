"""elevation — Windows-UAC-Helfer fuer rechte-pflichtige Aktionen Phase C).

Stellt zwei Funktionen bereit:

*:func:`is_admin` — prueft, ob der aktuelle Prozess mit Administrator-Rechten
  laeuft.
*:func:`relaunch_elevated` — startet die laufende Anwendung per
  ``ShellExecute "runas"`` mit einem zusaetzlichen CLI-Flag neu und loest dabei
  genau eine UAC-Abfrage aus. Wird genutzt, um die elevated-pflichtige
  Registrierung der Collector-Aufgabe aus der (unelevated) GUI heraus
  anzustossen; danach laeuft die geplante Aufgabe ohne weiteren Prompt.

Schicht: ``core/`` — geteiltes Utility, keine Tool-Imports. ``is_admin`` ist
bewusst hier (statt aus ``tools.network_monitor.data``) definiert, weil ``core``
nicht von ``tools`` abhaengen darf (hexagonale Schichtregel).

Nur Windows: Auf anderen Plattformen liefert ``is_admin`` ``False`` und
``relaunch_elevated`` wirft ``RuntimeError``.
"""

from __future__ import annotations

import sys
from pathlib import Path

from core.logger import get_logger

log = get_logger(__name__)

#: ShellExecute liefert Rueckgabewerte <= 32 als Fehlercode (WinAPI-Konvention).
_SHELL_EXECUTE_MIN_SUCCESS = 32


def is_admin() -> bool:
    """Prueft, ob der aktuelle Prozess Administrator-Rechte besitzt.

    Returns:
        True bei elevated Windows-Prozess, sonst False (auch auf
        Nicht-Windows-Plattformen).
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError, AttributeError) as exc:
        log.warning("Admin-Status nicht ermittelbar: %s", exc)
        return False


def _elevation_target() -> tuple[str, str]:
    """Ermittelt ``(exe, basis_argumente)`` fuer einen elevated Neustart.

    Returns:
        Im gepackten Build (``sys.frozen``) die Anwendungs-Exe ohne
        Basis-Argumente; im Dev-Betrieb der aktuelle Interpreter
        (``pythonw`` bevorzugt, kein Konsolenfenster) plus das laufende
        Entry-Skript als gequotetes Argument.
    """
    if getattr(sys, "frozen", False):
        return sys.executable, ""
    interpreter = Path(sys.executable)
    pythonw = interpreter.with_name("pythonw.exe")
    exe = str(pythonw if pythonw.exists() else interpreter)
    script = Path(sys.argv[0]).resolve()
    return exe, f'"{script}"'


def _quote_arg(arg: str) -> str:
    """Quotet ein CLI-Argument, falls es Whitespace enthaelt (z. B. Pfade).

    Bereits gequotete Argumente bleiben unveraendert. Flags ohne Whitespace
    (``--install-collector-task``) werden nicht gequotet.
    """
    if not arg or (arg.startswith('"') and arg.endswith('"')):
        return arg
    return f'"{arg}"' if any(c.isspace() for c in arg) else arg


def relaunch_elevated(flag: str, *extra_args: str) -> bool:
    """Startet die laufende Anwendung elevated mit ``flag`` neu (eine UAC-Abfrage).

    Args:
        flag: CLI-Flag, das der elevated Prozess auswertet
            (z. B. ``"--install-collector-task"``).
        *extra_args: Optionale Zusatz-Argumente, die hinter ``flag`` angehaengt
            werden (z. B. ``"--finlai-home", "<dir>"`` zur Profil-Weitergabe).
            Argumente mit Whitespace werden automatisch gequotet.

    Returns:
        True, wenn der elevated Prozess gestartet wurde (User hat die
        UAC-Abfrage bestaetigt); False, wenn sie abgelehnt wurde oder der
        Start fehlschlug.

    Raises:
        RuntimeError: Wenn die Funktion nicht unter Windows aufgerufen wird.
    """
    if sys.platform != "win32":
        raise RuntimeError("Elevation wird nur unter Windows unterstuetzt.")
    import ctypes

    exe, base_args = _elevation_target()
    parts = [base_args, flag, *(_quote_arg(a) for a in extra_args)]
    params = " ".join(p for p in parts if p).strip()
    work_dir = str(Path(exe).parent)
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", exe, params, work_dir, 1
    )
    if result <= _SHELL_EXECUTE_MIN_SUCCESS:
        log.info(
            "Elevation abgelehnt oder fehlgeschlagen (ShellExecute=%s, flag=%s).",
            result,
            flag,
        )
        return False
    log.info("Elevierter Neustart gestartet (flag=%s).", flag)
    return True
