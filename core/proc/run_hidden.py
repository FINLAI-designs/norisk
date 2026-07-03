"""
run_hidden — zentraler ``subprocess.run``-Wrapper ohne Konsolen-Flackern.

Auf Windows oeffnet jeder ``powershell``/``winget``/``wmic``/``cmd``-Start
ohne ``creationflags=CREATE_NO_WINDOW`` kurz ein schwarzes Konsolenfenster.
Bei Scans mit vielen Subprozessen (Hardening-Probe, Patch-Inventar) ist das
ein sichtbares Flackern.:func:`run_hidden` unterdrueckt dieses
Fenster zentral — und erzwingt zugleich die sichere Aufruf-Form.

**Security-Vorgaben (verbindlich):**

- **LIST-args erzwungen:** ``cmd`` MUSS eine Sequenz von Argumenten sein
  (``list``/``tuple``), niemals ein String. Ein String-Command wuerde unter
  Windows von ``subprocess`` an die Shell delegiert (Injection-Flaeche) —
:func:`run_hidden` lehnt das mit:class:`TypeError` ab.
- **Niemals ``shell=True``:** Wird ``shell=True`` uebergeben, wirft
:func:`run_hidden`:class:`ValueError`.

**Plattform-Verhalten:**

- Windows: ``creationflags |= CREATE_NO_WINDOW`` und ein
  ``STARTUPINFO`` mit ``STARTF_USESHOWWINDOW`` + ``SW_HIDE`` werden gesetzt.
- Nicht-Windows: keine Flags, keine ``STARTUPINFO`` — der Aufruf ist ein
  reiner Passthrough an:func:`subprocess.run`.

Alle weiteren keyword-Argumente (``timeout``, ``capture_output``, ``text``,
``encoding``, ``errors``, ``check``...) werden unveraendert an
:func:`subprocess.run` durchgereicht. Rueckgabe ist die unveraenderte
:class:`subprocess.CompletedProcess` — die Parsing-Schnittstelle der
Aufrufer bleibt damit identisch zum direkten ``subprocess.run``.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from typing import Any

_WINDOWS = sys.platform == "win32"

#: ``CREATE_NO_WINDOW`` ist nur auf Windows in:mod:`subprocess` definiert.
#: Auf anderen Plattformen ist der Wert irrelevant (wird nie verwendet).
_CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _build_hidden_startupinfo() -> Any:
    """Erzeugt ein ``STARTUPINFO`` mit verstecktem Fenster (nur Windows).

    Returns:
        Ein:class:`subprocess.STARTUPINFO` mit ``STARTF_USESHOWWINDOW`` und
        ``wShowWindow = SW_HIDE`` — doppelter Gurt zu ``CREATE_NO_WINDOW``
        fuer GUI-Subprozesse, die das Flag allein ignorieren wuerden.
    """
    info = subprocess.STARTUPINFO()  # type: ignore[attr-defined]
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # type: ignore[attr-defined]
    info.wShowWindow = subprocess.SW_HIDE  # type: ignore[attr-defined]
    return info


def run_hidden(
    cmd: Sequence[str],
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    """Fuehrt einen Subprozess ohne aufflackerndes Konsolenfenster aus.

    Plattformneutraler Ersatz fuer:func:`subprocess.run`: identische
    Parsing-Schnittstelle (Rueckgabe:class:`subprocess.CompletedProcess`),
    aber auf Windows ohne kurzes schwarzes Konsolenfenster.

    Args:
        cmd: Argument-Liste (``list``/``tuple``). **Kein String** — ein
            String-Command wuerde an die Shell gehen und ist daher verboten.
        **kwargs: Werden unveraendert an:func:`subprocess.run` durchgereicht
            (z.B. ``timeout``, ``capture_output``, ``text``, ``encoding``,
            ``errors``, ``check``). ``shell`` ist nicht erlaubt.

    Returns:
        Die:class:`subprocess.CompletedProcess` von:func:`subprocess.run`.

    Raises:
        TypeError: Wenn ``cmd`` ein String (oder Bytes) statt einer
            Argument-Liste ist.
        ValueError: Wenn ``shell=True`` uebergeben wird.
    """
    if isinstance(cmd, (str, bytes)):
        raise TypeError(
            "run_hidden erwartet eine Argument-Liste, keinen String "
            f"(shell-Injection-Schutz) — erhalten: {type(cmd).__name__}"
        )
    if kwargs.get("shell"):
        raise ValueError("run_hidden erlaubt kein shell=True (Injection-Schutz)")

    if _WINDOWS:
        # CREATE_NO_WINDOW additiv zu evtl. vom Aufrufer gesetzten Flags.
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | _CREATE_NO_WINDOW
        # STARTUPINFO nur setzen, wenn der Aufrufer keine eigene mitgibt.
        if kwargs.get("startupinfo") is None:
            kwargs["startupinfo"] = _build_hidden_startupinfo()

    # shell-Default ist False; cmd ist garantiert eine Liste → kein Shell-Pfad.
    return subprocess.run(cmd, shell=False, **kwargs)  # noqa: S603


__all__ = ["run_hidden"]
