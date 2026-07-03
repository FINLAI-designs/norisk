"""
core.proc — Geteilte Subprozess-Hilfen.

Enthaelt:func:`run_hidden` — den zentralen Wrapper um
:func:`subprocess.run`, der auf Windows das kurz aufflackernde
Konsolenfenster unterdrueckt (``CREATE_NO_WINDOW`` + ``SW_HIDE``).

Hintergrund: Jeder ``powershell``/``winget``/``wmic``-Start ohne
``creationflags=CREATE_NO_WINDOW`` reisst auf Windows kurz ein schwarzes
Konsolenfenster auf — bei Scans mit vielen Subprozessen ein sichtbares
Flackern. ``run_hidden`` buendelt die korrekte (und sichere) Aufruf-Form
an einer Stelle.
"""

from __future__ import annotations

from core.proc.run_hidden import run_hidden

__all__ = ["run_hidden"]
