"""finlai_paths — zentrale Aufloesung der FINLAI-Datenwurzel (``~/.finlai``).

Single Source of Truth fuer das Verzeichnis, in dem alle persistenten FINLAI-
Daten liegen (Schluessel, DBs, Settings, Lizenz, Audit, Fingerprint-Cache).
Ersetzt die zuvor ~18-fach duplizierte Konstante ``Path.home / ".finlai"``.

Aufloesungs-Reihenfolge (hoechste Prioritaet zuerst):

1. Laufzeit-Override via:func:`set_finlai_home` (nur Tests/In-Process-Isolation).
2. Umgebungsvariable ``FINLAI_HOME`` (Test-/Release-/E2E-Isolation per Subprozess).
3. Default ``~/.finlai`` (Produktion — unveraendertes Verhalten).

**Test-/Release-Isolation.** Destruktive E2E-/Release-Prozeduren
MUESSEN ``FINLAI_HOME`` auf ein Wegwerf-Verzeichnis setzen, damit das echte
Profil nie gelesen oder ueberschrieben wird. Der Incident vom 2026-06-02
(Verlust des DEK → alle norisk-DBs unlesbar) entstand genau dadurch, dass das
echte ``~/.finlai`` mangels Override direkt mutiert wurde.

Default-Pfad bleibt ``~/.finlai`` — **keine** Datenmigration, kein Standort-
wechsel fuer Bestands-Installationen.

Schichtzugehoerigkeit: ``core/`` (Shared Utility, kein PySide6-Import,
framework-agnostisch). Modul-State-Pattern analog:mod:`core.database.db_context`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

#: Name der Umgebungsvariable fuer den Daten-Dir-Override.
_ENV_VAR: Final[str] = "FINLAI_HOME"

#: Default-Verzeichnisname unterhalb von ``Path.home``.
_DEFAULT_DIRNAME: Final[str] = ".finlai"

#: Laufzeit-Override (nur Tests). Modul-State analog ``db_context`` — NICHT
#: fuer Produktion gedacht. ``None`` = kein Override aktiv.
_override: Path | None = None


def finlai_home_override() -> Path | None:
    """Liefert den aktiven FINLAI_HOME-Override (Laufzeit > Env), sonst ``None``.

    ``None`` bedeutet: es gilt der Default ``~/.finlai`` (Produktion). Anders als
:func:`finlai_dir` (das immer einen Pfad liefert) unterscheidet diese Funktion,
    ob eine **explizite** Isolation aktiv ist. Genutzt, um eine aktive Test-/
    Release-Isolation an Subprozesse weiterzureichen (z. B. den elevated Collector-
    Install → geplante Aufgabe), damit diese im selben Profil arbeiten statt still
    ins echte ``~/.finlai`` zu schreiben.

    Returns:
        Den Override-Pfad, oder ``None`` wenn der Default gilt.
    """
    if _override is not None:
        return _override
    env = os.environ.get(_ENV_VAR)
    if env:
        return Path(env)
    return None


def finlai_dir() -> Path:
    """Liefert die FINLAI-Datenwurzel.

    Aufloesung: Laufzeit-Override > ``FINLAI_HOME`` > ``~/.finlai``. Legt das
    Verzeichnis NICHT an — Caller erzeugen ihre Subpfade bei Bedarf selbst
    (``mkdir(parents=True, exist_ok=True)``).

    Returns:
        Pfad zur Datenwurzel.
    """
    override = finlai_home_override()
    return override if override is not None else Path.home() / _DEFAULT_DIRNAME


def set_finlai_home(path: Path | str | None) -> None:
    """Setzt einen Laufzeit-Override fuer die Datenwurzel (Tests).

    Wirkt nur auf Pfade, die:func:`finlai_dir` **nach** diesem Aufruf
    auswerten. Modul-Konstanten anderer Module, die ``finlai_dir`` bereits
    beim Import gebunden haben, bleiben unveraendert — fuer In-Process-Tests
    diese Konstanten weiterhin gezielt monkeypatchen.

    Args:
        path: Zielverzeichnis, oder ``None`` um den Override zu loeschen.
    """
    global _override
    _override = Path(path) if path is not None else None
