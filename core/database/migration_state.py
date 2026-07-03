"""migration_state — JSON-State-File fuer Bestandsdaten-Migration §3.6).

Stellt die persistente State-Verwaltung fuer die Bestandsdaten-Migration
(Subtask 3) bereit. Migration ist potentiell unterbrechbar (App-Crash,
Stromausfall) und muss crash-safe wieder aufnehmbar sein. Der State liegt
in einer einzigen JSON-Datei ``~/.finlai/migration-state.json`` (
 §3.6 fuer das Schema).

Public-API:

*:func:`set_state` — atomar schreiben (``.tmp`` + ``fsync`` + ``os.replace``).
*:func:`get_state` — laden, ``None`` bei fehlender Datei oder
  Schema-Version-Mismatch.
*:func:`clear_state` — loeschen (no-op wenn nicht existiert).
*:func:`is_state_stale` — Stale-State-Detection (>24 h ohne
  ``completed_at``), siehe §3.6 / Test-ID I-3.

Atomares Schreiben: ``.tmp``-Datei + ``flush`` + ``os.fsync`` +
``os.replace``. ``os.replace`` ist atomar auf POSIX und Windows. Bei
Schreibfehler wird die ``.tmp``-Datei aufgeraeumt — kein
halb-geschriebener Zustand bleibt zurueck.

Permissions: 0600 auf POSIX. Windows ignoriert ``chmod`` leise (kein
Fehler) — die Datei ist dort durch User-Profile-ACL geschuetzt.

Schichtzugehoerigkeit: ``core/database/`` (Migrations-Infrastruktur,
kein PySide6-Import — testbar ohne GUI).

Author: Patrick Riederich
Version: 1.0 (Subtask 3 Schritt 3.1 §3.6)
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

from core.finlai_paths import finlai_dir

log = logging.getLogger(__name__)

#: Pfad zur Migration-State-Datei im User-Profile.
#:
#: Crash-safe: wird via:func:`set_state` immer atomar (``.tmp`` +
#: ``os.replace``) geschrieben.
_MIGRATION_STATE_FILE: Final[Path] = finlai_dir() / "migration-state.json"

#: Schema-Version des State-Files.
#:
#: Wird vom Caller (Migrations-Code) im State-dict gesetzt.
#::func:`get_state` prueft beim Laden — bei Mismatch wird ``None``
#: zurueckgegeben und der Caller startet die Migration neu (
#: MIGRATION_TEST_PLAN S-3).
_STATE_SCHEMA_VERSION: Final[int] = 1

#: Schwellwert fuer Stale-State-Detection (:func:`is_state_stale`).
_STALE_AGE_HOURS: Final[int] = 24


def _state_file_path(app_id: str | None = None) -> Path:
    """Liefert den Pfad zur (app-spezifischen) Migration-State-Datei.

    App-scoped (``migration-state-<app_id>.json``), damit die Migration EINER
    App nicht die Selbstheilung einer ANDEREN App blockiert. Der Incident
    2026-06-02 entstand, weil eine Schwester-App ``completed_at`` in die GLOBAL geteilte
    Datei schrieb und norisk daraufhin seine eigene Migration uebersprang
    (no-op) — wodurch die unlesbaren norisk-DBs nie nach ``.unrecoverable``
    geheilt, sondern beim ersten Open zum Absturz fuehrten.

    Der Verzeichnisanteil kommt aus:data:`_MIGRATION_STATE_FILE` (damit
    Tests, die die Konstante auf ein tmp-Verzeichnis monkeypatchen, weiter
    greifen); nur der Dateiname wird app-spezifisch.

    Args:
        app_id: App-Bezeichner, oder ``None`` fuer die globale Legacy-Datei
            (nur Tests / Kontext ohne App-Boot).

    Returns:
        Pfad zur State-Datei.
    """
    if app_id:
        return _MIGRATION_STATE_FILE.with_name(
            f"migration-state-{app_id}.json"
        )
    return _MIGRATION_STATE_FILE


def set_state(state: dict[str, Any], app_id: str | None = None) -> None:
    """Schreibt den State atomar nach:data:`_MIGRATION_STATE_FILE`.

    Atomares Schreiben (analog ``KeyManager.initialize`` aus Subtask 1):
    ``.tmp`` + ``flush`` + ``os.fsync`` + ``os.replace``. ``os.replace``
    ist atomar auf Windows + POSIX.

    Permissions: 0600 auf POSIX. ``chmod`` schlaegt auf Windows leise
    fehl (durch:func:`contextlib.suppress` abgefangen).

    Caller verantwortet Schema-Konformitaet (siehe §3.6). Diese
    Funktion schreibt den dict unveraendert.

    Args:
        state: State-dict mit mindestens dem Feld ``schema_version``.
:func:`get_state` rejected spaeter beim Laden, falls die
            Version nicht:data:`_STATE_SCHEMA_VERSION` entspricht.

    Raises:
        OSError: Filesystem-Schreibfehler (Disk voll, Permissions). Die
            ``.tmp``-Datei wird in diesem Fall aufgeraeumt — die
            existierende Datei bleibt unangetastet.
    """
    state_file = _state_file_path(app_id)
    state_file.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = state_file.with_name(state_file.name + ".tmp")
    payload = json.dumps(state, indent=2, ensure_ascii=False).encode(
        "utf-8"
    )
    try:
        with open(tmp_path, "wb") as fp:
            fp.write(payload)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp_path, state_file)
    except OSError:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise

    # Permissions 0600 (Windows ignoriert es leise — kein Fehler).
    with contextlib.suppress(OSError, NotImplementedError):
        state_file.chmod(0o600)


def get_state(app_id: str | None = None) -> dict[str, Any] | None:
    """Liefert den persistierten State oder ``None``.

    ``None``-Faelle:
        - Datei existiert nicht (frischer Start).
        - JSON kann nicht geparsed werden (log.warning).
        - Top-Level ist kein dict (log.warning).
        - ``schema_version`` weicht von:data:`_STATE_SCHEMA_VERSION` ab
          (log.warning — siehe MIGRATION_TEST_PLAN S-3).

    In allen ``None``-Faellen interpretiert der Caller (Migrations-Code)
    das als "Migration startet neu".

    Returns:
        Der geladene State-dict, oder ``None`` falls keine valide
        State-Datei vorhanden ist.

    Raises:
        OSError: Filesystem-Lesefehler (Permissions). NICHT wenn Datei
            fehlt — das ist kein Fehler, sondern frischer Start.
    """
    state_file = _state_file_path(app_id)
    if not state_file.exists():
        return None

    raw = state_file.read_bytes()

    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        log.warning(
            "migration-state.json kann nicht geparsed werden (%s). "
            "Wird ignoriert — Migration startet neu.",
            exc,
        )
        return None

    if not isinstance(state, dict):
        log.warning(
            "migration-state.json hat unerwartetes Top-Level-Format "
            "(%s, erwartet dict). Wird ignoriert — Migration startet neu.",
            type(state).__name__,
        )
        return None

    schema_version = state.get("schema_version")
    if schema_version != _STATE_SCHEMA_VERSION:
        log.warning(
            "migration-state.json hat schema_version=%r (erwartet %r). "
            "Wird ignoriert — Migration startet neu.",
            schema_version,
            _STATE_SCHEMA_VERSION,
        )
        return None

    return state


def clear_state(app_id: str | None = None) -> None:
    """Loescht:data:`_MIGRATION_STATE_FILE` (no-op wenn nicht existiert).

    Wird typisch nach erfolgreich abgeschlossener Migration aufgerufen.
    Beim naechsten App-Start ist dann kein State mehr da → Migration
    startet nicht erneut (Idempotenz).
    """
    with contextlib.suppress(FileNotFoundError):
        _state_file_path(app_id).unlink()


def is_state_stale(state: dict[str, Any]) -> bool:
    """Prueft ob der State stale ist (Migration unterbrochen, > 24 h alt).

    Stale-Definition §3.6 / Test-ID I-3):
        - ``started_at`` ist gesetzt und parsable.
        - ``completed_at`` ist ``None`` (Migration noch nicht fertig).
        - Differenz ``now`` - ``started_at`` ist >=:data:`_STALE_AGE_HOURS`.

    Caller-Konvention: bei stale State log.warning + Resume trotzdem
    (Resume aus ``pending``-Status ist sicher — kein Auto-Reset).

    Args:
        state: State-dict aus:func:`get_state`.

    Returns:
        ``True`` wenn der State alt und nicht abgeschlossen ist.
    """
    started_at = state.get("started_at")
    completed_at = state.get("completed_at")

    if not started_at or completed_at is not None:
        return False

    try:
        started_dt = datetime.fromisoformat(started_at)
    except (TypeError, ValueError):
        # Unparsable timestamp — konservativ: nicht stale, damit der
        # Caller den Datei-Inhalt unangetastet laesst und aus get_state
        # bereits ``None`` (oder eine Logwarn) bekommen hat.
        return False

    if started_dt.tzinfo is None:
        # Defensiver Default: naive datetime als UTC interpretieren.
        started_dt = started_dt.replace(tzinfo=UTC)

    age = datetime.now(tz=UTC) - started_dt
    return age >= timedelta(hours=_STALE_AGE_HOURS)
