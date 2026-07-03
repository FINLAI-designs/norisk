"""
patch_monitor.onboarding_marker — User-Entscheidung fuer das winget-Modul-Onboarding.

Bug-Fix-Sprint C-3 (Option D, siehe interne Entscheidungs-Doku, C-3-Sektion). Das Marker-File ``~/.finlai/winget_module_onboarding.json`` haelt
die einmal getroffene User-Entscheidung fest, damit der Patch-Monitor beim
zweiten Open nicht erneut fragt — ausser der User hat explizit
"diesmal ueberspringen" gewaehlt.

Schema v1::

    {
      "schema_version": 1,
      "decided_at": "2026-05-07T14:23:00+00:00",
      "decision": "installed" | "skip_session" | "never"
    }

Forward-compat: Marker mit ``schema_version`` >:data:`SCHEMA_VERSION` werden
behandelt wie kein Marker (User darf neu entscheiden).

Architektur-Hinweis: Der Marker enthaelt keine sensitiven Daten. Daher direkter
JSON-Write ohne Crypto-Pfad — analog ``~/.finlai/license.json``.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final

from core.finlai_paths import finlai_dir
from core.logger import get_logger

log = get_logger(__name__)

#: Pfad zum Marker-File. Default unter Windows + Unix einheitlich
#: ``~/.finlai/winget_module_onboarding.json``.
MARKER_FILE_DEFAULT: Final[Path] = (
    finlai_dir() / "winget_module_onboarding.json"
)

#: Aktuelle Schema-Version. Beim Schreiben immer dieser Wert.
SCHEMA_VERSION: Final[int] = 1


class OnboardingDecision(StrEnum):
    """User-Entscheidung im Onboarding-Dialog (Bug-Fix-Sprint C-3, Option D).

    -:attr:`INSTALLED`: ``Install-Module``-Aufruf war erfolgreich, der
      Detection-Cache liefert ``ModuleStatus.AVAILABLE``. Onboarding ist
      abgeschlossen.
    -:attr:`SKIP_SESSION`: User hat "diesmal ueberspringen" gewaehlt (oder den
      Dialog per X geschlossen). Seit wird der modale Dialog **nicht**
      erneut gezeigt — stattdessen erinnert ein kritisches Homescreen-Task
      (``onboarding_orchestrator.create_scan_reminder_task``) an die Einrichtung.
      Der Enum-Wert bleibt ``"skip_session"`` (kein Schema-Bruch fuer
      Bestands-Marker).
    -:attr:`NEVER`: User hat "nie wieder fragen" gewaehlt. Patch-Monitor
      laeuft im Fallback-Pfad ohne Erinnerung (kein Dialog, kein Task).
    """

    INSTALLED = "installed"
    SKIP_SESSION = "skip_session"
    NEVER = "never"


@dataclass(frozen=True)
class OnboardingMarker:
    """Persistierte User-Entscheidung mit Zeitstempel.

    Attributes:
        schema_version: Schema-Version dieser Marker-Instanz. Beim Lesen
            kann es eine hoehere Version aus zukuenftigen App-Versionen
            sein —:func:`load_marker` filtert solche faelle bereits.
        decided_at: UTC-Zeitstempel der Entscheidung.
        decision: User-Entscheidung (:class:`OnboardingDecision`).
    """

    schema_version: int
    decided_at: datetime
    decision: OnboardingDecision


def load_marker(path: Path | None = None) -> OnboardingMarker | None:
    """Liest den Marker, falls vorhanden und gueltig.

    Args:
        path: Optional alternativer Pfad (Tests). Default
:data:`MARKER_FILE_DEFAULT`.

    Returns:
:class:`OnboardingMarker` bei gueltigem Marker, sonst ``None``.

    Behandelt fehlende Datei, JSON-Parse-Fehler, fehlende Felder, unbekannte
    Decision-Werte und Schema-Versionen >:data:`SCHEMA_VERSION` jeweils als
    "kein Marker" — keine Exception nach aussen.
    """
    target = path if path is not None else MARKER_FILE_DEFAULT
    if not target.is_file():
        return None
    try:
        raw = target.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("onboarding marker unreadable (%s): %s", target, exc)
        return None
    if not isinstance(data, dict):
        log.warning("onboarding marker is not a JSON object (%s)", target)
        return None
    try:
        schema_version = int(data["schema_version"])
        decided_at_raw = data["decided_at"]
        decision_raw = data["decision"]
    except (KeyError, TypeError, ValueError) as exc:
        log.warning("onboarding marker malformed (%s): %s", target, exc)
        return None
    if schema_version > SCHEMA_VERSION:
        log.warning(
            "onboarding marker schema_version=%s > %s, treating as absent",
            schema_version,
            SCHEMA_VERSION,
        )
        return None
    try:
        decision = OnboardingDecision(decision_raw)
    except ValueError:
        log.warning("onboarding marker has unknown decision=%r", decision_raw)
        return None
    try:
        decided_at = datetime.fromisoformat(decided_at_raw)
    except (TypeError, ValueError):
        log.warning(
            "onboarding marker has invalid decided_at=%r", decided_at_raw
        )
        return None
    return OnboardingMarker(
        schema_version=schema_version,
        decided_at=decided_at,
        decision=decision,
    )


def save_marker(
    decision: OnboardingDecision,
    *,
    path: Path | None = None,
    now: datetime | None = None,
) -> OnboardingMarker:
    """Schreibt einen neuen Marker (atomar via temp + rename).

    Args:
        decision: User-Entscheidung.
        path: Optional alternativer Pfad (Tests). Default
:data:`MARKER_FILE_DEFAULT`.
        now: Optional UTC-Zeitstempel (Tests). Default
            ``datetime.now(timezone.utc)``.

    Returns:
        Den geschriebenen:class:`OnboardingMarker`.

    Raises:
        OSError: Wenn Verzeichnis nicht angelegt oder Datei nicht
            geschrieben werden kann. Caller behandelt das als "Marker
            konnte nicht gespeichert werden, naechstes Mal fragen wir
            wieder" — kein App-Crash.
    """
    target = path if path is not None else MARKER_FILE_DEFAULT
    timestamp = now if now is not None else datetime.now(UTC)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "decided_at": timestamp.isoformat(),
        "decision": decision.value,
    }
    # Atomar via temp-File + os.replace. Verhindert halb-geschriebene Dateien
    # bei Crash und ist auf POSIX atomar gegen Concurrent-Reader; auf Windows
    # ist os.replace seit Python 3.3 ebenfalls atomar (MoveFileExW mit
    # MOVEFILE_REPLACE_EXISTING).
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=target.parent,
        prefix=".onboarding-",
        suffix=".tmp",
        delete=False,
    ) as tmp:
        json.dump(payload, tmp, indent=2)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    # 0600 vor dem Rename (Windows ignoriert chmod weitgehend; harmlos).
    try:
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        log.warning("could not chmod onboarding marker: %s", exc)
    os.replace(tmp_path, target)
    return OnboardingMarker(
        schema_version=SCHEMA_VERSION,
        decided_at=timestamp,
        decision=decision,
    )


def wipe_marker(path: Path | None = None) -> None:
    """Loescht den Marker, falls vorhanden. Idempotent."""
    target = path if path is not None else MARKER_FILE_DEFAULT
    try:
        target.unlink(missing_ok=True)
    except OSError as exc:
        log.warning("could not wipe onboarding marker (%s): %s", target, exc)
