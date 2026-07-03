"""
login_attempts — Persistenter Brute-Force-Schutz für den Login.

Speichert pro Username eine Liste der Fehlversuch-Zeitstempel in
``~/.finlai/login_attempts.json``. Nach:data:`MAX_ATTEMPTS_PER_WINDOW`
Fehlversuchen innerhalb von:data:`WINDOW_MINUTES` wird der User für
:data:`LOCKOUT_MINUTES` gesperrt — auch über App-Neustart hinweg.

Der bisherige In-Memory-Counter (``LoginWindow._failed_attempts`` mit
Limit 3) bleibt als zusätzliche UX-Schranke bestehen: 3 Fehlversuche im
laufenden Dialog beenden die App. Diese Datei ergänzt das um den Schutz
gegen Brute-Force-Skripte, die ``users.json`` lesen und beliebig oft
neu starten könnten.

Bei erfolgreichem Login wird die Versuchs-Historie des Users geleert.

Audit-Events (in:mod:`core.audit_log`):
    ``LOGIN_FAILED`` — jeder fehlgeschlagene Versuch (bereits vorhanden).
    ``LOGIN_LOCKED`` — wird vom GUI ausgelöst, wenn die Schranke greift.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from core.finlai_paths import finlai_dir
from core.logger import get_logger

log = get_logger(__name__)

_FINLAI_DIR = finlai_dir()
_ATTEMPTS_FILE = _FINLAI_DIR / "login_attempts.json"

# Konfiguration der Schranke. Effekt: nach MAX_ATTEMPTS_PER_WINDOW
# Fehlversuchen innerhalb WINDOW_MINUTES wird der User fuer
# LOCKOUT_MINUTES gesperrt. Werte konservativ — Pre-Launch-Hardening
# soll Brute-Force gegen lokal lesbare bcrypt-Hashes verteuern, ohne
# legitime Tipper hart zu treffen.
MAX_ATTEMPTS_PER_WINDOW: int = 5
WINDOW_MINUTES: int = 30
LOCKOUT_MINUTES: int = 30


def _load_all() -> dict[str, list[str]]:
    """Lädt die JSON-Datei mit allen User → Timestamp-Listen."""
    if not _ATTEMPTS_FILE.exists():
        return {}
    try:
        data = json.loads(_ATTEMPTS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("login_attempts.json nicht lesbar: %s", exc)
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _save_all(data: dict[str, list[str]]) -> None:
    """Schreibt die Datei atomar. Schreibfehler werden geloggt, nicht propagiert.

    Sec-5-Fix (Code-Review 2026-05-19): vorher direkter ``write_text`` —
    bei abgebrochenem Schreibvorgang (Stromausfall, Kill, Disk-Full mitten
    im Schreiben) konnte die Datei korrupt bleiben und beim naechsten
    ``_load_all`` zu ``json.JSONDecodeError`` fuehren. Atomarer Write via
    Temp-Datei + ``Path.replace`` ist POSIX-atomar und auf Windows
    halt-mehr-atomar als Direkt-Schreiben.
    """
    try:
        _FINLAI_DIR.mkdir(parents=True, exist_ok=True)
        tmp = _ATTEMPTS_FILE.with_suffix(_ATTEMPTS_FILE.suffix + ".tmp")
        tmp.write_text(
            json.dumps(data, ensure_ascii=False), encoding="utf-8"
        )
        tmp.replace(_ATTEMPTS_FILE)
    except OSError as exc:
        log.warning("login_attempts.json kann nicht geschrieben werden: %s", exc)


def _within_window(timestamps: list[str], window: timedelta) -> list[datetime]:
    """Filtert ISO-Timestamps auf die letzten ``window``-Minuten."""
    cutoff = datetime.now() - window
    valid: list[datetime] = []
    for ts in timestamps:
        try:
            t = datetime.fromisoformat(ts)
        except (TypeError, ValueError):
            continue
        if t >= cutoff:
            valid.append(t)
    return valid


def is_locked_out(username: str) -> tuple[bool, int]:
    """Prüft, ob ein User aktuell gesperrt ist.

    Sperre greift, sobald >=:data:`MAX_ATTEMPTS_PER_WINDOW` Fehlversuche
    innerhalb von:data:`WINDOW_MINUTES` registriert wurden. Die Sperre
    läuft:data:`LOCKOUT_MINUTES` ab dem letzten Fehlversuch.

    Args:
        username: Benutzername (Klein-/Grossschreibung relevant — wir
                  stellen pro tatsaechlich eingegebenem Wert nach).

    Returns:
        Tupel ``(locked, seconds_remaining)``. ``locked=False`` heisst
        ``seconds_remaining == 0`` — Login ist erlaubt.
    """
    if not username:
        return False, 0

    data = _load_all()
    timestamps = data.get(username, [])
    if not timestamps:
        return False, 0

    valid = _within_window(timestamps, timedelta(minutes=WINDOW_MINUTES))
    if len(valid) < MAX_ATTEMPTS_PER_WINDOW:
        return False, 0

    last = max(valid)
    unlock_at = last + timedelta(minutes=LOCKOUT_MINUTES)
    now = datetime.now()
    if now >= unlock_at:
        return False, 0
    return True, int((unlock_at - now).total_seconds())


def record_failed_attempt(username: str) -> None:
    """Speichert einen fehlgeschlagenen Login-Versuch für ``username``.

    Behält pro User maximal ``MAX_ATTEMPTS_PER_WINDOW * 2`` Einträge in
    der Datei — das reicht für die Schwellwert-Prüfung und verhindert,
    dass die Datei bei einem Brute-Force-Sturm unbegrenzt wächst.
    """
    if not username:
        return

    data = _load_all()
    timestamps = data.get(username, [])
    valid = _within_window(timestamps, timedelta(minutes=WINDOW_MINUTES))
    valid_iso = [t.isoformat() for t in valid]
    valid_iso.append(datetime.now().isoformat())
    data[username] = valid_iso[-(MAX_ATTEMPTS_PER_WINDOW * 2):]
    _save_all(data)


def clear_attempts(username: str) -> None:
    """Löscht die Versuchs-Historie eines Users (nach erfolgreichem Login).

    Damit greift die Sperre nicht mehr, sobald sich der User legitimiert
    einmal angemeldet hat — auch wenn vorher Fehlversuche im Window lagen.
    """
    if not username:
        return
    data = _load_all()
    if username in data:
        del data[username]
        _save_all(data)
