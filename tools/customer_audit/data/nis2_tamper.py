"""nis2_tamper — HMAC-Hashkette (Tamper-Evidence) fuer NIS2-Phasen-Events.

Implementiert die manipulationssichere Verkettung der ``nis2_phase_events``-
Zeilen pro Incident §3). Jedes Event traegt einen ``event_hash``
ueber ``HMAC-SHA256(chain_key, prev_hash || canonical(event))`` — verkettet
ueber den ``prev_hash`` des Vorgaengers. Eine stille Aenderung an Inhalt,
Reihenfolge oder am Bestand der Events bricht die Kette und wird von
:func:`verify_chain` erkannt.

Ehrliche Grenze "Akzeptierte Konsequenzen"): die Kette schuetzt gegen
Manipulation durch Dritte/Subprozesse OHNE ``chain_key`` — NICHT gegen den
legitimen DB-Besitzer MIT Key (der kann neu rechnen). Es ist Tamper-*Evidence*,
keine Non-Repudiation. Die autorisierte Anonymisierung (DSGVO Art.17) re-kettet
bewusst und dokumentiert das via Marker-Event.

Der ``chain_key`` (32 Byte) wird ueber den KeyManager abgeleitet
(``derive_secondary_key("nis2_phase_events_hmac")`` — HKDF, NICHT der
DB-at-rest-Key) und fail-closed bezogen (:func:`load_chain_key`).

Schichtzugehoerigkeit: data/ — DB-nah, aber pure Crypto (kein DB-Zugriff hier).

ADR-Bezug: docs/adr/-nis2-tracker-revisionssicher.md §3.

Author: Patrick Riederich
Version: 0.1 (NIS2-revisionssicher, Schicht 1 Backend)
"""

from __future__ import annotations

import hashlib
import hmac
import json

#: Start-Hash der Kette (vor dem ersten Event eines Incidents).
GENESIS: str = "0" * 64

#: HKDF-Purpose fuer den Ketten-HMAC-Schluessel (Domain-Separation §3).
_CHAIN_KEY_PURPOSE: str = "nis2_phase_events_hmac"


def _canonical(ev: dict) -> bytes:
    """Pure: kanonische Byte-Repraesentation der Identitaets-/Inhaltsfelder.

    Bewusst NUR die Felder, die den fachlichen Inhalt eines Events ausmachen —
    NIEMALS ``event_id`` (DB-Autoincrement, nicht reproduzierbar), ``event_hash``
    oder ``prev_hash`` (die Kette selbst). Damit ist die Kanonik unabhaengig von
    der DB-Vergabe der ID und reproduzierbar beim Re-Verify.

    Serialisierung wie das Hausmuster (``encryption.py:553``): ``json.dumps``
    mit ``sort_keys=True`` und kompakten Separatoren, deterministisch.

    ``personenbezug`` ist BEWUSST NICHT Teil der Kanonik: es ist ein mutables
    Header-Flag der ``nis2_incidents``-Zeile (DSGVO-Art.33-Verzweigung), kein
    Inhalt des einzelnen Events. Wuerde es in den Hash eingehen, wuerde
    ``set_personenbezug`` nachtraeglich die Hashes aller Bestands-Events
    invalidieren und ``verify_chain`` faelschlich TAMPERED melden (P0).

    Args:
        ev: Event-Map mit den Schluesseln ``incident_id``, ``phase``, ``status``,
            ``actor``, ``note``, ``occurred_at``, ``payload_schema_version`` und
            ``payload``. ``payload`` darf JSON-String ODER bereits geparstes Dict
            sein.

    Returns:
        UTF-8-kodierte kanonische JSON-Bytes.
    """
    payload = ev["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    canonical = {
        "incident_id": ev["incident_id"],
        "phase": ev["phase"],
        "status": ev["status"],
        "actor": ev["actor"],
        "note": ev["note"],
        "occurred_at": ev["occurred_at"],
        "payload_schema_version": ev["payload_schema_version"],
        "payload": payload,
    }
    return json.dumps(
        canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def compute_event_hash(chain_key: bytes, prev_hash: str, ev: dict) -> str:
    """Pure: berechnet den ``event_hash`` eines Events.

    ``HMAC-SHA256(chain_key, prev_hash || "|" || canonical(ev))``.

    Args:
        chain_key: 32-Byte HMAC-Schluessel (:func:`load_chain_key`).
        prev_hash: ``event_hash`` des Vorgaenger-Events, oder:data:`GENESIS`.
        ev: Event-Map (:func:`_canonical`).

    Returns:
        Hexadezimaler HMAC-SHA256-Digest (64 Zeichen).
    """
    msg = prev_hash.encode("ascii") + b"|" + _canonical(ev)
    return hmac.new(chain_key, msg, hashlib.sha256).hexdigest()


def verify_chain(
    events: list[dict], chain_key: bytes
) -> tuple[bool, int | None]:
    """Pure: verifiziert die Hashkette einer Event-Liste eines Incidents.

    Sortiert die Events deterministisch nach ``occurred_at`` dann ``event_id``
    und prueft fuer jedes Event:

    1. ``prev_hash`` stimmt mit dem ``event_hash`` des Vorgaengers ueberein
       (bzw.:data:`GENESIS` fuer das erste verkettete Event).
    2. ``event_hash`` ist der korrekt neu berechnete HMAC.

    Alt-Events mit leerem ``event_hash`` (legacy, vor der Hashketten-Migration)
    duerfen NUR einen zusammenhaengenden Praefix am Ketten-Anfang bilden — der
    Bestand vor der Migration. Sie brechen die Kette nicht, leiten aber auch
    keinen ``prev_hash`` weiter (das erste verkettete Event zeigt auf
:data:`GENESIS`). Sobald ein gehashtes Event verarbeitet wurde, ist ein
    danach auftauchendes leeres Event ein BRUCH — sonst koennte ein Angreifer
    ohne ``chain_key`` ein sichtbares Fake-Event mit ``event_hash=''`` hinter
    die echte Kette haengen und ``verify_chain`` bliebe gruen (P1).

    Alle Vergleiche via:func:`hmac.compare_digest` (timing-sicher).

    Args:
        events: Liste von Event-Maps (:func:`_canonical`); muss zusaetzlich
                   ``event_id``, ``event_hash`` und ``prev_hash`` enthalten.
        chain_key: 32-Byte HMAC-Schluessel.

    Returns:
        ``(True, None)`` wenn die Kette intakt ist, sonst ``(False, event_id)``
        des ersten gebrochenen Events (``event_id`` kann ``None`` sein, wenn das
        Event noch keine DB-ID hat).
    """
    ordered = sorted(
        events,
        key=lambda e: (str(e.get("occurred_at", "")), e.get("event_id") or 0),
    )
    prev_hash = GENESIS
    seen_hashed = False
    for ev in ordered:
        stored = str(ev.get("event_hash", ""))
        if stored == "":
            # Leeres event_hash ist nur als Legacy-Praefix VOR dem ersten
            # gehashten Event zulaessig. Danach (auch zwischen gehashten
            # Events) ist es ein Einschleus-Versuch ohne chain_key -> Bruch.
            if seen_hashed:
                return False, ev.get("event_id")
            # Legacy-Praefix-Event ueberspringen, prev_hash NICHT weiterleiten
            # (das erste verkettete Event ist der Ketten-Start auf GENESIS).
            continue
        seen_hashed = True
        # 1. Verkettung: prev_hash muss auf den Vorgaenger zeigen.
        if not hmac.compare_digest(str(ev.get("prev_hash", "")), prev_hash):
            return False, ev.get("event_id")
        # 2. Inhalt: event_hash muss korrekt neu berechenbar sein.
        expected = compute_event_hash(chain_key, prev_hash, ev)
        if not hmac.compare_digest(stored, expected):
            return False, ev.get("event_id")
        prev_hash = stored
    return True, None


def load_chain_key(key_manager: object | None = None) -> bytes:
    """Bezieht den 32-Byte-Ketten-HMAC-Schluessel fail-closed.

    Leitet ``derive_secondary_key("nis2_phase_events_hmac")`` ueber den aktiven
    KeyManager (oder einen explizit injizierten) ab. Fehlt der Schluessel, wird
    eine Exception propagiert — KEIN Klartext-/Null-Key-Fallback (SECURITY.md
    fail-closed).

    Args:
        key_manager: Optionaler expliziter KeyManager (Constructor-Injection
            fuer Tests §2.5 β-Variante). ``None`` → aktiver Manager
            aus:mod:`core.database.key_manager_context`.

    Returns:
        32-Byte HMAC-Schluessel.

    Raises:
        ConfigurationError: Kein aktiver KeyManager und keiner injiziert.
        KeyManagerError: DEK nicht ableitbar (transitiv).
    """
    if key_manager is None:
        from core.database.key_manager_context import (  # noqa: PLC0415
            get_active_key_manager,
        )

        key_manager = get_active_key_manager()
    return key_manager.derive_secondary_key(_CHAIN_KEY_PURPOSE)  # type: ignore[attr-defined]
