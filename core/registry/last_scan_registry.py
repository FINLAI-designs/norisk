"""last_scan_registry — Zentraler Lookup für "letzter Scan pro Tool".

Sprint S0b: Aggregiert die heute über 8 Tool-DBs verteilten Last-Scan-
Zeitpunkte in einem einzigen Service mit einheitlicher Schnittstelle::

    get_last_scan(tool_name) -> datetime | None
    list_known_tools -> list[str]

Konsumenten (Score-Vollständigkeits-Banner S3c, Dashboard-Hero S4b)
müssen so weder die jeweiligen Tabellennamen noch die unterschiedlichen
Persistenz-Formate (ISO-String / Unix-Timestamp / float-Sekunden) kennen.

Designentscheidungen
--------------------
1. **Read-only.** Der Registry liest ausschließlich — keine Schemata
   werden hier angelegt. Wenn eine DB/Tabelle/Spalte fehlt (Tool nie
   benutzt, oder Schema gedriftet), wird ``None`` zurückgegeben statt
   geworfen — der Konsument zeigt dann "noch nie gescannt" an.
2. **Defensive Fehler-Behandlung.** Jeder Fehler-Fall (DB locked,
   sqlite-OperationalError, leere Spalte, kaputtes ISO-Format) ist
   aus Konsumenten-Sicht ``None`` — Fehler werden auf DEBUG-Level
   geloggt, damit die UI sie nicht eskaliert.
3. **Statischer Dispatch.** Ein Modul-Konstanten-Dict mappt Tool-Name
   auf eine ``_ScanQuery``-Spec (DB-Name + SELECT-Statement +
   Konvertierungs-Funktion). Damit ist die Abhängigkeit zu Tool-DBs
   an einer Stelle sichtbar — neue Tools werden hier hinzugefügt.

Schichtzugehörigkeit: core/ — kein PySide6, nur SQLCipher-Reads.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger

log = get_logger(__name__)

# Perf C-Hebel-2: jeder get_last_scan oeffnet eine EncryptedDatabase-
# Connection, deren ``PRAGMA key`` 256.000 PBKDF2-HMAC-SHA512-Iterationen zahlt
# (~95 ms). Cockpit-Render + Completeness-Banner sweepen ~16 Tool-DBs -> ~1,6 s
# Post-Paint-Tick. Ein kurzer Result-Cache (TTL) deduppt diese Sweeps. Gecacht
# werden AUSSCHLIESSLICH datetimes (kein Schluessel, kein DB-Inhalt) -> KEIN
# Crypto-Impact. Die Frische ist tag-granular -> Sekunden-Staleness ist
# unsichtbar; ``clear_cache`` invalidiert explizit (Tests / nach einem Scan).
_CACHE_TTL_SECONDS: Final[float] = 30.0
_scan_cache: dict[str, tuple[float, datetime | None]] = {}


def clear_cache() -> None:
    """Leert den Last-Scan-Cache (Tests + explizite Invalidierung nach Scan)."""
    _scan_cache.clear()

# ---------------------------------------------------------------------------
# Datenmodell
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ScanQuery:
    """Spezifikation, wie für ein Tool der letzte Scan-Zeitpunkt ermittelt wird.

    Attributes:
        db_name: Name der ``EncryptedDatabase`` (ohne ``.db``-Endung).
        table_name: Name der Tabelle, aus der ``sql`` liest. Wird in
:func:`_query_one` VOR dem SELECT gegen ``sqlite_master`` geprueft.
            Fehlt die Tabelle (Tool noch nie benutzt, oder frische konsolidierte
            ``norisk``-DB direkt nach dem-Alt-DB-Wipe), liefert die
            Registry ``None`` OHNE den SELECT auszufuehren. Damit entsteht KEIN
            ``no such table``-ERROR-Log in ``EncryptedDatabase`` — der den
            fail-soft Catch in:func:`get_last_scan` optisch unterlaufen wuerde
            (er loggt auf ERROR, bevor der Registry-Catch ihn auf DEBUG schluckt).
            Haelt den Read-only-Vertrag der Registry ein (kein ``CREATE TABLE``
            im Lesepfad — loest das fruehere ``ensure_table_sql`` aus/
            ab, das eine Tabelle anlegte und damit gegen genau diesen Vertrag
            verstiess).
        sql: SELECT-Statement, das genau eine Spalte mit dem Last-Scan-Wert
            zurückliefert (oder keine Zeile = "noch nie gescannt"). Liest
            ausschliesslich aus ``table_name``.
        converter: Wandelt den Datenbank-Rohwert in ``datetime | None``.
            Liefert ``None`` bei kaputten/leeren Werten.
    """

    db_name: str
    table_name: str
    sql: str
    converter: Callable[[Any], datetime | None]


# ---------------------------------------------------------------------------
# Konvertierungs-Helper
# ---------------------------------------------------------------------------


def _from_iso_string(value: Any) -> datetime | None:
    """Parst einen ISO-8601-String in ein UTC-bewusstes datetime.

    Defensiv: leere Strings, ``None`` und nicht-parsebare Werte → ``None``.
    Naive datetimes (ohne tz-Info) werden als UTC interpretiert, damit
    Konsumenten sich nicht um tz-Mix kümmern müssen.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _from_unix_seconds(value: Any) -> datetime | None:
    """Parst einen Unix-Timestamp (int oder float) in UTC-datetime."""
    if value is None:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Registry — die 8 heute persistenten Tool-Quellen
# ---------------------------------------------------------------------------

# Tools mit DB-persistiertem Last-Scan-Zeitpunkt. Aus Sicht der
# Information-Value-Strategie (Schicht 1, Foundation) sind das die
# Quellen, die das Score-Vollständigkeits-Banner und der Dashboard-Hero
# anzeigen. ``dependency_auditor`` und ``password_policy`` haben heute
# keine eigenständige Scan-Persistenz und sind bewusst nicht registriert
# — Konsumenten erkennen sie als "nicht persistent" am Fehlen im
#:func:`list_known_tools`-Ergebnis bzw. am ``None``-Return.
_REGISTRY: dict[str, _ScanQuery | tuple[_ScanQuery, ...]] = {
    "api_security": _ScanQuery(
        db_name="api_security",
        table_name="api_scan_laeufe",
        sql=(
            "SELECT scan_start FROM api_scan_laeufe"
            " ORDER BY scan_start DESC LIMIT 1"
        ),
        converter=_from_iso_string,
    ),
    "network_scanner": _ScanQuery(
        db_name="network_scanner",
        # Tabelle in port_scans umbenannt (Kollision mit system_scanner.scans
        # in der konsolidierten norisk-DB). db_name bleibt "network_scanner" — die
        # EncryptedDatabase lenkt ihn in Produktion auf norisk.db.
        table_name="port_scans",
        sql=(
            "SELECT COALESCE(beendet_am, gestartet_am) FROM port_scans"
            " ORDER BY COALESCE(beendet_am, gestartet_am) DESC LIMIT 1"
        ),
        converter=_from_iso_string,
    ),
    "network_monitor": _ScanQuery(
        db_name="network_monitor",
        # connection_history wird erst beim ersten Pro-Feature-Snapshot durch
        # ``ConnectionHistoryRepository`` angelegt. Auf einer frischen
        # Workstation fehlt sie -> die table_name-Existenzpruefung in
        #:func:`_query_one` liefert None ohne ERROR-Log (loest das fruehere
        # ensure_table_sql ab, das gegen den Read-only-Vertrag verstiess).
        table_name="connection_history",
        sql=(
            "SELECT timestamp FROM connection_history"
            " ORDER BY timestamp DESC LIMIT 1"
        ),
        converter=_from_unix_seconds,
    ),
    "cert_monitor": _ScanQuery(
        db_name="cert_monitor",
        table_name="cert_scan_results",
        sql=(
            "SELECT letzte_pruefung FROM cert_scan_results"
            " WHERE letzte_pruefung IS NOT NULL AND letzte_pruefung != ''"
            " ORDER BY letzte_pruefung DESC LIMIT 1"
        ),
        converter=_from_iso_string,
    ),
    "csaf_advisor": _ScanQuery(
        db_name="csaf_advisor",
        table_name="csaf_providers",
        sql=(
            "SELECT MAX(last_fetch) FROM csaf_providers"
            " WHERE last_fetch IS NOT NULL"
        ),
        converter=_from_iso_string,
    ),
    "cyber_dashboard": _ScanQuery(
        db_name="nvd_cache",
        table_name="nvd_cache",
        sql="SELECT MAX(fetched_at) FROM nvd_cache",
        converter=_from_unix_seconds,
    ),
    "system_scanner": _ScanQuery(
        db_name="system_scanner",
        table_name="scans",
        sql=(
            "SELECT timestamp FROM scans"
            " ORDER BY timestamp DESC LIMIT 1"
        ),
        converter=_from_iso_string,
    ),
    # Datei-Scanner-B): vereint E-Mail-Anhang-, Office- und PDF-Scans.
    # Office + PDF persistieren in der document_scanner-DB (document_scans),
    # E-Mail-Anhaenge weiterhin in der email_scanner-DB (mail_reports — audit-
    # relevant, unangetastet). Der juengste Datei-Scan = MAX ueber beide Quellen
    # (get_last_scan aggregiert Mehrfach-Quellen).
    "document_scanner": (
        _ScanQuery(
            db_name="document_scanner",
            table_name="document_scans",
            sql=(
                "SELECT scanned_at FROM document_scans"
                " ORDER BY scanned_at DESC LIMIT 1"
            ),
            converter=_from_iso_string,
        ),
        _ScanQuery(
            db_name="email_scanner",
            table_name="mail_reports",
            sql=(
                "SELECT scan_ts FROM mail_reports"
                " ORDER BY scan_ts DESC LIMIT 1"
            ),
            converter=_from_iso_string,
        ),
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def list_known_tools() -> list[str]:
    """Gibt die Tool-Namen zurück, für die ein Last-Scan abrufbar ist.

    Reihenfolge ist alphabetisch (deterministisch), damit Konsumenten
    in stabiler Reihenfolge rendern können.
    """
    return sorted(_REGISTRY.keys())


def get_last_scan(tool_name: str) -> datetime | None:
    """Liefert den Zeitpunkt des letzten Scans für ein Tool.

    Args:
        tool_name: Tool-Bezeichner (z. B. ``"api_security"``,
            ``"cert_monitor"``). Liste verfügbarer Namen:func:`list_known_tools`.

    Returns:
        ``datetime`` (UTC-bewusst) des letzten Scans oder ``None`` wenn:

        - das Tool nicht im Registry registriert ist,
        - die DB/Tabelle noch nicht initialisiert wurde,
        - die Spalte leer/``NULL`` ist,
        - der Wert nicht parsebar ist,
        - die DB-Verbindung scheitert (z. B. Lock).

        Fehler werden auf DEBUG-Level geloggt — die UI muss sich nicht um
        Detail-Fehlerklassen kümmern.
    """
    cached = _scan_cache.get(tool_name)
    if cached is not None and (time.monotonic() - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    spec = _REGISTRY.get(tool_name)
    if spec is None:
        log.debug("LastScanRegistry: unbekanntes Tool '%s'", tool_name)
        return None  # unbekanntes Tool = Programmierfehler -> nicht cachen

    # B: ein Tool kann aus MEHREREN Quellen gespeist werden (z. B. der
    # Datei-Scanner aus document_scans UND mail_reports). Der juengste Scan ist
    # das MAX ueber alle Quellen, die einen Wert liefern.
    quellen = spec if isinstance(spec, tuple) else (spec,)
    zeitpunkte = [
        ts for q in quellen if (ts := _query_one(tool_name, q)) is not None
    ]
    result = max(zeitpunkte) if zeitpunkte else None
    _scan_cache[tool_name] = (time.monotonic(), result)
    return result


def _query_one(tool_name: str, spec: _ScanQuery) -> datetime | None:
    """Liest den Last-Scan-Zeitpunkt aus EINER Quelle (fail-soft, nie Crash)."""
    try:
        db = EncryptedDatabase(spec.db_name)
        with db.connection() as conn:
            # Read-only-Vertrag: existiert die Tabelle noch nicht (Tool nie
            # benutzt, oder frische konsolidierte norisk-DB direkt nach dem
            # Alt-DB-Wipe), liefern wir None OHNE den SELECT. Sonst
            # wuerde EncryptedDatabase "no such table" auf ERROR loggen, bevor
            # der Catch-Block unten ihn auf DEBUG schluckt — irrefuehrender
            # ERROR-Laerm auf jedem Erststart/ ehemals via
            # ensure_table_sql geloest, das aber eine Tabelle ANLEGTE).
            table_exists = conn.execute(
                "SELECT 1 FROM sqlite_master"
                " WHERE type='table' AND name=? LIMIT 1",
                (spec.table_name,),
            ).fetchone()
            if table_exists is None:
                return None
            row = conn.execute(spec.sql).fetchone()
    except Exception as exc:  # noqa: BLE001 -- Registry-Read darf nie crashen
        log.debug(
            "LastScanRegistry: %s-Read (%s) fehlgeschlagen (%s)",
            tool_name,
            spec.db_name,
            type(exc).__name__,
        )
        return None

    if row is None or row[0] is None:
        return None
    return spec.converter(row[0])
