"""Tests für ``core.registry.last_scan_registry`` (Sprint S0b).

Deckt ab:
  - ``list_known_tools`` liefert die 8 dokumentierten Tools.
  - ``get_last_scan`` für unbekannte Tools → ``None``.
  - ``get_last_scan`` für nicht-initialisierte DBs → ``None``.
  - ``get_last_scan`` für jedes der 8 Tools mit echtem DB-Setup → datetime.
  - ISO-String-Konverter behandelt Z-Suffix, naive datetimes, leere Werte.
  - Unix-Timestamp-Konverter behandelt int, float, ungültige Werte.

Tests verwenden ``DB_DIR``-Patching (analog test_db_isolation), damit
keine Schreibzugriffe auf das echte ``~/.finlai/db/`` erfolgen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC
from pathlib import Path
from unittest.mock import patch

import pytest

from core.database.db_context import clear_db_app_id
from core.database.encrypted_db import EncryptedDatabase
from core.registry.last_scan_registry import (
    _from_iso_string,
    _from_unix_seconds,
    get_last_scan,
    list_known_tools,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_db_context():
    """Setzt App-Kontext vor und nach jedem Test zurück."""
    clear_db_app_id()
    yield
    clear_db_app_id()


@pytest.fixture
def isolated_db_dir(tmp_path: Path):
    """Patcht ``DB_DIR`` auf ein temporäres Verzeichnis."""
    with patch("core.database.encrypted_db.DB_DIR", tmp_path):
        yield tmp_path


# ---------------------------------------------------------------------------
# Konverter
# ---------------------------------------------------------------------------


def test_from_iso_string_parsiert_z_suffix():
    """ISO-String mit Z-Suffix wird zu UTC-datetime."""
    dt = _from_iso_string("2026-04-29T10:00:00Z")
    assert dt is not None
    assert dt.tzinfo is not None
    assert dt.year == 2026


def test_from_iso_string_naive_wird_utc():
    """Naive ISO-String wird als UTC interpretiert (kein Crash)."""
    dt = _from_iso_string("2026-04-29T10:00:00")
    assert dt is not None
    assert dt.tzinfo == UTC


def test_from_iso_string_leere_werte():
    """Leerer String, None, Whitespace → None."""
    assert _from_iso_string(None) is None
    assert _from_iso_string("") is None
    assert _from_iso_string("   ") is None


def test_from_iso_string_kaputter_input():
    """Nicht parsebarer Input → None statt Exception."""
    assert _from_iso_string("not-an-iso-date") is None
    assert _from_iso_string(12345) is None  # type: ignore[arg-type]


def test_from_unix_seconds_int_und_float():
    """Sowohl int- als auch float-Timestamps werden akzeptiert."""
    ts = 1714386000  # 2024-04-29T11:00:00Z
    dt_int = _from_unix_seconds(ts)
    dt_float = _from_unix_seconds(float(ts))
    assert dt_int is not None and dt_float is not None
    assert dt_int == dt_float
    assert dt_int.tzinfo == UTC


def test_from_unix_seconds_ungueltig():
    """None, Strings, 0, negative Werte → None."""
    assert _from_unix_seconds(None) is None
    assert _from_unix_seconds("foo") is None
    assert _from_unix_seconds(0) is None
    assert _from_unix_seconds(-1) is None


# ---------------------------------------------------------------------------
# list_known_tools / unbekannte Tools
# ---------------------------------------------------------------------------


def test_list_known_tools_enthält_die_8_kernkomponenten():
    """Die im Sprint dokumentierten 8 Tools sind alle registriert."""
    expected = {
        "api_security",
        "cert_monitor",
        "csaf_advisor",
        "cyber_dashboard",
        "document_scanner",
        "network_monitor",
        "network_scanner",
        "system_scanner",
    }
    assert set(list_known_tools()) == expected


def test_list_known_tools_alphabetisch():
    """Reihenfolge ist deterministisch (alphabetisch)."""
    tools = list_known_tools()
    assert tools == sorted(tools)


def test_get_last_scan_unbekanntes_tool_none(isolated_db_dir: Path):
    """Unregistrierte Tools liefern ``None`` ohne Side-Effects."""
    assert get_last_scan("password_checker") is None
    assert get_last_scan("") is None


def test_get_last_scan_db_nie_initialisiert_none(isolated_db_dir: Path):
    """Ohne DB-Setup liefert jedes registrierte Tool ``None``."""
    for tool in list_known_tools():
        assert get_last_scan(tool) is None


# ---------------------------------------------------------------------------
# Per-Tool Round-Trip mit echtem Schema
# ---------------------------------------------------------------------------


def _seed_iso_table(
    db_name: str,
    schema: str,
    insert_sql: str,
    values: tuple,
) -> None:
    """Hilfsroutine: Tabelle in ``db_name``-DB anlegen + 1 Zeile schreiben."""
    db = EncryptedDatabase(db_name)
    with db.connection() as conn:
        conn.executescript(schema)
        conn.execute(insert_sql, values)


def test_get_last_scan_api_security(isolated_db_dir: Path):
    """api_security: liest neuesten ``scan_start`` aus ``api_scan_laeufe``."""
    _seed_iso_table(
        "api_security",
        """
        CREATE TABLE IF NOT EXISTS api_scan_laeufe (
            id          TEXT PRIMARY KEY,
            scan_start  TEXT NOT NULL
        );
        """,
        "INSERT INTO api_scan_laeufe(id, scan_start) VALUES (?, ?)",
        ("scan-1", "2026-04-29T08:00:00+00:00"),
    )
    dt = get_last_scan("api_security")
    assert dt is not None
    assert dt.year == 2026 and dt.month == 4 and dt.day == 29


def test_get_last_scan_network_scanner_nutzt_beendet_am_falls_vorhanden(
    isolated_db_dir: Path,
):
    """network_scanner: ``COALESCE(beendet_am, gestartet_am)``."""
    _seed_iso_table(
        "network_scanner",
        # Tabelle heisst port_scans (Kollision mit system_scanner.scans).
        """
        CREATE TABLE IF NOT EXISTS port_scans (
            id            TEXT PRIMARY KEY,
            gestartet_am  TEXT NOT NULL,
            beendet_am    TEXT
        );
        """,
        "INSERT INTO port_scans(id, gestartet_am, beendet_am) VALUES (?, ?, ?)",
        ("s1", "2026-04-29T08:00:00Z", "2026-04-29T08:05:00Z"),
    )
    dt = get_last_scan("network_scanner")
    assert dt is not None
    assert dt.minute == 5


def test_get_last_scan_network_monitor_unix_timestamp(isolated_db_dir: Path):
    """network_monitor: Unix-Sekunden aus ``connection_history.timestamp``."""
    _seed_iso_table(
        "network_monitor",
        """
        CREATE TABLE IF NOT EXISTS connection_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL
        );
        """,
        "INSERT INTO connection_history(timestamp) VALUES (?)",
        (1714386000.0,),
    )
    dt = get_last_scan("network_monitor")
    assert dt is not None
    assert dt.tzinfo == UTC


def test_get_last_scan_cert_monitor(isolated_db_dir: Path):
    """cert_monitor: liest ``letzte_pruefung`` aus ``cert_scan_results``."""
    _seed_iso_table(
        "cert_monitor",
        """
        CREATE TABLE IF NOT EXISTS cert_scan_results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            letzte_pruefung TEXT
        );
        """,
        "INSERT INTO cert_scan_results(letzte_pruefung) VALUES (?)",
        ("2026-04-28T10:00:00Z",),
    )
    dt = get_last_scan("cert_monitor")
    assert dt is not None
    assert dt.day == 28


def test_get_last_scan_csaf_advisor(isolated_db_dir: Path):
    """csaf_advisor: ``MAX(last_fetch)`` über alle Provider."""
    _seed_iso_table(
        "csaf_advisor",
        """
        CREATE TABLE IF NOT EXISTS csaf_providers (
            id         TEXT PRIMARY KEY,
            last_fetch TEXT
        );
        """,
        "INSERT INTO csaf_providers(id, last_fetch) VALUES (?, ?)",
        ("p1", "2026-04-27T12:00:00Z"),
    )
    # Zweiter Provider mit jüngerem Datum — MAX muss diesen wählen
    db = EncryptedDatabase("csaf_advisor")
    with db.connection() as conn:
        conn.execute(
            "INSERT INTO csaf_providers(id, last_fetch) VALUES (?, ?)",
            ("p2", "2026-04-29T06:00:00Z"),
        )

    dt = get_last_scan("csaf_advisor")
    assert dt is not None
    assert dt.day == 29


def test_get_last_scan_cyber_dashboard_nvd_cache(isolated_db_dir: Path):
    """cyber_dashboard liest ``MAX(fetched_at)`` aus ``nvd_cache`` (Unix)."""
    _seed_iso_table(
        "nvd_cache",
        """
        CREATE TABLE IF NOT EXISTS nvd_cache (
            cache_key   TEXT PRIMARY KEY,
            data        TEXT NOT NULL,
            fetched_at  INTEGER NOT NULL
        );
        """,
        "INSERT INTO nvd_cache(cache_key, data, fetched_at) VALUES (?, ?, ?)",
        ("k1", "[]", 1714386000),
    )
    dt = get_last_scan("cyber_dashboard")
    assert dt is not None
    assert dt.tzinfo == UTC


def test_get_last_scan_system_scanner(isolated_db_dir: Path):
    """system_scanner: liest neuesten ``timestamp`` aus ``scans``."""
    _seed_iso_table(
        "system_scanner",
        """
        CREATE TABLE IF NOT EXISTS scans (
            scan_id   TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL
        );
        """,
        "INSERT INTO scans(scan_id, timestamp) VALUES (?, ?)",
        ("sys-1", "2026-04-29T05:00:00Z"),
    )
    dt = get_last_scan("system_scanner")
    assert dt is not None
    assert dt.hour == 5


def test_get_last_scan_document_scanner_aus_email(isolated_db_dir: Path):
    """Datei-Scanner liest E-Mail-Anhang-Scans (email_scanner.mail_reports)."""
    _seed_iso_table(
        "email_scanner",
        """
        CREATE TABLE IF NOT EXISTS mail_reports (
            id      TEXT PRIMARY KEY,
            scan_ts TEXT NOT NULL
        );
        """,
        "INSERT INTO mail_reports(id, scan_ts) VALUES (?, ?)",
        ("m1", "2026-04-29T03:00:00Z"),
    )
    dt = get_last_scan("document_scanner")
    assert dt is not None
    assert dt.hour == 3


def test_get_last_scan_document_scanner_aus_document_scans(isolated_db_dir: Path):
    """Datei-Scanner liest Office-/PDF-Scans (document_scanner.document_scans)."""
    _seed_iso_table(
        "document_scanner",
        """
        CREATE TABLE IF NOT EXISTS document_scans (
            id         INTEGER PRIMARY KEY,
            scanned_at TEXT NOT NULL
        );
        """,
        "INSERT INTO document_scans(id, scanned_at) VALUES (?, ?)",
        (1, "2026-05-01T09:00:00Z"),
    )
    dt = get_last_scan("document_scanner")
    assert dt is not None
    assert dt.day == 1
    assert dt.hour == 9


def test_get_last_scan_document_scanner_max_ueber_quellen(isolated_db_dir: Path):
    """-B: der juengste Datei-Scan = MAX(mail_reports, document_scans)."""
    _seed_iso_table(
        "email_scanner",
        "CREATE TABLE IF NOT EXISTS mail_reports "
        "(id TEXT PRIMARY KEY, scan_ts TEXT NOT NULL);",
        "INSERT INTO mail_reports(id, scan_ts) VALUES (?, ?)",
        ("m1", "2026-04-29T03:00:00Z"),  # aelter
    )
    _seed_iso_table(
        "document_scanner",
        "CREATE TABLE IF NOT EXISTS document_scans "
        "(id INTEGER PRIMARY KEY, scanned_at TEXT NOT NULL);",
        "INSERT INTO document_scans(id, scanned_at) VALUES (?, ?)",
        (1, "2026-05-03T11:00:00Z"),  # neuer -> MAX
    )
    dt = get_last_scan("document_scanner")
    assert dt is not None
    assert (dt.month, dt.day, dt.hour) == (5, 3, 11)


def test_get_last_scan_cached_kein_zweiter_db_read(isolated_db_dir, monkeypatch):
    """Perf C-Hebel-2: der 2. get_last_scan kommt aus dem TTL-Cache (kein DB-
    Read), clear_cache erzwingt einen erneuten Read."""
    import core.registry.last_scan_registry as reg

    _seed_iso_table(
        "api_security",
        "CREATE TABLE IF NOT EXISTS api_scan_laeufe "
        "(id INTEGER PRIMARY KEY, scan_start TEXT NOT NULL);",
        "INSERT INTO api_scan_laeufe(id, scan_start) VALUES (?, ?)",
        (1, "2026-05-01T10:00:00Z"),
    )
    first = get_last_scan("api_security")  # Cache-MISS -> DB-Read + cachen
    assert first is not None

    calls = {"n": 0}
    orig = reg._query_one

    def _spy(tool, spec):
        calls["n"] += 1
        return orig(tool, spec)

    monkeypatch.setattr(reg, "_query_one", _spy)

    assert get_last_scan("api_security") == first  # Cache-HIT
    assert calls["n"] == 0  # KEIN DB-Read

    reg.clear_cache()
    assert get_last_scan("api_security") == first  # nach clear -> wieder Read
    assert calls["n"] >= 1


def test_get_last_scan_leere_tabelle_none(isolated_db_dir: Path):
    """Leere Tabelle → None (kein Crash)."""
    _seed_iso_table(
        "api_security",
        "CREATE TABLE IF NOT EXISTS api_scan_laeufe (id TEXT, scan_start TEXT);",
        # Dummy-Insert, gleich wieder gelöscht
        "INSERT INTO api_scan_laeufe(id, scan_start) VALUES (?, ?)",
        ("x", "2026-01-01T00:00:00Z"),
    )
    db = EncryptedDatabase("api_security")
    with db.connection() as conn:
        conn.execute("DELETE FROM api_scan_laeufe")
    assert get_last_scan("api_security") is None


@pytest.mark.parametrize("tool_name", list_known_tools())
def test_get_last_scan_ohne_tabelle_kein_error_log(
    tool_name: str, isolated_db_dir: Path, caplog
):
    """Fehlende Tabelle → None OHNE ``no such table``-ERROR-Log (alle Tools).

    Frische Workstation bzw. frische konsolidierte ``norisk``-DB direkt nach
    dem-Alt-DB-Wipe: die Tool-Tabellen werden erst beim ersten Oeffnen
    des jeweiligen Tools (lazy im Repository-``__init__``) angelegt. Bis dahin
    existieren sie nicht.

    Die ``table_name``-Existenzpruefung in ``_query_one`` faengt das ab: der
    SELECT laeuft gar nicht erst, also wirft ``EncryptedDatabase`` keinen
    ``DB-Fehler... no such table``-ERROR-Log (der den fail-soft Registry-Catch
    optisch unterlaufen wuerde). Vor dem Fix produzierte die Konsolidierung
    genau diese ERROR-Zeile fuer api_security/network_scanner/cert_monitor/
    document_scanner/email_scanner auf jedem Erststart.
    """
    import logging  # noqa: PLC0415

    # Bewusst KEIN Schema vorbereiten — DBs sind frisch (leeres tmp-Verzeichnis).
    with caplog.at_level(logging.ERROR, logger="finlai.core.database.encrypted_db"):
        result = get_last_scan(tool_name)

    assert result is None
    assert not any(
        "no such table" in rec.message and rec.levelname == "ERROR"
        for rec in caplog.records
    ), (
        f"ERROR-Log mit 'no such table' fuer {tool_name!r}: "
        f"{[r.message for r in caplog.records]}"
    )
