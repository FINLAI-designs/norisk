"""Tests für ``tools.network_monitor.gui.labels`` (Sprint S1b).

Pure-Python-Tests — kein PySide6, kein Qt-Loop. Decken die zwei
Mappings + Helfer ab, auf denen die Verbindungstabelle V1 (Status-
Klartext) und V3 (Port-Anreicherung) aufbauen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

from tools.network_monitor.gui.labels import (
    PORT_SERVICES,
    STATUS_LABELS,
    friendly_status,
    port_with_service,
)

# ---------------------------------------------------------------------------
# friendly_status (V1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ESTABLISHED", "Aktiv verbunden"),
        ("LISTEN", "Wartet auf Verbindung"),
        ("TIME_WAIT", "Wird geschlossen"),
        ("CLOSE_WAIT", "Schließt"),
        ("SYN_SENT", "Verbindet"),
        ("FIN_WAIT1", "Beendet"),
        ("LAST_ACK", "Beendet"),
        ("CLOSED", "Geschlossen"),
    ],
)
def test_friendly_status_kanonisch(raw: str, expected: str):
    """Bekannte psutil-Status-Strings werden Klartext zugeordnet."""
    assert friendly_status(raw) == expected


def test_friendly_status_case_insensitive():
    """Großschreibung normalisiert — psutil schwankt zwischen Versionen."""
    assert friendly_status("established") == "Aktiv verbunden"
    assert friendly_status("  Established  ") == "Aktiv verbunden"


def test_friendly_status_unbekannt_und_none():
    """Unbekannter / leerer / None-Status wird zu 'Unbekannt'."""
    assert friendly_status(None) == "Unbekannt"
    assert friendly_status("") == "Unbekannt"
    assert friendly_status("FOO_BAR") == "Unbekannt"


def test_status_labels_decken_alle_psutil_states_ab():
    """Sicherheits-Check: die zentralen TCP-Stati sind gemappt.

    Falls psutil einen neuen Status liefert (z. B. ``"DELETE"`` aus
    älteren BSDs), ist:func:`friendly_status` mit dem
    ``"Unbekannt"``-Fallback abgesichert. Dieser Test fixiert die
    aktuell unterstützten Schlüssel als Regressionsfangnetz.
    """
    must_have = {
        "ESTABLISHED",
        "LISTEN",
        "TIME_WAIT",
        "CLOSE_WAIT",
        "CLOSED",
        "SYN_SENT",
        "SYN_RECV",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "LAST_ACK",
        "CLOSING",
        "NONE",
    }
    assert must_have.issubset(STATUS_LABELS.keys())


# ---------------------------------------------------------------------------
# port_with_service (V3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "port,expected",
    [
        (443, "443 (HTTPS)"),
        (80, "80 (HTTP)"),
        (22, "22 (SSH)"),
        (3389, "3389 (RDP)"),
        (3306, "3306 (MySQL)"),
        (5432, "5432 (PostgreSQL)"),
        (587, "587 (SMTP-Mail)"),
    ],
)
def test_port_with_service_well_known(port: int, expected: str):
    """Well-Known-Ports werden mit Service-Suffix angereichert."""
    assert port_with_service(port) == expected


def test_port_with_service_unbekannt_nur_zahl():
    """Unbekannte Ports liefern nur die Zahl, ohne Klammer-Suffix."""
    assert port_with_service(54321) == "54321"
    assert port_with_service(12345) == "12345"


def test_port_with_service_leere_eingaben():
    """None / 0 / negativ → '–' (gleiche Konvention wie der Tabellen-Stil)."""
    assert port_with_service(None) == "–"
    assert port_with_service(0) == "–"
    assert port_with_service(-1) == "–"


def test_port_services_enthaelt_kmu_relevante_ports():
    """Sicherheits-Check: die für KMU relevanten Ports sind alle gemappt."""
    must_have = {
        22,    # SSH
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        465,   # SMTPS
        587,   # SMTP-Mail (Submission)
        993,   # IMAPS
        995,   # POP3S
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
    }
    assert must_have.issubset(PORT_SERVICES.keys())
