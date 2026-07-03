"""
ics_exporter — RFC-5545 VCALENDAR-Export fuer Schulungs-Renewals.

Erzeugt eine ``.ics``-Datei mit einem ``VEVENT`` pro auslaufender Schulung.
Die Datei kann in Outlook / Google Calendar / Thunderbird importiert
werden — der ``DTSTART`` ist ``valid_until`` minus ``reminder_lead_days``
(Default 30), damit der Termin rechtzeitig vor Ablauf im Kalender steht.

Wir schreiben ICS in einem strict-konformen Minimal-Format selbst und
ziehen keine Bibliothek dafuer (icalendar/vobject), weil:
- nur wenige Felder gebraucht (PRODID, METHOD, VEVENT mit DTSTART/SUMMARY/
  DESCRIPTION/UID),
- der Import-Pfad gut testbar bleibt,
- keine externe Abhaengigkeit fuer eine 50-Zeilen-Aufgabe noetig ist.

Schichtzugehoerigkeit: application/ — darf domain/ + core/ importieren,
keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from tools.awareness_tracker.domain.models import Training, ValidityStatus

PRODID: str = "-//FINLAI//NoRisk Awareness-Tracker//DE"

# Verlaengerter Standard-Vorlauf in Tagen — bei DSGVO-2-Jahres-Auffrischungen
# bekommt der Office-Manager 30 Tage Vorlauf fuer Termin-Findung mit dem
# Schulungsanbieter.
DEFAULT_REMINDER_LEAD_DAYS: int = 30


class IcsExportError(ValueError):
    """Geworfen wenn der ICS-Export aufgrund inkonsistenter Daten scheitert."""


def export_renewals_to_ics(
    trainings: Iterable[Training],
    employee_names: dict[int, str] | None = None,
    *,
    reminder_lead_days: int = DEFAULT_REMINDER_LEAD_DAYS,
    now: datetime | None = None,
) -> str:
    """Wandelt Trainings mit ``valid_until``-Stamps in einen ICS-Text.

    Schulungen mit Status ``PERMANENT`` (kein ``valid_until``) werden
    uebersprungen — sie haben keinen Termin. ``VALID``/``EXPIRING_SOON``/
    ``EXPIRED`` werden alle ausgegeben, damit der User auch abgelaufene
    Schulungen im Kalender sieht (vergangenes Datum, klare Warnung).

    Args:
        trainings: Iterable:class:`Training` zum Exportieren.
        employee_names: Optionales Mapping ``{employee_id: full_name}``
                             fuer die SUMMARY. Fehlt der Eintrag, wird
                             ``"Mitarbeiter #<id>"`` verwendet.
        reminder_lead_days: Vorlauf vor ``valid_until`` fuer den Termin.
                             Default 30 Tage.
        now: Referenz-Zeitpunkt fuer den DTSTAMP (testbar).

    Returns:
        Den ICS-Inhalt als String (UTF-8, CRLF-Line-Endings).

    Raises:
        IcsExportError: Wenn ``trainings`` keine exportierbare Schulung
            enthaelt (alle Permanent oder Liste leer).
    """
    employee_names = employee_names or {}
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    lead = timedelta(days=max(0, reminder_lead_days))

    events: list[str] = []
    for training in trainings:
        if training.valid_until is None:
            continue
        # Wir geben fuer alle Non-Permanent-Trainings ein Event aus,
        # auch fuer VALID — der User entscheidet im Kalender ob er das
        # behalten will. Filter passiert vor dem Export.
        if training.validity_status(now=now) is ValidityStatus.PERMANENT:
            continue
        events.append(_build_vevent(training, employee_names, stamp, lead))

    if not events:
        raise IcsExportError(
            "Keine exportierbaren Renewals — alle Schulungen sind permanent "
            "oder die Liste war leer."
        )

    lines: list[str] = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        f"PRODID:{PRODID}",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        *events,
        "END:VCALENDAR",
    ]
    return "\r\n".join(lines) + "\r\n"


def _build_vevent(
    training: Training,
    employee_names: dict[int, str],
    stamp: str,
    lead: timedelta,
) -> str:
    # valid_until ist hier garantiert gesetzt (Caller hat gefiltert), aber
    # mypy/Type-Narrowing sieht das nicht — explizite Defensive statt assert.
    if training.valid_until is None:
        raise IcsExportError(
            "Interner Fehler: Permanent-Training wurde nicht ausgefiltert."
        )
    employee_label = employee_names.get(
        training.employee_id, f"Mitarbeiter #{training.employee_id}"
    )
    summary = (
        f"Schulungs-Renewal: {training.display_type_label} "
        f"({employee_label})"
    )
    description = (
        f"Schulung '{training.title}' laeuft am "
        f"{training.valid_until.strftime('%Y-%m-%d')} ab. "
        f"Bitte rechtzeitig neue Schulung buchen."
    )
    if training.provider:
        description += f" Anbieter: {training.provider}."
    dtstart_date = (training.valid_until - lead).strftime("%Y%m%d")
    dtend_date = (training.valid_until - lead + timedelta(days=1)).strftime(
        "%Y%m%d"
    )
    uid = _stable_uid(training)
    return "\r\n".join(
        [
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"DTSTAMP:{stamp}",
            f"DTSTART;VALUE=DATE:{dtstart_date}",
            f"DTEND;VALUE=DATE:{dtend_date}",
            f"SUMMARY:{_escape_text(summary)}",
            f"DESCRIPTION:{_escape_text(description)}",
            "STATUS:CONFIRMED",
            "TRANSP:OPAQUE",
            "END:VEVENT",
        ]
    )


def _stable_uid(training: Training) -> str:
    """Stabile UID pro Schulung, damit Re-Imports keine Duplikate erzeugen."""
    # ID kann None sein (transientes Training) — wir fallen dann auf einen
    # Hash aus employee + completed_at + title zurueck.
    if training.id is not None:
        return f"awareness-tracker-{training.id}@finlai.eu"
    raw = (
        f"{training.employee_id}|{training.title}|"
        f"{training.completed_at.isoformat()}"
    )
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]  # noqa: S324 — UID-Hash
    return f"awareness-tracker-{digest}@finlai.eu"


def _escape_text(value: str) -> str:
    """RFC-5545-Text-Escape fuer SUMMARY/DESCRIPTION (Backslash, Semikolon,
    Komma, Zeilenumbruch).
    """
    return (
        value.replace("\\", "\\\\")
        .replace(";", r"\;")
        .replace(",", r"\,")
        .replace("\n", r"\n")
        .replace("\r", "")
    )
