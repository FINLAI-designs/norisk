"""
test_awareness_tracker_ics_exporter.

Tests fuer den ICS-Export. Strict-Format-Checks (CRLF, VCALENDAR-
Wrapper, VEVENT-Anzahl, Escape-Verhalten).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.awareness_tracker.application.ics_exporter import (
    DEFAULT_REMINDER_LEAD_DAYS,
    PRODID,
    IcsExportError,
    export_renewals_to_ics,
)
from tools.awareness_tracker.domain.models import (
    Training,
    TrainingType,
)

NOW = datetime(2026, 5, 16, 8, 0, tzinfo=UTC)


def _training(
    valid_until: datetime | None,
    *,
    title: str = "DSGVO-Auffrischung",
    employee_id: int = 1,
    provider: str = "",
    training_id: int | None = 100,
) -> Training:
    return Training(
        id=training_id,
        employee_id=employee_id,
        training_type=TrainingType.DSGVO_BASICS,
        title=title,
        completed_at=NOW - timedelta(days=365),
        valid_until=valid_until,
        provider=provider,
    )


# ---------------------------------------------------------------------------
# Happy-Path
# ---------------------------------------------------------------------------


class TestExport:
    def test_einfacher_export_enthaelt_wrapper(self) -> None:
        ics = export_renewals_to_ics(
            [_training(valid_until=NOW + timedelta(days=10))],
            employee_names={1: "Anna Schmidt"},
            now=NOW,
        )
        assert ics.startswith("BEGIN:VCALENDAR\r\n")
        assert ics.endswith("END:VCALENDAR\r\n")
        assert f"PRODID:{PRODID}" in ics
        assert "BEGIN:VEVENT" in ics
        assert "END:VEVENT" in ics

    def test_crlf_line_endings(self) -> None:
        ics = export_renewals_to_ics(
            [_training(valid_until=NOW + timedelta(days=10))],
            employee_names={1: "Anna"},
            now=NOW,
        )
        # Pruefe dass keine LF-only-Zeilen drin sind.
        assert "\r\n" in ics
        for line in ics.split("\r\n"):
            assert "\n" not in line

    def test_summary_enthaelt_employee_name(self) -> None:
        ics = export_renewals_to_ics(
            [_training(valid_until=NOW + timedelta(days=10))],
            employee_names={1: "Anna Schmidt"},
            now=NOW,
        )
        assert "Anna Schmidt" in ics
        assert "Renewal" in ics

    def test_unbekannter_employee_fallback(self) -> None:
        ics = export_renewals_to_ics(
            [_training(valid_until=NOW + timedelta(days=10))],
            employee_names={},
            now=NOW,
        )
        assert "Mitarbeiter #1" in ics

    def test_dtstart_ist_valid_until_minus_lead(self) -> None:
        valid_until = datetime(2026, 8, 16, tzinfo=UTC)
        ics = export_renewals_to_ics(
            [_training(valid_until=valid_until)],
            employee_names={1: "Anna"},
            now=NOW,
            reminder_lead_days=30,
        )
        # 2026-08-16 - 30 Tage = 2026-07-17
        assert "DTSTART;VALUE=DATE:20260717" in ics

    def test_custom_lead_days(self) -> None:
        valid_until = datetime(2026, 8, 16, tzinfo=UTC)
        ics = export_renewals_to_ics(
            [_training(valid_until=valid_until)],
            employee_names={1: "Anna"},
            now=NOW,
            reminder_lead_days=7,
        )
        # 2026-08-16 - 7 Tage = 2026-08-09
        assert "DTSTART;VALUE=DATE:20260809" in ics

    def test_default_lead_days_konstante(self) -> None:
        assert DEFAULT_REMINDER_LEAD_DAYS == 30

    def test_mehrere_vevents(self) -> None:
        ics = export_renewals_to_ics(
            [
                _training(
                    valid_until=NOW + timedelta(days=10),
                    title="A",
                    training_id=1,
                ),
                _training(
                    valid_until=NOW + timedelta(days=20),
                    title="B",
                    training_id=2,
                ),
            ],
            employee_names={1: "Anna"},
            now=NOW,
        )
        assert ics.count("BEGIN:VEVENT") == 2

    def test_permanent_schulung_wird_uebersprungen(self) -> None:
        ics = export_renewals_to_ics(
            [
                _training(
                    valid_until=NOW + timedelta(days=10),
                    training_id=1,
                ),
                _training(valid_until=None, training_id=2),
            ],
            employee_names={1: "Anna"},
            now=NOW,
        )
        assert ics.count("BEGIN:VEVENT") == 1

    def test_provider_landet_in_description(self) -> None:
        ics = export_renewals_to_ics(
            [
                _training(
                    valid_until=NOW + timedelta(days=10),
                    provider="DATEV-Akademie",
                )
            ],
            employee_names={1: "Anna"},
            now=NOW,
        )
        assert "DATEV-Akademie" in ics


# ---------------------------------------------------------------------------
# Edge-Cases / Errors
# ---------------------------------------------------------------------------


class TestExportErrors:
    def test_leere_liste_wirft(self) -> None:
        with pytest.raises(IcsExportError, match="Keine exportierbaren"):
            export_renewals_to_ics([], employee_names={}, now=NOW)

    def test_nur_permanent_wirft(self) -> None:
        with pytest.raises(IcsExportError):
            export_renewals_to_ics(
                [_training(valid_until=None)],
                employee_names={1: "Anna"},
                now=NOW,
            )


# ---------------------------------------------------------------------------
# Escape-Verhalten (RFC 5545)
# ---------------------------------------------------------------------------


class TestIcsEscape:
    def test_komma_wird_escaped(self) -> None:
        ics = export_renewals_to_ics(
            [_training(valid_until=NOW + timedelta(days=10), title="A,B")],
            employee_names={1: "Anna"},
            now=NOW,
        )
        assert "A\\,B" in ics
        assert "A,B" not in ics.replace("A\\,B", "")

    def test_semikolon_wird_escaped(self) -> None:
        ics = export_renewals_to_ics(
            [_training(valid_until=NOW + timedelta(days=10), title="A;B")],
            employee_names={1: "Anna"},
            now=NOW,
        )
        assert "A\\;B" in ics

    def test_backslash_wird_escaped(self) -> None:
        ics = export_renewals_to_ics(
            [_training(valid_until=NOW + timedelta(days=10), title="A\\B")],
            employee_names={1: "Anna"},
            now=NOW,
        )
        assert "A\\\\B" in ics


# ---------------------------------------------------------------------------
# Stable UID
# ---------------------------------------------------------------------------


class TestStableUid:
    def test_gleiche_id_gleiche_uid(self) -> None:
        ics_a = export_renewals_to_ics(
            [
                _training(
                    valid_until=NOW + timedelta(days=10), training_id=42
                )
            ],
            employee_names={1: "Anna"},
            now=NOW,
        )
        ics_b = export_renewals_to_ics(
            [
                _training(
                    valid_until=NOW + timedelta(days=20),
                    training_id=42,
                    title="andere title",
                )
            ],
            employee_names={1: "Anna"},
            now=NOW,
        )
        # Beide UIDs sind id-basiert, also gleich.
        assert "awareness-tracker-42@finlai.eu" in ics_a
        assert "awareness-tracker-42@finlai.eu" in ics_b

    def test_transientes_training_uid_hash_basiert(self) -> None:
        ics = export_renewals_to_ics(
            [
                _training(
                    valid_until=NOW + timedelta(days=10),
                    training_id=None,
                )
            ],
            employee_names={1: "Anna"},
            now=NOW,
        )
        # Kein "tracker-None" und kein numerischer ID-Suffix.
        assert "awareness-tracker-None" not in ics
        # Aber Hash-UID muss da sein.
        import re  # noqa: PLC0415

        assert re.search(
            r"awareness-tracker-[0-9a-f]{16}@finlai\.eu", ics
        )
