"""
test_light_siem_domain.

Tests fuer das Light-SIEM-Domain-Modell: Validierung,
Dedup-Hash-Stabilitaet, Severity-Gewichte.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tools.norisk_dashboard.domain.light_siem_models import (
    MAX_EVENT_TYPE_LENGTH,
    MAX_PAYLOAD_LENGTH,
    MAX_SUMMARY_LENGTH,
    EventSeverity,
    EventSource,
    LightSiemEvent,
    compute_dedup_hash,
)

NOW = datetime(2026, 5, 16, 8, 0, tzinfo=UTC)


def _event(
    *,
    source: EventSource = EventSource.AWARENESS_TRACKER,
    event_type: str = "training_expired",
    severity: EventSeverity = EventSeverity.WARN,
    summary: str = "Schulung X laeuft ab",
) -> LightSiemEvent:
    return LightSiemEvent(
        id=None,
        timestamp=NOW,
        source=source,
        event_type=event_type,
        severity=severity,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEventSource:
    def test_from_value_bekannt(self) -> None:
        assert (
            EventSource.from_value("patch_monitor")
            is EventSource.PATCH_MONITOR
        )

    def test_from_value_unbekannt_faellt_auf_other(self) -> None:
        assert EventSource.from_value("does_not_exist") is EventSource.OTHER


class TestEventSeverity:
    def test_from_value_bekannt(self) -> None:
        assert (
            EventSeverity.from_value("critical")
            is EventSeverity.CRITICAL
        )

    def test_from_value_unbekannt_faellt_auf_info(self) -> None:
        assert EventSeverity.from_value("nope") is EventSeverity.INFO

    def test_numeric_weight_monoton_steigend(self) -> None:
        # CRITICAL muss schwerer wiegen als ERROR > WARN > INFO.
        assert (
            EventSeverity.INFO.numeric_weight
            < EventSeverity.WARN.numeric_weight
            < EventSeverity.ERROR.numeric_weight
            < EventSeverity.CRITICAL.numeric_weight
        )
        # Konkret: 1 < 3 < 5 < 10
        assert EventSeverity.INFO.numeric_weight == 1
        assert EventSeverity.CRITICAL.numeric_weight == 10


# ---------------------------------------------------------------------------
# LightSiemEvent — Validierung
# ---------------------------------------------------------------------------


class TestLightSiemEventDomain:
    def test_minimal_event_valid(self) -> None:
        event = _event()
        assert event.event_type == "training_expired"
        assert event.dedup_hash  # Auto-berechnet
        assert len(event.dedup_hash) == 16

    def test_leerer_event_type_wirft(self) -> None:
        with pytest.raises(ValueError, match="event_type"):
            _event(event_type="   ")

    def test_zu_langer_event_type_wirft(self) -> None:
        with pytest.raises(ValueError, match="event_type"):
            _event(event_type="x" * (MAX_EVENT_TYPE_LENGTH + 1))

    def test_leeres_summary_wirft(self) -> None:
        with pytest.raises(ValueError, match="summary"):
            _event(summary="   ")

    def test_zu_langes_summary_wird_gekuerzt(self) -> None:
        long = "x" * (MAX_SUMMARY_LENGTH + 50)
        event = _event(summary=long)
        # Kuerzung statt Wurf — Adapter koennten lange Logs liefern.
        assert len(event.summary) == MAX_SUMMARY_LENGTH

    def test_payload_zu_lang_wirft(self) -> None:
        with pytest.raises(ValueError, match="payload_json"):
            LightSiemEvent(
                id=None,
                timestamp=NOW,
                source=EventSource.OTHER,
                event_type="x",
                severity=EventSeverity.INFO,
                summary="y",
                payload_json="z" * (MAX_PAYLOAD_LENGTH + 1),
            )

    def test_summary_wird_getrimmt(self) -> None:
        event = _event(summary="   Hallo   ")
        assert event.summary == "Hallo"


# ---------------------------------------------------------------------------
# compute_dedup_hash
# ---------------------------------------------------------------------------


class TestDedupHash:
    def test_stable_fuer_gleiche_inputs(self) -> None:
        h1 = compute_dedup_hash(
            EventSource.PATCH_MONITOR, "patch_failed", "DATEV update failed"
        )
        h2 = compute_dedup_hash(
            EventSource.PATCH_MONITOR, "patch_failed", "DATEV update failed"
        )
        assert h1 == h2

    def test_unterscheidet_source(self) -> None:
        h1 = compute_dedup_hash(
            EventSource.PATCH_MONITOR, "x", "y"
        )
        h2 = compute_dedup_hash(
            EventSource.SYSTEM_SCANNER, "x", "y"
        )
        assert h1 != h2

    def test_unterscheidet_event_type(self) -> None:
        h1 = compute_dedup_hash(EventSource.OTHER, "a", "y")
        h2 = compute_dedup_hash(EventSource.OTHER, "b", "y")
        assert h1 != h2

    def test_unterscheidet_summary(self) -> None:
        h1 = compute_dedup_hash(EventSource.OTHER, "x", "y1")
        h2 = compute_dedup_hash(EventSource.OTHER, "x", "y2")
        assert h1 != h2

    def test_trim_fuehrt_zum_gleichen_hash(self) -> None:
        h1 = compute_dedup_hash(EventSource.OTHER, "x", "  y  ")
        h2 = compute_dedup_hash(EventSource.OTHER, "x", "y")
        assert h1 == h2

    def test_event_setzt_dedup_hash_automatisch(self) -> None:
        event = _event()
        expected = compute_dedup_hash(
            event.source, event.event_type, event.summary
        )
        assert event.dedup_hash == expected
