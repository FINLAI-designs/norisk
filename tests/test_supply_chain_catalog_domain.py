"""
test_supply_chain_catalog_domain.

Domain-Tests fuer die Iter-2b-Erweiterungen: VendorCatalogEntry,
VendorDetection, VendorSuggestion + DetectionSource/Confidence/Status.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.supply_chain_monitor.domain.models import (
    DETECTION_SOURCE_WEIGHTS,
    MAX_NOTES_LENGTH,
    MAX_PATTERNS_PER_FIELD,
    DetectionConfidence,
    DetectionSource,
    DetectionStatus,
    VendorCatalogEntry,
    VendorCategory,
    VendorDetection,
    VendorSuggestion,
)


class TestDetectionConfidence:
    @pytest.mark.parametrize(
        "points,expected",
        [
            (0, DetectionConfidence.LOW),
            (1, DetectionConfidence.LOW),
            (2, DetectionConfidence.LOW),
            (3, DetectionConfidence.MEDIUM),
            (4, DetectionConfidence.MEDIUM),
            (5, DetectionConfidence.HIGH),
            (6, DetectionConfidence.HIGH),
            (99, DetectionConfidence.HIGH),
        ],
    )
    def test_from_points(self, points: int, expected: DetectionConfidence) -> None:
        assert DetectionConfidence.from_points(points) is expected


class TestSourceWeights:
    def test_weights_sind_cert_groesser_mx_groesser_installed(self) -> None:
        assert (
            DETECTION_SOURCE_WEIGHTS[DetectionSource.CERT_ISSUER]
            > DETECTION_SOURCE_WEIGHTS[DetectionSource.MX_LOOKUP]
            > DETECTION_SOURCE_WEIGHTS[DetectionSource.INSTALLED_APP]
        )

    def test_cert_plus_mx_ergibt_high_confidence(self) -> None:
        # Cert (3) + MX (2) = 5 → HIGH
        total = (
            DETECTION_SOURCE_WEIGHTS[DetectionSource.CERT_ISSUER]
            + DETECTION_SOURCE_WEIGHTS[DetectionSource.MX_LOOKUP]
        )
        assert DetectionConfidence.from_points(total) is DetectionConfidence.HIGH


class TestVendorCatalogEntry:
    def test_minimaler_eintrag_ist_gueltig(self) -> None:
        entry = VendorCatalogEntry(
            id=1,
            canonical_name="Microsoft",
            default_category=VendorCategory.CLOUD,
        )
        assert entry.canonical_name == "Microsoft"
        assert entry.aliases == ()

    def test_patterns_werden_normalisiert_und_dedupliziert(self) -> None:
        entry = VendorCatalogEntry(
            id=1,
            canonical_name="Microsoft",
            default_category=VendorCategory.CLOUD,
            aliases=("MICROSOFT", "  msft  ", "msft", "ms"),
            app_name_patterns=("Microsoft", "MICROSOFT", "onedrive"),
        )
        assert entry.aliases == ("microsoft", "msft", "ms")
        assert entry.app_name_patterns == ("microsoft", "onedrive")

    def test_leerer_canonical_name_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="canonical_name"):
            VendorCatalogEntry(
                id=1,
                canonical_name="   ",
                default_category=VendorCategory.CLOUD,
            )

    def test_zu_lange_notizen_werden_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match=f"max. {MAX_NOTES_LENGTH}"):
            VendorCatalogEntry(
                id=1,
                canonical_name="X",
                default_category=VendorCategory.CLOUD,
                notes="x" * (MAX_NOTES_LENGTH + 1),
            )

    def test_zu_viele_patterns_werden_abgelehnt(self) -> None:
        too_many = tuple(f"pat-{i}" for i in range(MAX_PATTERNS_PER_FIELD + 5))
        with pytest.raises(ValueError, match="Maximal"):
            VendorCatalogEntry(
                id=1,
                canonical_name="X",
                default_category=VendorCategory.CLOUD,
                app_name_patterns=too_many,
            )

    def test_patterns_for_source(self) -> None:
        entry = VendorCatalogEntry(
            id=1,
            canonical_name="X",
            default_category=VendorCategory.CLOUD,
            app_name_patterns=("a",),
            mx_hostname_patterns=("b",),
            cert_issuer_patterns=("c",),
        )
        assert entry.patterns_for(DetectionSource.INSTALLED_APP) == ("a",)
        assert entry.patterns_for(DetectionSource.MX_LOOKUP) == ("b",)
        assert entry.patterns_for(DetectionSource.CERT_ISSUER) == ("c",)


class TestVendorDetection:
    def test_minimaler_treffer_ist_gueltig(self) -> None:
        det = VendorDetection(
            id=1,
            catalog_entry_id=1,
            source=DetectionSource.INSTALLED_APP,
            raw_match="Microsoft OneDrive",
        )
        assert det.raw_match == "Microsoft OneDrive"
        assert det.status is DetectionStatus.PENDING
        assert det.is_actionable() is True

    def test_leerer_raw_match_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="raw_match"):
            VendorDetection(
                id=1,
                catalog_entry_id=1,
                source=DetectionSource.INSTALLED_APP,
                raw_match="   ",
            )

    def test_sehr_langer_raw_match_wird_gekuerzt_nicht_abgelehnt(self) -> None:
        # Cert-Issuer-Strings koennen > 200 Zeichen sein — wir kuerzen statt
        # zu crashen.
        long_match = "X" * 500
        det = VendorDetection(
            id=1,
            catalog_entry_id=1,
            source=DetectionSource.CERT_ISSUER,
            raw_match=long_match,
        )
        assert len(det.raw_match) == 200  # MAX_NAME_LENGTH
        assert det.raw_match == "X" * 200

    @pytest.mark.parametrize(
        "status,actionable",
        [
            (DetectionStatus.PENDING, True),
            (DetectionStatus.DEFERRED, True),
            (DetectionStatus.ACCEPTED, False),
            (DetectionStatus.REJECTED, False),
        ],
    )
    def test_is_actionable(self, status: DetectionStatus, actionable: bool) -> None:
        det = VendorDetection(
            id=1,
            catalog_entry_id=1,
            source=DetectionSource.INSTALLED_APP,
            raw_match="X",
            status=status,
        )
        assert det.is_actionable() is actionable


def _make_entry(entry_id: int = 1) -> VendorCatalogEntry:
    return VendorCatalogEntry(
        id=entry_id,
        canonical_name="Microsoft",
        default_category=VendorCategory.CLOUD,
    )


def _make_detection(
    entry_id: int = 1,
    source: DetectionSource = DetectionSource.INSTALLED_APP,
    status: DetectionStatus = DetectionStatus.PENDING,
    detected_at: datetime | None = None,
) -> VendorDetection:
    return VendorDetection(
        id=10,
        catalog_entry_id=entry_id,
        source=source,
        raw_match=f"raw-{source.value}",
        status=status,
        detected_at=detected_at or datetime.now(UTC),
    )


class TestVendorSuggestion:
    def test_alle_drei_quellen_geben_high_confidence(self) -> None:
        entry = _make_entry()
        dets = (
            _make_detection(source=DetectionSource.INSTALLED_APP),
            _make_detection(source=DetectionSource.MX_LOOKUP),
            _make_detection(source=DetectionSource.CERT_ISSUER),
        )
        sug = VendorSuggestion.from_detections(entry, dets)
        assert sug.source_points == 6
        assert sug.confidence is DetectionConfidence.HIGH

    def test_nur_cert_ergibt_medium_confidence(self) -> None:
        entry = _make_entry()
        sug = VendorSuggestion.from_detections(
            entry,
            (_make_detection(source=DetectionSource.CERT_ISSUER),),
        )
        assert sug.source_points == 3
        assert sug.confidence is DetectionConfidence.MEDIUM

    def test_nur_mx_ergibt_low_confidence(self) -> None:
        entry = _make_entry()
        sug = VendorSuggestion.from_detections(
            entry,
            (_make_detection(source=DetectionSource.MX_LOOKUP),),
        )
        assert sug.source_points == 2
        assert sug.confidence is DetectionConfidence.LOW

    def test_doppelte_quelle_zaehlt_nur_einmal(self) -> None:
        entry = _make_entry()
        # 3x Installed-App-Treffer → trotzdem nur 1 Punkt (unique source).
        dets = (
            _make_detection(source=DetectionSource.INSTALLED_APP),
            _make_detection(source=DetectionSource.INSTALLED_APP),
            _make_detection(source=DetectionSource.INSTALLED_APP),
        )
        sug = VendorSuggestion.from_detections(entry, dets)
        assert sug.source_points == 1
        assert sug.confidence is DetectionConfidence.LOW

    def test_rejected_detections_zaehlen_nicht(self) -> None:
        entry = _make_entry()
        # Cert ist REJECTED, MX und Installed sind PENDING.
        dets = (
            _make_detection(
                source=DetectionSource.CERT_ISSUER,
                status=DetectionStatus.REJECTED,
            ),
            _make_detection(source=DetectionSource.MX_LOOKUP),
            _make_detection(source=DetectionSource.INSTALLED_APP),
        )
        sug = VendorSuggestion.from_detections(entry, dets)
        # MX(2) + Installed(1) = 3 → MEDIUM (Cert REJECTED faellt raus)
        assert sug.source_points == 3
        assert sug.confidence is DetectionConfidence.MEDIUM

    def test_accepted_detections_zaehlen_nicht(self) -> None:
        entry = _make_entry()
        sug = VendorSuggestion.from_detections(
            entry,
            (
                _make_detection(
                    source=DetectionSource.CERT_ISSUER,
                    status=DetectionStatus.ACCEPTED,
                ),
            ),
        )
        # Alle ACCEPTED → 0 Punkte → LOW
        assert sug.source_points == 0
        assert sug.confidence is DetectionConfidence.LOW

    def test_empty_detections_wird_abgelehnt(self) -> None:
        entry = _make_entry()
        with pytest.raises(ValueError, match="mindestens"):
            VendorSuggestion.from_detections(entry, ())

    def test_mismatch_zwischen_catalog_id_wird_abgelehnt(self) -> None:
        entry = _make_entry(entry_id=1)
        det = _make_detection(entry_id=999)
        with pytest.raises(ValueError, match="catalog_entry_id"):
            VendorSuggestion.from_detections(entry, (det,))

    def test_last_detected_at_ist_max_aller_stamps(self) -> None:
        entry = _make_entry()
        now = datetime.now(UTC)
        earlier = now - timedelta(hours=2)
        latest = now + timedelta(hours=1)
        dets = (
            _make_detection(detected_at=earlier),
            _make_detection(detected_at=now, source=DetectionSource.MX_LOOKUP),
            _make_detection(detected_at=latest, source=DetectionSource.CERT_ISSUER),
        )
        sug = VendorSuggestion.from_detections(entry, dets)
        assert sug.last_detected_at == latest
