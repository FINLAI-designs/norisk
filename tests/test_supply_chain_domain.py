"""
test_supply_chain_domain.

Domain-Tests fuer:class:`Vendor` und:class:`VendorCategory`. Pruefen die
Validierungs-Logik in ``Vendor.__post_init__`` und die robuste
DB-String-Konvertierung in ``VendorCategory.from_value``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.supply_chain_monitor.domain.models import (
    MAX_CRITICALITY,
    MAX_NAME_LENGTH,
    MAX_NOTES_LENGTH,
    MIN_CRITICALITY,
    Vendor,
    VendorCategory,
)


class TestVendorCategory:
    def test_from_value_bekannter_eintrag(self) -> None:
        assert VendorCategory.from_value("cloud") is VendorCategory.CLOUD
        assert VendorCategory.from_value("kanzleisoftware") is VendorCategory.KANZLEISOFTWARE

    def test_from_value_unbekannter_eintrag_faellt_auf_spezial_zurueck(self) -> None:
        assert VendorCategory.from_value("nicht_existent") is VendorCategory.SPEZIAL
        assert VendorCategory.from_value("") is VendorCategory.SPEZIAL


class TestVendor:
    def test_minimal_vendor_ist_gueltig(self) -> None:
        vendor = Vendor(
            id=None,
            name="DATEV",
            category=VendorCategory.KANZLEISOFTWARE,
            criticality_score=5,
        )
        assert vendor.name == "DATEV"
        assert vendor.notes == ""
        assert vendor.is_critical() is True

    def test_namen_werden_normalisiert(self) -> None:
        vendor = Vendor(
            id=None,
            name="  Microsoft 365  ",
            category=VendorCategory.CLOUD,
            criticality_score=4,
        )
        assert vendor.name == "Microsoft 365"

    def test_leerer_name_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="name darf nicht leer sein"):
            Vendor(
                id=None,
                name="   ",
                category=VendorCategory.CLOUD,
                criticality_score=3,
            )

    def test_zu_langer_name_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match=f"max. {MAX_NAME_LENGTH}"):
            Vendor(
                id=None,
                name="x" * (MAX_NAME_LENGTH + 1),
                category=VendorCategory.CLOUD,
                criticality_score=3,
            )

    @pytest.mark.parametrize("score", [0, -1, MAX_CRITICALITY + 1, 99])
    def test_kritikalitaet_ausserhalb_grenzen_wird_abgelehnt(self, score: int) -> None:
        with pytest.raises(ValueError, match="criticality_score muss zwischen"):
            Vendor(
                id=None,
                name="X",
                category=VendorCategory.CLOUD,
                criticality_score=score,
            )

    @pytest.mark.parametrize("score", [MIN_CRITICALITY, 2, 3, 4, MAX_CRITICALITY])
    def test_kritikalitaet_innerhalb_grenzen_ist_gueltig(self, score: int) -> None:
        vendor = Vendor(
            id=None,
            name="X",
            category=VendorCategory.CLOUD,
            criticality_score=score,
        )
        assert vendor.criticality_score == score

    def test_zu_lange_notizen_werden_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match=f"max. {MAX_NOTES_LENGTH}"):
            Vendor(
                id=None,
                name="X",
                category=VendorCategory.CLOUD,
                criticality_score=3,
                notes="x" * (MAX_NOTES_LENGTH + 1),
            )

    def test_is_critical_grenze_bei_4(self) -> None:
        weniger = Vendor(
            id=None, name="A", category=VendorCategory.MSP, criticality_score=3
        )
        gerade_kritisch = Vendor(
            id=None, name="B", category=VendorCategory.MSP, criticality_score=4
        )
        hoechst = Vendor(
            id=None, name="C", category=VendorCategory.MSP, criticality_score=5
        )
        assert weniger.is_critical() is False
        assert gerade_kritisch.is_critical() is True
        assert hoechst.is_critical() is True

    def test_default_timestamps_sind_utc_und_aktuell(self) -> None:
        before = datetime.now(UTC) - timedelta(seconds=1)
        vendor = Vendor(
            id=None,
            name="X",
            category=VendorCategory.CLOUD,
            criticality_score=3,
        )
        after = datetime.now(UTC) + timedelta(seconds=1)
        assert before <= vendor.created_at <= after
        assert before <= vendor.updated_at <= after
        assert vendor.created_at.tzinfo is not None
