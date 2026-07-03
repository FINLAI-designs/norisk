"""
test_supply_chain_avv_domain.

Domain-Tests fuer die Iter-2c-Erweiterungen: AvvDocument + Art28Check +
AvvChecklistEntry + Subprocessor + VendorSubprocessorLink.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.supply_chain_monitor.domain.models import (
    MAX_AVV_FILE_SIZE_BYTES,
    MAX_CUSTOM_CHECK_LABEL_LENGTH,
    RENEWAL_WARNING_DAYS_DEFAULT,
    Art28Check,
    AvvChecklistEntry,
    AvvDocument,
    AvvDocumentStatus,
    RenewalStatus,
    Subprocessor,
    VendorCategory,
    VendorSubprocessorLink,
)

NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


def _make_avv(
    valid_until_offset_days: int = 365,
    size_bytes: int = 1024,
) -> AvvDocument:
    return AvvDocument(
        id=None,
        vendor_id=1,
        file_path="/tmp/x.pdf",
        sha256="a" * 64,
        size_bytes=size_bytes,
        original_filename="Microsoft_DPA_2025.pdf",
        valid_from=NOW - timedelta(days=30),
        valid_until=NOW + timedelta(days=valid_until_offset_days),
    )


class TestAvvDocument:
    def test_minimaler_avv_ist_gueltig(self) -> None:
        avv = _make_avv()
        assert avv.status is AvvDocumentStatus.ACTIVE
        assert avv.original_filename == "Microsoft_DPA_2025.pdf"

    def test_negative_size_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="negativ"):
            _make_avv(size_bytes=-1)

    def test_zu_grosse_pdf_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="ueberschreitet"):
            _make_avv(size_bytes=MAX_AVV_FILE_SIZE_BYTES + 1)

    def test_falscher_sha256_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="64-Zeichen"):
            AvvDocument(
                id=None,
                vendor_id=1,
                file_path="/tmp/x.pdf",
                sha256="kurz",
                size_bytes=10,
                original_filename="x.pdf",
                valid_from=NOW,
                valid_until=NOW + timedelta(days=1),
            )

    def test_leerer_filename_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="filename"):
            AvvDocument(
                id=None,
                vendor_id=1,
                file_path="/tmp/x.pdf",
                sha256="a" * 64,
                size_bytes=10,
                original_filename="   ",
                valid_from=NOW,
                valid_until=NOW + timedelta(days=1),
            )

    def test_valid_until_vor_valid_from_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="valid_until"):
            AvvDocument(
                id=None,
                vendor_id=1,
                file_path="/tmp/x.pdf",
                sha256="a" * 64,
                size_bytes=10,
                original_filename="x.pdf",
                valid_from=NOW,
                valid_until=NOW - timedelta(days=1),
            )


class TestRenewalStatus:
    def test_avv_ueber_90_tage_ist_ok(self) -> None:
        avv = _make_avv(valid_until_offset_days=365)
        assert avv.renewal_status(now=NOW) is RenewalStatus.OK

    def test_avv_unter_90_tage_ist_expiring_soon(self) -> None:
        avv = _make_avv(valid_until_offset_days=30)
        assert avv.renewal_status(now=NOW) is RenewalStatus.EXPIRING_SOON

    def test_avv_gestern_abgelaufen_ist_overdue(self) -> None:
        avv = AvvDocument(
            id=None,
            vendor_id=1,
            file_path="/tmp/x.pdf",
            sha256="a" * 64,
            size_bytes=10,
            original_filename="x.pdf",
            valid_from=NOW - timedelta(days=365),
            valid_until=NOW - timedelta(days=1),
        )
        assert avv.renewal_status(now=NOW) is RenewalStatus.OVERDUE

    def test_warning_days_anpassbar(self) -> None:
        avv = _make_avv(valid_until_offset_days=120)
        # Default-Threshold = 90 → OK
        assert avv.renewal_status(now=NOW) is RenewalStatus.OK
        # Threshold 180 → EXPIRING_SOON
        assert (
            avv.renewal_status(now=NOW, warning_days=180)
            is RenewalStatus.EXPIRING_SOON
        )

    def test_threshold_konstante_ist_90(self) -> None:
        assert RENEWAL_WARNING_DAYS_DEFAULT == 90


class TestArt28Check:
    def test_alle_10_pflichtinhalte_definiert(self) -> None:
        # DSGVO Art. 28 Abs. 3 lit. a-h + 2 Praxis-Checks = 10
        assert len(list(Art28Check)) == 10

    def test_from_value_robust(self) -> None:
        assert Art28Check.from_value("weisungsbindung") is Art28Check.WEISUNGSBINDUNG
        assert Art28Check.from_value("nicht_existent") is None
        assert Art28Check.from_value("") is None


class TestAvvChecklistEntry:
    def test_default_check_ist_gueltig(self) -> None:
        entry = AvvChecklistEntry(
            id=None,
            avv_id=1,
            is_present=True,
            art28_check=Art28Check.WEISUNGSBINDUNG,
        )
        assert entry.is_custom is False
        assert entry.display_label == "Weisungsbindung"

    def test_custom_check_ist_gueltig(self) -> None:
        entry = AvvChecklistEntry(
            id=None,
            avv_id=1,
            is_present=None,
            custom_label="Eigene Frage",
            is_custom=True,
        )
        assert entry.display_label == "Eigene Frage"

    def test_default_ohne_art28_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="art28_check ist Pflicht"):
            AvvChecklistEntry(
                id=None,
                avv_id=1,
                is_present=True,
            )

    def test_custom_ohne_label_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="custom_label"):
            AvvChecklistEntry(
                id=None,
                avv_id=1,
                is_present=None,
                custom_label="",
                is_custom=True,
            )

    def test_custom_mit_art28_wird_abgelehnt(self) -> None:
        # is_custom=True erlaubt KEIN art28_check.
        with pytest.raises(ValueError, match="schliesst art28_check aus"):
            AvvChecklistEntry(
                id=None,
                avv_id=1,
                is_present=None,
                art28_check=Art28Check.WEISUNGSBINDUNG,
                custom_label="X",
                is_custom=True,
            )

    def test_zu_langes_custom_label_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match=f"max. {MAX_CUSTOM_CHECK_LABEL_LENGTH}"):
            AvvChecklistEntry(
                id=None,
                avv_id=1,
                is_present=None,
                custom_label="x" * (MAX_CUSTOM_CHECK_LABEL_LENGTH + 1),
                is_custom=True,
            )

    def test_is_present_drei_states(self) -> None:
        for state in (True, False, None):
            e = AvvChecklistEntry(
                id=None,
                avv_id=1,
                is_present=state,
                art28_check=Art28Check.TOMS,
            )
            assert e.is_present is state


class TestSubprocessor:
    def test_minimaler_sub_ist_gueltig(self) -> None:
        sub = Subprocessor(
            id=None,
            name="AWS",
            country="us",
            category=VendorCategory.CLOUD,
        )
        assert sub.country == "US"  # normalisiert

    def test_leerer_name_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="name"):
            Subprocessor(
                id=None,
                name="   ",
                country="DE",
                category=VendorCategory.MSP,
            )

    @pytest.mark.parametrize("bad_country", ["USA", "D", "12", "us-east", "  "])
    def test_ungueltige_country_wird_abgelehnt(self, bad_country: str) -> None:
        with pytest.raises(ValueError, match="country"):
            Subprocessor(
                id=None,
                name="X",
                country=bad_country,
                category=VendorCategory.MSP,
            )


class TestVendorSubprocessorLink:
    def test_minimaler_link_ist_gueltig(self) -> None:
        link = VendorSubprocessorLink(
            id=None, vendor_id=1, subprocessor_id=2, role="Storage"
        )
        assert link.role == "Storage"

    def test_zu_lange_rolle_wird_abgelehnt(self) -> None:
        with pytest.raises(ValueError, match="role"):
            VendorSubprocessorLink(
                id=None,
                vendor_id=1,
                subprocessor_id=2,
                role="x" * 9999,
            )
