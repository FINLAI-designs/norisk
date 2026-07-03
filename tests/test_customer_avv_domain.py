"""
test_customer_avv_domain.

Domain-Tests fuer CustomerAvvDocument + den geteilten renewal_status_for-Helfer.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.supply_chain_monitor.domain.models import (
    AvvDocument,
    AvvDocumentStatus,
    CustomerAvvDocument,
    RenewalStatus,
    renewal_status_for,
)

_SHA = "a" * 64


def _make_customer_avv(
    subject_id: str = "subj-1",
    days_until: int = 365,
) -> CustomerAvvDocument:
    now = datetime.now(UTC)
    return CustomerAvvDocument(
        id=None,
        subject_id=subject_id,
        file_path="/tmp/x.pdf.enc",
        sha256=_SHA,
        size_bytes=1024,
        original_filename="kunden_dpa.pdf",
        valid_from=now - timedelta(days=30),
        valid_until=now + timedelta(days=days_until),
    )


class TestCustomerAvvDocumentValidation:
    def test_gueltiges_dokument(self) -> None:
        doc = _make_customer_avv()
        assert doc.subject_id == "subj-1"
        assert doc.status is AvvDocumentStatus.ACTIVE

    def test_leerer_subject_id_wirft(self) -> None:
        with pytest.raises(ValueError, match="subject_id"):
            _make_customer_avv(subject_id="   ")

    def test_falsche_hash_laenge_wirft(self) -> None:
        now = datetime.now(UTC)
        with pytest.raises(ValueError, match="64-Zeichen"):
            CustomerAvvDocument(
                id=None,
                subject_id="subj-1",
                file_path="/tmp/x.pdf.enc",
                sha256="zu-kurz",
                size_bytes=10,
                original_filename="x.pdf",
                valid_from=now,
                valid_until=now + timedelta(days=1),
            )

    def test_valid_until_vor_valid_from_wirft(self) -> None:
        now = datetime.now(UTC)
        with pytest.raises(ValueError, match="valid_until"):
            CustomerAvvDocument(
                id=None,
                subject_id="subj-1",
                file_path="/tmp/x.pdf.enc",
                sha256=_SHA,
                size_bytes=10,
                original_filename="x.pdf",
                valid_from=now,
                valid_until=now - timedelta(days=1),
            )

    def test_leerer_dateiname_wirft(self) -> None:
        now = datetime.now(UTC)
        with pytest.raises(ValueError, match="original_filename"):
            CustomerAvvDocument(
                id=None,
                subject_id="subj-1",
                file_path="/tmp/x.pdf.enc",
                sha256=_SHA,
                size_bytes=10,
                original_filename="   ",
                valid_from=now,
                valid_until=now + timedelta(days=1),
            )


class TestRenewalStatusFor:
    """Der geteilte Helfer wird von beiden Perspektiven genutzt (DRY)."""

    def test_ok_bei_weit_in_der_zukunft(self) -> None:
        now = datetime.now(UTC)
        assert (
            renewal_status_for(now + timedelta(days=200), now=now) is RenewalStatus.OK
        )

    def test_expiring_soon_innerhalb_warnfenster(self) -> None:
        now = datetime.now(UTC)
        assert (
            renewal_status_for(now + timedelta(days=30), now=now)
            is RenewalStatus.EXPIRING_SOON
        )

    def test_overdue_in_der_vergangenheit(self) -> None:
        now = datetime.now(UTC)
        assert (
            renewal_status_for(now - timedelta(days=1), now=now)
            is RenewalStatus.OVERDUE
        )

    def test_customer_doc_delegiert_an_helfer(self) -> None:
        now = datetime.now(UTC)
        doc = _make_customer_avv(days_until=10)
        assert doc.renewal_status(now=now) is RenewalStatus.EXPIRING_SOON

    def test_vendor_doc_unveraendert_nach_refactor(self) -> None:
        """Regression: AvvDocument.renewal_status delegiert jetzt, gleiches Ergebnis."""
        now = datetime.now(UTC)
        doc = AvvDocument(
            id=None,
            vendor_id=1,
            file_path="/tmp/x.pdf.enc",
            sha256=_SHA,
            size_bytes=10,
            original_filename="x.pdf",
            valid_from=now - timedelta(days=10),
            valid_until=now - timedelta(days=1),
        )
        assert doc.renewal_status(now=now) is RenewalStatus.OVERDUE
