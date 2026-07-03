"""test_storytelling_adapter_cert_monitor (a)+(b)."""

from __future__ import annotations

from core.security.severity import Severity
from tools.cert_monitor.application.storytelling_adapter import (
    cert_infos_to_ki_inputs,
)
from tools.cert_monitor.domain.models import CertInfo, CertStatus


def _cert(
    domain: str = "example.test",
    days: int = 60,
    status: CertStatus = CertStatus.OK,
    gueltig_bis: str = "2026-07-07",
    serial: str = "deadbeef",
) -> CertInfo:
    return CertInfo(
        domain=domain,
        tage_verbleibend=days,
        status=status,
        gueltig_bis=gueltig_bis,
        serial_number=serial,
    )


class TestCertExpiringFilter:
    """Nur Zertifikate ≤90 Tage werden gemeldet."""

    def test_60_tage_wird_gemeldet(self) -> None:
        inputs = cert_infos_to_ki_inputs([_cert(days=60)])
        assert len(inputs) == 1
        assert inputs[0].finding_type == "cert_expiring"
        assert inputs[0].details["days_left"] == 60
        assert inputs[0].details["expires_at"] == "2026-07-07"

    def test_120_tage_wird_uebersprungen(self) -> None:
        assert cert_infos_to_ki_inputs([_cert(days=120)]) == []

    def test_genau_90_tage_wird_gemeldet(self) -> None:
        """Grenzwert: 90 Tage ist inklusiv (≤ 90)."""
        assert len(cert_infos_to_ki_inputs([_cert(days=90)])) == 1


class TestSeverityMapping:
    def test_5_tage_critical(self) -> None:
        assert cert_infos_to_ki_inputs([_cert(days=5)])[0].severity == Severity.CRITICAL

    def test_abgelaufen_critical(self) -> None:
        assert cert_infos_to_ki_inputs([_cert(days=-1)])[0].severity == Severity.CRITICAL

    def test_20_tage_high(self) -> None:
        assert cert_infos_to_ki_inputs([_cert(days=20)])[0].severity == Severity.HIGH

    def test_60_tage_medium(self) -> None:
        assert cert_infos_to_ki_inputs([_cert(days=60)])[0].severity == Severity.MEDIUM


class TestSkipInvalid:
    """Status FEHLER/UNBEKANNT + leeres gueltig_bis werden uebersprungen."""

    def test_status_fehler(self) -> None:
        assert cert_infos_to_ki_inputs([_cert(days=10, status=CertStatus.FEHLER)]) == []

    def test_status_unbekannt(self) -> None:
        assert cert_infos_to_ki_inputs([_cert(days=10, status=CertStatus.UNBEKANNT)]) == []

    def test_kein_gueltig_bis(self) -> None:
        assert cert_infos_to_ki_inputs([_cert(days=10, gueltig_bis="")]) == []


class TestSubject:
    def test_subject_ist_anzeige_domain(self) -> None:
        inputs = cert_infos_to_ki_inputs([_cert(domain="api.example.test", days=60)])
        assert inputs[0].subject == "api.example.test"

    def test_evidence_id_enthaelt_serial(self) -> None:
        inputs = cert_infos_to_ki_inputs([_cert(serial="abc123", days=60)])
        assert "abc123" in inputs[0].evidence_id

    def test_evidence_id_default_bei_fehlendem_serial(self) -> None:
        inputs = cert_infos_to_ki_inputs([_cert(serial="", days=60)])
        assert "no-serial" in inputs[0].evidence_id
