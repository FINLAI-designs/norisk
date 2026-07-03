"""
test_tls_check — Tests fuer TLS/SSL-Check 9 des API Security Analyzers.

Prueft:
    check_tls_certificate: 12 Szenarien (valides Cert, abgelaufen,
    Vorwarnzeit 30d/90d, TLS 1.0/1.1/1.2, self-signed, Hostname-Mismatch,
    schwache/mittlere Cipher, Gueltigkeitsbeginn in der Zukunft)
    _fetch_tls_info: HTTP-URL gibt None zurueck

Alle Tests sind netzwerkfrei — kein echter TLS-Handshake.

Author: Patrick Riederich
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# ---------------------------------------------------------------------------
# Hilfsfunktion
# ---------------------------------------------------------------------------


def _make_tls_info(**kwargs):
    """Erstellt ein TLSInfo-Objekt mit sicheren Standard-Werten."""
    from tools.api_security.domain.models import TLSInfo

    defaults = {
        "subject_cn": "api.example.com",
        "subject_org": "Example GmbH",
        "issuer_cn": "Let's Encrypt R3",
        "issuer_org": "Let's Encrypt",
        "not_before": "2024-01-01T00:00:00+00:00",
        "not_after": "2027-01-01T00:00:00+00:00",
        "san": ("api.example.com",),
        "tls_version": "TLSv1.3",
        "cipher_name": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "is_self_signed": False,
        "hostname_valid": True,
    }
    defaults.update(kwargs)
    return TLSInfo(**defaults)


# ---------------------------------------------------------------------------
# check_tls_certificate — 12 Tests
# ---------------------------------------------------------------------------


class TestCheckTlsCertificate:
    """Tests fuer die reine check_tls_certificate Funktion."""

    def test_valides_zertifikat_keine_findings(self):
        """Einwandfreies Zertifikat → keine Findings."""
        from tools.api_security.domain.checks import check_tls_certificate

        tls = _make_tls_info()
        assert check_tls_certificate(tls) == []

    def test_abgelaufenes_zertifikat_critical(self):
        """Abgelaufenes Zertifikat → CRITICAL TLS_CERT_EXPIRED."""
        from tools.api_security.domain.checks import check_tls_certificate
        from tools.api_security.domain.models import Severity

        tls = _make_tls_info(not_after="2020-01-01T00:00:00+00:00")
        findings = check_tls_certificate(tls)
        codes = [f.code for f in findings]
        assert "TLS_CERT_EXPIRED" in codes
        expired = next(f for f in findings if f.code == "TLS_CERT_EXPIRED")
        assert expired.severity == Severity.CRITICAL

    def test_expiring_30_tage_high(self):
        """Zertifikat laeuft in < 30 Tagen ab → HIGH TLS_CERT_EXPIRING_SOON."""
        from tools.api_security.domain.checks import check_tls_certificate
        from tools.api_security.domain.models import Severity

        soon = (datetime.now(UTC) + timedelta(days=15)).isoformat()
        tls = _make_tls_info(not_after=soon)
        findings = check_tls_certificate(tls)
        codes = [f.code for f in findings]
        assert "TLS_CERT_EXPIRING_SOON" in codes
        f = next(x for x in findings if x.code == "TLS_CERT_EXPIRING_SOON")
        assert f.severity == Severity.HIGH

    def test_expiring_90_tage_medium(self):
        """Zertifikat laeuft in < 90 Tagen ab → MEDIUM TLS_CERT_EXPIRING_90D."""
        from tools.api_security.domain.checks import check_tls_certificate
        from tools.api_security.domain.models import Severity

        soon = (datetime.now(UTC) + timedelta(days=60)).isoformat()
        tls = _make_tls_info(not_after=soon)
        findings = check_tls_certificate(tls)
        codes = [f.code for f in findings]
        assert "TLS_CERT_EXPIRING_90D" in codes
        f = next(x for x in findings if x.code == "TLS_CERT_EXPIRING_90D")
        assert f.severity == Severity.MEDIUM

    def test_tls_10_critical(self):
        """TLS 1.0 → CRITICAL TLS_WEAK_PROTOCOL."""
        from tools.api_security.domain.checks import check_tls_certificate
        from tools.api_security.domain.models import Severity

        tls = _make_tls_info(tls_version="TLSv1")
        findings = check_tls_certificate(tls)
        codes = [f.code for f in findings]
        assert "TLS_WEAK_PROTOCOL" in codes
        f = next(x for x in findings if x.code == "TLS_WEAK_PROTOCOL")
        assert f.severity == Severity.CRITICAL

    def test_tls_11_critical(self):
        """TLS 1.1 → CRITICAL TLS_WEAK_PROTOCOL."""
        from tools.api_security.domain.checks import check_tls_certificate

        tls = _make_tls_info(tls_version="TLSv1.1")
        codes = [f.code for f in check_tls_certificate(tls)]
        assert "TLS_WEAK_PROTOCOL" in codes

    def test_tls_12_low(self):
        """TLS 1.2 → LOW TLS_VERSION_1_2."""
        from tools.api_security.domain.checks import check_tls_certificate
        from tools.api_security.domain.models import Severity

        tls = _make_tls_info(tls_version="TLSv1.2")
        findings = check_tls_certificate(tls)
        codes = [f.code for f in findings]
        assert "TLS_VERSION_1_2" in codes
        f = next(x for x in findings if x.code == "TLS_VERSION_1_2")
        assert f.severity == Severity.LOW

    def test_self_signed_high(self):
        """Selbstsigniertes Zertifikat → HIGH TLS_SELF_SIGNED."""
        from tools.api_security.domain.checks import check_tls_certificate
        from tools.api_security.domain.models import Severity

        tls = _make_tls_info(is_self_signed=True)
        findings = check_tls_certificate(tls)
        codes = [f.code for f in findings]
        assert "TLS_SELF_SIGNED" in codes
        f = next(x for x in findings if x.code == "TLS_SELF_SIGNED")
        assert f.severity == Severity.HIGH

    def test_hostname_mismatch_critical(self):
        """Hostname-Mismatch → CRITICAL TLS_HOSTNAME_MISMATCH."""
        from tools.api_security.domain.checks import check_tls_certificate
        from tools.api_security.domain.models import Severity

        tls = _make_tls_info(hostname_valid=False)
        findings = check_tls_certificate(tls)
        codes = [f.code for f in findings]
        assert "TLS_HOSTNAME_MISMATCH" in codes
        f = next(x for x in findings if x.code == "TLS_HOSTNAME_MISMATCH")
        assert f.severity == Severity.CRITICAL

    def test_weak_cipher_critical(self):
        """Cipher < 128 Bit → CRITICAL TLS_WEAK_CIPHER."""
        from tools.api_security.domain.checks import check_tls_certificate
        from tools.api_security.domain.models import Severity

        tls = _make_tls_info(cipher_name="RC4-MD5", cipher_bits=64)
        findings = check_tls_certificate(tls)
        codes = [f.code for f in findings]
        assert "TLS_WEAK_CIPHER" in codes
        f = next(x for x in findings if x.code == "TLS_WEAK_CIPHER")
        assert f.severity == Severity.CRITICAL

    def test_medium_cipher_medium(self):
        """Cipher 128 Bit → MEDIUM TLS_MEDIUM_CIPHER."""
        from tools.api_security.domain.checks import check_tls_certificate
        from tools.api_security.domain.models import Severity

        tls = _make_tls_info(cipher_name="AES-128-GCM", cipher_bits=128)
        findings = check_tls_certificate(tls)
        codes = [f.code for f in findings]
        assert "TLS_MEDIUM_CIPHER" in codes
        f = next(x for x in findings if x.code == "TLS_MEDIUM_CIPHER")
        assert f.severity == Severity.MEDIUM

    def test_gueltigkeitsbeginn_zukunft_critical(self):
        """not_before in der Zukunft → CRITICAL TLS_CERT_NOT_YET_VALID."""
        from tools.api_security.domain.checks import check_tls_certificate
        from tools.api_security.domain.models import Severity

        future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
        tls = _make_tls_info(not_before=future)
        findings = check_tls_certificate(tls)
        codes = [f.code for f in findings]
        assert "TLS_CERT_NOT_YET_VALID" in codes
        f = next(x for x in findings if x.code == "TLS_CERT_NOT_YET_VALID")
        assert f.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# _fetch_tls_info — netzwerkfreier Test
# ---------------------------------------------------------------------------


class TestFetchTlsInfo:
    """Tests fuer HttpScanner._fetch_tls_info ohne echten TLS-Handshake."""

    def test_http_url_gibt_none_zurueck(self):
        """HTTP-URL (kein HTTPS) → None wird zurueckgegeben."""
        from tools.api_security.data.http_scanner import HttpScanner
        from tools.api_security.domain.models import ScanTarget

        scanner = HttpScanner()
        target = ScanTarget(url="http://api.example.com/v1")
        assert scanner._fetch_tls_info(target) is None
