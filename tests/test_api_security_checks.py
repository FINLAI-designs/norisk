"""
tests/test_api_security_checks.py — Unit-Tests für die domain/checks.py.

Prüft alle 8 Check-Funktionen mit positiven und negativen Fällen.
Kein Netzwerk-I/O — reine Einheitstests auf Pure Functions.

Author: Patrick Riederich
"""

from __future__ import annotations

from tools.api_security.domain.checks import (
    check_auth_headers,
    check_cors,
    check_error_leakage,
    check_https,
    check_rate_limiting,
    check_response_data,
    check_security_headers,
    check_ssrf_indicators,
)
from tools.api_security.domain.models import OWASPCategory, Severity

# ---------------------------------------------------------------------------
# check_https
# ---------------------------------------------------------------------------


class TestCheckHttps:
    def test_http_gibt_finding(self):
        findings = check_https("http://api.example.com/v1")
        assert len(findings) == 1
        assert findings[0].code == "NO_HTTPS"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].owasp == OWASPCategory.API8

    def test_https_kein_finding(self):
        assert check_https("https://api.example.com/v1") == []

    def test_leerer_string_kein_finding(self):
        assert check_https("") == []


# ---------------------------------------------------------------------------
# check_security_headers
# ---------------------------------------------------------------------------


class TestCheckSecurityHeaders:
    def test_alle_header_vorhanden_keine_findings(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'",
        }
        # Nur Info-Findings möglich (kein Server/X-Powered-By)
        findings = check_security_headers(headers)
        assert all(f.severity == Severity.INFO for f in findings)

    def test_alle_header_fehlen(self):
        findings = check_security_headers({})
        codes = {f.code for f in findings}
        assert "MISSING_HSTS" in codes
        assert "MISSING_XCTO" in codes
        assert "MISSING_XFO" in codes
        assert "MISSING_CSP" in codes

    def test_server_header_info_finding(self):
        findings = check_security_headers({"Server": "nginx/1.21.0"})
        codes = {f.code for f in findings}
        assert "SERVER_HEADER_DISCLOSURE" in codes
        server_finding = next(
            f for f in findings if f.code == "SERVER_HEADER_DISCLOSURE"
        )
        assert server_finding.severity == Severity.INFO

    def test_powered_by_info_finding(self):
        findings = check_security_headers({"X-Powered-By": "PHP/8.1"})
        codes = {f.code for f in findings}
        assert "POWERED_BY_DISCLOSURE" in codes

    def test_header_keys_case_insensitive(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'none'",
        }
        findings = check_security_headers(headers)
        codes = {f.code for f in findings}
        assert "MISSING_HSTS" not in codes
        assert "MISSING_XCTO" not in codes


# ---------------------------------------------------------------------------
# check_cors
# ---------------------------------------------------------------------------


class TestCheckCors:
    def test_wildcard_ohne_credentials_medium(self):
        findings = check_cors({"Access-Control-Allow-Origin": "*"})
        assert len(findings) == 1
        assert findings[0].code == "CORS_WILDCARD"
        assert findings[0].severity == Severity.MEDIUM

    def test_wildcard_mit_credentials_kritisch(self):
        findings = check_cors(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        assert len(findings) == 1
        assert findings[0].code == "CORS_WILDCARD_WITH_CREDENTIALS"
        assert findings[0].severity == Severity.CRITICAL

    def test_explizite_origin_kein_finding(self):
        findings = check_cors(
            {"Access-Control-Allow-Origin": "https://app.example.com"}
        )
        assert findings == []

    def test_kein_cors_header_kein_finding(self):
        assert check_cors({}) == []


# ---------------------------------------------------------------------------
# check_error_leakage
# ---------------------------------------------------------------------------


class TestCheckErrorLeakage:
    def test_python_traceback_hoch(self):
        body = "Traceback (most recent call last):\n  File 'app.py', line 10"
        findings = check_error_leakage(body, 500)
        assert len(findings) >= 1
        codes = {f.code for f in findings}
        assert "STACK_TRACE_LEAKAGE" in codes
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_200_response_keine_pruefung(self):
        body = "Traceback (most recent call last):"
        assert check_error_leakage(body, 200) == []

    def test_keine_leakage_leere_antwort(self):
        assert check_error_leakage("Not Found", 404) == []

    def test_java_exception_erkannt(self):
        body = "Exception in thread main java.lang.NullPointerException"
        findings = check_error_leakage(body, 500)
        codes = {f.code for f in findings}
        assert "STACK_TRACE_LEAKAGE" in codes


# ---------------------------------------------------------------------------
# check_rate_limiting
# ---------------------------------------------------------------------------


class TestCheckRateLimiting:
    def test_keine_header_gibt_finding(self):
        findings = check_rate_limiting({})
        assert len(findings) == 1
        assert findings[0].code == "NO_RATE_LIMIT_HEADERS"
        assert findings[0].owasp == OWASPCategory.API4

    def test_x_ratelimit_limit_vorhanden(self):
        assert check_rate_limiting({"X-RateLimit-Limit": "100"}) == []

    def test_retry_after_vorhanden(self):
        assert check_rate_limiting({"Retry-After": "60"}) == []

    def test_ratelimit_limit_klein(self):
        assert check_rate_limiting({"ratelimit-limit": "50"}) == []


# ---------------------------------------------------------------------------
# check_auth_headers
# ---------------------------------------------------------------------------


class TestCheckAuthHeaders:
    def test_401_ohne_www_authenticate(self):
        findings = check_auth_headers({}, 401)
        codes = {f.code for f in findings}
        assert "MISSING_WWW_AUTHENTICATE" in codes

    def test_401_mit_www_authenticate_kein_missing(self):
        findings = check_auth_headers({"WWW-Authenticate": "Bearer realm='api'"}, 401)
        codes = {f.code for f in findings}
        assert "MISSING_WWW_AUTHENTICATE" not in codes

    def test_basic_auth_erkannt(self):
        findings = check_auth_headers({"WWW-Authenticate": "Basic realm='API'"}, 401)
        codes = {f.code for f in findings}
        assert "BASIC_AUTH_DETECTED" in codes
        basic = next(f for f in findings if f.code == "BASIC_AUTH_DETECTED")
        assert basic.severity == Severity.MEDIUM

    def test_200_kein_auth_finding(self):
        findings = check_auth_headers({}, 200)
        assert findings == []


# ---------------------------------------------------------------------------
# check_response_data
# ---------------------------------------------------------------------------


class TestCheckResponseData:
    def test_passwort_in_json_erkannt(self):
        body = '{"user": "alice", "password": "secret123"}'
        findings = check_response_data(body, "application/json")
        assert len(findings) == 1
        assert findings[0].code == "SENSITIVE_DATA_IN_RESPONSE"
        assert findings[0].severity == Severity.HIGH

    def test_token_in_json_erkannt(self):
        body = '{"access_token": "eyJhbGciOiJIUzI1NiJ9.abc.def"}'
        findings = check_response_data(body, "application/json; charset=utf-8")
        assert len(findings) == 1

    def test_normales_json_kein_finding(self):
        body = '{"id": 1, "name": "Alice", "email": "alice@example.com"}'
        assert check_response_data(body, "application/json") == []

    def test_nicht_json_wird_ignoriert(self):
        body = '{"password": "geheim"}'
        assert check_response_data(body, "text/html") == []


# ---------------------------------------------------------------------------
# check_ssrf_indicators
# ---------------------------------------------------------------------------


class TestCheckSsrfIndicators:
    def test_url_parameter_erkannt(self):
        findings = check_ssrf_indicators(
            "https://api.example.com/fetch?url=http://internal"
        )
        assert len(findings) == 1
        assert findings[0].code == "SSRF_PARAMETER_INDICATOR"
        assert findings[0].owasp == OWASPCategory.API7
        assert findings[0].severity == Severity.HIGH

    def test_redirect_parameter_erkannt(self):
        findings = check_ssrf_indicators(
            "https://api.example.com/auth?redirect=http://evil.com"
        )
        assert len(findings) == 1

    def test_callback_erkannt(self):
        findings = check_ssrf_indicators(
            "https://api.example.com/webhook?callback=http://evil.com"
        )
        assert len(findings) == 1

    def test_normale_url_kein_finding(self):
        assert (
            check_ssrf_indicators("https://api.example.com/users?page=1&limit=10") == []
        )

    def test_leere_url_kein_finding(self):
        assert check_ssrf_indicators("") == []
