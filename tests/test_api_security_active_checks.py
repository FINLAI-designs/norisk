"""
test_api_security_active_checks — Tests fuer Active Checks 10–14.

Getestete Funktionen (domain/checks.py):
    check_http_methods
    check_content_type_enforcement
    check_auth_bypass
    check_request_size_limits
    check_verbose_errors

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.api_security.domain.checks import (
    check_auth_bypass,
    check_content_type_enforcement,
    check_http_methods,
    check_request_size_limits,
    check_verbose_errors,
)
from tools.api_security.domain.models import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_URL = "https://api.example.com/v1"


def _codes(findings) -> set[str]:
    return {f.code for f in findings}


# ---------------------------------------------------------------------------
# Check 10: check_http_methods
# ---------------------------------------------------------------------------


class TestCheckHttpMethods:
    def test_put_200_returns_high_finding(self):
        responses = {
            "PUT": 200,
            "DELETE": 405,
            "PATCH": 405,
            "HEAD": 200,
            "OPTIONS": 200,
        }
        findings = check_http_methods(_URL, [], responses)
        codes = _codes(findings)
        assert "UNEXPECTED_PUT_ALLOWED" in codes
        put_finding = next(f for f in findings if f.code == "UNEXPECTED_PUT_ALLOWED")
        assert put_finding.severity == Severity.HIGH

    def test_delete_200_returns_high_finding(self):
        responses = {
            "PUT": 405,
            "DELETE": 204,
            "PATCH": 405,
            "HEAD": 200,
            "OPTIONS": 200,
        }
        findings = check_http_methods(_URL, [], responses)
        assert "UNEXPECTED_DELETE_ALLOWED" in _codes(findings)

    def test_patch_200_returns_high_finding(self):
        responses = {
            "PUT": 405,
            "DELETE": 405,
            "PATCH": 200,
            "HEAD": 200,
            "OPTIONS": 200,
        }
        findings = check_http_methods(_URL, [], responses)
        assert "UNEXPECTED_PATCH_ALLOWED" in _codes(findings)

    def test_all_405_no_destructive_finding(self):
        responses = {
            "PUT": 405,
            "DELETE": 405,
            "PATCH": 405,
            "HEAD": 200,
            "OPTIONS": 200,
        }
        findings = check_http_methods(_URL, [], responses)
        codes = _codes(findings)
        assert "UNEXPECTED_PUT_ALLOWED" not in codes
        assert "UNEXPECTED_DELETE_ALLOWED" not in codes
        assert "UNEXPECTED_PATCH_ALLOWED" not in codes

    def test_options_exposes_put_medium_finding(self):
        # OPTIONS says PUT is allowed, but PUT itself returns 405 (not confirmed)
        responses = {
            "PUT": 405,
            "DELETE": 405,
            "PATCH": 405,
            "HEAD": 200,
            "OPTIONS": 200,
        }
        allowed = ["GET", "POST", "PUT"]
        findings = check_http_methods(_URL, allowed, responses)
        assert "OPTIONS_EXPOSES_DANGEROUS_METHODS" in _codes(findings)
        opt_f = next(
            f for f in findings if f.code == "OPTIONS_EXPOSES_DANGEROUS_METHODS"
        )
        assert opt_f.severity == Severity.MEDIUM

    def test_options_exposes_not_reported_if_method_already_2xx(self):
        # If PUT actually returned 2xx, we already report HIGH — no double reporting via OPTIONS
        responses = {
            "PUT": 200,
            "DELETE": 405,
            "PATCH": 405,
            "HEAD": 200,
            "OPTIONS": 200,
        }
        allowed = ["GET", "POST", "PUT"]
        findings = check_http_methods(_URL, allowed, responses)
        codes = _codes(findings)
        assert "UNEXPECTED_PUT_ALLOWED" in codes
        # OPTIONS_EXPOSES should NOT fire because PUT is already confirmed 2xx
        assert "OPTIONS_EXPOSES_DANGEROUS_METHODS" not in codes

    def test_head_405_returns_low_finding(self):
        responses = {
            "PUT": 405,
            "DELETE": 405,
            "PATCH": 405,
            "HEAD": 405,
            "OPTIONS": 200,
        }
        findings = check_http_methods(_URL, [], responses)
        assert "HEAD_NOT_SUPPORTED" in _codes(findings)
        head_f = next(f for f in findings if f.code == "HEAD_NOT_SUPPORTED")
        assert head_f.severity == Severity.LOW

    def test_head_minus1_returns_low_finding(self):
        responses = {
            "PUT": 405,
            "DELETE": 405,
            "PATCH": 405,
            "HEAD": -1,
            "OPTIONS": 200,
        }
        findings = check_http_methods(_URL, [], responses)
        assert "HEAD_NOT_SUPPORTED" in _codes(findings)

    def test_head_200_no_head_finding(self):
        responses = {
            "PUT": 405,
            "DELETE": 405,
            "PATCH": 405,
            "HEAD": 200,
            "OPTIONS": 200,
        }
        findings = check_http_methods(_URL, [], responses)
        assert "HEAD_NOT_SUPPORTED" not in _codes(findings)

    def test_empty_responses_no_crash(self):
        findings = check_http_methods(_URL, [], {})
        # HEAD missing → -1 default → LOW finding expected
        assert "HEAD_NOT_SUPPORTED" in _codes(findings)


# ---------------------------------------------------------------------------
# Check 11: check_content_type_enforcement
# ---------------------------------------------------------------------------


class TestCheckContentTypeEnforcement:
    def test_no_ct_200_returns_medium(self):
        findings = check_content_type_enforcement({"no_ct": 200, "wrong_ct": 415})
        assert "MISSING_CONTENT_TYPE_ACCEPTED" in _codes(findings)
        f = next(f for f in findings if f.code == "MISSING_CONTENT_TYPE_ACCEPTED")
        assert f.severity == Severity.MEDIUM

    def test_no_ct_415_no_finding(self):
        findings = check_content_type_enforcement({"no_ct": 415, "wrong_ct": 415})
        assert "MISSING_CONTENT_TYPE_ACCEPTED" not in _codes(findings)

    def test_wrong_ct_200_returns_medium(self):
        findings = check_content_type_enforcement({"no_ct": 415, "wrong_ct": 200})
        assert "WRONG_CONTENT_TYPE_ACCEPTED" in _codes(findings)
        f = next(f for f in findings if f.code == "WRONG_CONTENT_TYPE_ACCEPTED")
        assert f.severity == Severity.MEDIUM

    def test_wrong_ct_415_no_finding(self):
        findings = check_content_type_enforcement({"no_ct": 415, "wrong_ct": 415})
        assert "WRONG_CONTENT_TYPE_ACCEPTED" not in _codes(findings)

    def test_both_200_two_findings(self):
        findings = check_content_type_enforcement({"no_ct": 200, "wrong_ct": 200})
        codes = _codes(findings)
        assert "MISSING_CONTENT_TYPE_ACCEPTED" in codes
        assert "WRONG_CONTENT_TYPE_ACCEPTED" in codes

    def test_both_minus1_no_finding(self):
        findings = check_content_type_enforcement({"no_ct": -1, "wrong_ct": -1})
        assert len(findings) == 0

    def test_empty_responses_no_crash(self):
        findings = check_content_type_enforcement({})
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Check 12: check_auth_bypass
# ---------------------------------------------------------------------------


class TestCheckAuthBypass:
    def test_no_auth_configured_returns_empty(self):
        responses = {"Kein Auth-Header": (200, "OK")}
        findings = check_auth_bypass(auth_configured=False, responses=responses)
        assert findings == []

    def test_empty_bearer_200_returns_critical(self):
        responses = {"Leerer Bearer": (200, "OK")}
        findings = check_auth_bypass(auth_configured=True, responses=responses)
        assert len(findings) == 1
        assert findings[0].code == "AUTH_BYPASS_POSSIBLE"
        assert findings[0].severity == Severity.CRITICAL

    def test_bearer_null_200_returns_critical(self):
        responses = {"Bearer null": (200, "OK")}
        findings = check_auth_bypass(auth_configured=True, responses=responses)
        assert "AUTH_BYPASS_POSSIBLE" in _codes(findings)

    def test_all_401_no_finding(self):
        responses = {
            "Kein Auth-Header": (401, "Unauthorized"),
            "Leerer Bearer": (401, "Unauthorized"),
            "Bearer null": (401, "Unauthorized"),
            "Bearer undefined": (401, "Unauthorized"),
        }
        findings = check_auth_bypass(auth_configured=True, responses=responses)
        assert findings == []

    def test_mixed_one_bypass_found(self):
        responses = {
            "Kein Auth-Header": (401, "Unauthorized"),
            "Leerer Bearer": (200, "OK"),
        }
        findings = check_auth_bypass(auth_configured=True, responses=responses)
        assert len(findings) == 1
        assert findings[0].code == "AUTH_BYPASS_POSSIBLE"

    def test_403_not_bypass(self):
        responses = {"Kein Auth-Header": (403, "Forbidden")}
        findings = check_auth_bypass(auth_configured=True, responses=responses)
        assert findings == []

    def test_minus1_not_bypass(self):
        responses = {"Kein Auth-Header": (-1, "ConnectionError")}
        findings = check_auth_bypass(auth_configured=True, responses=responses)
        assert findings == []


# ---------------------------------------------------------------------------
# Check 13: check_request_size_limits
# ---------------------------------------------------------------------------


class TestCheckRequestSizeLimits:
    def test_big_header_431_no_finding(self):
        findings = check_request_size_limits({"big_header": 431, "long_url": 414})
        assert "LARGE_HEADER_ACCEPTED" not in _codes(findings)

    def test_big_header_413_no_finding(self):
        findings = check_request_size_limits({"big_header": 413, "long_url": 200})
        assert "LARGE_HEADER_ACCEPTED" not in _codes(findings)

    def test_big_header_400_no_finding(self):
        findings = check_request_size_limits({"big_header": 400, "long_url": -1})
        assert "LARGE_HEADER_ACCEPTED" not in _codes(findings)

    def test_big_header_minus1_no_finding(self):
        findings = check_request_size_limits({"big_header": -1, "long_url": -1})
        assert "LARGE_HEADER_ACCEPTED" not in _codes(findings)

    def test_big_header_200_returns_medium(self):
        findings = check_request_size_limits({"big_header": 200, "long_url": 414})
        assert "LARGE_HEADER_ACCEPTED" in _codes(findings)
        f = next(f for f in findings if f.code == "LARGE_HEADER_ACCEPTED")
        assert f.severity == Severity.MEDIUM

    def test_long_url_414_no_finding(self):
        findings = check_request_size_limits({"big_header": -1, "long_url": 414})
        assert "LONG_URL_ACCEPTED" not in _codes(findings)

    def test_long_url_200_returns_medium(self):
        findings = check_request_size_limits({"big_header": -1, "long_url": 200})
        assert "LONG_URL_ACCEPTED" in _codes(findings)
        f = next(f for f in findings if f.code == "LONG_URL_ACCEPTED")
        assert f.severity == Severity.MEDIUM

    def test_both_200_two_findings(self):
        findings = check_request_size_limits({"big_header": 200, "long_url": 200})
        codes = _codes(findings)
        assert "LARGE_HEADER_ACCEPTED" in codes
        assert "LONG_URL_ACCEPTED" in codes

    def test_empty_responses_no_crash(self):
        findings = check_request_size_limits({})
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Check 14: check_verbose_errors
# ---------------------------------------------------------------------------


class TestCheckVerboseErrors:
    _TRACE_BODY = (
        "Traceback (most recent call last):\n"
        '  File "/app/server.py", line 42, in handle\n'
        "    raise ValueError('bad input')\n"
        "ValueError: bad input"
    )

    def test_stack_trace_in_body_returns_finding(self):
        responses = {"invalid_json": (400, self._TRACE_BODY)}
        findings = check_verbose_errors(responses)
        assert len(findings) >= 1
        # check_error_leakage erkennt Stack-Traces als HIGH
        severities = {f.severity for f in findings}
        assert Severity.HIGH in severities

    def test_clean_response_no_finding(self):
        responses = {"invalid_json": (400, '{"error": "Bad Request"}')}
        findings = check_verbose_errors(responses)
        assert len(findings) == 0

    def test_duplicate_finding_codes_deduplicated(self):
        # Alle drei Szenarien geben denselben Stack-Trace zurueck
        responses = {
            "invalid_json": (400, self._TRACE_BODY),
            "invalid_accept": (406, self._TRACE_BODY),
            "probe_404": (404, self._TRACE_BODY),
        }
        findings = check_verbose_errors(responses)
        codes = [f.code for f in findings]
        # Kein Code soll doppelt vorkommen
        assert len(codes) == len(set(codes))

    def test_minus1_status_no_crash(self):
        responses = {"probe_404": (-1, "")}
        findings = check_verbose_errors(responses)
        assert isinstance(findings, list)

    def test_empty_responses_no_crash(self):
        findings = check_verbose_errors({})
        assert findings == []
