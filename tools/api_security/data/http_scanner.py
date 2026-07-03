"""
http_scanner — Konkreter HTTP-Scanner fuer den API Security Analyzer.

Implementiert IScannerPort mit dem requests-Paket.

Passive Checks (immer):
    1. check_https — Protokollpruefung (keine HTTP-Anfrage noetig)
    2. check_ssrf_indicators — URL-Parameter-Analyse
    3. check_security_headers — Response-Header des GET-Requests
    4. check_cors — CORS-Header
    5. check_rate_limiting — Rate-Limit-Header
    6. check_auth_headers — Auth-Header bei 200/401
    7. check_error_leakage — 404-Response auf Stack-Traces pruefen
    8. check_response_data — JSON-Antwort auf sensible Felder pruefen
    9. check_tls_certificate — TLS-Zertifikat-Details (Version, Ablauf, Cipher)

Active Checks (nur wenn ScanTarget.active_checks=True):
    10. check_http_methods — HTTP-Methoden-Enumeration (max. 5 Requests)
    11. check_content_type_enforcement — Content-Type-Erzwingung (2 Requests)
    12. check_auth_bypass — Auth-Bypass-Probes (4 Requests, nur mit Auth)
    13. check_request_size_limits — Request-Groessenlimits (2 Requests)
    14. check_verbose_errors — Verbose Error Triggering (3 Requests)

Sicherheitsdesign (STRIDE):
    Spoofing: SSL-Zertifikat wird verifiziert (verify=True, default).
    SSRF: Ausgehende Anfragen nur an die angegebene URL;
                       keine Redirects zu internen Adressen folgen
                       (allow_redirects=False bei Probe-Anfragen).
    Info Disclosure: Response-Body wird nicht geloggt.
    DoS: Timeout konfigurierbar (Standard: ScanTarget.timeout).
                       Active Checks mit 200ms-Pause je Request.

Schichtzugehoerigkeit: data/ — darf IScannerPort und Domain importieren.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import datetime
import time

from core.logger import get_logger
from tools.api_security.domain.checks import (
    check_auth_bypass,
    check_auth_headers,
    check_content_type_enforcement,
    check_cors,
    check_error_leakage,
    check_http_methods,
    check_https,
    check_rate_limiting,
    check_request_size_limits,
    check_response_data,
    check_security_headers,
    check_ssrf_indicators,
    check_tls_certificate,
    check_verbose_errors,
)
from tools.api_security.domain.interfaces import IScannerPort
from tools.api_security.domain.models import (
    AuthType,
    Finding,
    OWASPCategory,
    ScanResult,
    ScanTarget,
    Severity,
    TLSInfo,
)

_log = get_logger(__name__)

# User-Agent fuer Scan-Anfragen — klar als Scanner identifiziert
_USER_AGENT = "NoRisk-by-FINLAI APISecurityScanner/2.0 (passive+active)"

# Pause zwischen Active-Check-Requests (Hoeflichkeit gegenueber dem Ziel)
_ACTIVE_PAUSE_S: float = 0.2


class HttpScanner(IScannerPort):
    """Passiver HTTP-Scanner mit requests.

    Sendet maximal 2 Anfragen an das Ziel:
        1. GET <base_url> — primäre Header-Analyse
        2. GET <base_url>/404-probe — Error-Leakage-Test (404-Antwort)

    Attributes:
        _verify_ssl: TLS-Zertifikat verifizieren (Standard: True).
    """

    def __init__(self, verify_ssl: bool = True) -> None:
        """Initialisiert den Scanner.

        Args:
            verify_ssl: TLS-Zertifikat verifizieren. Nur für Tests deaktivieren.
        """
        self._verify_ssl = verify_ssl

    def scan(self, target: ScanTarget) -> ScanResult:
        """Führt den vollständigen passiven Scan durch.

        Args:
            target: Scan-Ziel.

        Returns:
            ScanResult mit allen Befunden.
        """
        try:
            import requests  # noqa: PLC0415 — lazy import
        except ImportError:
            return ScanResult(
                target=target,
                scan_time=_utcnow(),
                error="requests-Bibliothek nicht installiert (pip install requests)",
            )

        findings: list[Finding] = []
        start = time.monotonic()
        scan_time = _utcnow()

        # -- Check 1: HTTPS-Protokoll (kein Netzwerk nötig)
        findings.extend(check_https(target.url))

        # -- Check 2: SSRF-Indikatoren in URL
        findings.extend(check_ssrf_indicators(target.url))

        # -- Primäre Anfrage: GET Basis-URL
        primary_headers: dict[str, str] = {}
        primary_status = 0
        primary_body = ""
        primary_ct = ""

        req_headers = {
            "User-Agent": _USER_AGENT,
            **target.headers,
        }

        try:
            resp = requests.get(
                target.url,
                headers=req_headers,
                timeout=target.timeout,
                verify=self._verify_ssl,
                allow_redirects=True,
            )
            primary_headers = dict(resp.headers)
            primary_status = resp.status_code
            primary_body = resp.text
            primary_ct = resp.headers.get("Content-Type", "")

        except requests.exceptions.SSLError as exc:
            findings.append(
                Finding(
                    code="SSL_ERROR",
                    title="TLS/SSL-Zertifikatfehler",
                    description=(
                        "Das TLS-Zertifikat der API ist ungültig oder abgelaufen. "
                        "Clients werden Verbindungen ablehnen."
                    ),
                    severity=Severity.CRITICAL,
                    owasp=OWASPCategory.API8,
                    detail=str(exc)[:200],
                    remediation="TLS-Zertifikat erneuern und korrekte Zertifikatskette konfigurieren.",
                )
            )
        except requests.exceptions.ConnectionError as exc:
            duration = int((time.monotonic() - start) * 1000)
            return ScanResult(
                target=target,
                findings=findings,
                scan_time=scan_time,
                duration_ms=duration,
                error=f"Verbindung fehlgeschlagen: {exc}",
            )
        except requests.exceptions.Timeout:
            duration = int((time.monotonic() - start) * 1000)
            return ScanResult(
                target=target,
                findings=findings,
                scan_time=scan_time,
                duration_ms=duration,
                error=f"Timeout nach {target.timeout}s",
            )
        except (requests.RequestException, ValueError, OSError) as exc:
            _log.error("HttpScanner: unerwarteter Fehler: %s", exc)
            duration = int((time.monotonic() - start) * 1000)
            return ScanResult(
                target=target,
                findings=findings,
                scan_time=scan_time,
                duration_ms=duration,
                error=str(exc),
            )

        if primary_headers:
            # -- Check 3: Security-Header
            findings.extend(check_security_headers(primary_headers))

            # -- Check 4: CORS
            findings.extend(check_cors(primary_headers))

            # -- Check 5: Rate-Limiting
            findings.extend(check_rate_limiting(primary_headers))

            # -- Check 6: Auth-Header
            findings.extend(check_auth_headers(primary_headers, primary_status))

            # -- Check 8: Response-Daten auf sensible Felder
            findings.extend(check_response_data(primary_body, primary_ct))

        # -- Check 7: Error-Leakage — 404-Probe
        probe_url = target.url.rstrip("/") + "/finlai-scan-probe-404"
        try:
            probe_resp = requests.get(
                probe_url,
                headers=req_headers,
                timeout=target.timeout,
                verify=self._verify_ssl,
                allow_redirects=False,
            )
            findings.extend(
                check_error_leakage(probe_resp.text, probe_resp.status_code)
            )
        except requests.RequestException:
            pass  # Probe-Fehler sind nicht scan-kritisch

        # -- Check 9: TLS-Zertifikat (eigene SSL-Verbindung, unabhaengig von requests)
        tls_info = self._fetch_tls_info(target)
        if tls_info is not None:
            findings.extend(check_tls_certificate(tls_info))

        # -- Active Checks 10–14 (nur wenn Opt-In gesetzt) --
        if target.active_checks:
            findings.extend(self._run_active_checks(target, requests))

        duration = int((time.monotonic() - start) * 1000)
        return ScanResult(
            target=target,
            findings=findings,
            scan_time=scan_time,
            duration_ms=duration,
        )

    def _fetch_tls_info(self, target: ScanTarget) -> TLSInfo | None:
        """Holt TLS-Zertifikatsinformationen via ssl-Standardmodul.

        Öffnet eine eigene SSL-Verbindung — unabhängig von requests.
        Versucht zuerst mit Hostname-Verifikation; bei SSLCertVerificationError
        wird ohne Verifikation wiederholt um auch fehlerhafte Zertifikate
        auszulesen (hostname_valid wird auf False gesetzt).

        Args:
            target: Scan-Ziel (nur HTTPS-URLs werden verarbeitet).

        Returns:
            TLSInfo oder None bei HTTP-URL oder Verbindungsfehler.
        """
        import socket
        import ssl
        from urllib.parse import urlparse

        parsed = urlparse(target.url)
        if parsed.scheme != "https":
            return None

        hostname = parsed.hostname
        port = parsed.port or 443

        if not hostname:
            return None

        hostname_valid = True
        cert: dict | None = None
        tls_version = ""
        cipher_name = ""
        cipher_bits = 0

        # Versuch 1: mit Hostname-Verifikation
        try:
            ctx = ssl.create_default_context()
            with (
                socket.create_connection(
                    (hostname, port), timeout=target.timeout
                ) as sock,
                ctx.wrap_socket(sock, server_hostname=hostname) as ssock,
            ):
                cert = ssock.getpeercert()
                tls_version = ssock.version() or ""
                cipher_info = ssock.cipher()
                if cipher_info:
                    cipher_name = cipher_info[0]
                    cipher_bits = cipher_info[2] or 0

        except ssl.SSLCertVerificationError:
            # Versuch 2: ohne Verifikation um Zertifikats-Daten zu lesen
            hostname_valid = False
            try:
                ctx_nocheck = ssl.create_default_context()
                ctx_nocheck.check_hostname = False
                ctx_nocheck.verify_mode = ssl.CERT_NONE
                with (
                    socket.create_connection(
                        (hostname, port), timeout=target.timeout
                    ) as sock,
                    ctx_nocheck.wrap_socket(sock, server_hostname=hostname) as ssock,
                ):
                    cert = ssock.getpeercert()
                    tls_version = ssock.version() or ""
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_name = cipher_info[0]
                        cipher_bits = cipher_info[2] or 0
            except (ssl.SSLError, OSError):
                pass

        except (ssl.SSLError, OSError):
            return None

        if cert is None:
            return TLSInfo(hostname_valid=hostname_valid)

        subject = cert.get("subject", ())
        issuer = cert.get("issuer", ())
        subject_cn = _extract_cn(subject)
        subject_org = _extract_org(subject)
        issuer_cn = _extract_cn(issuer)
        issuer_org = _extract_org(issuer)
        san = _extract_san(cert.get("subjectAltName", ()))
        not_before = _parse_ssl_date(cert.get("notBefore", ""))
        not_after = _parse_ssl_date(cert.get("notAfter", ""))
        is_self_signed = bool(
            subject_cn and subject_cn == issuer_cn and subject_org == issuer_org
        )

        return TLSInfo(
            subject_cn=subject_cn,
            subject_org=subject_org,
            issuer_cn=issuer_cn,
            issuer_org=issuer_org,
            not_before=not_before,
            not_after=not_after,
            san=tuple(san),
            tls_version=tls_version,
            cipher_name=cipher_name,
            cipher_bits=cipher_bits,
            is_self_signed=is_self_signed,
            hostname_valid=hostname_valid,
        )

    # ------------------------------------------------------------------
    # Active Checks — Data-Adapter-Methoden
    # ------------------------------------------------------------------

    def _run_active_checks(self, target: ScanTarget, requests) -> list[Finding]:
        """Koordiniert alle Active Checks (10-14) und sammelt Findings.

        Args:
            target: Scan-Ziel mit active_checks=True.
            requests: Bereits importiertes requests-Modul.

        Returns:
            Kombinierte Liste aller Active-Check-Findings.
        """
        findings: list[Finding] = []

        # Check 10: HTTP-Methoden
        try:
            allowed, method_responses = self._check_http_methods(target, requests)
            findings.extend(check_http_methods(target.url, allowed, method_responses))
        except (requests.RequestException, ValueError, OSError):
            _log.debug("Active Check 10 (HTTP-Methoden) fehlgeschlagen")

        # Check 11: Content-Type Enforcement
        try:
            ct_responses = self._check_content_type_enforcement(target, requests)
            findings.extend(check_content_type_enforcement(ct_responses))
        except (requests.RequestException, ValueError, OSError):
            _log.debug("Active Check 11 (Content-Type) fehlgeschlagen")

        # Check 12: Auth-Bypass
        try:
            auth_configured = target.auth_type != AuthType.NONE
            bypass_responses = self._check_auth_bypass(target, requests)
            findings.extend(check_auth_bypass(auth_configured, bypass_responses))
        except (requests.RequestException, ValueError, OSError):
            _log.debug("Active Check 12 (Auth-Bypass) fehlgeschlagen")

        # Check 13: Request Size Limits
        try:
            size_responses = self._check_request_size_limits(target, requests)
            findings.extend(check_request_size_limits(size_responses))
        except (requests.RequestException, ValueError, OSError):
            _log.debug("Active Check 13 (Request-Size) fehlgeschlagen")

        # Check 14: Verbose Errors
        try:
            error_responses = self._check_verbose_errors(target, requests)
            findings.extend(check_verbose_errors(error_responses))
        except (requests.RequestException, ValueError, OSError):
            _log.debug("Active Check 14 (Verbose-Errors) fehlgeschlagen")

        return findings

    def _build_headers(self, target: ScanTarget) -> dict[str, str]:
        """Baut den Standard-Header-Dict fuer Scan-Requests.

        Args:
            target: Scan-Ziel.

        Returns:
            Header-Dict mit User-Agent und optionalen Ziel-Headern.
        """
        return {"User-Agent": _USER_AGENT, **target.headers}

    def _check_http_methods(
        self,
        target: ScanTarget,
        requests,
    ) -> tuple[list[str], dict[str, int]]:
        """Sendet OPTIONS, HEAD, PUT, DELETE, PATCH an die Ziel-URL (Check 10).

        PUT/DELETE/PATCH werden ohne Body gesendet — nichts wird veraendert.
        Der Server sollte mit 405 antworten wenn korrekt konfiguriert.

        Args:
            target: Scan-Ziel.
            requests: requests-Modul.

        Returns:
            Tuple (allowed_by_options, responses):
            - allowed_by_options: Methoden aus dem OPTIONS-Allow-Header.
            - responses: Status-Codes je Methode (-1 = Fehler).
        """
        methods_to_test = ["OPTIONS", "HEAD", "PUT", "DELETE", "PATCH"]
        responses: dict[str, int] = {}
        allowed_by_options: list[str] = []
        headers = self._build_headers(target)

        for method in methods_to_test:
            try:
                resp = requests.request(
                    method,
                    target.url,
                    headers=headers,
                    timeout=target.timeout,
                    verify=self._verify_ssl,
                    allow_redirects=False,
                )
                responses[method] = resp.status_code
                if method == "OPTIONS":
                    allow_hdr = resp.headers.get("Allow", "")
                    allowed_by_options = [
                        m.strip().upper() for m in allow_hdr.split(",") if m.strip()
                    ]
            except requests.RequestException:
                responses[method] = -1
            time.sleep(_ACTIVE_PAUSE_S)

        return allowed_by_options, responses

    def _check_content_type_enforcement(
        self,
        target: ScanTarget,
        requests,
    ) -> dict[str, int]:
        """Sendet GET-Requests mit fehlendem/falschem Content-Type (Check 11).

        Args:
            target: Scan-Ziel.
            requests: requests-Modul.

        Returns:
            Dict mit Status-Codes fuer "no_ct" und "wrong_ct".
        """
        results: dict[str, int] = {}
        base_headers = self._build_headers(target)

        # Test 1: Kein Content-Type Header (schon Standard, aber explizit ohne)
        try:
            resp = requests.get(
                target.url,
                headers=base_headers,
                timeout=target.timeout,
                verify=self._verify_ssl,
                allow_redirects=False,
            )
            results["no_ct"] = resp.status_code
        except requests.RequestException:
            results["no_ct"] = -1
        time.sleep(_ACTIVE_PAUSE_S)

        # Test 2: Falscher Content-Type (text/plain statt application/json)
        try:
            wrong_headers = {**base_headers, "Content-Type": "text/plain"}
            resp = requests.get(
                target.url,
                headers=wrong_headers,
                timeout=target.timeout,
                verify=self._verify_ssl,
                allow_redirects=False,
            )
            results["wrong_ct"] = resp.status_code
        except requests.RequestException:
            results["wrong_ct"] = -1
        time.sleep(_ACTIVE_PAUSE_S)

        return results

    def _check_auth_bypass(
        self,
        target: ScanTarget,
        requests,
    ) -> dict[str, tuple[int, str]]:
        """Sendet Requests mit manipulierten Auth-Headern (Check 12).

        Nur wenn Auth im ScanTarget konfiguriert ist. Die echten
        Credentials werden NICHT verwendet — nur leere/falsche Tokens.

        Args:
            target: Scan-Ziel.
            requests: requests-Modul.

        Returns:
            Dict mit (Status-Code, Reason) je Bypass-Variante.
            Leer wenn keine Auth konfiguriert.
        """
        if target.auth_type == AuthType.NONE:
            return {}

        base_headers = self._build_headers(target)
        bypass_probes = [
            ("Kein Auth-Header", {}),
            ("Leerer Bearer", {"Authorization": "Bearer "}),
            ("Bearer null", {"Authorization": "Bearer null"}),
            ("Bearer undefined", {"Authorization": "Bearer undefined"}),
        ]

        results: dict[str, tuple[int, str]] = {}
        for label, extra_headers in bypass_probes:
            probe_headers = {**base_headers, **extra_headers}
            try:
                resp = requests.get(
                    target.url,
                    headers=probe_headers,
                    timeout=target.timeout,
                    verify=self._verify_ssl,
                    allow_redirects=False,
                )
                results[label] = (resp.status_code, resp.reason or "")
            except requests.RequestException as exc:
                results[label] = (-1, type(exc).__name__)
            time.sleep(_ACTIVE_PAUSE_S)

        return results

    def _check_request_size_limits(
        self,
        target: ScanTarget,
        requests,
    ) -> dict[str, int]:
        """Sendet Requests mit uebergrossen Headern und URLs (Check 13).

        Args:
            target: Scan-Ziel.
            requests: requests-Modul.

        Returns:
            Dict mit Status-Codes fuer "big_header" und "long_url".
            -1 = Verbindung abgebrochen (korrekte Abweisung).
        """
        from urllib.parse import urlparse, urlunparse

        results: dict[str, int] = {}
        base_headers = self._build_headers(target)

        # Test 1: Uebergrosse Custom-Header (8 KB)
        big_value = "A" * 8192
        try:
            resp = requests.get(
                target.url,
                headers={**base_headers, "X-FinLai-Size-Test": big_value},
                timeout=target.timeout,
                verify=self._verify_ssl,
                allow_redirects=False,
            )
            results["big_header"] = resp.status_code
        except (OSError, requests.RequestException):
            results["big_header"] = -1
        time.sleep(_ACTIVE_PAUSE_S)

        # Test 2: Extrem langer URL-Pfad (2000+ Zeichen)
        parsed = urlparse(target.url)
        long_path = parsed.path.rstrip("/") + "/" + "a" * 2000
        long_url = urlunparse(parsed._replace(path=long_path))
        try:
            resp = requests.get(
                long_url,
                headers=base_headers,
                timeout=target.timeout,
                verify=self._verify_ssl,
                allow_redirects=False,
            )
            results["long_url"] = resp.status_code
        except (OSError, requests.RequestException):
            results["long_url"] = -1
        time.sleep(_ACTIVE_PAUSE_S)

        return results

    def _check_verbose_errors(
        self,
        target: ScanTarget,
        requests,
    ) -> dict[str, tuple[int, str]]:
        """Provoziert Fehlermeldungen um Information Disclosure zu testen (Check 14).

        Sendet 3 Requests die spezifisch Fehlerantworten ausloesen sollen.
        Die Response-Bodies werden von check_verbose_errors mit
        check_error_leakage analysiert.

        Args:
            target: Scan-Ziel.
            requests: requests-Modul.

        Returns:
            Dict mit (Status-Code, Body) je Szenario.
        """
        results: dict[str, tuple[int, str]] = {}
        base_headers = self._build_headers(target)

        # Test 1: Ungueltiger JSON-Body via POST
        json_headers = {**base_headers, "Content-Type": "application/json"}
        try:
            resp = requests.post(
                target.url,
                headers=json_headers,
                data=b"{{INVALID_JSON_BODY",
                timeout=target.timeout,
                verify=self._verify_ssl,
                allow_redirects=False,
            )
            results["invalid_json"] = (resp.status_code, resp.text[:10_000])
        except requests.RequestException:
            results["invalid_json"] = (-1, "")
        time.sleep(_ACTIVE_PAUSE_S)

        # Test 2: Ungueltiger Accept-Header
        invalid_accept_headers = {
            **base_headers,
            "Accept": "application/x-finlai-nonexistent",
        }
        try:
            resp = requests.get(
                target.url,
                headers=invalid_accept_headers,
                timeout=target.timeout,
                verify=self._verify_ssl,
                allow_redirects=False,
            )
            results["invalid_accept"] = (resp.status_code, resp.text[:10_000])
        except requests.RequestException:
            results["invalid_accept"] = (-1, "")
        time.sleep(_ACTIVE_PAUSE_S)

        # Test 3: Nicht-existierender Endpunkt (andere URL als Check 7)
        probe_url = target.url.rstrip("/") + "/finlai-active-probe-verbose-error"
        try:
            resp = requests.get(
                probe_url,
                headers=base_headers,
                timeout=target.timeout,
                verify=self._verify_ssl,
                allow_redirects=False,
            )
            results["probe_404"] = (resp.status_code, resp.text[:10_000])
        except requests.RequestException:
            results["probe_404"] = (-1, "")

        return results


def _utcnow() -> str:
    """Gibt aktuellen UTC-Zeitstempel im ISO 8601 Format zurueck."""
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_cn(rdns: tuple) -> str:
    """Extrahiert den Common Name aus einer RDN-Sequenz."""
    for rdn in rdns:
        for attr, val in rdn:
            if attr == "commonName":
                return str(val)
    return ""


def _extract_org(rdns: tuple) -> str:
    """Extrahiert den Organisationsnamen aus einer RDN-Sequenz."""
    for rdn in rdns:
        for attr, val in rdn:
            if attr == "organizationName":
                return str(val)
    return ""


def _extract_san(san_list: tuple) -> list[str]:
    """Extrahiert DNS-Einträge aus der subjectAltName-Liste."""
    return [val for typ, val in san_list if typ == "DNS"]


def _parse_ssl_date(ssl_date: str) -> str:
    """Konvertiert SSL-Datumsformat zu ISO-8601-UTC-String.

    SSL-Format: ``"Jan 1 00:00:00 2025 GMT"`` (Tag ist space-padded).
    """
    if not ssl_date:
        return ""
    try:
        dt = datetime.datetime.strptime(ssl_date, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=datetime.UTC).isoformat()
    except ValueError:
        return ""
