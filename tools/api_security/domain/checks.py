"""
checks — Reine Check-Funktionen für den API Security Analyzer.

Alle Funktionen sind zustandslos und pure: sie erhalten HTTP-Response-
Daten als primitive Typen und geben eine Liste von Finding-Objekten zurück.
Kein Netzwerk-I/O, keine Datenbankzugriffe.

Implementierte passive Checks:
    check_security_headers — Fehlende/fehlerhafte Security-Header (API8)
    check_cors — CORS-Fehlkonfiguration (API8)
    [...]

Implementierte Active Checks:
    check_http_methods — HTTP-Methoden-Enumeration (API5)
    check_content_type_enforcement— Content-Type-Erzwingung (API8)
    check_auth_bypass — Auth-Bypass-Probes (API2)
    check_request_size_limits — Request-Groessenlimits (API4)
    check_verbose_errors — Verbose Error Triggering (API8)
    check_https — Kein HTTPS / unsicheres Protokoll (API8)
    check_error_leakage — Stack-Traces und interne Pfade in Responses (API8)
    check_rate_limiting — Fehlende Rate-Limit-Header (API4)
    check_auth_headers — Fehlende/schwache Authentifizierungshinweise (API2)
    check_response_data — Potenzielle Datenlecks in JSON-Responses (API3)
    check_ssrf_indicators — SSRF-gefährdete Parameter in URLs (API7)
    check_tls_certificate — TLS/SSL-Zertifikat-Details (API8)

Sicherheitsdesign (STRIDE):
    Information Disclosure: Keine externen Daten werden in Findings eingebettet,
                            nur normalisierte Flags (True/False) und Header-Namen.
    Tampering: Alle Funktionen sind pure — keine Seiteneffekte.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from tools.api_security.domain.models import Finding, OWASPCategory, Severity, TLSInfo

# ---------------------------------------------------------------------------
# Konfigurations-Schwellwerte
# ---------------------------------------------------------------------------

# TLS-Zertifikats-Ablauf: ab wann wird gewarnt.
CERT_CRITICAL_DAYS = 30  # Restlaufzeit < CRITICAL → Severity HIGH
CERT_WARNING_DAYS = 90  # Restlaufzeit < WARNING (aber >= CRITICAL) → Severity MEDIUM


# ---------------------------------------------------------------------------
# Kompilierte Muster — einmalig, thread-safe
# ---------------------------------------------------------------------------

# Stack-Trace-Signaturen (Error-Leakage)
_STACKTRACE_PATTERNS = [
    re.compile(r"at\s+[\w$.]+\([\w.]+:\d+\)"),  # Java stack trace
    re.compile(r"Traceback \(most recent call last\)"),  # Python
    re.compile(r"Exception in thread"),  # Java/JVM
    re.compile(r"System\.Web\.Http"),  # ASP.NET
    re.compile(r"Microsoft\.AspNetCore"),  #.NET Core
    re.compile(r"django\.core\.exceptions"),  # Django
    re.compile(r"SQLSTATE\[", re.IGNORECASE),  # SQL-Fehler
    re.compile(r"ORA-\d{5}"),  # Oracle DB-Fehler
    re.compile(r"mysql_fetch_array\(\)"),  # PHP/MySQL
    re.compile(r"Warning: [\w\\]+\(\)"),  # PHP-Warnings
]

# Interne Pfade in Responses
_PATH_PATTERNS = [
    re.compile(r"[A-Z]:\\[\w\\]+\.(?:py|php|java|cs|rb)", re.IGNORECASE),  # Win
    re.compile(r"/(?:var|usr|opt|home|srv)/[\w/]+\.(?:py|php|java|rb|conf)"),
    re.compile(r"/app/[\w/]+"),
]

# SSRF-gefährdete URL-Parameter
_SSRF_PARAMS = re.compile(
    r"[?&](?:url|uri|endpoint|redirect|callback|dest|destination|"
    r"return|returnurl|next|target|redir|redirect_uri|path|site|"
    r"webhook|feed|source|src|proxy|host|domain)=",
    re.IGNORECASE,
)

# Potenzielle Passwort-/Secret-Felder in JSON-Responses
_SENSITIVE_FIELDS = re.compile(
    r'"(?:password|passwd|secret|token|api_key|apikey|private_key|'
    r"access_token|refresh_token|auth_token|bearer|credential|ssn|"
    r'credit_card|card_number|cvv|pin)\s*"\s*:\s*"[^"]{1,}(?<!\\)"',
    re.IGNORECASE,
)

# Bekannte unsichere CORS-Origins
_CORS_WILDCARD = re.compile(r"^\*$")


# ---------------------------------------------------------------------------
# Check-Funktionen
# ---------------------------------------------------------------------------


def check_https(url: str) -> list[Finding]:
    """Prüft ob die URL HTTPS verwendet.

    Args:
        url: Ziel-URL des Scans.

    Returns:
        Liste mit einem Finding wenn HTTP (nicht HTTPS) erkannt wird.
    """
    if url.startswith("http://"):
        return [
            Finding(
                code="NO_HTTPS",
                title="Kein HTTPS",
                description=(
                    "Die API wird über unverschlüsseltes HTTP erreichbar. "
                    "Angreifer können Daten im Transit lesen und manipulieren (MITM)."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.API8,
                detail=url,
                remediation=(
                    "API ausschließlich über HTTPS (TLS 1.2+) betreiben. "
                    "HTTP-Anfragen per 301 auf HTTPS umleiten."
                ),
            )
        ]
    return []


def check_security_headers(headers: dict[str, str]) -> list[Finding]:
    """Prüft auf fehlende oder fehlerhafte Security-Header.

    Geprüfte Header:
        - Strict-Transport-Security (HSTS)
        - X-Content-Type-Options
        - X-Frame-Options
        - Content-Security-Policy
        - X-XSS-Protection (nur Warnung — veraltet)
        - Server (Information Disclosure)
        - X-Powered-By (Information Disclosure)

    Args:
        headers: HTTP-Response-Header als Dict (Keys case-insensitive normalisiert).

    Returns:
        Liste der gefundenen Header-Probleme.
    """
    # Normalisierung: alle Keys lowercase
    h = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    # HSTS — Pflicht für HTTPS-APIs
    if "strict-transport-security" not in h:
        findings.append(
            Finding(
                code="MISSING_HSTS",
                title="Strict-Transport-Security fehlt",
                description=(
                    "Der HSTS-Header fehlt. Browser und Clients könnten auf "
                    "HTTP-Downgrade-Angriffe hereinfallen."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API8,
                remediation="Header setzen: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            )
        )

    # X-Content-Type-Options
    if "x-content-type-options" not in h:
        findings.append(
            Finding(
                code="MISSING_XCTO",
                title="X-Content-Type-Options fehlt",
                description=(
                    "Ohne diesen Header können Browser MIME-Type-Sniffing betreiben "
                    "und ausführbare Inhalte falsch interpretieren."
                ),
                severity=Severity.LOW,
                owasp=OWASPCategory.API8,
                remediation="Header setzen: X-Content-Type-Options: nosniff",
            )
        )

    # X-Frame-Options
    if "x-frame-options" not in h:
        findings.append(
            Finding(
                code="MISSING_XFO",
                title="X-Frame-Options fehlt",
                description=(
                    "Ohne Clickjacking-Schutz können Angreifer API-Antworten "
                    "in unsichtbare iFrames einbetten."
                ),
                severity=Severity.LOW,
                owasp=OWASPCategory.API8,
                remediation="Header setzen: X-Frame-Options: DENY",
            )
        )

    # Content-Security-Policy
    if "content-security-policy" not in h:
        findings.append(
            Finding(
                code="MISSING_CSP",
                title="Content-Security-Policy fehlt",
                description=(
                    "Keine CSP definiert. XSS-Angriffe sind ohne diese "
                    "Richtlinie schwerer zu mitigieren."
                ),
                severity=Severity.LOW,
                owasp=OWASPCategory.API8,
                remediation="Minimale CSP setzen: Content-Security-Policy: default-src 'none'",
            )
        )

    # Server-Header — Information Disclosure
    server = h.get("server", "")
    if server:
        findings.append(
            Finding(
                code="SERVER_HEADER_DISCLOSURE",
                title="Server-Header gibt Software-Version preis",
                description=(
                    "Der Server-Header enthält Informationen über die verwendete "
                    "Server-Software. Angreifer nutzen diese für gezielte Exploits."
                ),
                severity=Severity.INFO,
                owasp=OWASPCategory.API8,
                detail=server[:120],
                remediation="Server-Header entfernen oder auf einen generischen Wert setzen.",
            )
        )

    # X-Powered-By — Information Disclosure
    powered_by = h.get("x-powered-by", "")
    if powered_by:
        findings.append(
            Finding(
                code="POWERED_BY_DISCLOSURE",
                title="X-Powered-By gibt Framework preis",
                description=(
                    "Der X-Powered-By-Header verrät das verwendete Framework "
                    "(z. B. PHP/7.4, Express). Angreifer können bekannte Schwachstellen gezielt ausnutzen."
                ),
                severity=Severity.INFO,
                owasp=OWASPCategory.API8,
                detail=powered_by[:120],
                remediation="X-Powered-By-Header aus der Antwort entfernen.",
            )
        )

    return findings


def check_cors(headers: dict[str, str]) -> list[Finding]:
    """Prüft auf CORS-Fehlkonfigurationen.

    Args:
        headers: HTTP-Response-Header (Keys normalisiert oder nicht).

    Returns:
        Findings für Wildcard-CORS oder gefährliche CORS-Konfigurationen.
    """
    h = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    origin = h.get("access-control-allow-origin", "")
    credentials = h.get("access-control-allow-credentials", "").lower()

    if _CORS_WILDCARD.match(origin.strip()):
        if credentials == "true":
            # CORS Wildcard + Credentials = kritisch
            findings.append(
                Finding(
                    code="CORS_WILDCARD_WITH_CREDENTIALS",
                    title="CORS Wildcard mit Credentials",
                    description=(
                        "Access-Control-Allow-Origin: * kombiniert mit "
                        "Access-Control-Allow-Credentials: true erlaubt "
                        "jeder Website, authentifizierte Anfragen zu stellen. "
                        "Dies ist eine kritische CORS-Fehlkonfiguration."
                    ),
                    severity=Severity.CRITICAL,
                    owasp=OWASPCategory.API8,
                    detail=f"Origin: {origin} | Credentials: {credentials}",
                    remediation=(
                        "Entweder explizite Origins in die Allowlist aufnehmen "
                        "oder Credentials-Sharing deaktivieren."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    code="CORS_WILDCARD",
                    title="CORS erlaubt alle Origins",
                    description=(
                        "Access-Control-Allow-Origin: * erlaubt jeder Website, "
                        "Anfragen an diese API zu stellen. Für öffentliche "
                        "Read-Only-APIs ggf. akzeptabel, für authentifizierte "
                        "APIs ein Risiko."
                    ),
                    severity=Severity.MEDIUM,
                    owasp=OWASPCategory.API8,
                    detail=origin,
                    remediation="Origins explizit auf vertrauenswürdige Domains einschränken.",
                )
            )

    return findings


def check_error_leakage(body: str, status_code: int) -> list[Finding]:
    """Prüft Response-Body auf Stack-Traces und interne Pfade.

    Args:
        body: HTTP-Response-Body als String (max. erste 10 KB prüfen).
        status_code: HTTP-Statuscode der Antwort.

    Returns:
        Findings wenn Stack-Traces oder interne Pfade erkannt werden.
    """
    # Nur Fehlerantworten (4xx/5xx) auf Leakage prüfen
    if status_code < 400:
        return []

    findings: list[Finding] = []
    sample = body[:10_000]  # Nur ersten 10 KB auswerten

    for pattern in _STACKTRACE_PATTERNS:
        if pattern.search(sample):
            findings.append(
                Finding(
                    code="STACK_TRACE_LEAKAGE",
                    title="Stack-Trace in Fehlerantwort",
                    description=(
                        "Die API gibt bei Fehlern interne Stack-Traces zurück. "
                        "Diese verraten Framework, Bibliotheken, Dateinamen und "
                        "Zeilennummern — wertvolle Informationen für Angreifer."
                    ),
                    severity=Severity.HIGH,
                    owasp=OWASPCategory.API8,
                    remediation=(
                        "Globalen Exception-Handler implementieren, der nur "
                        "generische Fehlermeldungen zurückgibt. Details intern loggen."
                    ),
                )
            )
            break  # Ein Finding pro Response reicht

    for pattern in _PATH_PATTERNS:
        if pattern.search(sample):
            findings.append(
                Finding(
                    code="INTERNAL_PATH_LEAKAGE",
                    title="Interne Dateipfade in Response",
                    description=(
                        "Die API gibt interne Server-Pfade in der Antwort preis. "
                        "Angreifer können damit die Serverstruktur kartieren."
                    ),
                    severity=Severity.MEDIUM,
                    owasp=OWASPCategory.API8,
                    remediation="Interne Pfade aus Fehlerresponses entfernen.",
                )
            )
            break

    return findings


def check_rate_limiting(headers: dict[str, str]) -> list[Finding]:
    """Prüft auf fehlende Rate-Limit-Header.

    Args:
        headers: HTTP-Response-Header.

    Returns:
        Finding wenn keine Rate-Limit-Header vorhanden sind.
    """
    h = {k.lower(): v for k, v in headers.items()}

    # Bekannte Rate-Limit-Header
    rate_limit_headers = {
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "ratelimit-limit",
        "x-rate-limit-limit",
        "retry-after",
    }

    if not any(rh in h for rh in rate_limit_headers):
        return [
            Finding(
                code="NO_RATE_LIMIT_HEADERS",
                title="Keine Rate-Limit-Header",
                description=(
                    "Die API sendet keine Rate-Limit-Header zurück. "
                    "Ohne diese können Clients das API-Limit nicht "
                    "erkennen und Brute-Force- oder DoS-Angriffe sind schwerer erkennbar."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API4,
                remediation=(
                    "Rate-Limiting implementieren und mit Standard-Headern "
                    "kommunizieren: X-RateLimit-Limit, X-RateLimit-Remaining, "
                    "X-RateLimit-Reset."
                ),
            )
        ]
    return []


def check_auth_headers(
    headers: dict[str, str],
    status_code: int,
) -> list[Finding]:
    """Prüft auf schwache oder fehlende Authentifizierungshinweise.

    Args:
        headers: HTTP-Response-Header.
        status_code: HTTP-Statuscode.

    Returns:
        Findings für schwache/fehlende Auth-Konfiguration.
    """
    h = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    # 401-Antwort ohne WWW-Authenticate-Header
    if status_code == 401 and "www-authenticate" not in h:
        findings.append(
            Finding(
                code="MISSING_WWW_AUTHENTICATE",
                title="401 ohne WWW-Authenticate-Header",
                description=(
                    "Bei HTTP 401 Unauthorized fehlt der WWW-Authenticate-Header. "
                    "Clients können den erwarteten Authentifizierungsmechanismus "
                    "nicht ermitteln."
                ),
                severity=Severity.LOW,
                owasp=OWASPCategory.API2,
                remediation="WWW-Authenticate-Header mit dem erwarteten Auth-Schema senden.",
            )
        )

    # Basis-Authentifizierung erkennbar
    www_auth = h.get("www-authenticate", "").lower()
    if "basic" in www_auth:
        findings.append(
            Finding(
                code="BASIC_AUTH_DETECTED",
                title="HTTP Basic Authentication erkannt",
                description=(
                    "Die API verwendet HTTP Basic Auth. Credentials werden "
                    "nur Base64-kodiert (nicht verschlüsselt) übertragen. "
                    "Sicher nur über HTTPS, besser durch Bearer/OAuth2 ersetzen."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API2,
                detail=www_auth[:120],
                remediation=(
                    "Basic Auth durch OAuth2 Bearer Token oder API-Keys ersetzen. "
                    "Falls Basic Auth nötig, ausschließlich über HTTPS."
                ),
            )
        )

    return findings


def check_response_data(body: str, content_type: str) -> list[Finding]:
    """Prüft JSON-Response auf potenzielle sensible Datenfelder.

    Args:
        body: HTTP-Response-Body.
        content_type: Content-Type-Header der Antwort.

    Returns:
        Finding wenn Passwörter/Secrets in der JSON-Antwort erkannt werden.
    """
    if "json" not in content_type.lower():
        return []

    sample = body[:50_000]  # Max. 50 KB prüfen
    match = _SENSITIVE_FIELDS.search(sample)
    if match:
        return [
            Finding(
                code="SENSITIVE_DATA_IN_RESPONSE",
                title="Sensible Felder in API-Response",
                description=(
                    "Die API-Antwort enthält potenziell sensible Felder "
                    "(Passwörter, Tokens, API-Keys). Solche Werte sollten "
                    "nie in Responses enthalten sein."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.API3,
                remediation=(
                    "Sensible Felder aus API-Responses entfernen. "
                    "Property-Level-Authorization implementieren (OWASP API3). "
                    "Antworten nach dem Least-Privilege-Prinzip filtern."
                ),
            )
        ]
    return []


def check_ssrf_indicators(url: str) -> list[Finding]:
    """Prüft die URL auf SSRF-gefährdete Parameter.

    Args:
        url: Vollständige Scan-URL inklusive Query-Parameter.

    Returns:
        Finding wenn SSRF-gefährdete Parameter erkannt werden.
    """
    if _SSRF_PARAMS.search(url):
        return [
            Finding(
                code="SSRF_PARAMETER_INDICATOR",
                title="Potenziell SSRF-gefährdeter URL-Parameter",
                description=(
                    "Die URL enthält Parameter, die häufig für SSRF-Angriffe "
                    "(Server-Side Request Forgery) missbraucht werden "
                    "(z. B. url=, redirect=, callback=). "
                    "Wenn diese Parameter serverseitig für HTTP-Anfragen verwendet werden, "
                    "kann ein Angreifer interne Dienste erreichen."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.API7,
                detail=url[:200],
                remediation=(
                    "URL-Parameter, die für serverseitige Anfragen verwendet werden, "
                    "gegen eine Allowlist prüfen. Keine beliebigen URLs akzeptieren. "
                    "Ausgehende Anfragen auf benötigte Hosts beschränken."
                ),
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Check 9: TLS/SSL-Zertifikat
# ---------------------------------------------------------------------------

_WEAK_TLS_VERSIONS: frozenset[str] = frozenset(
    {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
)


def check_tls_certificate(tls_info: TLSInfo) -> list[Finding]:
    """Prüft TLS/SSL-Zertifikat auf 10 Sicherheitsprobleme (Check 9).

    Pure Funktion — kein Netzwerk-I/O. Erhält ein TLSInfo-Objekt
    und gibt eine Liste von Finding-Objekten zurück.

    Sub-Checks:
        1. Zertifikat abgelaufen (CRITICAL)
        2. Ablauf in < 30 Tagen (HIGH)
        3. Ablauf in < 90 Tagen (MEDIUM)
        4. TLS < 1.2 aktiv (CRITICAL)
        5. TLS 1.2 aktiv (nicht 1.3) (LOW)
        6. Selbstsigniertes Zertifikat (HIGH)
        7. Hostname-Mismatch (CRITICAL)
        8. Cipher-Schlüssel < 128 Bit (CRITICAL)
        9. Cipher-Schlüssel < 256 Bit (MEDIUM)
        10. Gültigkeitsbeginn in der Zukunft (CRITICAL)

    Args:
        tls_info: TLS-Informationen aus _fetch_tls_info.

    Returns:
        Liste von Finding-Objekten. Leer bei unauffälligem Zertifikat.
    """
    findings: list[Finding] = []
    now = datetime.now(UTC)

    # -- Ablaufdatum parsen --
    not_after: datetime | None = None
    not_before: datetime | None = None

    if tls_info.not_after:
        try:
            not_after = datetime.fromisoformat(tls_info.not_after)
        except ValueError:
            pass

    if tls_info.not_before:
        try:
            not_before = datetime.fromisoformat(tls_info.not_before)
        except ValueError:
            pass

    # -- Sub-Check 1: Abgelaufen --
    if not_after and not_after < now:
        findings.append(
            Finding(
                code="TLS_CERT_EXPIRED",
                title="TLS-Zertifikat abgelaufen",
                description=(
                    f"Das TLS-Zertifikat ist seit "
                    f"{not_after.strftime('%Y-%m-%d')} abgelaufen. "
                    "Clients lehnen die Verbindung ab."
                ),
                severity=Severity.CRITICAL,
                owasp=OWASPCategory.API8,
                detail=f"Ablauf: {tls_info.not_after}",
                remediation="Zertifikat sofort erneuern.",
            )
        )
    elif not_after:
        days_remaining = (not_after - now).days

        # -- Sub-Check 2: Läuft in < CERT_CRITICAL_DAYS ab --
        if days_remaining < CERT_CRITICAL_DAYS:
            findings.append(
                Finding(
                    code="TLS_CERT_EXPIRING_SOON",
                    title=(
                        f"TLS-Zertifikat läuft in weniger als "
                        f"{CERT_CRITICAL_DAYS} Tagen ab"
                    ),
                    description=(
                        f"Noch {days_remaining} Tage bis zum Ablauf. "
                        "Nach Ablauf verweigern Clients die Verbindung."
                    ),
                    severity=Severity.HIGH,
                    owasp=OWASPCategory.API8,
                    detail=f"Ablauf: {tls_info.not_after}",
                    remediation=(
                        f"Zertifikat innerhalb der nächsten "
                        f"{CERT_CRITICAL_DAYS} Tage erneuern."
                    ),
                )
            )

        # -- Sub-Check 3: Läuft in < CERT_WARNING_DAYS ab --
        elif days_remaining < CERT_WARNING_DAYS:
            findings.append(
                Finding(
                    code="TLS_CERT_EXPIRING_90D",
                    title=(
                        f"TLS-Zertifikat läuft in weniger als "
                        f"{CERT_WARNING_DAYS} Tagen ab"
                    ),
                    description=(
                        f"Noch {days_remaining} Tage bis zum Ablauf. "
                        "Ablauf-Monitoring einrichten."
                    ),
                    severity=Severity.MEDIUM,
                    owasp=OWASPCategory.API8,
                    detail=f"Ablauf: {tls_info.not_after}",
                    remediation=(
                        "Zertifikat rechtzeitig erneuern und "
                        "automatisches Ablauf-Monitoring einrichten."
                    ),
                )
            )

    # -- Sub-Check 10: Gültigkeitsbeginn in der Zukunft --
    if not_before and not_before > now:
        findings.append(
            Finding(
                code="TLS_CERT_NOT_YET_VALID",
                title="TLS-Zertifikat noch nicht gültig",
                description=(
                    f"Das Zertifikat wird erst ab "
                    f"{not_before.strftime('%Y-%m-%d')} gültig. "
                    "Aktuell verweigern Clients die Verbindung."
                ),
                severity=Severity.CRITICAL,
                owasp=OWASPCategory.API8,
                detail=f"Gültig ab: {tls_info.not_before}",
                remediation=(
                    "Serverzeitstempel prüfen und korrektes Zertifikat deployen."
                ),
            )
        )

    # -- Sub-Checks 4+5: TLS-Version --
    if tls_info.tls_version:
        if tls_info.tls_version in _WEAK_TLS_VERSIONS:
            findings.append(
                Finding(
                    code="TLS_WEAK_PROTOCOL",
                    title=f"Schwaches TLS-Protokoll: {tls_info.tls_version}",
                    description=(
                        f"Das Protokoll {tls_info.tls_version} ist als unsicher bekannt "
                        "und sollte nicht mehr eingesetzt werden."
                    ),
                    severity=Severity.CRITICAL,
                    owasp=OWASPCategory.API8,
                    detail=tls_info.tls_version,
                    remediation=(
                        "TLS 1.3 aktivieren. TLS < 1.2 auf dem Server deaktivieren."
                    ),
                )
            )
        elif tls_info.tls_version == "TLSv1.2":
            findings.append(
                Finding(
                    code="TLS_VERSION_1_2",
                    title="TLS 1.2 aktiv — Upgrade auf TLS 1.3 empfohlen",
                    description=(
                        "TLS 1.2 ist noch sicher, bietet aber nicht die "
                        "Vorwärtsgeheimnis-Garantien von TLS 1.3."
                    ),
                    severity=Severity.LOW,
                    owasp=OWASPCategory.API8,
                    detail=tls_info.tls_version,
                    remediation=(
                        "TLS 1.3 aktivieren für bessere Sicherheit und Performance."
                    ),
                )
            )

    # -- Sub-Check 6: Selbstsigniert --
    if tls_info.is_self_signed:
        findings.append(
            Finding(
                code="TLS_SELF_SIGNED",
                title="Selbstsigniertes Zertifikat",
                description=(
                    "Das Zertifikat wurde nicht von einer vertrauenswürdigen "
                    "Zertifizierungsstelle (CA) ausgestellt. "
                    "Browser und Clients zeigen Sicherheitswarnungen."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.API8,
                detail=f"Aussteller: {tls_info.issuer_cn}",
                remediation=(
                    "Zertifikat einer öffentlichen CA (z. B. Let's Encrypt) "
                    "oder internen vertrauenswürdigen CA verwenden."
                ),
            )
        )

    # -- Sub-Check 7: Hostname-Mismatch --
    if not tls_info.hostname_valid:
        san_preview = ", ".join(tls_info.san[:5]) if tls_info.san else "–"
        findings.append(
            Finding(
                code="TLS_HOSTNAME_MISMATCH",
                title="Hostname stimmt nicht mit Zertifikat überein",
                description=(
                    "Der Hostname der API ist nicht im Zertifikat enthalten "
                    "(weder in Subject CN noch in Subject Alternative Names). "
                    "Clients lehnen die Verbindung ab."
                ),
                severity=Severity.CRITICAL,
                owasp=OWASPCategory.API8,
                detail=f"SANs: {san_preview}",
                remediation=(
                    "Zertifikat erneuern das den korrekten Hostnamen "
                    "im SAN-Feld enthält."
                ),
            )
        )

    # -- Sub-Checks 8+9: Cipher-Stärke --
    if tls_info.cipher_bits > 0:
        if tls_info.cipher_bits < 128:
            findings.append(
                Finding(
                    code="TLS_WEAK_CIPHER",
                    title=(
                        f"Schwache Cipher-Suite: {tls_info.cipher_name} "
                        f"({tls_info.cipher_bits} Bit)"
                    ),
                    description=(
                        f"Die Cipher-Suite verwendet nur {tls_info.cipher_bits}-Bit-Schlüssel "
                        "und gilt als kryptografisch unsicher."
                    ),
                    severity=Severity.CRITICAL,
                    owasp=OWASPCategory.API8,
                    detail=f"{tls_info.cipher_name} / {tls_info.cipher_bits} Bit",
                    remediation=(
                        "Server-Konfiguration auf starke Cipher-Suites beschränken "
                        "(AES-256-GCM, CHACHA20-POLY1305)."
                    ),
                )
            )
        elif tls_info.cipher_bits < 256:
            findings.append(
                Finding(
                    code="TLS_MEDIUM_CIPHER",
                    title=(
                        f"Mittlere Cipher-Stärke: {tls_info.cipher_name} "
                        f"({tls_info.cipher_bits} Bit)"
                    ),
                    description=(
                        f"Die Cipher-Suite verwendet {tls_info.cipher_bits}-Bit-Schlüssel. "
                        "256-Bit-Cipher-Suites bieten bessere Langzeitsicherheit."
                    ),
                    severity=Severity.MEDIUM,
                    owasp=OWASPCategory.API8,
                    detail=f"{tls_info.cipher_name} / {tls_info.cipher_bits} Bit",
                    remediation=("AES-256-GCM oder CHACHA20-POLY1305 bevorzugen."),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Active Checks (10–14) — senden konstruierte Anfragen, aber harmlos
# ---------------------------------------------------------------------------

# HTTP-Methoden die potenziell destruktiv sind
_DESTRUCTIVE_METHODS: frozenset[str] = frozenset({"PUT", "DELETE", "PATCH"})


def check_http_methods(
    url: str,
    allowed_by_options: list[str],
    responses: dict[str, int],
) -> list[Finding]:
    """Prueft welche HTTP-Methoden der Server akzeptiert (Check 10).

    Erkennt:
    - Unerwartete 2xx-Antworten auf PUT/DELETE/PATCH → HOCH
    - OPTIONS-Allow-Header enthaelt destruktive Methoden → MITTEL
    - HEAD-Methode nicht unterstuetzt → NIEDRIG

    Args:
        url: URL des Scan-Ziels (nur fuer Finding-Detail).
        allowed_by_options: Methoden aus dem Allow-Header der OPTIONS-Antwort.
        responses: Status-Codes je HTTP-Methode (Schluessel = Methode).
                            -1 bedeutet Verbindungsfehler/Timeout.

    Returns:
        Liste der gefundenen Probleme.
    """
    findings: list[Finding] = []

    # -- Unerwartete 2xx auf destruktive Methoden --
    for method in ("PUT", "DELETE", "PATCH"):
        code = responses.get(method, -1)
        if 200 <= code <= 299:
            findings.append(
                Finding(
                    code=f"UNEXPECTED_{method}_ALLOWED",
                    title=f"{method}-Methode ohne Autorisierung akzeptiert",
                    description=(
                        f"Der Server antwortete auf einen {method}-Request ohne "
                        f"Authentifizierung mit HTTP {code}. "
                        f"{method}-Requests koennen Daten veraendern oder loeschen."
                    ),
                    severity=Severity.HIGH,
                    owasp=OWASPCategory.API5,
                    detail=f"HTTP {code} auf {method} {url}",
                    remediation=(
                        f"{method}-Methode auf autorisierte Nutzer einschraenken "
                        "oder deaktivieren wenn nicht benoetigt."
                    ),
                )
            )

    # -- OPTIONS-Allow enthaelt destruktive Methoden --
    allowed_upper = {m.upper() for m in allowed_by_options}
    dangerous_allowed = allowed_upper & _DESTRUCTIVE_METHODS
    if dangerous_allowed and not any(
        200 <= responses.get(m, -1) <= 299 for m in dangerous_allowed
    ):
        findings.append(
            Finding(
                code="OPTIONS_EXPOSES_DANGEROUS_METHODS",
                title="OPTIONS gibt destruktive HTTP-Methoden preis",
                description=(
                    "Der OPTIONS-Allow-Header listet potenziell destruktive "
                    f"Methoden auf: {', '.join(sorted(dangerous_allowed))}. "
                    "Angreifer erhalten dadurch Informationen ueber angreifbare "
                    "Endpunkte."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API5,
                detail=f"Allow: {', '.join(sorted(allowed_upper))}",
                remediation=(
                    "OPTIONS-Antwort auf minimal benoetigte Methoden beschraenken. "
                    "Destruktive Methoden hinter Auth absichern."
                ),
            )
        )

    # -- HEAD nicht unterstuetzt --
    head_code = responses.get("HEAD", -1)
    if head_code == 405 or head_code == -1:
        findings.append(
            Finding(
                code="HEAD_NOT_SUPPORTED",
                title="HEAD-Methode nicht unterstuetzt",
                description=(
                    "Die API unterstuetzt die HEAD-Methode nicht. "
                    "HEAD ist ein harmloses Standard-HTTP-Verb und sollte "
                    "von REST-APIs akzeptiert werden."
                ),
                severity=Severity.LOW,
                owasp=OWASPCategory.API5,
                detail=f"HTTP {head_code} auf HEAD {url}",
                remediation="HEAD-Methode in der API-Konfiguration erlauben.",
            )
        )

    return findings


def check_content_type_enforcement(responses: dict[str, int]) -> list[Finding]:
    """Prueft ob der Server Content-Type-Header erzwingt (Check 11).

    Erkennt:
    - Server akzeptiert Requests ohne Content-Type → MITTEL
    - Server akzeptiert Requests mit falschem Content-Type → MITTEL

    Args:
        responses: Status-Codes je Test-Szenario:
                   ``"no_ct"`` — Request ohne Content-Type
                   ``"wrong_ct"`` — Request mit Content-Type: text/plain

    Returns:
        Liste der gefundenen Probleme.
    """
    findings: list[Finding] = []

    no_ct_code = responses.get("no_ct", -1)
    wrong_ct_code = responses.get("wrong_ct", -1)

    # Kein Content-Type akzeptiert (2xx oder nicht 415/400)
    if 200 <= no_ct_code <= 299:
        findings.append(
            Finding(
                code="MISSING_CONTENT_TYPE_ACCEPTED",
                title="Request ohne Content-Type akzeptiert",
                description=(
                    "Der Server akzeptiert Requests ohne Content-Type-Header "
                    f"(HTTP {no_ct_code}). APIs sollten explizit den "
                    "erwarteten Content-Type erzwingen."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API8,
                detail=f"HTTP {no_ct_code} ohne Content-Type-Header",
                remediation=(
                    "Content-Type-Validierung implementieren: "
                    "415 Unsupported Media Type bei fehlendem oder falschem CT."
                ),
            )
        )

    # Falscher Content-Type akzeptiert
    if 200 <= wrong_ct_code <= 299:
        findings.append(
            Finding(
                code="WRONG_CONTENT_TYPE_ACCEPTED",
                title="Falscher Content-Type akzeptiert (text/plain statt application/json)",
                description=(
                    "Der Server akzeptiert Requests mit Content-Type: text/plain "
                    f"(HTTP {wrong_ct_code}). Korrekt konfigurierte APIs "
                    "sollten mit 415 Unsupported Media Type antworten."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API8,
                detail=f"HTTP {wrong_ct_code} mit Content-Type: text/plain",
                remediation=(
                    "Content-Type-Validierung auf Middleware-Ebene implementieren."
                ),
            )
        )

    return findings


def check_auth_bypass(
    auth_configured: bool,
    responses: dict[str, tuple[int, str]],
) -> list[Finding]:
    """Prueft ob Authentifizierung umgangen werden kann (Check 12).

    Wird nur ausgefuehrt wenn Auth im ScanTarget konfiguriert ist.
    Sendet KEINE echten Credentials — nur leere/falsche Tokens.

    Erkennt:
    - Jede Probe mit HTTP 2xx → KRITISCH (Auth-Bypass!)

    Args:
        auth_configured: True wenn im ScanTarget Auth konfiguriert ist.
        responses: Status-Code und Reason je Test-Label:
                         ``"Kein Auth-Header"``, ``"Leerer Bearer"``,
                         ``"Bearer null"``, ``"Bearer undefined"``

    Returns:
        Liste der gefundenen Auth-Bypass-Probleme.
    """
    if not auth_configured:
        return []

    findings: list[Finding] = []

    for label, (status_code, reason) in responses.items():
        if 200 <= status_code <= 299:
            findings.append(
                Finding(
                    code="AUTH_BYPASS_POSSIBLE",
                    title=f"Auth-Bypass moeglich: {label}",
                    description=(
                        f"Der Server antwortete mit HTTP {status_code} auf eine "
                        f"Anfrage mit manipuliertem Auth-Header ({label}). "
                        "Authentifizierung kann umgangen werden!"
                    ),
                    severity=Severity.CRITICAL,
                    owasp=OWASPCategory.API2,
                    detail=f"Probe '{label}' → HTTP {status_code} {reason}",
                    remediation=(
                        "Auth-Validierung serverseitig fuer alle Endpunkte "
                        "erzwingen. Leere und falsche Tokens explizit ablehnen (401)."
                    ),
                )
            )

    return findings


def check_request_size_limits(responses: dict[str, int]) -> list[Finding]:
    """Prueft ob der Server Request-Groessen begrenzt (Check 13).

    Erkennt:
    - Server akzeptiert uebergrossen Header (8KB+) → MITTEL
    - Server akzeptiert extrem langen URL-Pfad → MITTEL

    Verbindungsabbruch (-1) gilt als korrekte Abweisung.

    Args:
        responses: Status-Codes je Test-Szenario:
                   ``"big_header"`` — Request mit 8KB+ Custom-Header
                   ``"long_url"`` — Request mit 2000+ Zeichen URL-Pfad

    Returns:
        Liste der gefundenen Probleme.
    """
    findings: list[Finding] = []

    big_header_code = responses.get("big_header", -1)
    long_url_code = responses.get("long_url", -1)

    # -1 und 413/414/431 sind korrekte Abweisungen
    _acceptable = {-1, 400, 413, 414, 431}

    if big_header_code not in _acceptable and 200 <= big_header_code <= 299:
        findings.append(
            Finding(
                code="LARGE_HEADER_ACCEPTED",
                title="Uebergrosse Request-Header akzeptiert (8KB+)",
                description=(
                    f"Der Server akzeptierte einen Request mit mehr als 8 KB "
                    f"Header-Daten (HTTP {big_header_code}). "
                    "Fehlende Header-Groessenlimits koennen fuer DoS-Angriffe "
                    "ausgenutzt werden."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API4,
                detail=f"HTTP {big_header_code} mit 8KB Custom-Header",
                remediation=(
                    "Maximale Header-Groesse auf Web-Server-/Proxy-Ebene "
                    "begrenzen (z. B. Nginx: large_client_header_buffers)."
                ),
            )
        )

    if long_url_code not in _acceptable and 200 <= long_url_code <= 299:
        findings.append(
            Finding(
                code="LONG_URL_ACCEPTED",
                title="Extrem langer URL-Pfad akzeptiert (2000+ Zeichen)",
                description=(
                    f"Der Server akzeptierte einen Request mit einem URL-Pfad "
                    f"von mehr als 2000 Zeichen (HTTP {long_url_code}). "
                    "Fehlende URL-Laengenlimits koennen fuer DoS-Angriffe "
                    "genutzt werden."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API4,
                detail=f"HTTP {long_url_code} mit 2000+ Zeichen URL-Pfad",
                remediation=(
                    "Maximale URL-Laenge auf Reverse-Proxy-Ebene begrenzen "
                    "(z. B. Nginx: large_client_header_buffers, "
                    "Apache: LimitRequestLine)."
                ),
            )
        )

    return findings


def check_verbose_errors(responses: dict[str, tuple[int, str]]) -> list[Finding]:
    """Analysiert provozierte Fehlerantworten auf Information Disclosure (Check 14).

    Delegiert die eigentliche Erkennung an check_error_leakage —
    kein doppelter Code.

    Args:
        responses: Status-Code und Body je Test-Szenario:
                   ``"invalid_json"`` — POST mit ungueltigem JSON-Body
                   ``"invalid_accept"`` — GET mit ungueltigem Accept-Header
                   ``"probe_404"`` — GET auf nicht-existierenden Endpunkt

    Returns:
        Liste der gefundenen Information-Disclosure-Probleme
        (Duplikate anhand Code dedupliziert).
    """
    findings: list[Finding] = []
    seen_codes: set[str] = set()

    for _label, (status_code, body) in responses.items():
        for finding in check_error_leakage(body, status_code):
            if finding.code not in seen_codes:
                seen_codes.add(finding.code)
                findings.append(finding)

    return findings
