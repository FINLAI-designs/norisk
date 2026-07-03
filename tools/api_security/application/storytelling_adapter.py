"""storytelling_adapter — api_security Findings → FindingInput a/b).

Konvertiert ``ScanResult.findings`` in eine Liste von ``FindingInput``-Objekten,
die der:class:`core.storytelling.ki_todo_emitter.KiTodoEmitter` an die
Regelengine + Storytelling-Engine weiterreicht.

Heute unterstuetztes Storytelling-Template: ``("api_security",
"missing_security_header")`` aus ``core/storytelling/finding_templates.py``.
Andere Findings (TLS-Probleme, CORS, Rate-Limit etc.) werden mit dem
finding_type ``"unknown"`` durchgereicht — die Regelengine wirft sie still
weg, bis ein passendes Template existiert.

Schichtzugehoerigkeit: ``application/`` (kein GUI, kein direktes data/).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable

from core.logger import get_logger
from core.security.severity import Severity as CanonicalSeverity
from core.security.severity import from_csaf
from core.storytelling.schemas import FindingInput
from tools.api_security.domain.models import Finding, ScanResult

log = get_logger(__name__)

# Mapping vom api_security-Finding-``code`` auf
# (storytelling_finding_type, header_name, risk-Substantiv).
# Heute nur fuer Header-Findings; weitere Codes folgen mit neuen Templates.
_HEADER_FINDING_MAP: dict[str, tuple[str, str, str]] = {
    "MISSING_HSTS": (
        "missing_security_header",
        "Strict-Transport-Security",
        "HTTPS-Downgrade-Angriffen",
    ),
    "MISSING_CSP": (
        "missing_security_header",
        "Content-Security-Policy",
        "Cross-Site-Scripting-Angriffen",
    ),
    "MISSING_X_FRAME_OPTIONS": (
        "missing_security_header",
        "X-Frame-Options",
        "Clickjacking-Angriffen",
    ),
    "MISSING_X_CONTENT_TYPE_OPTIONS": (
        "missing_security_header",
        "X-Content-Type-Options",
        "MIME-Sniffing-Angriffen",
    ),
    "MISSING_REFERRER_POLICY": (
        "missing_security_header",
        "Referrer-Policy",
        "Information-Leakage durch Referrer-Header",
    ),
}


def findings_to_ki_inputs(
    scan_result: ScanResult,
    *,
    target_label: str | None = None,
) -> list[FindingInput]:
    """Wandelt:class:`ScanResult.findings` in:class:`FindingInput`.

    Args:
        scan_result: Ergebnis von:func:`ScannerService.scan`.
        target_label: Optionaler User-Facing-Label fuer ``subject``.
            Default: ``scan_result.target.url``.

    Returns:
        Liste von:class:`FindingInput`. Findings mit unbekanntem Code werden
        mit ``finding_type="unknown"`` durchgereicht — die Regelengine ignoriert
        sie still (kein Storytelling-Template). Leere Liste wenn ``scan_result``
        keine Findings hat oder ein ``error`` gesetzt ist.
    """
    if scan_result.error or not scan_result.findings:
        return []

    subject = target_label or scan_result.target.url
    # Pydantic FindingInput verlangt min_length=1 fuer subject + evidence_id.
    # Wenn target.url leer ist (Pre-Validation hat versagt), bricht der ganze
    # Adapter mit ValidationError. Defensive: Adapter liefert leere Liste,
    # Hook bricht den Scan nicht.
    if not subject:
        return []
    inputs: list[FindingInput] = []
    for finding in scan_result.findings:
        ft, details = _map_finding(finding)
        evidence_id = _evidence_id_for(scan_result, finding)
        if not evidence_id:
            continue
        inputs.append(
            FindingInput(
                tool="api_security",
                finding_type=ft,
                severity=_to_canonical_severity(finding.severity.value),
                subject=subject,
                evidence_id=evidence_id,
                details=details,
            )
        )
    return inputs


def _map_finding(finding: Finding) -> tuple[str, dict]:
    """Mappt einen ``Finding.code`` auf ``(finding_type, details)``.

    Unbekannte Codes bekommen ``finding_type="unknown"`` mit minimalen
    Details — die Regelengine sortiert sie still aus.
    """
    if finding.code in _HEADER_FINDING_MAP:
        ft, header_name, risk = _HEADER_FINDING_MAP[finding.code]
        return ft, {
            "header_name": header_name,
            "recommended_value": finding.remediation or "siehe OWASP-Empfehlung",
            "risk": risk,
        }
    return "unknown", {
        "code": finding.code,
        "title": finding.title,
        "owasp": finding.owasp.value,
    }


def _evidence_id_for(scan_result: ScanResult, finding: Finding) -> str:
    """Stabile Referenz: ``<target_url>#<finding_code>``.

    Reicht aus, weil pro Scan-Lauf jedes Finding-Code-Paar nur einmal
    auftritt. Fuer mehrfache Vorkommen mit unterschiedlichen Details
    waere ``<scan_id>#<code>`` praeziser — heute reicht das einfache
    Pattern, weil die Engine via ``dedup_key`` zusaetzlich auf Tool +
    Type + Evidence dedupliziert.
    """
    return f"{scan_result.target.url}#{finding.code}"


def _to_canonical_severity(value: str) -> CanonicalSeverity:
    """``api_security.Severity`` (StrEnum, lowercase) -> kanonisches ``Severity``.

    Beide Enums haben dieselben Werte (lowercase english), aber der
    KiTodoService erwartet ``core.security.severity.Severity``. Die
    ``from_csaf``-Routine kann sowohl CSAF-Strings als auch das StrEnum-
    Format parsen — wir delegieren dorthin fuer Symmetrie.
    """
    return from_csaf(value)


def emit_to_ki_emitter(emitter, scan_result: ScanResult) -> Iterable[FindingInput]:
    """Convenience: konvertiert + ruft ``emitter.emit`` auf.

    Args:
        emitter::class:`core.storytelling.ki_todo_emitter.KiTodoEmitter`.
        scan_result: Ergebnis aus dem ScannerService.

    Returns:
        Die konvertierten ``FindingInput``-Objekte (z. B. fuer Tests oder
        Logging im Aufrufer). Side-effect: ``emitter.emit(inputs)`` wird
        aufgerufen — Hook ist No-op falls Service nicht init. Fail-safe:
        Konvertierungs-Fehler werden geloggt und schlucken.
    """
    try:
        inputs = findings_to_ki_inputs(scan_result)
    except Exception as exc:  # noqa: BLE001 -- Hook darf Scan nicht brechen
        log.warning(
            "api_security → FindingInput-Konvertierung fehlgeschlagen: %s: %s",
            type(exc).__name__,
            str(exc)[:200],
        )
        return []
    emitter.emit(inputs)
    return inputs
