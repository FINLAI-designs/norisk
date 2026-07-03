"""storytelling_adapter — cert_monitor → FindingInput a/b).

Konvertiert:class:`CertInfo` in ``FindingInput`` fuer das ``cert_expiring``-
Storytelling-Template. Triggert nur wenn ``tage_verbleibend <= 90`` —
ablaufende Zertifikate sind das einzige hier abgedeckte Finding.

Schichtzugehoerigkeit: ``application/`` (kein GUI, kein direktes data/).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable

from core.logger import get_logger
from core.security.severity import Severity
from core.storytelling.schemas import FindingInput
from tools.cert_monitor.domain.models import CertInfo, CertStatus

log = get_logger(__name__)

# Schwellwerte gemaess _render_cert_expiring (Storytelling-Template):
# ≤ 90 Tage = relevantes Finding (TREND/WICHTIG/AKUT je nach Schwere).
_EMIT_THRESHOLD_DAYS = 90


def cert_infos_to_ki_inputs(
    certs: Iterable[CertInfo],
) -> list[FindingInput]:
    """Wandelt eine Liste:class:`CertInfo` in:class:`FindingInput`.

    Nur Zertifikate mit ``tage_verbleibend <= 90`` werden gemeldet — alles
    darueber ist nicht akut genug fuer ein KI-Todo. Zertifikate ohne
    valide Ablauf-Info (Status FEHLER/UNBEKANNT, ``gueltig_bis`` leer)
    werden uebersprungen.

    Args:
        certs: Liste der Cert-Eintraege aus:class:`CertRepository`.

    Returns:
        Liste der:class:`FindingInput`. Leer wenn keine relevanten
        Zertifikate.
    """
    inputs: list[FindingInput] = []
    for cert in certs:
        if cert.status in (CertStatus.FEHLER, CertStatus.UNBEKANNT):
            continue
        if not cert.gueltig_bis:
            continue
        if cert.tage_verbleibend > _EMIT_THRESHOLD_DAYS:
            continue
        # Pydantic FindingInput verlangt min_length=1 fuer subject.
        # `anzeige_domain` ist normalerweise immer gesetzt — aber defensive
        # Skip falls eine Repository-Migration leere Domains durchschleust.
        if not cert.anzeige_domain:
            continue
        inputs.append(
            FindingInput(
                tool="cert_monitor",
                finding_type="cert_expiring",
                severity=_severity_for_days(cert.tage_verbleibend),
                subject=cert.anzeige_domain,
                evidence_id=f"{cert.anzeige_domain}#{cert.serial_number or 'no-serial'}",
                details={
                    "days_left": cert.tage_verbleibend,
                    "expires_at": cert.gueltig_bis,
                },
            )
        )
    return inputs


def _severity_for_days(days_left: int) -> Severity:
    """Mapping Tage→Severity (analog zum Urgency-Mapping im Template).

    - ≤ 0 oder ≤ 7 Tage → CRITICAL
    - ≤ 30 Tage → HIGH
    - ≤ 90 Tage → MEDIUM
    """
    if days_left <= 7:
        return Severity.CRITICAL
    if days_left <= 30:
        return Severity.HIGH
    return Severity.MEDIUM


def emit_to_ki_emitter(emitter, certs: Iterable[CertInfo]) -> list[FindingInput]:
    """Convenience: konvertiert + ruft ``emitter.emit`` auf.

    Fail-safe: Konvertierungs-Fehler werden geloggt und schlucken — Hook
    darf den Scan nicht brechen.

    Args:
        emitter::class:`core.storytelling.ki_todo_emitter.KiTodoEmitter`.
        certs: Cert-Eintraege.

    Returns:
        Konvertierte:class:`FindingInput`-Liste (Side-effect: emitter.emit).
    """
    try:
        inputs = cert_infos_to_ki_inputs(certs)
    except Exception as exc:  # noqa: BLE001 -- Hook darf Scan nicht brechen
        log.warning(
            "cert_monitor → FindingInput-Konvertierung fehlgeschlagen: %s: %s",
            type(exc).__name__,
            str(exc)[:200],
        )
        return []
    emitter.emit(inputs)
    return inputs
