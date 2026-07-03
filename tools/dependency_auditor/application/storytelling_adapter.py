"""storytelling_adapter — dependency_auditor → FindingInput a/b).

Konvertiert:class:`VulnerabilityInfo` aus:class:`DependencyAuditResult` in
``FindingInput``-Objekte fuer das ``vulnerable_package``-Storytelling-Template.

Versions-verifizierte Vulnerabilities erzeugen weiterhin ein Finding
pro CVE. Unverifizierte Advisories (Kategorie „Version unbekannt") erzeugen
KEINE Einzel-Tasks mehr — stattdessen hoechstens EIN aggregiertes
Hinweis-Finding (``unpinned_dependency``, niedrige Severity), damit das
Taskboard nicht geflutet wird.

Reconcile-Review-Fix): Beim SELF-Audit ist ``audit_to_ki_inputs``
die VOLLSTAENDIGE Findings-Liste des Laufs — ``emit_to_ki_emitter`` darf
dann mit ``reconcile_tool="dependency_auditor"`` emittieren, damit
verschwundene Findings ihre Taskboard-Karten auto-schliessen.

Schichtzugehoerigkeit: ``application/`` (kein GUI, kein direktes data/).

Author: Patrick Riederich
Version: 1.2
"""

from __future__ import annotations

import hashlib

from core.logger import get_logger
from core.security.severity import Severity
from core.storytelling.schemas import FindingInput
from tools.dependency_auditor.domain.models import (
    DependencyAuditResult,
    VulnSeverity,
)

log = get_logger(__name__)

# Tool-Bezeichner fuer den Voll-Sync (KiTodoService.sync_findings).
_RECONCILE_TOOL = "dependency_auditor"

# Aggregiertes Hinweis-Finding fuer Packages ohne Versionsabgleich.
# finding_type matcht die bestehende Regel `dep_unpinned_dependency` in
# configs/rules/dependency.yaml + das Template in finding_templates.py.
_UNVERIFIED_FINDING_TYPE = "unpinned_dependency"
# Stabile evidence_id-Basis → KiTodo-Dedup erzeugt hoechstens EINE Karte
# pro Quelle. Quell-Diskriminator (Self-Audit vs. Fremddatei) wird in
# _unverified_evidence_id angehaengt, damit Self- und Fremdscan nicht
# auf derselben Karte kollidieren.
_UNVERIFIED_EVIDENCE_ID = "dependency_auditor#versionsabgleich-unbekannt"
_UNVERIFIED_SEVERITY = Severity.LOW
# Obergrenze fuer die Package-Namensliste in den Details (Lesbarkeit).
_MAX_PACKAGES_IN_DETAILS = 10
# Laenge des Datei-Diskriminators (sha256-Praefix) in der evidence_id.
_SOURCE_HASH_LEN = 8


def audit_to_ki_inputs(
    audit_result: DependencyAuditResult,
    *,
    self_audit: bool = False,
) -> list[FindingInput]:
    """Wandelt:class:`DependencyAuditResult.vulnerabilities` in:class:`FindingInput`.

    Pro versions-verifizierter Vulnerability ein Finding. Unverifizierte
    Advisories (Kategorie „Version unbekannt") werden zu hoechstens
    EINEM aggregierten Hinweis-Finding zusammengefasst. Audits mit
    ``error`` liefern leere Liste.

    Die Rueckgabe ist die VOLLSTAENDIGE Findings-Liste des Laufs —
    geeignet als Eingabe fuer den Reconcile-Pfad
    (:meth:`KiTodoService.sync_findings`).

    Args:
        audit_result: Ergebnis von:func:`AuditService.audit_*`.
        self_audit: True beim Selbst-Audit (eigene requirements.txt) —
            steuert den Quell-Diskriminator der Aggregat-evidence_id.

    Returns:
        Liste der:class:`FindingInput`. Leer wenn nichts zu melden ist.
    """
    if audit_result.error:
        return []

    # Pro Package die effektive Version aus den Dependencies finden — fuer
    # die Storytelling-Details. Dependencies sind nicht garantiert vorhanden,
    # daher Fallback auf "?".
    deps_by_name = {
        dep.name.lower(): dep for dep in audit_result.dependencies
    }

    inputs: list[FindingInput] = []
    for vuln in audit_result.vulnerabilities:
        # Pydantic FindingInput verlangt min_length=1 fuer subject + evidence_id.
        # Defekte OSV-/GHSA-Antworten ohne package_name oder vuln_id werden
        # uebersprungen — Hook darf den Audit nicht brechen.
        if not vuln.package_name or not vuln.vuln_id:
            continue
        dep = deps_by_name.get(vuln.package_name.lower())
        version = (dep.effective_version() if dep else None) or "?"
        inputs.append(
            FindingInput(
                tool="dependency_auditor",
                finding_type="vulnerable_package",
                severity=_to_canonical_severity(vuln.severity),
                subject=vuln.package_name,
                evidence_id=f"{vuln.package_name}#{vuln.vuln_id}",
                details={
                    "package": vuln.package_name,
                    "version": version,
                    "cve_id": vuln.vuln_id,
                    "summary": vuln.summary,
                    "fixed_version": vuln.fixed_version or "?",
                },
            )
        )

    hint = _unverified_hint_input(audit_result, self_audit=self_audit)
    if hint is not None:
        inputs.append(hint)
    return inputs


def _unverified_evidence_id(source_file: str, *, self_audit: bool) -> str:
    """Baut die evidence_id des Aggregat-Findings mit Quell-Diskriminator.

    Self-Audit erhaelt den stabilen Suffix ``#self``; Fremddatei-Audits
    einen sha256-Praefix des Dateipfads. Damit kollidieren Self- und
    Fremdscan (bzw. zwei verschiedene Fremddateien) nicht auf derselben
    Taskboard-Karte.

    Args:
        source_file: Pfad der gescannten requirements-Quelle.
        self_audit: True beim Selbst-Audit.

    Returns:
        evidence_id-String, z. B.
        ``dependency_auditor#versionsabgleich-unbekannt#self``.
    """
    if self_audit:
        suffix = "self"
    else:
        digest = hashlib.sha256(source_file.encode("utf-8")).hexdigest()
        suffix = digest[:_SOURCE_HASH_LEN]
    return f"{_UNVERIFIED_EVIDENCE_ID}#{suffix}"


def _unverified_hint_input(
    audit_result: DependencyAuditResult,
    *,
    self_audit: bool = False,
) -> FindingInput | None:
    """Baut das aggregierte Hinweis-Finding fuer „Version unbekannt".

    Statt einer Task-Flut pro CVE entsteht hoechstens EIN Finding:
    „N Pakete ohne verifizierbare Version — Versionsabgleich nicht
    moeglich".

    Args:
        audit_result: Abgeschlossenes Audit-Ergebnis.
        self_audit: True beim Selbst-Audit (evidence_id-Diskriminator).

    Returns:
        FindingInput oder None wenn alle Advisories verifiziert wurden.
    """
    if not audit_result.unverified_vulnerabilities:
        return None

    package_names = sorted({d.name for d in audit_result.unverified_dependencies})
    if not package_names:
        # Defensive: Advisories ohne zugehoerige Dependency-Liste.
        package_names = sorted(
            {v.package_name for v in audit_result.unverified_vulnerabilities}
        )
    if not package_names:
        return None

    shown = ", ".join(package_names[:_MAX_PACKAGES_IN_DETAILS])
    if len(package_names) > _MAX_PACKAGES_IN_DETAILS:
        shown += f" … (+{len(package_names) - _MAX_PACKAGES_IN_DETAILS} weitere)"

    return FindingInput(
        tool="dependency_auditor",
        finding_type=_UNVERIFIED_FINDING_TYPE,
        severity=_UNVERIFIED_SEVERITY,
        subject="requirements-Versionsabgleich",
        evidence_id=_unverified_evidence_id(
            audit_result.source_file, self_audit=self_audit
        ),
        details={
            "count": len(package_names),
            "packages": shown,
            "advisories": len(audit_result.unverified_vulnerabilities),
            "source_file": audit_result.source_file,
        },
    )


def _to_canonical_severity(value: VulnSeverity) -> Severity:
    """``VulnSeverity`` (deutsche UPPERCASE) → kanonisches ``Severity``."""
    _map = {
        VulnSeverity.CRITICAL: Severity.CRITICAL,
        VulnSeverity.HIGH: Severity.HIGH,
        VulnSeverity.MEDIUM: Severity.MEDIUM,
        VulnSeverity.LOW: Severity.LOW,
    }
    return _map.get(value, Severity.INFO)


def emit_to_ki_emitter(
    emitter,
    audit_result: DependencyAuditResult,
    *,
    self_audit: bool = False,
) -> list[FindingInput]:
    """Convenience: konvertiert + ruft ``emitter.emit`` auf.

    Beim SELF-Audit (``self_audit=True``) wird mit
    ``reconcile_tool="dependency_auditor"`` emittiert:
:func:`audit_to_ki_inputs` liefert die VOLLSTAENDIGE Findings-Liste
    des Laufs (Vorbedingung von:meth:`KiTodoService.sync_findings`
    erfuellt). Damit werden (1) Karten auto-erledigt, deren Finding
    verschwunden ist (z. B. „Pakete ohne verifizierbare Version" nach
    dem Pinnen), (2) erledigte Karten bei erneutem Auftreten wieder
    angelegt und (3) Zaehler/Titel beim Refresh aktualisiert.
    Bewusst akzeptiert: Der Self-Audit-Reconcile raeumt dabei auch stale
    Fremdscan-Karten desselben Tools auf — Fremddatei-Audits emittieren
    weiterhin OHNE Reconcile (nur anlegen), weil ihre Findings-Liste
    nicht den kompletten Tool-Bestand abbildet.

    Fail-safe: Konvertierungs-Fehler werden geloggt und geschluckt — Hook
    darf den Audit nicht brechen.

    Args:
        emitter: ``KiTodoEmitter``-kompatibles Objekt.
        audit_result: Abgeschlossenes Audit-Ergebnis.
        self_audit: True beim Selbst-Audit → Reconcile-Emit.

    Returns:
        Die emittierten:class:`FindingInput` (leer bei Fehler).
    """
    try:
        inputs = audit_to_ki_inputs(audit_result, self_audit=self_audit)
    except Exception as exc:  # noqa: BLE001 -- Hook darf Audit nicht brechen
        log.warning(
            "dependency_auditor → FindingInput-Konvertierung fehlgeschlagen: %s: %s",
            type(exc).__name__,
            str(exc)[:200],
        )
        return []
    if self_audit:
        emitter.emit(inputs, reconcile_tool=_RECONCILE_TOOL)
    else:
        emitter.emit(inputs)
    return inputs
