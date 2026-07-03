"""
analyzer — Reine Analyse-Logik fuer den Dependency-Auditor.

Keine Netzwerk-Calls, keine Datei-I/O — nur Matching und Aggregation.

Prueft:
  1. Ob eine gepinnte Version in einem affected-Versionsbereich liegt.
  2. Welche Dependencies von bekannten Vulnerabilities betroffen sind.
  3. Welche Dependencies unpinned sind.

Hinweis: Verwendet `packaging` fuer korrekte Semver-Vergleiche.
packaging ist eine Python-Stdlib-nahe Bibliothek (Bestandteil von pip).

Schichtzugehoerigkeit: domain/ — kein GUI, keine DB, kein Netzwerk.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from tools.dependency_auditor.domain.models import (
    DependencyAuditResult,
    DependencyInfo,
    VulnerabilityInfo,
)


def is_version_affected(pinned_version: str, affected_spec: str) -> bool | None:
    """Prueft ob eine gepinnte Version in den affected-Bereich faellt.

    Verwendet packaging.version fuer korrekte Semver-Vergleiche.

    Behandelt zwei Formate:
    - Bereichs-Spec: ``">=2.0,<2.32"`` (Standard-PEP-440, AND-Semantik)
    - Versions-Liste: ``"==2.0.0,==2.1.0"`` (OR-Semantik — explizite Betroffene)

    Tri-State Drop-Gate-Fix): Nicht-auswertbare Eingaben liefern
    ``None`` statt ``False`` — der Aufrufer entscheidet, wie er damit
    umgeht. Vorher fielen OSV-Treffer mit Spec ``"unbekannt"`` oder
    ungueltigem Range still aus der Meldung (fail-open).

    Args:
        pinned_version: Exakte Version (z. B. ``"2.31.0"``).
        affected_spec: Versionsbereich im PEP-440-Format
                        (z. B. ``">=2.0,<2.32"``).

    Returns:
        True wenn die Version nachweislich betroffen ist.
        False wenn die Version nachweislich NICHT betroffen ist.
        None wenn der Abgleich nicht auswertbar ist (leere Eingaben,
        Spec ``"unbekannt"``, ungueltige Version oder ungueltiger Spec —
        z. B. GIT-Commit-Ranges aus OSV).
    """
    if not pinned_version or not affected_spec or affected_spec == "unbekannt":
        return None
    try:
        ver = Version(pinned_version)
        # Explizite Versions-Liste (nur == Operatoren) → OR-Semantik
        # Beispiel: "==2.0.0,==2.1.0,==2.31.0" → betroffen wenn Version eine davon
        parts = [s.strip() for s in affected_spec.split(",") if s.strip()]
        if parts and all(p.startswith("==") for p in parts):
            return any(ver in SpecifierSet(p) for p in parts)
        # Standard-Bereichs-Spec (AND-Semantik): ">=2.0,<2.32"
        spec = SpecifierSet(affected_spec)
        return ver in spec
    except (InvalidVersion, InvalidSpecifier):
        return None


def analyze_dependencies(
    dependencies: list[DependencyInfo],
    vulnerabilities: dict[str, list[VulnerabilityInfo]],
) -> DependencyAuditResult:
    """Matcht Dependencies gegen Vulnerabilities und baut das Audit-Ergebnis.

    Fuer jede Dependency wird geprueft:
    1. Ist sie betroffen (effektive Version im affected-Bereich)?
       Effektive Version = ``version_pinned`` vor ``version_installed``
,:meth:`DependencyInfo.effective_version`).
    2. Ist sie unpinned?
    3. Ist gar keine Version ermittelbar? Dann landen ihre Advisories in
       der eigenen Kategorie „Version unbekannt"
       (``unverified_vulnerabilities``) statt als Voll-Severity-Treffer.

    Drop-Gate-Regel: Liegt eine effektive Version vor, wurde die
    OSV-Abfrage bereits MIT dieser Version gestellt — die Server-Antwort
    ist nach Betroffenheit gefiltert und damit autoritativ. Das lokale
    Matching via:func:`is_version_affected` ist nur eine Verfeinerung:
    Es darf Treffer entfernen (``False``), aber ein nicht-auswertbarer
    Abgleich (``None`` — Spec „unbekannt", GIT-Range, ungueltige Spec)
    zaehlt als BETROFFEN, sonst verschwinden server-bestaetigte
    Advisories still (fail-open).

    Args:
        dependencies: Geparste Dependencies aus requirements.txt.
        vulnerabilities: Map Package-Name (lowercase) →
                         Liste der abgefragten VulnerabilityInfo.
                         Vorbedingung: mit der effektiven Version der
                         jeweiligen Dependency abgefragt (so wie
                         ``AuditService._run_audit`` es tut).

    Returns:
        DependencyAuditResult mit allen gefundenen Befunden.
    """
    matched_vulns: list[VulnerabilityInfo] = []
    unverified_vulns: list[VulnerabilityInfo] = []
    unpinned: list[DependencyInfo] = []
    unverified_deps: list[DependencyInfo] = []

    for dep in dependencies:
        name_lower = dep.name.lower()
        vulns_for_pkg = vulnerabilities.get(name_lower, [])

        if dep.version_pinned is None:
            unpinned.append(dep)

        effective = dep.effective_version()
        if effective is None:
            # Kein Pin, keine installierte Version → Abgleich nicht moeglich.
            # Advisories getrennt fuehren statt alle als betroffen zu melden.
            if vulns_for_pkg:
                unverified_deps.append(dep)
                unverified_vulns.extend(vulns_for_pkg)
            continue

        for vuln in vulns_for_pkg:
            # None (nicht auswertbar) => betroffen: Die OSV-Antwort wurde
            # mit der effektiven Version abgefragt und ist autoritativ —
            # nur ein eindeutiges False darf den Treffer verwerfen.
            if is_version_affected(effective, vuln.affected_versions) is not False:
                matched_vulns.append(vuln)

    # Severity-Zusammenfassung — nur versions-verifizierte Treffer
    sev_summary: dict[str, int] = {}
    for v in matched_vulns:
        key = v.severity.value
        sev_summary[key] = sev_summary.get(key, 0) + 1

    return DependencyAuditResult(
        source_file="",
        scan_timestamp=datetime.now(UTC).isoformat(),
        total_dependencies=len(dependencies),
        total_vulnerabilities=len(matched_vulns),
        dependencies=list(dependencies),
        vulnerabilities=sorted(matched_vulns, key=lambda v: v.severity.sort_order()),
        unpinned_dependencies=unpinned,
        unverified_vulnerabilities=sorted(
            unverified_vulns, key=lambda v: v.severity.sort_order()
        ),
        unverified_dependencies=unverified_deps,
        severity_summary=sev_summary,
    )
