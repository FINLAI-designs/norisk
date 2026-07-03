"""
mode_gate — Use-Case-Invariante: Kunden-Audit ohne Eigenscan.

Ein Fremd-Audit (:attr:`AuditMode.CUSTOMER`) darf NIE Scan-Daten des eigenen
Beraterrechners enthalten — die Auto-Detektion (Backup-Detektor, DNS-MX-/SPF-/
Software-Scan) läuft auf dem Berater-Rechner, nicht beim Mandanten.

Scope dieser Assertion (Stand Phase 2/3): geprüft werden die
**scan-exklusiven** Felder, die es ausschliesslich aus einer Messung geben kann
— Backup-Detektion (``detection_enabled``/``detected_tools``/
``last_successful_runs``) und Souveränitäts-Scan (``detection_enabled``/
``detected``/``scan_errors``). Diese werden fail-closed auf Use-Case-Ebene
erzwungen (nicht nur in der GUI; vgl. Leitplanke „Assertion auf
Use-Case-Ebene").

NICHT von dieser Assertion abgedeckt sind die **dual-use** Prefill-Felder aus
 Phase 2/3 (Firewall/RDP/Verschlüsselung/OS/Patch/offene-Ports): dieselben
``InfrastructureData``/``NetworkData``-Felder sind im Kunden-Audit auch als
legitime Selbst-Deklaration gültig, daher kann die Domäne „gemessen" nicht von
„deklariert" unterscheiden, solange keine Herkunft mitpersistiert wird. Für diese
Felder ist die GUI die fail-closed Durchsetzung (CUSTOMER → harter Reset in
``InfrastructureStep.set_prefill_available``/``NetworkStep``). Die Schliessung
auch auf Use-Case-Ebene braucht ein ``is_prefilled``-Provenance-Flag durch das
Datenmodell — getrackt als Backlog (S-1, change-impact-review).

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui, keine I/O.

Author: Patrick Riederich
Version: 1.1 Phase 1; Scope-Klarstellung S-1)
"""

from __future__ import annotations

from tools.customer_audit.domain.entities import (
    AuditMode,
    BackupAuditResult,
    SovereigntyAuditResult,
)
from tools.customer_audit.domain.exceptions import AuditModeViolationError


def assert_customer_audit_has_no_scan_data(
    audit_mode: AuditMode,
    backup_audit: BackupAuditResult,
    sovereignty_audit: SovereigntyAuditResult,
) -> None:
    """Stellt sicher, dass ein Kunden-Audit keine Eigenscan-Daten trägt.

    Nur:attr:`AuditMode.SELF` darf gemessene Scan-Daten tragen. Für jeden
    anderen Modus (heute:attr:`AuditMode.CUSTOMER`) müssen die scanner-
    gespeisten Felder leer sein — als fail-safe Default geprüft, damit ein
    künftig ergänzter Modus nicht versehentlich scan-offen ist:

      - Backup-Detektion: ``detection_enabled`` / ``detected_tools`` /
        ``last_successful_runs``
      - Souveränitäts-Scan: ``detection_enabled`` / ``detected`` /
        ``scan_errors``

    Selbst-deklarierte Fragebogen-Angaben (``declared``, eingegebene
    ``domain`` und die daraus abgeleiteten ``rechtshinweise``) bleiben
    ausdrücklich erlaubt — sie stammen nicht aus einem Scan.

    Args:
        audit_mode: Sicht des Audits (SELF vs. CUSTOMER).
        backup_audit: Backup-Audit-Eintrag.
        sovereignty_audit: Datensouveränitäts-Audit-Eintrag.

    Raises:
        AuditModeViolationError: Wenn ``audit_mode`` CUSTOMER ist und Scan-
            Daten vorhanden sind (fail-closed Phase 1).
    """
    if audit_mode is AuditMode.SELF:
        # Nur das Selbst-Audit darf gemessene Scan-Daten tragen. Jeder andere
        # Modus wird geprüft (fail-safe Default für künftige Modi).
        return

    scan_sources: list[str] = []
    if (
        backup_audit.detection_enabled
        or backup_audit.detected_tools
        or backup_audit.last_successful_runs
    ):
        scan_sources.append("Backup-Detektion")
    if (
        sovereignty_audit.detection_enabled
        or sovereignty_audit.detected
        or sovereignty_audit.scan_errors
    ):
        scan_sources.append("Souveränitäts-Scan")

    if scan_sources:
        raise AuditModeViolationError(
            "Ein Kunden-Audit darf keine Eigenscan-Daten enthalten "
            f"({', '.join(scan_sources)}). Die Scanner laufen nicht auf der "
            "Mandanten-Maschine — deaktivieren Sie die automatische Detektion "
            "für ein Fremd-Audit (ADR-038)."
        )
