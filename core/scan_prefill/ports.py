"""core.scan_prefill.ports — Port für gemessene Audit-Vorbefüllung.

Definiert den:class:`ScanDataPort`-Vertrag, den ``security_scoring``
implementiert (es hält die Scanner-Wiring-Kette: Hardening-Baseline, Netzwerk-
Scan, OS-Info). Konsumenten (``customer_audit``-SELF-Wizard) typisieren gegen
diesen Port und erhalten die konkrete Implementierung über den lazy Resolver
:func:`core.scan_prefill.resolver.create_scan_data_provider` — kein tool→tool-
Import §3.2 /).

Schichtzugehörigkeit: core/ — reiner Protocol-Vertrag, keine I/O.

Author: Patrick Riederich
Version: 1.0 Phase 2, 2026-06-27)
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.scan_prefill.models import AuditPrefill


@runtime_checkable
class ScanDataPort(Protocol):
    """Vertrag für die Erhebung gemessener Audit-Vorbefüll-Werte.

    Die konkrete Implementierung (security_scoring) erhebt die Mess-Werte über
    die bestehenden headless application-Pfade (``run_hardening_baseline_scan``,
    ``NetworkService.lade_letzte_scans``, ``detect_os_info``) — **ohne Persistenz
    und ohne Score-History-Pollution**. Fehlende/nicht messbare Werte
    liefern ein leeres bzw. teilbefülltes:class:`AuditPrefill` (fail-soft).
    """

    def build_audit_prefill(self) -> AuditPrefill:
        """Erhebt einen frischen Mess-Snapshot als:class:`AuditPrefill`.

        Headless + transient: führt die Messungen aus, persistiert NICHTS und
        gibt die gemessenen Werte mit Herkunft zurück. Nicht messbare Felder
        bleiben ``None`` (kein Prefill).

        Returns:
            Ein:class:`AuditPrefill`; ``has_measurements == False`` wenn nichts
            messbar war (z. B. Non-Windows ohne Netzwerk-Scan).
        """
        ...
