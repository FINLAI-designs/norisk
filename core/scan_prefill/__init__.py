"""core.scan_prefill — Gemessene Audit-Vorbefüllung.

Tool-übergreifende Brücke, über die ``security_scoring`` **gemessene**
Hardening-/Netzwerk-/OS-Werte (mit Herkunft) an den ``customer_audit``-SELF-
Wizard liefert, ohne dass ein Tool das andere importiert. Die
zwei Score-Dimensionen bleiben getrennt: dieser Pfad trägt ausschließlich
``measured``-Daten, die Fragebogen-Antwort bleibt ``self_declared``.

Bestandteile:

*:class:`AuditPrefill` /:class:`MeasuredField` — die transienten DTOs (models).
*:class:`ScanDataPort` — der Port-Vertrag (ports).
*:func:`core.scan_prefill.resolver.create_scan_data_provider` — der lazy
  Resolver auf die security_scoring-Implementierung.

Schichtzugehörigkeit: core/ — reine Modelle + Port, keine I/O.

Author: Patrick Riederich
Version: 1.0 Phase 2, 2026-06-27)
"""

from __future__ import annotations

from core.scan_prefill.models import AuditPrefill, MeasuredField
from core.scan_prefill.ports import ScanDataPort

__all__ = ["AuditPrefill", "MeasuredField", "ScanDataPort"]
