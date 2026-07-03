"""core.scan_prefill.resolver — Lazy-Resolver auf die ScanDataPort-Impl.

Der **einzige** Punkt im Codebestand, der die konkrete (security_scoring-)
:class:`ScanDataPort`-Implementierung referenziert. Konsumenten
(``customer_audit``-SELF-Wizard) importieren ausschließlich diesen core-Resolver
(tools→core, import-linter-konform) und bekommen die Implementierung als
:class:`ScanDataPort`-Port geliefert — kein tool→tool-Import §3.2 /
). Identisches Hausmuster wie
:func:`core.security_subject.resolver.create_subject_store`.

Schichtzugehörigkeit: core/ — der ``tools``-Import läuft bewusst **lazy**
innerhalb der Funktion, damit keine statische ``core → tools``-Kante entsteht
(die eine bewusste Lazy-Kante ist in der import-linter-Baseline hinterlegt,
).

Author: Patrick Riederich
Version: 1.0 Phase 2, 2026-06-27)
"""

from __future__ import annotations

from core.logger import get_logger
from core.scan_prefill.ports import ScanDataPort

log = get_logger(__name__)


def create_scan_data_provider() -> ScanDataPort | None:
    """Liefert die konkrete:class:`ScanDataPort`-Implementierung (fail-soft).

    Returns:
        Einsatzbereiter Provider oder ``None``, wenn die Implementierung nicht
        ladbar bzw. das zugrunde liegende Wiring nicht initialisierbar ist
        (z. B. fehlender SQLCipher-Schlüssel). Die Fehlerbehandlung bleibt
        fail-soft beim Aufrufer (z. B. „Auto-Vorbefüllung deaktiviert").
    """
    try:
        # Lazy import: hält core frei von einer statischen tools-Abhängigkeit.
        from tools.security_scoring.application.scan_prefill_provider import (  # noqa: PLC0415
            create_default_scan_prefill_provider,
        )

        return create_default_scan_prefill_provider()
    except Exception as exc:  # noqa: BLE001 — fail-soft Cross-Tool-Resolver-Grenze
        # warning statt info: eine degradierte Auto-Vorbefüllung soll sichtbar
        # sein. Broad except bleibt bewusst (Cross-Tool-Grenze, Hausmuster
        # security_subject.resolver) — es darf den Konsumenten nie crashen.
        log.warning(
            "ScanDataProvider nicht verfuegbar (%s) — Audit-Vorbefuellung "
            "fail-soft deaktiviert.",
            type(exc).__name__,
        )
        return None
