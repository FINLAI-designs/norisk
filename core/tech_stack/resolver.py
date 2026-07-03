"""core.tech_stack.resolver — Lazy-Resolver auf den eigenen Tech-Stack.

Liefert die Namen der im ``security_scoring``-Tool erfassten eigenen Software/
Dienste, OHNE dass der Konsument (``customer_audit``-Souveraenitaets-Scanner)
``security_scoring`` direkt importiert §3.2 /). Identisches
Hausmuster wie:func:`core.scan_prefill.resolver.create_scan_data_provider`.

Greift wie die Schwester-Resolver ueber die **application**-Schicht
(``create_default_manage_profiles_use_case``), nicht direkt auf ``data/`` — die
Datenzugriffs-Details bleiben in ``security_scoring`` gekapselt.

Schichtzugehoerigkeit: core/ — der ``tools``-Import laeuft bewusst **lazy**
innerhalb der Funktion, damit keine statische ``core -> tools``-Kante entsteht
(die eine bewusste Lazy-Kante ist in der import-linter-Baseline hinterlegt,
Contract 5 /).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger

log = get_logger(__name__)


def get_own_tech_stack_names() -> list[str]:
    """Namen der erfassten eigenen Software/Dienste (fail-soft).

    Sammelt die frei eingegebenen bzw. erkannten Dienst-Namen aus dem
    ``SystemProfile.tech_stack`` des eigenen Systems — Felder, die ein Cloud-/
    SaaS-Provider sein koennen: ``custom_software``, ``vpn``, ``remote_access``,
    Browser-Namen, ``server_infra``. (Betriebssysteme/Encryption sind keine
    Provider und bleiben aussen vor.)

    Returns:
        Liste nicht-leerer Namens-Strings zum Abgleich gegen den Provider-
        Catalog. Leere Liste, wenn kein eigenes Profil existiert oder das
        Repository/der Tech-Stack nicht ladbar ist (fail-soft beim Aufrufer).
    """
    try:
        # Lazy import: haelt core frei von einer statischen tools-Abhaengigkeit.
        # Ueber die application-Schicht (Schwester-Resolver-Muster), nicht data/.
        from tools.security_scoring.application.tech_stack.manage_profiles_use_case import (  # noqa: PLC0415
            create_default_manage_profiles_use_case,
        )

        use_case = create_default_manage_profiles_use_case()
        if use_case is None:
            return []
        profile = use_case.get_own_system()
        if profile is None or profile.tech_stack is None:
            return []
        ts = profile.tech_stack
        names: list[str] = list(ts.custom_software)
        if ts.vpn:
            names.append(ts.vpn)
        names.extend(ts.remote_access)
        names.extend(b.name for b in ts.browsers if b.name)
        if ts.server_infra:
            names.append(ts.server_infra)
        return [n for n in (s.strip() for s in names) if n]
    except Exception as exc:  # noqa: BLE001 — fail-soft Cross-Tool-Resolver-Grenze
        log.warning(
            "TechStack nicht verfuegbar (%s) — Sovereignty-Abgleich via "
            "tech_stack uebersprungen.",
            type(exc).__name__,
        )
        return []
