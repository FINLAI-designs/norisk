"""
core/deeplink_registry.py — zentraler Navigations-/Deep-Link-Contract.

Deklaratives Manifest aller Tool-Deep-Links (Cross-Tool-Navigation mit
vorausgefülltem Wert/Filter). Single Source of Truth statt verstreuter
``hasattr``-Checks und hart kodierter ``if key == "<tool>"``-Zweige im Router.

Ein Deep-Link läuft über genau EINEN Empfangs-Contract: ``navigate_to(key,
**kwargs)`` zeigt das Ziel-Dock und reicht ``kwargs`` an
``widget.apply_navigation(**kwargs)`` durch. Die Registry deklariert, welche
kwargs ein Tool akzeptiert, und übersetzt den getypten Dashboard-Filter-Payload
in den richtigen kwarg.

Cross-App: Diese Registry ist das familienweite Deep-Link-Pattern; der
Inhalt ist app-spezifisch (je Tool-Set), der Mechanismus identisch. Bei
Spiegelung in andere FINLAI-Apps NUR den Inhalt anpassen, nicht den Contract.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

# nav_key -> akzeptierte ``apply_navigation``-kwargs (Name -> Typ).
# Deklaratives Manifest des Deep-Link-Contracts pro Tool.
DEEPLINK_TARGETS: dict[str, dict[str, type]] = {
    "network_scanner": {"target": str},  # IP/Hostname vorbelegen + Scan-Tab
    "api_security": {"url": str},  # API-URL vorbelegen
    "cert_monitor": {"domain": str},  # Domain vorbelegen
    "csaf_advisor": {"cve_id": str},  # CVE-Filter vorbelegen
    # Bewerten-Merge — der Container „Security-Bewertung" akzeptiert
    # ``tab`` (Sub-Tab 'audit'/'score'/'awareness'/'nis2'). Die alten Einzel-Keys
    # (customer_audit/nis2_incidents/security_scoring/awareness_tracker) und
    # 'techstack' biegt der Router per Alias auf diesen Container bzw. den
    # Advisory-Monitor um (core.navigation_mixin._TOOL_ALIASES) — daher kein
    # eigenes 'techstack'-Manifest mehr.
    "security_assessment": {"tab": str},
    # customer_audit BEHALTEN (kein Dock mehr, aber NOETIG): die Cockpit-NIS2-CTA
    # ``open_with_filter('customer_audit', 'nis2')`` validiert ihren Payload gegen
    # dieses Manifest; ``navigate_to`` biegt den Key danach per Alias auf
    # security_assessment + Sub-Tab 'nis2' um. Ohne diesen Eintrag liefe die CTA
    # ohne tab-Payload und landete auf dem Audit- statt NIS2-Tab.
    "customer_audit": {"tab": str},  #/: NIS2-Tab-Vorauswahl (via Alias)
    "file_scanner": {"tab": str},  # 3b: Sub-Tab ('email'/'pdf'/'office')
    # 3c 1b Vision B): Cockpit-interner Deep-Link — der
    # „Alle im Board →"-Sprung des Aufgaben-Snippets klappt im Cockpit
    # (Welcome-Dock) die Kanban-Sektion auf (apply_navigation(section=...)).
    "norisk:dashboard": {"section": str},
    # Cockpit-Inc-2: Status-Kacheln deeplinken mit ``focus``-Filter.
    "patch_monitor": {"focus": str},  # focus='outdated' -> Updates-verfuegbar-Filter
    "supply_chain_monitor": {"focus": str},  # focus='open' -> AVV-Tracker
    "password_checker": {"focus": str},  # focus='check' -> Eingabe-Fokus
}

# nav_key -> kwarg-Name, in den ein Dashboard-Filter-Payload übersetzt wird
# (``open_with_filter(key, payload)`` -> ``navigate_to(key, <kwarg>=payload)``).
# None/fehlend = Tool nimmt keinen Dashboard-Filter-Payload entgegen (nur öffnen).
_DASHBOARD_FILTER_KWARG: dict[str, str] = {
    "csaf_advisor": "cve_id",
    #/: Dashboard-NIS2-CTA -> tab='nis2'-Payload; Router aliast
    # customer_audit danach auf den Bewerten-Container (security_assessment).
    "customer_audit": "tab",
    # 3c 1b: TaskSnippet ``board_requested`` -> Cockpit-Kanban aufklappen.
    "norisk:dashboard": "section",
    # Cockpit-Inc-2: Status-Kachel-Filter-Payload -> ``focus``-kwarg.
    "patch_monitor": "focus",
    "supply_chain_monitor": "focus",
    "password_checker": "focus",
}


def accepted_kwargs(nav_key: str) -> dict[str, type]:
    """Gibt die erlaubten ``apply_navigation``-kwargs für ein Tool zurück.

    Args:
        nav_key: Navigationsschlüssel (z. B. ``"csaf_advisor"``).

    Returns:
        Mapping kwarg-Name -> Typ; leeres Dict, wenn das Tool keine
        Deep-Link-Parameter akzeptiert.
    """
    return DEEPLINK_TARGETS.get(nav_key, {})


def dashboard_filter_kwarg(nav_key: str) -> str | None:
    """Gibt den kwarg-Namen für den Dashboard-Filter-Payload zurück.

    Args:
        nav_key: Navigationsschlüssel des Ziel-Tools.

    Returns:
        kwarg-Name (z. B. ``"cve_id"``) oder ``None``, wenn das Tool keinen
        Dashboard-Filter-Payload entgegennimmt (dann nur öffnen).
    """
    return _DASHBOARD_FILTER_KWARG.get(nav_key)
