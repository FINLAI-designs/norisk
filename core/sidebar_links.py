"""
sidebar_links — Datenquellen-Aggregation fuer die "Wichtige Links"-Gruppe.

Sprint 5 Phase 4: Auslagerung der Link-Lade-Logik aus dem
God-File ``core/sidebar.py``. Die Lade-Logik kombiniert drei Quellen
(Session, AppConfig, LinksRepository, curated_links bzw. link_profile)
und ist deutlich besser als reine Datenschicht testbar als als
verschachtelte Methode in ``SidebarWidget``.

Diese Datei ist bewusst **PySide6-frei** — nur Dataclass + Funktion mit
``logging``. Die Widget-Erstellung passiert weiter in
:meth:`core.sidebar.SidebarWidget._populate_links_group`.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

_log = logging.getLogger("finlai.sidebar_links")


@dataclass
class LinkSpec:
    """Einheitliches Datenformat fuer einen Sidebar-Link-Eintrag.

    Vereinheitlicht die zwei Quellen-Modelle ``CuratedLink`` (Modul
:mod:`core.curated_links`) und ``UserLink`` (Modul
:mod:`core.links_repository`) in eine flache Struktur, mit der der
    Sidebar-Builder direkt arbeiten kann.

    Attributes:
        key: Eindeutiger Sidebar-Schluessel (z. B. ``"link:curated:0"``,
            ``"link:user:3"``). Wird vom Click-Handler zur Identifikation
            verwendet.
        label: Anzeigetext.
        icon: Material-Symbol-Name oder Emoji-String. Der Builder
            entscheidet anhand des Inhalts ob ``get_icon`` gerufen wird.
        url: Ziel-URL — wird vom Click-Handler im Browser geoeffnet.
        category: Gruppierungsbegriff fuer Subheader in der Sidebar. Aus:attr:`CuratedLink.category` bzw.
            ``"Eigene Links"`` fuer benutzereigene Eintraege. Leer-
            String erzeugt keinen Subheader (Backwards-Compat).
    """

    key: str
    label: str
    icon: str
    url: str
    category: str = ""


def load_sidebar_links(groups: list[dict], links_repo) -> list[LinkSpec]:
    """Aggregiert curated + user-defined Links zu einer LinkSpec-Liste.

    Reihenfolge: erst alle curated Links (entweder aus dem konfigurierten
    Link-Profil oder aus:mod:`core.curated_links`), dann alle user-
    definierten Links aus dem ``LinksRepository``.

    Args:
        groups: ``AppConfig.sidebar_groups`` -- wird nach einem Eintrag
            mit ``key=="links"`` durchsucht; dessen optionales
            ``links_profile``-Feld bestimmt das geladene Curated-Profil.
        links_repo: ``LinksRepository``-Instanz fuer User-Links. Wird
            via ``links_repo.lade(user_id, app_id=app_id)`` aufgerufen.

    Returns:
        Geordnete Liste von ``LinkSpec``. Leer wenn beide Quellen leer
        sind oder Fehler werfen — geworfene Exceptions werden geloggt
        und schlucken die jeweilige Quelle (Sidebar darf nicht crashen).
    """
    # User-Identifikation aus aktiver Session
    from .auth.session import Session  # noqa: PLC0415

    user = Session().current_user
    user_id = user.username if user else "_default"

    # AppId aus aktiver AppConfig (Default: "finlai")
    app_id = "finlai"
    try:
        from apps.app_config import get_active_config  # noqa: PLC0415

        cfg = get_active_config()
        if cfg is not None:
            app_id = cfg.app_id
    except (ImportError, OSError, AttributeError):
        _log.exception("AppConfig konnte nicht geladen werden")

    # User-Links via Repository
    user_links: list = []
    try:
        user_links = links_repo.lade(user_id, app_id=app_id)
    except (OSError, RuntimeError):
        _log.exception("Fehler beim Laden der User-Links fuer '%s'", user_id)

    # Curated-Links: links_profile aus Sidebar-Config hat Vorrang vor
    # dem App-Default in curated_links.py.
    links_profile: str | None = None
    for grp_cfg in groups:
        if grp_cfg.get("key") == "links":
            links_profile = grp_cfg.get("links_profile")
            break

    curated: list = []
    try:
        if links_profile:
            from core.link_profile_loader import load_link_profile  # noqa: PLC0415

            curated = load_link_profile(links_profile)
        else:
            from core.curated_links import get_curated_links  # noqa: PLC0415

            curated = get_curated_links(app_id)
    except (ImportError, OSError, ValueError):
        _log.exception("Fehler beim Laden der kuratierten Links")

    specs: list[LinkSpec] = []
    for i, lnk in enumerate(curated):
        specs.append(
            LinkSpec(
                key=f"link:curated:{i}",
                label=lnk.title,
                icon=lnk.icon,
                url=lnk.url,
                category=getattr(lnk, "category", "") or "",
            )
        )
    for i, lnk in enumerate(user_links):
        specs.append(
            LinkSpec(
                key=f"link:user:{i}",
                label=lnk.label,
                icon=lnk.icon,
                url=lnk.url,
                category="Eigene Links",
            )
        )
    return specs
