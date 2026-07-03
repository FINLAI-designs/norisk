"""network_monitor.application.game_cdn — Game-/Download-CDN-Domain-Matcher Regel 3).

Kuratierte Liste bekannter Spiele-Publisher-/CDN-Domains (Suffix → Label). Die
Game-CDN-Regel matcht **DNS-Query-Namen** (Hostname, wie in der Spec gefordert)
gegen diese Liste — bewusst domain- statt IP-basiert: Domains sind stabil und
verifizierbar, waehrend die IP-Ranges der Spiele-CDNs auf geteilten CDNs
(Akamai/CloudFront/Cloudflare) liegen und nicht sauber zuordenbar sind.

Pure Logik (``application/``), nur stdlib. User-erweiterbar (spaeter Config).
"""

from __future__ import annotations

from typing import Final

#: Domain-Suffix → CDN-/Publisher-Label. Matcht die Domain selbst und alle
#: Subdomains (Download-CDNs nutzen i.d.R. Subdomains dieser Domains).
GAME_CDN_DOMAINS: Final[dict[str, str]] = {
    # Valve / Steam
    "steampowered.com": "Steam",
    "steamcontent.com": "Steam",
    "steamstatic.com": "Steam",
    "steamserver.net": "Steam",
    # Epic Games
    "epicgames.com": "Epic Games",
    "unrealengine.com": "Epic Games",
    # EA / Origin
    "ea.com": "EA/Origin",
    "origin.com": "EA/Origin",
    # Blizzard / Battle.net
    "battle.net": "Battle.net",
    "blizzard.com": "Battle.net",
    "blzdist.com": "Battle.net",
    # Riot Games
    "riotgames.com": "Riot",
    "riotcdn.net": "Riot",
    # Ubisoft
    "ubisoft.com": "Ubisoft",
    "ubi.com": "Ubisoft",
    # Weitere Stores/Plattformen
    "gog.com": "GOG",
    "xboxlive.com": "Xbox",
}


def match_game_cdn(hostname: str) -> str:
    """Gibt das CDN-/Publisher-Label zurueck, wenn ``hostname`` matcht, sonst ``""``.

    Matcht exakte Domain oder Subdomain (``suffix`` bzw. ``*.suffix``),
    case-insensitiv; ein optionaler End-Punkt (FQDN-Wurzel) wird ignoriert.
    """
    host = hostname.lower().rstrip(".")
    if not host:
        return ""
    for suffix, label in GAME_CDN_DOMAINS.items():
        if host == suffix or host.endswith("." + suffix):
            return label
    return ""
