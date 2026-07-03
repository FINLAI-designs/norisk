"""core.url_guard — Sicheres Oeffnen externer URLs mit Scheme-Whitelist.

Zentrale Mitigation gegen ``file://`` / ``javascript:`` / ``ms-msdt:``
(Follina-Klasse) in nicht-vertrauenswuerdigen Eingaben — insbesondere
URLs aus externen RSS-Feeds. Nur ``http`` und ``https`` werden an den
OS-Default-Handler weitergereicht; alles andere wird mit einer Warnung
im Log abgelehnt.

Hintergrund: Security-Review follow-up P1 (cyber_dashboard) und
 (Phishing-Radar). Die Logik lag vorher privat im
``cyber_dashboard``-Widget; sie ist hier zentralisiert, damit alle
Tools dieselbe gehaertete Funktion nutzen statt sie zu duplizieren.
"""

from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices

from core.logger import get_logger

log = get_logger(__name__)

#: Schemes, die ueber den OS-Default-Handler geoeffnet werden duerfen.
ALLOWED_URL_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def open_external_url(url: str) -> bool:
    """Oeffnet ``url`` im Standard-Browser — nur bei http/https-Scheme.

    Args:
        url: Die zu oeffnende URL (z.B. aus einem RSS-Feed-Item).

    Returns:
        True wenn die URL geoeffnet wurde, False wenn sie leer war oder
        das Scheme nicht in der Whitelist liegt (dann nur Log-Warnung).
    """
    if not url:
        return False
    parsed = QUrl(url)
    scheme = parsed.scheme().lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        log.warning(
            "URL-Open verweigert — Scheme %r nicht in Whitelist (url=%r)",
            scheme,
            url[:120],
        )
        return False
    QDesktopServices.openUrl(parsed)
    return True


__all__ = ["ALLOWED_URL_SCHEMES", "open_external_url"]
