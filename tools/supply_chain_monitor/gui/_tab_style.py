"""
_tab_style — Gemeinsame Theme-Tokens fuer Supply-Chain-Monitor-Tabs.

Iter Bug-Fix-Sprint (2026-05-16 Smoke-Findings): Vor dieser Datei
hatten die AVV/Subprocessor-Tabs nur ObjectNames ohne QSS-Regeln, weshalb
sie als weisser-Schrift-auf-schwarz erschienen. Hier definieren wir einen
gemeinsamen Stylesheet-Block, der ueber alle Tabs des Tools angewendet
wird — Section-Header-Titel, gedaempfte Info-Texte, Card-Look fuer
Banner und Empty-Hint-Hinweise.

Schichtzugehoerigkeit: gui/ — darf core/theme importieren.

Author: Patrick Riederich
Version: 0.1 (Bug-Fix 2026-05-16)
"""

from __future__ import annotations

from core import theme


def supply_chain_tab_stylesheet() -> str:
    """Liefert einen Stylesheet-String fuer die Supply-Chain-Tabs.

    Der String enthaelt Regeln fuer mehrere ObjectName-Selektoren, die in
    AvvTabView + SubprocessorTabView gleichermassen verwendet werden:

    - ``SupplyChainSectionTitle`` — Section-Header (16 px, SemiBold,
      Akzent-Farbe).
    - ``SupplyChainSectionInfo`` — Body-Info-Text (13 px, TEXT_DIM,
      Zeilenhoehe).
    - ``SupplyChainCard`` — Card-Frame mit Hintergrund + Padding +
      Border-Radius (analog Renewal-Banner aus 3b).
    - ``SupplyChainCardTitle`` / ``SupplyChainCardBody`` — Typografie
      innerhalb von Cards.
    - ``SupplyChainEmptyHint`` — Zentrierter Hint-Text in einer
      gedaempften Card.

    Returns:
        Stylesheet-String fuer ``widget.setStyleSheet``.
    """
    c = theme.get()
    return f"""
    /* Section-Header oben in einem Tab */
    QLabel#SupplyChainSectionTitle {{
        font-family: "Raleway", "Segoe UI", sans-serif;
        font-size: 16px;
        font-weight: 600;
        color: {c.ACCENT};
        padding: 0px 0px 4px 0px;
    }}

    /* Info-Text unter dem Section-Header — gedaempfter Body */
    QLabel#SupplyChainSectionInfo,
    QLabel#AvvTabInfo,
    QLabel#SubprocessorTabInfo {{
        color: {c.TEXT_DIM};
        font-size: 13px;
        line-height: 1.45;
        padding: 0px 0px 6px 0px;
    }}

    /* Card — Hintergrund, Padding, Rand */
    QFrame#SupplyChainCard,
    QFrame#AvvRenewalBannerCard,
    QFrame#SubprocessorConcentrationCard {{
        background-color: {c.CARD_BG};
        border: 1px solid {theme.DARK_BORDER};
        border-radius: 6px;
        padding: 10px 14px;
    }}

    QLabel#SupplyChainCardTitle {{
        font-family: "Raleway", "Segoe UI", sans-serif;
        font-size: 13px;
        font-weight: 600;
        color: {c.TEXT_MAIN};
    }}

    QLabel#SupplyChainCardBody,
    QLabel#AvvRenewalBanner,
    QLabel#SubprocessorConcentrationBanner {{
        color: {c.TEXT_DIM};
        font-size: 13px;
        padding: 6px 0px 0px 0px;
    }}

    /* Empty-Hint — zentrierter Hinweis-Text in gedaempfter Card */
    QLabel#SupplyChainEmptyHint,
    QLabel#SubprocessorEmptyHint,
    QLabel#AvvEmptyHint {{
        color: {c.TEXT_DIM};
        font-size: 13px;
        font-style: italic;
        background-color: {c.CARD_BG};
        border: 1px dashed {theme.DARK_BORDER};
        border-radius: 6px;
        padding: 24px 16px;
    }}
    """
