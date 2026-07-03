"""
escape — Zentrale Output-Encoding-Hilfe für markup-interpretierende Senken.

 / (escape-at-render): Persistierte Daten sind Klartext;
JEDE Senke, die Markup interpretiert, escaped selbst unmittelbar vor dem
Rendern. Das betrifft zwei Senken-Familien mit identischer Zeichenmenge:

* **Qt-RichText** (``QLabel`` mit ``setTextFormat(RichText)`` bzw.
  Auto-RichText, Tooltips) — Coding-Rule R22.
* **ReportLab-``Paragraph``** (parst XML-Markup; ein rohes ``<`` führt zu
  Parse-Fehlern oder Markup-Injektion).

Wann NICHT escapen: Wenn das Widget den Text gar nicht interpretiert —
``setTextFormat(Qt.TextFormat.PlainText)`` ist für reine Text-Labels die
robustere Wahl (kein Escaping nötig, kein Doppel-Escape-Risiko).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import html


def escape_html(value: object) -> str:
    """Escaped einen Wert für HTML-/XML-Kontexte (Qt-RichText, ReportLab).

    Ersetzt ``& < > " '`` durch ihre Entities. Bewusst NICHT idempotent —
    doppeltes Escapen macht den Fehler sichtbar (``&amp;amp;``), statt ihn
    zu verstecken. Genau einmal anwenden: unmittelbar an der Render-Stelle.

    Args:
        value: Roh-Wert (Klartext aus DB, Scan-Ergebnis, User-Eingabe);
            Nicht-Strings werden via ``str`` konvertiert.

    Returns:
        Markup-sicherer Text für RichText-/Paragraph-Kontexte.
    """
    return html.escape(str(value), quote=True)


def unescape_legacy_html(value: str) -> str:
    """Macht das frühere Persist-HTML-Escaping rückgängig (NUR Migration).

    Bis escapten Persist-Pfade Freitexte beim Speichern
    (``sanitize_text`` in customer_audit). Diese Inverse wird ausschließlich
    von den einmaligen Daten-Migrationen ``t315_*`` genutzt — im
    Produktiv-Pfad NICHT verwenden. Die Ersetzungen laufen in
    umgekehrter Reihenfolge zum früheren Escape — ``&amp;`` zuletzt, sonst
    würde ``&amp;lt;`` fälschlich zu ``<`` statt ``&lt;``.

    Args:
        value: Mit dem Alt-Verhalten escapter Text.

    Returns:
        Der ursprüngliche Klartext.
    """
    return (
        value.replace("&#x27;", "'")
        .replace("&quot;", '"')
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
    )
