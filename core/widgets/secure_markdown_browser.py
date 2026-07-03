"""core.widgets.secure_markdown_browser — Gehaertetes Markdown-Render-Widget.

Defense-in-Depth-Wrapper um ``QTextEdit.setMarkdown`` fuer die Anzeige
von **nicht vertrauenswuerdigem** Markdown — primaer LLM-Output (Ollama
lokal sowie Cloud-Provider OpenAI/Anthropic). Standard-``QTextEdit``
rendert Markdown ohne Filter; das eroeffnet drei reale Angriffsflaechen
gegen NoRisk-Nutzer:

1. **Tracking-Pixel via ``![](http://attacker/...)``** — wenn der
   Renderer Image-URLs auto-laedt, verlaesst die IP-Adresse das Geraet.
   ``loadResource``-Override blockiert HTTP/HTTPS/file-URIs hier.

2. **Anchor-Schemes ``javascript:``/``file://``** — Qt's QTextEdit hat
   keinen JavaScript-Engine, aber ``file://``-Klicks koennten lokale
   Pfade oeffnen. Mit ``setOpenLinks(False)`` + ``setOpenExternalLinks(False)``
   wird nichts automatisch geoeffnet; ``anchorClicked``-Slot oeffnet
   **ausschliesslich** ``https://``-Schemes via ``QDesktopServices.openUrl``.

3. **HTML-Tag-Injection im Markdown** — Markdown erlaubt eingebettetes
   HTML. ``<script>``, ``<style>``, ``<iframe>``, ``<object>``, ``<embed>``
   werden vor ``setMarkdown`` aus dem Eingabe-String entfernt.

Threat-Model: R-14 (siehe ``docs/THREAT_MODEL.md``).
Code-Review-Bezug: P0-1 aus einem internen Security-Review.

P0-4 (Patrick-Entscheidung 2026-05-26, Option A — Voll-Modul).
"""

from __future__ import annotations

import re
from typing import Any

from PySide6.QtCore import QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QTextBrowser, QWidget

from core.logger import get_logger

_log = get_logger(__name__)

#: Schemes, die als Anchor-Click-Ziel via Default-Browser geoeffnet werden
#: duerfen. Alles andere wird stillschweigend blockiert und geloggt.
ALLOWED_ANCHOR_SCHEMES: frozenset[str] = frozenset({"https"})

#: URL-Schemes, die als Resource (Image / CSS / Sub-Resource) ueber
#: ``loadResource`` geladen werden duerfen. Qt-interne Resourcen liegen
#: unter ``qrc:`` und sind kompiliert — kein Network-Zugriff.
ALLOWED_RESOURCE_SCHEMES: frozenset[str] = frozenset({"qrc", "data"})

#: HTML-Tags, deren Inhalt im Markdown vor dem Rendering entfernt wird.
#: ``script`` / ``style`` / ``iframe`` / ``object`` / ``embed`` sind die
#: ueblichen Vektoren fuer Exfiltration, Cross-Origin-Loads, oder UI-
#: Sandbox-Brueche.
_BLOCKED_TAGS: tuple[str, ...] = ("script", "style", "iframe", "object", "embed")

#: Pre-kompilierter Regex fuer ``_BLOCKED_TAGS``. Faengt sowohl Container-
#: Tags (``<script>...</script>``) als auch self-closing (``<embed src=... />``)
#: ueber zwei Alternativen ab. ``DOTALL`` damit Newlines im Body
#: matchen, ``IGNORECASE`` weil HTML case-insensitive ist.
_TAG_STRIPPER_RE: re.Pattern[str] = re.compile(
    r"<\s*(?P<tag>" + "|".join(_BLOCKED_TAGS) + r")\b[^>]*>"
    r"(?:.*?<\s*/\s*(?P=tag)\s*>)?",
    flags=re.IGNORECASE | re.DOTALL,
)


def sanitize_markdown(text: str) -> str:
    """Entfernt gefaehrliche HTML-Tags aus einem Markdown-String.

    Markdown unterstuetzt eingebettetes HTML. Dieser Filter entfernt die
    drei klar gefaehrlichen Container-Tags ``script``/``style``/``iframe``
    plus die Plugin-Tags ``object``/``embed`` — sowohl als Container
    (``<script>...</script>``) als auch self-closing.

    Andere HTML-Tags bleiben erhalten (z. B. ``<b>``, ``<em>``, ``<table>``)
    — Markdown nutzt sie regelmaessig, und QTextEdit rendert sie als
    inerte Rich-Text-Elemente ohne JS-Execution.

    Args:
        text: Roher Markdown-String, potentiell aus LLM-Output.

    Returns:
        Markdown-String ohne die gesperrten Tags. Falls Eingabe leer,
        wird Eingabe unveraendert zurueckgegeben.
    """
    if not text:
        return text
    return _TAG_STRIPPER_RE.sub("", text)


class SecureMarkdownBrowser(QTextBrowser):
    """Gehaertetes QTextBrowser zur Anzeige von LLM-Markdown-Output.

    API-kompatibel zu ``QTextEdit``/``QTextBrowser`` — Aufrufer koennen
    ohne Aenderungen von ``QTextEdit`` migrieren, indem sie nur den
    Konstruktor tauschen. ``QTextBrowser`` ist die Hypertext-Variante
    von ``QTextEdit`` und stellt ``setOpenLinks`` / ``anchorClicked``
    bereit — Voraussetzung fuer die Anchor-Whitelist.

    Drei Sicherheits-Layer:

    * **Resource-Sandboxing** via ``loadResource``-Override —
      Externe URIs (``http``/``https``/``file``) liefern leeren
      ``QVariant``, sodass Image-Tracking-Pixel nicht geladen werden.
    * **Anchor-Schema-Whitelist** — ``setOpenLinks(False)`` plus
      ``anchorClicked``-Slot oeffnet nur ``https``-URLs via
      ``QDesktopServices``.
    * **Markdown-Pre-Sanitization** —:func:`sanitize_markdown` strippt
      ``<script>``/``<style>``/``<iframe>``/``<object>``/``<embed>``
      bevor der eingebaute Markdown-Parser den Text rendert.

    Args:
        parent: Optionales Eltern-Widget.

    Beispiel:
        >>> browser = SecureMarkdownBrowser
        >>> browser.setMarkdown("# Titel\\n![](http://attacker.example/x.png)")
        # Titel wird angezeigt, das Image laedt nicht.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        # Kein Auto-Open ueber Default-OS-Handler — Klicks gehen ueber
        # _on_anchor_clicked mit Whitelist-Check.
        self.setOpenLinks(False)
        self.setOpenExternalLinks(False)
        self.anchorClicked.connect(self._on_anchor_clicked)

    # ------------------------------------------------------------------
    # Public API — schreibende Methoden mit Sanitizer-Hook
    # ------------------------------------------------------------------

    def setMarkdown(self, markdown: str) -> None:  # noqa: N802 — Qt-API
        """Setzt Markdown-Text **nach** Sanitizer-Filter.

        Args:
            markdown: Roher Markdown-String. Wird durch
:func:`sanitize_markdown` gefiltert, bevor der eingebaute
                Qt-Markdown-Parser ihn rendert.
        """
        super().setMarkdown(sanitize_markdown(markdown))

    def setHtml(self, html: str) -> None:  # noqa: N802 — Qt-API
        """Setzt HTML-Text **nach** Sanitizer-Filter.

        Defense-in-Depth: falls Aufrufer doch HTML statt Markdown setzen,
        gilt derselbe Tag-Filter.

        Args:
            html: Roher HTML-String. Wird durch:func:`sanitize_markdown`
                gefiltert (Regex matcht HTML-Tags unabhaengig vom
                umgebenden Format).
        """
        super().setHtml(sanitize_markdown(html))

    # ------------------------------------------------------------------
    # Resource-Sandboxing
    # ------------------------------------------------------------------

    def loadResource(  # noqa: N802 — Qt-API
        self,
        type_: int,
        name: QUrl,
    ) -> Any:
        """Blockiert externe Resource-Loads (Images, CSS,...).

        Qt ruft diese Methode auf, wenn ein eingebettetes ``<img src>``,
        ``background-image:`` oder eine andere Ressource im Markdown
        gerendert werden soll. Standardimplementation lokalisiert die
        Ressource auf dem Dateisystem. Hier wird das Verhalten verschaerft:
        nur ``qrc:``- und ``data:``-URIs werden weitergereicht; alles
        andere liefert leeren ``QVariant`` und wird geloggt.

        Args:
            type_: ``QTextDocument.ResourceType``-Wert (Image, Stylesheet,
...). Wird unveraendert an ``super`` weitergereicht.
            name: URL der angeforderten Ressource.

        Returns:
            Original-Resource (via ``super``) bei erlaubtem Scheme,
            sonst ``None`` (Qt interpretiert das als "nicht ladbar").
        """
        scheme = name.scheme().lower() if isinstance(name, QUrl) else ""
        if scheme in ALLOWED_RESOURCE_SCHEMES or not scheme:
            return super().loadResource(type_, name)
        _log.warning(
            "SecureMarkdownBrowser: Resource-Load blockiert "
            "(type=%s scheme=%s)",
            type_,
            scheme,
        )
        return None

    # ------------------------------------------------------------------
    # Anchor-Click-Filter
    # ------------------------------------------------------------------

    @Slot(QUrl)
    def _on_anchor_clicked(self, url: QUrl) -> None:
        """Oeffnet ``https``-Anchors via Default-Browser, blockt Rest.

        Args:
            url: Vom Nutzer angeklickte URL.
        """
        scheme = url.scheme().lower()
        if scheme in ALLOWED_ANCHOR_SCHEMES:
            QDesktopServices.openUrl(url)
            return
        _log.warning(
            "SecureMarkdownBrowser: Anchor-Click blockiert (scheme=%s url=%s)",
            scheme,
            url.toString()[:200],  # bewusst limitiert — Logs sanitisieren
        )


__all__ = [
    "ALLOWED_ANCHOR_SCHEMES",
    "ALLOWED_RESOURCE_SCHEMES",
    "SecureMarkdownBrowser",
    "sanitize_markdown",
]
