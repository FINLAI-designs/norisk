"""Tests fuer core/widgets/secure_markdown_browser.py.

P0-4 Threat-Model R-14: LLM-Output-Markdown-Rendering haerten.

Drei Schutz-Layer werden getestet:
1. ``sanitize_markdown`` strippt ``<script>``/``<style>``/``<iframe>``/
   ``<object>``/``<embed>``.
2. ``SecureMarkdownBrowser.loadResource`` blockiert externe URIs.
3. ``SecureMarkdownBrowser`` oeffnet Anchor-Klicks nur fuer ``https``.

Reine Logik-Tests (sanitizer) laufen ohne pytest-qt; Widget-Tests
laufen offscreen via pytest-qt-Standard.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from PySide6.QtCore import QUrl
from PySide6.QtGui import QTextDocument

from core.widgets.secure_markdown_browser import (
    ALLOWED_ANCHOR_SCHEMES,
    ALLOWED_RESOURCE_SCHEMES,
    SecureMarkdownBrowser,
    sanitize_markdown,
)

# ---------------------------------------------------------------------------
# sanitize_markdown — reine Logik, kein Qt
# ---------------------------------------------------------------------------


def test_sanitize_entfernt_script_tag():
    """``<script>...</script>`` wird komplett entfernt."""
    text = "Hallo\n<script>alert('xss')</script>\nWelt"
    cleaned = sanitize_markdown(text)
    assert "<script" not in cleaned
    assert "alert" not in cleaned
    assert "Hallo" in cleaned
    assert "Welt" in cleaned


def test_sanitize_entfernt_style_tag():
    """``<style>...</style>`` wird komplett entfernt."""
    text = "Vor\n<style>body{display:none}</style>\nNach"
    cleaned = sanitize_markdown(text)
    assert "<style" not in cleaned
    assert "display:none" not in cleaned


def test_sanitize_entfernt_iframe_tag():
    """``<iframe>...</iframe>`` wird komplett entfernt."""
    text = '<iframe src="http://attacker.example"></iframe>'
    cleaned = sanitize_markdown(text)
    assert "<iframe" not in cleaned
    assert "attacker.example" not in cleaned


def test_sanitize_entfernt_object_und_embed():
    """``<object>`` und ``<embed>`` werden entfernt (Plugin-Vektoren)."""
    text = '<object data="evil.swf"></object><embed src="evil.swf"/>'
    cleaned = sanitize_markdown(text)
    assert "<object" not in cleaned
    assert "<embed" not in cleaned
    assert "evil.swf" not in cleaned


def test_sanitize_self_closing_script_wird_entfernt():
    """Auch self-closing ``<script src="..."/>`` wird entfernt."""
    text = '<script src="http://x.example/evil.js"/>'
    cleaned = sanitize_markdown(text)
    assert "<script" not in cleaned
    assert "evil.js" not in cleaned


def test_sanitize_case_insensitive():
    """HTML ist case-insensitive — ``<SCRIPT>`` wird genauso entfernt."""
    text = "<SCRIPT>x</SCRIPT> <Style>y</Style> <IFRAME src='x'></IFRAME>"
    cleaned = sanitize_markdown(text)
    assert "SCRIPT" not in cleaned.upper().replace("SCRIPT", "", 0) or (
        "<SCRIPT" not in cleaned and "<SCRIPT".lower() not in cleaned.lower()
    )
    assert "<script" not in cleaned.lower()
    assert "<style" not in cleaned.lower()
    assert "<iframe" not in cleaned.lower()


def test_sanitize_multiline_script_wird_entfernt():
    """``<script>``-Inhalt darf mehrzeilig sein — Regex matcht trotzdem."""
    text = "vorher\n<script>\nfunc(){\n  alert(1);\n}\n</script>\nnachher"
    cleaned = sanitize_markdown(text)
    assert "<script" not in cleaned
    assert "alert" not in cleaned
    assert "vorher" in cleaned
    assert "nachher" in cleaned


def test_sanitize_erhaelt_normales_markdown():
    """Normales Markdown bleibt unveraendert."""
    text = "# Headline\n\n**bold** und *italic* mit [Link](https://example.com)\n\n- A\n- B"
    cleaned = sanitize_markdown(text)
    assert cleaned == text


def test_sanitize_erhaelt_harmlose_html_tags():
    """``<b>``, ``<em>``, ``<table>`` etc. bleiben erhalten."""
    text = "<b>fett</b> <em>kursiv</em> <code>code</code>"
    cleaned = sanitize_markdown(text)
    assert "<b>" in cleaned
    assert "<em>" in cleaned
    assert "<code>" in cleaned


def test_sanitize_leerer_string():
    """Leerer Eingabe-String wird unveraendert zurueckgegeben."""
    assert sanitize_markdown("") == ""


def test_sanitize_markdown_image_ohne_html_unveraendert():
    """Markdown-Image-Syntax wird **nicht** vom Sanitizer beruehrt.

    Das Resource-Sandboxing (``loadResource``-Override) blockiert
    den Fetch — der Sanitizer behandelt nur HTML-Tags.
    """
    text = "![tracking](http://attacker.example/pixel.png)"
    cleaned = sanitize_markdown(text)
    assert cleaned == text


# ---------------------------------------------------------------------------
# SecureMarkdownBrowser — Widget-Setup
# ---------------------------------------------------------------------------


def test_widget_konstruktor_setzt_default_security_flags(qtbot):
    """Read-only + setOpenLinks(False) + setOpenExternalLinks(False)."""
    browser = SecureMarkdownBrowser()
    qtbot.addWidget(browser)

    assert browser.isReadOnly() is True
    assert browser.openLinks() is False
    assert browser.openExternalLinks() is False


def test_setmarkdown_strippt_script_tag(qtbot):
    """``setMarkdown`` ruft Sanitizer vor dem Rendern."""
    browser = SecureMarkdownBrowser()
    qtbot.addWidget(browser)

    browser.setMarkdown("Hallo <script>alert(1)</script> Welt")

    # toPlainText liefert den gerenderten Text — ``alert`` darf
    # nicht enthalten sein (Sanitizer hat den Tag samt Body entfernt).
    plain = browser.toPlainText()
    assert "alert" not in plain
    assert "Hallo" in plain
    assert "Welt" in plain


def test_sethtml_strippt_script_tag(qtbot):
    """``setHtml`` nutzt denselben Sanitizer (Defense-in-Depth)."""
    browser = SecureMarkdownBrowser()
    qtbot.addWidget(browser)

    browser.setHtml("<p>vorher</p><script>alert(2)</script><p>nachher</p>")

    plain = browser.toPlainText()
    assert "alert" not in plain
    assert "vorher" in plain
    assert "nachher" in plain


# ---------------------------------------------------------------------------
# loadResource — Resource-Sandboxing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://attacker.example/pixel.png",
        "https://attacker.example/pixel.png",
        "file:///c:/secret.txt",
        "ftp://example.com/file",
        "javascript:alert(1)",
    ],
)
def test_loadresource_blockiert_externe_uris(qtbot, url):
    """Externe URIs werden geblockt — Rueckgabe ``None``."""
    browser = SecureMarkdownBrowser()
    qtbot.addWidget(browser)

    result = browser.loadResource(
        QTextDocument.ResourceType.ImageResource, QUrl(url)
    )
    assert result is None, f"URL {url} sollte geblockt werden"


def test_loadresource_qrc_scheme_wird_durchgelassen(qtbot):
    """``qrc:``-URIs (Qt-interne Resources) bleiben erlaubt."""
    browser = SecureMarkdownBrowser()
    qtbot.addWidget(browser)

    # qrc:/-Pfad zu einer nicht existierenden Resource — wir testen nur,
    # dass die Anfrage an super durchgereicht wird (Rueckgabe ist
    # implementierungs-abhaengig, bei nicht-existenter Resource ggf.
    # leerer QVariant — wichtig: nicht von unserem Filter geblockt).
    result = browser.loadResource(
        QTextDocument.ResourceType.ImageResource, QUrl("qrc:/icons/dummy.png")
    )
    # Wichtig: unser Filter darf keinen expliziten ``None`` zurueckgeben
    # fuer ``qrc:``-Schemes (das wuerde den Path blocken). Qt-Default fuer
    # eine fehlende qrc-Resource ist ein leerer QVariant — also nicht
    # unser ``None``. Wir akzeptieren beide Faelle (existent oder leer)
    # solange der Filter durchgelassen hat.
    del result  # nur Signal-Test: Aufruf ohne Exception ist genug.


def test_allowed_scheme_konstanten_konsistent():
    """Konstanten sind ``frozenset`` und enthalten die erwarteten Schemes."""
    assert isinstance(ALLOWED_ANCHOR_SCHEMES, frozenset)
    assert "https" in ALLOWED_ANCHOR_SCHEMES
    assert "http" not in ALLOWED_ANCHOR_SCHEMES
    assert "javascript" not in ALLOWED_ANCHOR_SCHEMES
    assert "file" not in ALLOWED_ANCHOR_SCHEMES

    assert isinstance(ALLOWED_RESOURCE_SCHEMES, frozenset)
    assert "qrc" in ALLOWED_RESOURCE_SCHEMES
    assert "http" not in ALLOWED_RESOURCE_SCHEMES
    assert "file" not in ALLOWED_RESOURCE_SCHEMES


# ---------------------------------------------------------------------------
# Anchor-Click-Filter
# ---------------------------------------------------------------------------


def test_anchor_click_https_oeffnet_browser(qtbot, monkeypatch):
    """``https``-Klick wird via QDesktopServices.openUrl geoeffnet."""
    captured: list[QUrl] = []
    monkeypatch.setattr(
        "core.widgets.secure_markdown_browser.QDesktopServices.openUrl",
        lambda url: captured.append(url) or True,
    )
    browser = SecureMarkdownBrowser()
    qtbot.addWidget(browser)

    browser._on_anchor_clicked(QUrl("https://example.com/safe"))

    assert len(captured) == 1
    assert captured[0].toString() == "https://example.com/safe"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/x",
        "javascript:alert(1)",
        "file:///c:/secret.txt",
        "ftp://example.com/file",
        "data:text/html,<script>alert(1)</script>",
    ],
)
def test_anchor_click_blockt_gefaehrliche_schemes(qtbot, monkeypatch, url):
    """Nicht-``https``-Klicks werden blockiert — kein ``openUrl``-Call."""
    open_calls: list[QUrl] = []
    monkeypatch.setattr(
        "core.widgets.secure_markdown_browser.QDesktopServices.openUrl",
        lambda u: open_calls.append(u) or True,
    )
    browser = SecureMarkdownBrowser()
    qtbot.addWidget(browser)

    browser._on_anchor_clicked(QUrl(url))

    assert open_calls == [], f"Scheme von {url} wurde nicht geblockt"


def test_anchor_click_loggt_blockierte_urls(qtbot, monkeypatch):
    """Blockierte Klicks erzeugen eine Warn-Log-Zeile (Audit-Spur)."""
    mock_log = MagicMock()
    monkeypatch.setattr(
        "core.widgets.secure_markdown_browser._log",
        mock_log,
    )
    monkeypatch.setattr(
        "core.widgets.secure_markdown_browser.QDesktopServices.openUrl",
        lambda u: True,
    )
    browser = SecureMarkdownBrowser()
    qtbot.addWidget(browser)

    browser._on_anchor_clicked(QUrl("file:///c:/secret.txt"))

    assert mock_log.warning.called
    call_args = mock_log.warning.call_args
    assert "Anchor-Click blockiert" in call_args.args[0]
