"""GUI-Tests für die zentralen Seiten-Bausteine AP7).

Lockt die Verträge der nach ``core/widgets`` gehobenen Komponenten ein:

* ToolPage: Titel + Akzentlinie + Body-Layout; HelpPanel nur bei
  registriertem help_key.
* EmptyState: QLabel-Paritäts-API (setText/text), PlainText-Format
  (R22 — kein Auto-RichText für dynamische Teile), CTA-Signal.
* Section: Lift aus ``_DashboardSection`` — Re-Export-Alias bleibt
  identisch, Expand-Verhalten unverändert.

Headless via pytest-qt (offscreen), keine Services nötig.
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QLabel, QPushButton

from core.widgets.empty_state import EmptyState
from core.widgets.section import Section
from core.widgets.tool_page import ToolPage

pytestmark = pytest.mark.gui


# ---------------------------------------------------------------------------
# ToolPage
# ---------------------------------------------------------------------------


def test_tool_page_zeigt_titel_und_body(qtbot, app):  # noqa: ARG001
    """Titel-Label trägt den Seitentitel, Body-Layout ist andockbar."""
    page = ToolPage("Test-Seite")
    qtbot.add_widget(page)

    assert page._title_lbl.text() == "Test-Seite"  # noqa: SLF001
    lbl = QLabel("Inhalt")
    page.body.addWidget(lbl, stretch=1)
    assert page.body.indexOf(lbl) >= 0


def test_tool_page_ohne_help_key_kein_panel(qtbot, app):  # noqa: ARG001
    """Leerer help_key erzeugt kein HelpPanel."""
    page = ToolPage("Ohne Hilfe")
    qtbot.add_widget(page)
    assert page.help_panel is None


def test_tool_page_mit_registriertem_help_key(qtbot, app):  # noqa: ARG001
    """Ein registrierter help_key hängt das HelpPanel in die Seite.

    Die Registry wird im Test explizit befüllt (in der App macht das
    ``launch_app`` → ``init_registry``) und danach auf den vorherigen
    Stand zurückgesetzt — kein Skip, der den HelpPanel-Zweig maskiert.
    """
    from core.help.help_registry import HelpRegistry, init_registry

    snapshot = HelpRegistry.get_all()
    init_registry()
    try:
        page = ToolPage("Mit Hilfe", help_key="password_checker")
        qtbot.add_widget(page)
        assert page.help_panel is not None
    finally:
        HelpRegistry.clear()
        for content in snapshot.values():
            HelpRegistry.register(content)


def test_tool_page_titel_plaintext_und_apply_theme(qtbot, app):  # noqa: ARG001
    """Titel rendert nie als Auto-RichText (R22); apply_theme ist aufrufbar
    für Tools, die in-place restylen (z.B. techstack)."""
    page = ToolPage("Titel <b>mit</b> Markup")
    qtbot.add_widget(page)

    assert page._title_lbl.textFormat() == Qt.TextFormat.PlainText  # noqa: SLF001
    page.apply_theme()
    assert "Raleway" in page._title_lbl.styleSheet()  # noqa: SLF001


# ---------------------------------------------------------------------------
# EmptyState
# ---------------------------------------------------------------------------


def test_empty_state_settext_text_paritaet(qtbot, app):  # noqa: ARG001
    """setText/text verhalten sich wie bei QLabel (Drop-in für _empty_lbl)."""
    es = EmptyState("Noch keine Daten.")
    qtbot.add_widget(es)

    assert es.text() == "Noch keine Daten."
    es.setText("Suche läuft …")
    assert es.text() == "Suche läuft …"


def test_empty_state_rendert_plaintext(qtbot, app):  # noqa: ARG001
    """Dynamische Texte werden nie als Auto-RichText interpretiert (R22)."""
    es = EmptyState("Hinweis")
    qtbot.add_widget(es)
    assert es._message_lbl.textFormat() == Qt.TextFormat.PlainText  # noqa: SLF001


def test_empty_state_ohne_cta_kein_button(qtbot, app):  # noqa: ARG001
    """Leerer cta_text erzeugt keinen Button."""
    es = EmptyState("Nur Text")
    qtbot.add_widget(es)
    assert es.findChildren(QPushButton) == []


def test_empty_state_cta_emittiert_signal(qtbot, app):  # noqa: ARG001
    """Ein Klick auf den CTA-Button feuert cta_clicked."""
    es = EmptyState("Leer", cta_text="Jetzt starten")
    qtbot.add_widget(es)

    buttons = es.findChildren(QPushButton)
    assert len(buttons) == 1
    with qtbot.waitSignal(es.cta_clicked, timeout=1000):
        buttons[0].click()


def test_empty_state_mit_pixmap_zeigt_bild_oberhalb_der_message(qtbot, app):  # noqa: ARG001
    """: Ein übergebenes Pixmap erzeugt ein zentriertes Bild-Label
    OBERHALB der Message (Keyword-Param, Positions-Aufrufer unverändert)."""
    pm = QPixmap(24, 24)
    pm.fill(Qt.GlobalColor.transparent)
    es = EmptyState("Leer", pixmap=pm)
    qtbot.add_widget(es)

    assert es._pixmap_lbl is not None  # noqa: SLF001
    assert not es._pixmap_lbl.pixmap().isNull()  # noqa: SLF001
    lyt = es.layout()
    assert lyt.indexOf(es._pixmap_lbl) < lyt.indexOf(es._message_lbl)  # noqa: SLF001


def test_empty_state_ohne_pixmap_kein_bild_label(qtbot, app):  # noqa: ARG001
    """Ohne Pixmap bleibt das Widget unverändert (kein Bild-Label)."""
    es = EmptyState("Nur Text")
    qtbot.add_widget(es)
    assert es._pixmap_lbl is None  # noqa: SLF001


# ---------------------------------------------------------------------------
# Section (Lift aus _DashboardSection)
# ---------------------------------------------------------------------------


def test_section_set_expanded_toggles_inhalt(qtbot, app):  # noqa: ARG001
    """set_expanded klappt den Inhalt programmatisch auf und zu."""
    section = Section("Aufgaben", expanded=True)
    qtbot.add_widget(section)

    assert section.is_expanded()
    section.set_expanded(False)
    assert not section.is_expanded()
    assert not section._content_host.isVisibleTo(section)  # noqa: SLF001
    section.set_expanded(True)
    assert section.is_expanded()


def test_section_set_content_ersetzt_widget(qtbot, app):  # noqa: ARG001
    """set_content ersetzt das Inhalts-Widget."""
    section = Section("Notizen")
    qtbot.add_widget(section)

    erst = QLabel("Erst")
    section.set_content(erst)
    zweit = QLabel("Zweit")
    section.set_content(zweit)
    assert section._content is zweit  # noqa: SLF001


def test_section_titel_plaintext(qtbot, app):  # noqa: ARG001
    """set_title ist öffentlicher Mutator — Titel rendert nie als
    Auto-RichText (R22)."""
    section = Section("Titel")
    qtbot.add_widget(section)

    fmt = section._title_label.textFormat()  # noqa: SLF001
    assert fmt == Qt.TextFormat.PlainText
    section.set_title("Neuer <i>Titel</i>")
    assert section._title_label.text() == "Neuer <i>Titel</i>"  # noqa: SLF001


def test_section_reexport_alias_ist_identisch():
    """Der Alt-Import aus norisk_dashboard liefert exakt die core-Klasse."""
    from tools.norisk_dashboard.gui._section import _DashboardSection

    assert _DashboardSection is Section
