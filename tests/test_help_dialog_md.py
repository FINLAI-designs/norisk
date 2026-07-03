"""
test_help_dialog_md — HelpDialog rendert das.md-Anwenderhandbuch mit Screenshots.

Verifiziert die Verdrahtung: Navigation aus den.md-Kapiteln, Abschnitts-Rendering
mit eingebetteten Screenshots (Bild-URL umgeschrieben), Tool-Deeplink → Kapitel und
Volltextsuche über die Abschnitte.

Author: Patrick Riederich
"""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt  # noqa: E402

from core.help.help_dialog import HelpDialog  # noqa: E402

pytestmark = pytest.mark.gui


def _nav_keys(dlg: HelpDialog) -> list:
    return [
        dlg._nav_list.item(i).data(Qt.ItemDataRole.UserRole)
        for i in range(dlg._nav_list.count())
    ]


class TestHelpDialogMarkdown:
    def test_nav_built_from_md_sections(self, qtbot):
        dlg = HelpDialog()
        qtbot.addWidget(dlg)
        keys = _nav_keys(dlg)
        assert dlg.WELCOME_KEY in keys
        # Kapitel + Unterkapitel aus der.md sind da:
        assert "7.4" in keys and "9.1" in keys and "11.1" in keys and "13" in keys
        assert dlg._nav_list.count() > 40

    def test_section_renders_with_screenshot(self, qtbot):
        dlg = HelpDialog()
        qtbot.addWidget(dlg)
        dlg._render_section("7.4")  # Workflow-Reiter, enthält cockpit_workflow.png
        html = dlg._content_view.toHtml()
        assert "cockpit_workflow.png" in html
        # Absolute file://-URI (nicht der relative images/-Pfad)
        assert "images/cockpit_workflow.png" in html
        assert "file:" in html

    def test_screenshot_clamped_not_overflowing(self, qtbot):
        dlg = HelpDialog()
        qtbot.addWidget(dlg)
        dlg._render_section("7.4")  # Workflow-Reiter mit 1920px-Screenshot
        doc = dlg._content_view.document()
        widths = []
        block = doc.begin()
        while block.isValid():
            it = block.begin()
            while not it.atEnd():
                fmt = it.fragment().charFormat()
                if fmt.isImageFormat():
                    widths.append(fmt.toImageFormat().width())
                it += 1
            block = block.next()
        assert widths, "Screenshot muss als Bild-Fragment im Dokument liegen"
        # Auf die Content-Breite geklemmt (kein 1920px-Overflow)
        assert all(0 < w <= 900 for w in widths)

    def test_document_has_theme_stylesheet(self, qtbot):
        dlg = HelpDialog()
        qtbot.addWidget(dlg)
        css = dlg._content_view.document().defaultStyleSheet()
        assert "Raleway" in css and "color:" in css  # theme-konformes Styling gesetzt

    def test_deep_function_block_present(self, qtbot):
        dlg = HelpDialog()
        qtbot.addWidget(dlg)
        dlg._render_section("9.1")  # System-Scan
        assert "Alle Funktionen im Detail" in dlg._content_view.toMarkdown()

    def test_deeplink_tool_maps_to_chapter(self, qtbot):
        dlg = HelpDialog(initial_nav_key="system_scanner")
        qtbot.addWidget(dlg)
        current = dlg._nav_list.currentItem()
        assert current is not None
        assert current.data(Qt.ItemDataRole.UserRole) == "9.1"

    def test_search_filters_to_matching_sections(self, qtbot):
        dlg = HelpDialog()
        qtbot.addWidget(dlg)
        dlg._search_edit.setText("Workflow")
        dlg._apply_search()
        visible = [
            dlg._nav_list.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(dlg._nav_list.count())
            if not dlg._nav_list.item(i).isHidden()
        ]
        assert "7.4" in visible  # Workflow-Abschnitt bleibt sichtbar
        assert dlg.WELCOME_KEY not in visible  # Willkommen bei aktiver Suche versteckt


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
