"""
test_sidebar_links_categories.

Sidebar "Wichtige Links" rendert die Eintraege seit dieser Iteration
nach Kategorie (BSI & Deutschland / Oesterreich / Schwachstellen-
Datenbanken / Tools & Standards / Eigene Links) gruppiert. Dieser Test
deckt drei Schichten ab:

1. ``LinkSpec`` hat ein optionales ``category``-Feld.
2. ``load_sidebar_links`` propagiert die Kategorie aus ``CuratedLink``
   in den ``LinkSpec`` und vergibt fuer user-defined Links den Default
   ``"Eigene Links"``.
3. Der GUI-Renderer (``SidebarWidget._populate_links_group``) fuegt
   genau einen Subheader pro Kategorie-Wechsel ein — getestet via
   ``_GroupWidget._children``-Inspektion ohne sichtbaren Bildschirm.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# LinkSpec / load_sidebar_links — reine Datenschicht, kein GUI
# ---------------------------------------------------------------------------


def test_linkspec_hat_category_default_leer() -> None:
    from core.sidebar_links import LinkSpec

    spec = LinkSpec(key="x", label="y", icon="link", url="https://example.com")
    assert spec.category == ""


def test_linkspec_setzt_category_explizit() -> None:
    from core.sidebar_links import LinkSpec

    spec = LinkSpec(
        key="x", label="y", icon="link", url="https://example.com", category="BSI"
    )
    assert spec.category == "BSI"


def test_load_sidebar_links_propagiert_curated_category(monkeypatch) -> None:
    """``load_sidebar_links`` muss die ``category`` jedes ``CuratedLink``
    in den ``LinkSpec`` weiterreichen."""
    from core import sidebar_links
    from core.curated_links import CuratedLink

    fake_curated = [
        CuratedLink(
            title="BSI Link",
            url="https://bsi.bund.de",
            category="BSI & Deutschland",
            icon="shield",
            sort_order=1,
        ),
        CuratedLink(
            title="OIAT Link",
            url="https://watchlist-internet.at",
            category="Österreich",
            icon="flag",
            sort_order=2,
        ),
    ]
    monkeypatch.setattr(
        "core.curated_links.get_curated_links", lambda _app_id: fake_curated
    )

    repo = MagicMock()
    repo.lade.return_value = []
    specs = sidebar_links.load_sidebar_links([], repo)

    assert len(specs) == 2
    assert specs[0].category == "BSI & Deutschland"
    assert specs[1].category == "Österreich"


def test_load_sidebar_links_user_links_haben_eigene_links_category(monkeypatch) -> None:
    """User-Links bekommen die feste Kategorie ``Eigene Links``."""
    from core import sidebar_links

    monkeypatch.setattr(
        "core.curated_links.get_curated_links", lambda _app_id: []
    )

    user_link = MagicMock(label="Meine Seite", icon="link", url="https://meine.tld")
    repo = MagicMock()
    repo.lade.return_value = [user_link]
    specs = sidebar_links.load_sidebar_links([], repo)

    assert len(specs) == 1
    assert specs[0].category == "Eigene Links"


# ---------------------------------------------------------------------------
# GUI-Renderer — _populate_links_group fuegt Subheader pro Kategorie ein
# ---------------------------------------------------------------------------


class TestSubheaderRendering:
    pytestmark = pytest.mark.gui

    def test_subheader_pro_kategorie(self, qapp, qtbot, monkeypatch) -> None:  # noqa: ARG002
        """Bei drei verschiedenen Kategorien → genau drei Subheader-Labels."""
        from PySide6.QtWidgets import QLabel

        from core import sidebar_links
        from core.icons import Icons, get_sidebar_icon
        from core.sidebar import SidebarWidget, _GroupWidget

        specs = [
            sidebar_links.LinkSpec(
                key="link:curated:0",
                label="BSI A",
                icon="shield",
                url="https://a.de",
                category="BSI & Deutschland",
            ),
            sidebar_links.LinkSpec(
                key="link:curated:1",
                label="BSI B",
                icon="shield",
                url="https://b.de",
                category="BSI & Deutschland",
            ),
            sidebar_links.LinkSpec(
                key="link:curated:2",
                label="OIAT",
                icon="flag",
                url="https://c.at",
                category="Österreich",
            ),
            sidebar_links.LinkSpec(
                key="link:user:0",
                label="Meins",
                icon="link",
                url="https://meine.tld",
                category="Eigene Links",
            ),
        ]
        monkeypatch.setattr(
            "core.sidebar.load_sidebar_links", lambda *_a, **_kw: specs
        )

        widget = SidebarWidget.__new__(SidebarWidget)
        widget._groups = []
        widget._links_repo = MagicMock()
        widget._all_nav_items = []
        from PySide6.QtWidgets import QWidget

        QWidget.__init__(widget)
        qtbot.add_widget(widget)

        grp = _GroupWidget(
            "links", "Wichtige Links", get_sidebar_icon(Icons.LINK), expanded=False
        )
        widget._populate_links_group(grp)

        subheaders = [
            c for c in grp._subheaders
            if isinstance(c, QLabel) and c.objectName() == "SidebarSubheader"
        ]
        labels_text = [lbl.text() for lbl in subheaders]
        assert labels_text == [
            "BSI & DEUTSCHLAND",
            "ÖSTERREICH",
            "EIGENE LINKS",
        ]

    def test_children_enthaelt_keine_subheader_qlabels(
        self, qapp, qtbot, monkeypatch  # noqa: ARG002
    ) -> None:
        """Regression: Subheader-QLabels duerfen NICHT in ``_children``
        landen. Sonst crasht ``SidebarWidget.__init__`` bei der
        Suchindex-Erstellung (``child._key`` existiert nicht auf
        QLabel)."""
        from core import sidebar_links
        from core.icons import Icons, get_sidebar_icon
        from core.sidebar import SidebarWidget, _GroupWidget

        specs = [
            sidebar_links.LinkSpec(
                key="link:curated:0",
                label="BSI",
                icon="shield",
                url="https://bsi",
                category="BSI & Deutschland",
            ),
        ]
        monkeypatch.setattr(
            "core.sidebar.load_sidebar_links", lambda *_a, **_kw: specs
        )

        from unittest.mock import MagicMock

        from PySide6.QtWidgets import QWidget

        widget = SidebarWidget.__new__(SidebarWidget)
        widget._groups = []
        widget._links_repo = MagicMock()
        widget._all_nav_items = []
        QWidget.__init__(widget)
        qtbot.add_widget(widget)

        grp = _GroupWidget(
            "links", "Wichtige Links", get_sidebar_icon(Icons.LINK), expanded=False
        )
        widget._populate_links_group(grp)

        # Alle Children muessen ``_key`` haben — sonst crasht der
        # Suchindex-Aufbau in SidebarWidget.__init__.
        for child in grp._children:
            assert hasattr(child, "_key"), (
                f"Subheader leakt in _children: {child!r}"
            )

    def test_kein_subheader_bei_leerer_category(
        self, qapp, qtbot, monkeypatch  # noqa: ARG002
    ) -> None:
        """Specs ohne ``category`` (Legacy/Backwards-Compat) erzeugen
        keine Subheader."""
        from PySide6.QtWidgets import QLabel

        from core import sidebar_links
        from core.icons import Icons, get_sidebar_icon
        from core.sidebar import SidebarWidget, _GroupWidget

        specs = [
            sidebar_links.LinkSpec(
                key="link:curated:0",
                label="A",
                icon="link",
                url="https://a",
                category="",
            ),
            sidebar_links.LinkSpec(
                key="link:curated:1",
                label="B",
                icon="link",
                url="https://b",
                category="",
            ),
        ]
        monkeypatch.setattr(
            "core.sidebar.load_sidebar_links", lambda *_a, **_kw: specs
        )

        widget = SidebarWidget.__new__(SidebarWidget)
        widget._groups = []
        widget._links_repo = MagicMock()
        widget._all_nav_items = []
        from PySide6.QtWidgets import QWidget

        QWidget.__init__(widget)
        qtbot.add_widget(widget)

        grp = _GroupWidget(
            "links", "Wichtige Links", get_sidebar_icon(Icons.LINK), expanded=False
        )
        widget._populate_links_group(grp)

        subheaders = [
            c for c in grp._subheaders
            if isinstance(c, QLabel) and c.objectName() == "SidebarSubheader"
        ]
        assert subheaders == []
