"""test_sidebar_profile_gating — Profil-Gating der Sidebar, Phase 3d).

Verifiziert, dass profil-optionale Module (API-Security, Zertifikats-Monitor,
Dependency-Auditor) ausgegraut werden, wenn das W1-Profil die zugehörige
Eigenschaft explizit verneint (Flag ``0``) — und sichtbar/aktiv bleiben bei
``1`` (vorhanden) oder ``None`` (nicht erfasst). Das reversible Override
(``UISettings.profile_gating_enabled = False``) hebt das Gating auf.

Die Lizenzsperre wird per No-op gepatcht, um das Gating isoliert zu prüfen; das
eigene Subjekt kommt aus einem Fake-Store (kein echter DB-Zugriff).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from apps.app_config import NORISK_CONFIG

from core.auth.session import Session
from core.security_subject.models import Subject, SubjectKind
from core.sidebar import SidebarWidget
from core.ui_settings import UISettings

pytestmark = pytest.mark.gui

# (W1-Flag-Attribut, gegatetes Sidebar-Item) — Mapping aus sidebar_config.py.
_GATING_MAP: list[tuple[str, str]] = [
    ("hat_eigene_api", "api_security"),
    ("hat_eigene_website", "cert_monitor"),
    ("ist_entwickler", "dependency_auditor"),
]


class _FakeStore:
    """Minimaler SubjectStore-Stub, der nur ``get_self`` bedient."""

    def __init__(self, subject: Subject | None) -> None:
        self._subject = subject

    def get_self(self) -> Subject | None:
        return self._subject


def _subject(**w1_flags: object) -> Subject:
    """Eigenes Subjekt mit gesetzten W1-Flags (Rest Default)."""
    return Subject(
        subject_id="self",
        kind=SubjectKind.EIGENES,
        name="Mein System",
        **w1_flags,  # type: ignore[arg-type]
    )


def _build(qtbot, *, store: object, gating_enabled: bool = True) -> SidebarWidget:
    """Baut die config-driven Sidebar mit gepatchtem Store.

    Seit gibt es kein Lizenz-Nav-Gating mehr (``_apply_license_lock``
    entfernt) — nur noch das W1-Profil-Gating, das diese Tests prüfen.
    """
    settings = UISettings(profile_gating_enabled=gating_enabled)
    with patch("core.sidebar.create_subject_store", return_value=store):
        widget = SidebarWidget(
            [], Session(), settings, groups=NORISK_CONFIG.sidebar_groups
        )
    qtbot.addWidget(widget)
    return widget


def _item(widget: SidebarWidget, key: str):
    return next(
        (i for i in widget._all_nav_items if getattr(i, "_key", None) == key), None
    )


@pytest.mark.parametrize(("flag", "item_key"), _GATING_MAP)
def test_flag_zero_greys_module(qtbot, app, flag: str, item_key: str) -> None:
    """Flag explizit 0 (Eigenschaft fehlt) → Item ausgegraut."""
    widget = _build(qtbot, store=_FakeStore(_subject(**{flag: 0})))
    item = _item(widget, item_key)
    assert item is not None, f"{item_key} muss gerendert werden (nur ausgegraut)"
    assert item.isEnabled() is False


@pytest.mark.parametrize(("flag", "item_key"), _GATING_MAP)
@pytest.mark.parametrize("value", [1, None])
def test_flag_set_or_unknown_keeps_module(
    qtbot, app, flag: str, item_key: str, value: int | None
) -> None:
    """Flag 1 (vorhanden) oder None (nicht erfasst) → Item bleibt aktiv."""
    widget = _build(qtbot, store=_FakeStore(_subject(**{flag: value})))
    item = _item(widget, item_key)
    assert item is not None
    assert item.isEnabled() is True


def test_override_disables_gating(qtbot, app) -> None:
    """profile_gating_enabled=False → trotz Flag 0 alle Module aktiv."""
    store = _FakeStore(
        _subject(hat_eigene_api=0, hat_eigene_website=0, ist_entwickler=0)
    )
    widget = _build(qtbot, store=store, gating_enabled=False)
    for _flag, item_key in _GATING_MAP:
        item = _item(widget, item_key)
        assert item is not None
        assert item.isEnabled() is True


def test_no_store_no_gating(qtbot, app) -> None:
    """Kein SubjectStore (fail-soft) → kein Gating, kein Crash."""
    widget = _build(qtbot, store=None)
    assert _item(widget, "api_security").isEnabled() is True


def test_no_subject_no_gating(qtbot, app) -> None:
    """Store ohne eigenes Subjekt → kein Gating."""
    widget = _build(qtbot, store=_FakeStore(None))
    assert _item(widget, "cert_monitor").isEnabled() is True


def test_gating_does_not_touch_other_modules(qtbot, app) -> None:
    """Coverage bleibt: nur das gegatete Item ist betroffen, Nachbarn aktiv."""
    widget = _build(qtbot, store=_FakeStore(_subject(hat_eigene_api=0)))
    # gegatet
    assert _item(widget, "api_security").isEnabled() is False
    # nicht gegatete Module im selben Bereich bleiben aktiv
    assert _item(widget, "system_scanner").isEnabled() is True
    assert _item(widget, "network_scanner").isEnabled() is True
    # und das Item ist weiterhin vorhanden (versteckt es nicht)
    assert _item(widget, "api_security") is not None
