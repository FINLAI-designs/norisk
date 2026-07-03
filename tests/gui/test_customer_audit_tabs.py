"""test_customer_audit_tabs Phase B, fortgeschrieben fuer.

Der interne „NIS2-Vorfälle"-Tab entfällt — NIS2 lebt als
Geschwister-Tab im Bereich „Security-Bewertung". Der Audit-Toolbar-Button und
``apply_navigation(tab='nis2')`` stoßen daher das Signal ``nis2_requested`` an
(der Container verbindet es und springt auf den NIS2-Tab); kein interner
Tab-Wechsel mehr.

Konstruktion via ``__new__`` + ``QWidget.__init__`` initialisiert nur die
Qt-Basis (Signals funktionieren), umgeht aber ``CustomerAuditWidget.__init__``/
``_build_ui`` (kein DB-/Service-Zugriff).

Bezug: [[-bewerten-bereich-ia]].
"""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QWidget

from tools.customer_audit.gui.customer_audit_widget import CustomerAuditWidget

pytestmark = pytest.mark.gui


def _bare_widget() -> CustomerAuditWidget:
    """Instanz mit initialisierter Qt-Basis, aber ohne ``_build_ui``."""
    w = CustomerAuditWidget.__new__(CustomerAuditWidget)
    QWidget.__init__(w)  # C++-Basis init -> Signals funktionieren; kein _build_ui
    return w


def test_apply_navigation_nis2_emittiert_signal(app) -> None:
    """``apply_navigation(tab='nis2')`` stößt ``nis2_requested`` an (der
    Container springt dann auf den NIS2-Geschwister-Tab)."""
    w = _bare_widget()
    received: list[None] = []
    w.nis2_requested.connect(lambda: received.append(None))
    w.apply_navigation(tab="nis2")
    assert received == [None]


def test_apply_navigation_audits_ist_noop(app) -> None:
    """``tab='audits'`` zielt auf dieses Widget selbst — kein Signal."""
    w = _bare_widget()
    received: list[None] = []
    w.nis2_requested.connect(lambda: received.append(None))
    w.apply_navigation(tab="audits")
    assert received == []


def test_apply_navigation_unbekannter_tab_ist_noop(app) -> None:
    """Unbekannter Tab-Wert ist ein No-op (kein Signal)."""
    w = _bare_widget()
    received: list[None] = []
    w.nis2_requested.connect(lambda: received.append(None))
    w.apply_navigation(tab="bogus")
    assert received == []
