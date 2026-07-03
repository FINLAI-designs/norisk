"""
test_login_window — Tests für das Login-Fenster.

Prüft Erstellung, Feldbelegung, Passwort-Versteckung,
Eingabe-Validierung und das Kernverhalten bei falschen/richtigen Passwörtern.

Kernregel: Falsches Passwort → Dialog bleibt offen. Nur richtiges Passwort
oder explizites X/Abbrechen darf den Dialog schließen.

Hinweis: LoginWindow verwendet intern _txt_user und _txt_pw
(nicht _username/_password).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QLineEdit

from core.auth.login_window import LoginWindow
from core.auth.models import User

pytestmark = pytest.mark.gui

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

_MOCK_USER = User(
    username="admin",
    password_hash="$2b$12$fakehash",
    role="admin",
    full_name="Administrator",
    allowed_tools=[],
    last_login=None,
    created_at="2026-01-01T00:00:00",
    is_active=True,
)


class TestLoginWindow:
    """Testet das Login-Fenster."""

    @pytest.fixture
    def login_window(self, qtbot, app):
        """Erstellt Login-Fenster für Tests."""
        window = LoginWindow()
        qtbot.addWidget(window)
        return window

    def test_fenster_erstellt(self, login_window):
        """Login-Fenster kann erstellt werden."""
        assert login_window is not None

    def test_felder_vorhanden(self, login_window):
        """Username und Passwort Felder vorhanden."""
        assert hasattr(login_window, "_txt_user")
        assert hasattr(login_window, "_txt_pw")

    def test_passwort_versteckt(self, login_window):
        """Passwort-Feld versteckt Eingabe."""
        assert login_window._txt_pw.echoMode() == QLineEdit.EchoMode.Password

    def test_leere_felder_kein_login(self, qtbot, login_window):
        """Leere Felder verhindern Login — Dialog bleibt offen."""
        login_window._txt_user.clear()
        login_window._txt_pw.clear()
        qtbot.mouseClick(login_window._btn_login, Qt.MouseButton.LeftButton)
        assert login_window.result() == 0

    def test_username_eingabe(self, qtbot, login_window):
        """Username kann eingegeben werden."""
        qtbot.keyClicks(login_window._txt_user, "testuser")
        assert login_window._txt_user.text() == "testuser"

    def test_passwort_eingabe(self, qtbot, login_window):
        """Passwort kann eingegeben werden."""
        qtbot.keyClicks(login_window._txt_pw, "geheim123")
        assert login_window._txt_pw.text() == "geheim123"

    def test_beide_felder_aktivieren_button(self, qtbot, login_window):
        """Button wird aktiv wenn beide Felder befüllt sind."""
        qtbot.keyClicks(login_window._txt_user, "admin")
        qtbot.keyClicks(login_window._txt_pw, "passwort")
        assert login_window._btn_login.isEnabled()


# ---------------------------------------------------------------------------
# Bug-Regression: Falsches Passwort darf Dialog nicht schließen
# ---------------------------------------------------------------------------


def _falsch_login(win, *, vorherige_fehler: int = 0) -> None:
    """Hilfsfunktion: simuliert einen Fehlversuch mit Mock."""
    win._failed_attempts = vorherige_fehler
    with (
        patch.object(win._store, "requires_password_setup", return_value=False),
        patch.object(win._store, "authenticate", return_value=None),
        patch("core.auth.login_window.AuditLogger"),
    ):
        win._txt_user.setText("admin")
        win._txt_pw.setText("falsch")
        win._on_login()


class TestFalschesPasswort:
    """Versuch 1 und 2: Dialog bleibt offen, Fehlermeldung erscheint."""

    @pytest.fixture
    def win(self, qtbot, app):
        w = LoginWindow()
        qtbot.addWidget(w)
        return w

    def test_erster_fehlversuch_dialog_bleibt_offen(self, win):
        """1. Fehlversuch → Dialog bleibt offen (kein accept/reject)."""
        _falsch_login(win, vorherige_fehler=0)
        assert win.result() != QDialog.DialogCode.Accepted

    def test_zweiter_fehlversuch_dialog_bleibt_offen(self, win):
        """2. Fehlversuch → Dialog bleibt offen."""
        _falsch_login(win, vorherige_fehler=1)
        assert win.result() != QDialog.DialogCode.Accepted

    def test_erster_fehlversuch_zeigt_zwei_versuche_uebrig(self, win):
        """1. Fehlversuch → Meldung enthält '2 Versuche'."""
        _falsch_login(win, vorherige_fehler=0)
        assert "2" in win._lbl_error.text()

    def test_zweiter_fehlversuch_zeigt_einen_versuch_uebrig(self, win):
        """2. Fehlversuch → Meldung enthält '1 Versuch'."""
        _falsch_login(win, vorherige_fehler=1)
        assert "1" in win._lbl_error.text()

    def test_erster_fehlversuch_pw_feld_geleert(self, win):
        """1. Fehlversuch → Passwort-Feld wird geleert."""
        _falsch_login(win, vorherige_fehler=0)
        assert win._txt_pw.text() == ""

    def test_zweiter_fehlversuch_pw_feld_geleert(self, win):
        """2. Fehlversuch → Passwort-Feld wird geleert."""
        _falsch_login(win, vorherige_fehler=1)
        assert win._txt_pw.text() == ""

    def test_audit_log_fehler_bricht_dialog_nicht(self, win):
        """Exception im AuditLogger darf den Dialog nicht schließen."""
        audit_mock = MagicMock()
        audit_mock.return_value.log_action.side_effect = RuntimeError("DB locked")

        win._failed_attempts = 0
        with (
            patch.object(win._store, "requires_password_setup", return_value=False),
            patch.object(win._store, "authenticate", return_value=None),
            patch("core.auth.login_window.AuditLogger", audit_mock),
        ):
            win._txt_user.setText("admin")
            win._txt_pw.setText("falsch")
            win._on_login()

        assert win.result() != QDialog.DialogCode.Accepted
        assert win._lbl_error.text() != ""

    def test_authenticate_exception_dialog_bleibt_offen(self, win):
        """Exception in authenticate → Dialog bleibt offen, Fehlermeldung."""
        with (
            patch.object(win._store, "requires_password_setup", return_value=False),
            patch.object(
                win._store, "authenticate", side_effect=RuntimeError("DB error")
            ),
            patch("core.auth.login_window.AuditLogger"),
        ):
            win._txt_user.setText("admin")
            win._txt_pw.setText("irgendwas")
            win._on_login()

        assert win.result() != QDialog.DialogCode.Accepted
        assert win._lbl_error.text() != ""


# ---------------------------------------------------------------------------
# Drei-Versuche-Regel: 3. Fehlversuch → Dialog schließt sich nach kurzer Pause
# ---------------------------------------------------------------------------


class TestDreiVersuchsRegel:
    """Nach dem 3. Fehlversuch muss der Dialog selbst schließen."""

    @pytest.fixture
    def win(self, qtbot, app):
        w = LoginWindow()
        qtbot.addWidget(w)
        return w

    def test_dritter_fehlversuch_loest_rejected_aus(self, qtbot, win):
        """3. Fehlversuch → rejected-Signal wird nach der Pause emittiert."""
        win._failed_attempts = 2  # 2 Fehlversuche bereits

        with (
            patch.object(win._store, "requires_password_setup", return_value=False),
            patch.object(win._store, "authenticate", return_value=None),
            patch("core.auth.login_window.AuditLogger"),
        ):
            win._txt_user.setText("admin")
            win._txt_pw.setText("falsch3")
            with qtbot.waitSignal(win.rejected, timeout=4000):
                win._on_login()

        assert win.result() == QDialog.DialogCode.Rejected

    def test_dritter_fehlversuch_fehlermeldung_app_beendet(self, qtbot, win):
        """3. Fehlversuch → Fehlermeldung enthält 'App wird beendet'."""
        win._failed_attempts = 2

        with (
            patch.object(win._store, "requires_password_setup", return_value=False),
            patch.object(win._store, "authenticate", return_value=None),
            patch("core.auth.login_window.AuditLogger"),
        ):
            win._txt_user.setText("admin")
            win._txt_pw.setText("falsch3")
            with qtbot.waitSignal(win.rejected, timeout=4000):
                win._on_login()

        assert "beendet" in win._lbl_error.text().lower()

    def test_dritter_fehlversuch_button_deaktiviert(self, qtbot, win):
        """3. Fehlversuch → Login-Button ist sofort deaktiviert."""
        win._failed_attempts = 2

        with (
            patch.object(win._store, "requires_password_setup", return_value=False),
            patch.object(win._store, "authenticate", return_value=None),
            patch("core.auth.login_window.AuditLogger"),
        ):
            win._txt_user.setText("admin")
            win._txt_pw.setText("falsch3")
            with qtbot.waitSignal(win.rejected, timeout=4000):
                win._on_login()

        assert not win._btn_login.isEnabled()

    def test_zaehler_frisch_pro_dialog_instanz(self, qtbot, app):
        """Jede neue LoginWindow-Instanz startet mit failed_attempts=0."""
        w1 = LoginWindow()
        qtbot.addWidget(w1)
        w1._failed_attempts = 2

        w2 = LoginWindow()
        qtbot.addWidget(w2)
        assert w2._failed_attempts == 0


# ---------------------------------------------------------------------------
# Richtiges Passwort → Dialog schließt mit Accepted
# ---------------------------------------------------------------------------


class TestRichtigesPasswort:
    """Richtiges Passwort → Dialog schließt korrekt."""

    @pytest.fixture
    def win(self, qtbot, app):
        w = LoginWindow()
        qtbot.addWidget(w)
        return w

    def test_richtiges_passwort_schliesst_dialog(self, win):
        """Korrektes Passwort → Dialog wird mit Accepted geschlossen."""
        with (
            patch.object(win._store, "requires_password_setup", return_value=False),
            patch.object(win._store, "authenticate", return_value=_MOCK_USER),
            patch.object(win._store, "update_last_login"),
            patch("core.auth.login_window.Session"),
            patch("core.auth.login_window.AuditLogger"),
        ):
            win._txt_user.setText("admin")
            win._txt_pw.setText("richtiges_passwort_2026!")
            win._on_login()

        assert win.result() == QDialog.DialogCode.Accepted

    def test_richtiges_passwort_nach_zwei_fehlern(self, win):
        """Korrektes Passwort nach 2 Fehlversuchen → Dialog akzeptiert."""
        win._failed_attempts = 2  # 2 vorangegangene Fehlversuche

        with (
            patch.object(win._store, "requires_password_setup", return_value=False),
            patch.object(win._store, "authenticate", return_value=_MOCK_USER),
            patch.object(win._store, "update_last_login"),
            patch("core.auth.login_window.Session"),
            patch("core.auth.login_window.AuditLogger"),
        ):
            win._txt_user.setText("admin")
            win._txt_pw.setText("richtiges_passwort_2026!")
            win._on_login()

        assert win.result() == QDialog.DialogCode.Accepted

    def test_richtiges_passwort_keine_fehlermeldung(self, win):
        """Korrektes Passwort → kein Fehlertext."""
        with (
            patch.object(win._store, "requires_password_setup", return_value=False),
            patch.object(win._store, "authenticate", return_value=_MOCK_USER),
            patch.object(win._store, "update_last_login"),
            patch("core.auth.login_window.Session"),
            patch("core.auth.login_window.AuditLogger"),
        ):
            win._txt_user.setText("admin")
            win._txt_pw.setText("richtiges_passwort_2026!")
            win._on_login()

        assert win._lbl_error.text() == ""


# ---------------------------------------------------------------------------
# Tastatur-Regression: Escape/Enter-Verhalten
# ---------------------------------------------------------------------------


class TestTastaturVerhalten:
    """Regression für den Enter/Escape-Bug (keyPressEvent-Propagation).

    Bug: QDialog.keyPressEvent ruft bei Enter den Default-Button oder
    reject auf. Da Enter-Events aus QLineEdit trotzdem propagieren,
    musste keyPressEvent diese Tasten abfangen.
    """

    @pytest.fixture
    def win(self, qtbot, app):
        w = LoginWindow()
        qtbot.addWidget(w)
        return w

    def test_escape_schliesst_dialog_nicht(self, qtbot, win):
        """Escape-Taste darf den Dialog NICHT schließen (kein reject)."""
        win._txt_user.setText("admin")
        win._txt_pw.setText("geheim")
        # Escape simulieren — Dialog muss offen bleiben
        qtbot.keyClick(win, Qt.Key.Key_Escape)
        # result == 0 bedeutet: weder Accepted noch Rejected → Dialog noch offen
        assert win.result() == 0

    def test_enter_ruft_on_login_genau_einmal_auf(self, qtbot, win):
        """Enter-Taste ruft _on_login genau einmal auf (kein Doppelaufruf)."""
        win._txt_user.setText("admin")
        win._txt_pw.setText("falsch")
        call_count = 0

        original_on_login = win._on_login

        def counting_on_login():
            nonlocal call_count
            call_count += 1
            original_on_login()

        win._on_login = counting_on_login

        with (
            patch.object(win._store, "requires_password_setup", return_value=False),
            patch.object(win._store, "authenticate", return_value=None),
            patch("core.auth.login_window.AuditLogger"),
        ):
            qtbot.keyClick(win, Qt.Key.Key_Return)

        assert call_count == 1

    def test_returnPressed_nicht_verbunden(self, win):
        """_txt_pw.returnPressed ist NICHT mit _on_login verbunden.

        Verhindert Regression: returnPressed + keyPressEvent würden
        _on_login doppelt aufrufen.
        """
        # Zähle wie oft _on_login aufgerufen wird wenn returnPressed ausgelöst wird
        call_count = 0

        def counting():
            nonlocal call_count
            call_count += 1
            # Nicht original aufrufen — wir testen nur die Verbindung

        win._on_login = counting
        win._txt_pw.returnPressed.emit()
        assert call_count == 0, (
            "_txt_pw.returnPressed ist mit _on_login() verbunden — das verursacht Doppelaufruf!"
        )
