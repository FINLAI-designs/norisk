"""
login_window — Login-Dialog für FINLAI

Zeigt ein rahmenloses Login-Fenster mit Benutzername/Passwort-Eingabe.
Nach 3 Fehlversuchen wird der Login für 30 Sekunden gesperrt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtGui import QAction, QKeyEvent, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.audit_log import AuditLogger
from core.auth.login_attempts import (
    clear_attempts,
    is_locked_out,
    record_failed_attempt,
)
from core.auth.password_setup_dialog import (
    PasswordSetupDialog,  # noqa
)
from core.auth.session import Session
from core.auth.user_store import UserStore
from core.branding import robot_pixmap
from core.icons import Icons, get_icon
from core.logger import get_logger

log = get_logger(__name__)

_LOGO_PATH = Path(__file__).parent.parent.parent / "assets" / "logo" / "finlai_logo.png"
_MAX_ATTEMPTS = 3
# Millisekunden Pause zwischen „Zu viele Fehlversuche"-Meldung und reject
_REJECT_DELAY_MS = 1500


class LoginWindow(QDialog):
    """Rahmenloses Login-Fenster für FINLAI.

    Gibt dem Benutzer exakt ``_MAX_ATTEMPTS`` Versuche. Nach dem letzten
    Fehlversuch wird nach ``_REJECT_DELAY_MS`` Millisekunden ``reject``
    aufgerufen, was die App sauber beendet.

    Nach erfolgreichem Login:
    - Session.login(user) wird aufgerufen
    - AuditLogger protokolliert USER_LOGIN
    - Dialog wird mit ``Accepted`` geschlossen
    """

    def __init__(self, app_name: str = "FINLAI") -> None:
        super().__init__(None)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setModal(True)
        self.setFixedSize(380, 480)

        self._store = UserStore()
        self._failed_attempts = 0
        self._drag_pos: QPoint | None = None
        self._app_name = app_name

        self._build_ui()
        self._center_on_screen()

        # ------------------------------------------------------------------
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme.

        Wird bei Theme-Wechsel aufgerufen (register_listener).
        """
        from core import theme  # noqa: PLC0415

        c = theme.get()
        if hasattr(self, "_outer"):
            self._outer.setStyleSheet(
                f"QWidget#login_outer {{"
                f" background-color: {c.BG_MAIN};"
                f" border: 1px solid {c.ACCENT}; }}"
            )
        if hasattr(self, "_txt_user"):
            self._txt_user.setStyleSheet(self._field_style())
        if hasattr(self, "_txt_pw"):
            self._txt_pw.setStyleSheet(self._field_style(radius_right=0))
        if hasattr(self, "_btn_eye"):
            self._btn_eye.setStyleSheet(self._eye_btn_style())
        if hasattr(self, "_btn_login"):
            self._btn_login.setStyleSheet(self._login_btn_style())

    def _build_ui(self) -> None:
        """Erstellt die gesamte Dialog-Oberfläche."""
        # Äußerer Rahmen
        self._outer = QWidget(self)
        self._outer.setObjectName("login_outer")
        self._outer.setStyleSheet(f"""
            QWidget#login_outer {{
                background-color: {theme.get().BG_MAIN};
                border: 1px solid {theme.get().ACCENT};
            }}
        """)
        outer = self._outer
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(outer)

        main_layout = QVBoxLayout(outer)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Titelbalken
        main_layout.addWidget(self._build_titlebar())

        # Inhalt
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(36, 20, 36, 28)
        content_layout.setSpacing(0)

        # Logo — FINLAI-Roboter; Fallbacks: Emblem, dann Icon
        lbl_logo = QLabel()
        lbl_logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        robot = robot_pixmap(88)
        if not robot.isNull():
            lbl_logo.setPixmap(robot)
        elif _LOGO_PATH.exists():
            pix = QPixmap(str(_LOGO_PATH)).scaled(
                88,
                88,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            lbl_logo.setPixmap(pix)
        else:
            lbl_logo.setPixmap(get_icon(Icons.FINANCE_DASHBOARD).pixmap(88, 88))
        lbl_logo.setFixedHeight(96)
        content_layout.addWidget(lbl_logo)

        # App-Titel (aus AppConfig.app_name, Fallback "FINLAI")
        lbl_title = QLabel(self._app_name)
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_title.setWordWrap(True)
        lbl_title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 22px; font-weight: bold;"
            f" color: {theme.get().ACCENT}; margin-top: 4px;"
        )
        content_layout.addWidget(lbl_title)

        lbl_subtitle = QLabel("Tax Tech Suite")
        lbl_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_subtitle.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {theme.get().TEXT_DIM}; margin-bottom: 20px;"
        )
        content_layout.addWidget(lbl_subtitle)

        # Benutzername
        self._txt_user = QLineEdit()
        self._txt_user.setPlaceholderText("Benutzername")
        self._txt_user.setFixedHeight(40)
        self._txt_user.setStyleSheet(self._field_style())
        _user_icon_action = QAction(get_icon(Icons.PERSON), "", self._txt_user)
        self._txt_user.addAction(
            _user_icon_action, QLineEdit.ActionPosition.LeadingPosition
        )
        self._txt_user.textChanged.connect(self._update_last_login_label)
        content_layout.addWidget(self._txt_user)
        content_layout.addSpacing(10)

        # Passwort + Auge
        pw_row = QHBoxLayout()
        pw_row.setSpacing(0)
        self._txt_pw = QLineEdit()
        self._txt_pw.setPlaceholderText("Passwort")
        self._txt_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._txt_pw.setFixedHeight(40)
        self._txt_pw.setStyleSheet(self._field_style(radius_right=0))
        _pw_icon_action = QAction(get_icon(Icons.LOCK), "", self._txt_pw)
        self._txt_pw.addAction(
            _pw_icon_action, QLineEdit.ActionPosition.LeadingPosition
        )
        # returnPressed NICHT verbinden — keyPressEvent übernimmt Enter
        # (verhindert Doppelaufruf: returnPressed + QDialog-Propagation)

        self._btn_eye = QPushButton()
        self._btn_eye.setIcon(get_icon(Icons.VISIBILITY))
        self._btn_eye.setFixedSize(40, 40)
        self._btn_eye.setCheckable(True)
        self._btn_eye.setStyleSheet(self._eye_btn_style())
        self._btn_eye.toggled.connect(self._toggle_pw_visibility)

        pw_row.addWidget(self._txt_pw)
        pw_row.addWidget(self._btn_eye)
        content_layout.addLayout(pw_row)
        content_layout.addSpacing(20)

        # Anmelden-Button
        self._btn_login = QPushButton("Anmelden")
        self._btn_login.setFixedHeight(42)
        self._btn_login.setStyleSheet(self._login_btn_style())
        self._btn_login.clicked.connect(self._on_login)
        content_layout.addWidget(self._btn_login)
        content_layout.addSpacing(12)

        # Letzter Login
        self._lbl_last_login = QLabel("")
        self._lbl_last_login.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_last_login.setStyleSheet(
            f"font-size: 13px; color: {theme.get().TEXT_DIM}; font-family: 'Raleway';"
        )
        content_layout.addWidget(self._lbl_last_login)

        # Fehlermeldung
        self._lbl_error = QLabel("")
        self._lbl_error.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_error.setWordWrap(True)
        self._lbl_error.setStyleSheet(
            f"font-size: 13px; color: {theme.ERROR_RED};"
            f" font-family: 'Raleway'; margin-top: 4px;"
        )
        content_layout.addWidget(self._lbl_error)

        content_layout.addStretch()
        main_layout.addWidget(content)

    def _build_titlebar(self) -> QWidget:
        """Erstellt den eigenen Titelbalken mit nur Schließen-Button."""
        bar = QWidget()
        bar.setFixedHeight(36)
        bar.setStyleSheet(f"""
            QWidget {{
                background-color: {theme.get().BG_MAIN};
                border-bottom: 1px solid {theme.get().ACCENT};
            }}
        """)
        bar.mousePressEvent = self._bar_mouse_press
        bar.mouseMoveEvent = self._bar_mouse_move
        bar.mouseReleaseEvent = lambda e: setattr(self, "_drag_pos", None)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 0, 6, 0)

        lbl = QLabel("FINLAI — Anmeldung")
        lbl.setStyleSheet(
            f"color: {theme.get().TEXT_MAIN}; font-family: 'Raleway';"
            f" font-size: 13px; border: none;"
        )
        layout.addWidget(lbl)
        layout.addStretch()

        btn_close = QPushButton()
        btn_close.setIcon(get_icon(Icons.CLOSE))
        btn_close.setFixedSize(30, 24)
        btn_close.setStyleSheet(f"""
            QPushButton {{
                background: transparent; border: none;
                border-radius: 3px;
            }}
            QPushButton:hover {{ background-color: {theme.SEVERITY_SIGNAL_CRITICAL}; }}
        """)
        btn_close.clicked.connect(self.reject)
        layout.addWidget(btn_close)
        return bar

    # ------------------------------------------------------------------
    # Drag-Logik für rahmenlosen Dialog
    # ------------------------------------------------------------------
    def closeEvent(self, event) -> None:  # type: ignore[override]
        """Stellt sicher dass jeder Close (Alt+F4, OS-Close) reject auslöst.

        Qt's QDialog.closeEvent ruft standardmäßig reject auf — wir
        überschreiben es explizit um sicherzustellen dass der Caller
        (login.exec == Rejected) korrekt informiert wird und die App
        sauber beendet wird.

        Args:
            event: Close-Event vom Fenstersystem.
        """
        event.accept()  # Fenster darf geschlossen werden
        self.reject()  # Sicherstellen dass Accepted-State nicht gesetzt ist

    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Verwaltet alle Tastendrücke im Login-Dialog.

        Enter/Return → _on_login aufrufen und Event konsumieren.
        Escape → Event konsumieren ohne reject (Dialog bleibt offen).
        Alles andere → an super weiterleiten (Tab-Navigation etc.).

        Hintergrund: QDialog.keyPressEvent ruft bei Enter den Default-Button
        oder direkt reject auf. Da das Enter-Event aus QLineEdit trotzdem
        zum Dialog propagiert, müssen wir es hier abfangen bevor es super
        erreicht.

        Args:
            event: Tastaturevent.
        """
        key = event.key()
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._on_login()
            event.accept()
            return
        if key == Qt.Key.Key_Escape:
            event.accept()  # Escape bewusst ignorieren — kein reject
            return
        super().keyPressEvent(event)  # Tab, Pfeiltasten, etc.

    def _bar_mouse_press(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint()

    def _bar_mouse_move(self, event) -> None:
        if self._drag_pos and event.buttons() == Qt.MouseButton.LeftButton:
            delta = event.globalPosition().toPoint() - self._drag_pos
            self.move(self.pos() + delta)
            self._drag_pos = event.globalPosition().toPoint()

    # ------------------------------------------------------------------
    # UI-Hilfsmethoden
    # ------------------------------------------------------------------
    def _field_style(self, radius_right: int = 6) -> str:
        """Gibt das Stylesheet für Eingabefelder zurück."""
        c = theme.get()
        return (
            f"QLineEdit {{"
            f" background-color: {c.BG_INPUT};"
            f" color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.ACCENT};"
            f" border-radius: 6px;"
            f" border-top-right-radius: {radius_right}px;"
            f" border-bottom-right-radius: {radius_right}px;"
            f" padding: 0 10px;"
            f" font-family: 'Raleway'; font-size: 13px;"
            f"}}"
            f"QLineEdit:focus {{ border-color: {c.ACCENT}; }}"
        )

    def _eye_btn_style(self) -> str:
        """Gibt das Stylesheet für den Passwort-Sichtbarkeits-Button zurück."""
        c = theme.get()
        return (
            f"QPushButton {{"
            f" background-color: {c.BG_INPUT};"
            f" color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.ACCENT};"
            f" border-left: none;"
            f" border-radius: 0px;"
            f" border-top-right-radius: 6px;"
            f" border-bottom-right-radius: 6px;"
            f"}}"
            f"QPushButton:hover {{ background-color: {c.BG_BUTTON}; }}"
        )

    def _login_btn_style(self) -> str:
        """Gibt das Stylesheet für den Anmelden-Button zurück."""
        c = theme.get()
        return (
            f"QPushButton {{"
            f" background-color: {c.ACCENT};"
            f" color: {c.BG_DARK};"
            f" border: none;"
            f" border-radius: 6px;"
            f" font-family: 'Raleway';"
            f" font-size: 13px;"
            f" font-weight: bold;"
            f"}}"
            f"QPushButton:hover {{ background-color: {c.ACCENT_DIM}; }}"
            f"QPushButton:pressed {{ background-color: {c.ACCENT_DARK}; }}"
            f"QPushButton:disabled {{"
            f" background-color: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED};"
            f"}}"
        )

    def _center_on_screen(self) -> None:
        """Zentriert den Dialog auf dem Hauptmonitor."""
        from PySide6.QtWidgets import QApplication

        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)

    def _toggle_pw_visibility(self, checked: bool) -> None:
        """Schaltet die Passwort-Sichtbarkeit um."""
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self._txt_pw.setEchoMode(mode)
        icon_name = Icons.VISIBILITY_OFF if checked else Icons.VISIBILITY
        self._btn_eye.setIcon(get_icon(icon_name))

    def _show_error(self, msg: str) -> None:
        """Zeigt eine Fehlermeldung rot unter dem Button an."""
        self._lbl_error.setText(msg)

    def _update_last_login_label(self, username: str) -> None:
        """Aktualisiert die 'Letzter Login'-Anzeige wenn ein Benutzer existiert."""
        if not username.strip():
            self._lbl_last_login.setText("")
            return
        data = self._store._load()
        if username in data and data[username].get("last_login"):
            try:
                dt = datetime.fromisoformat(data[username]["last_login"])
                formatted = dt.strftime("%d.%m.%Y %H:%M")
                self._lbl_last_login.setText(f"Letzter Login: {formatted}")
            except ValueError:
                self._lbl_last_login.setText("")
        else:
            self._lbl_last_login.setText("")

    # ------------------------------------------------------------------
    # Login-Logik
    # ------------------------------------------------------------------
    def _on_login(self) -> None:
        """Verarbeitet den Login-Versuch."""
        username = self._txt_user.text().strip()
        password = self._txt_pw.text()

        if not username:
            self._show_error("Bitte Benutzername und Passwort eingeben.")
            return

        # Persistenter Brute-Force-Schutz: ueberlebt App-Neustarts.
        # Greift NACH dem Username-Check, damit ein leeres Eingabefeld
        # keinen Locked-Hinweis triggert.
        locked, seconds_remaining = is_locked_out(username)
        if locked:
            minutes = max(1, (seconds_remaining + 59) // 60)
            try:
                AuditLogger().log_action(
                    "LOGIN_LOCKED",
                    {"username": username, "seconds_remaining": seconds_remaining},
                )
            except (OSError, RuntimeError) as exc:
                log.warning("Audit-Log konnte nicht geschrieben werden: %s", exc)
            self._show_error(
                f"Konto vorübergehend gesperrt. Bitte in {minutes} Minute"
                f"{'n' if minutes != 1 else ''} erneut versuchen."
            )
            self._txt_pw.clear()
            return

        # Ersteinrichtung: kein Passwort gesetzt → Setup-Dialog erzwingen
        if self._store.requires_password_setup(username):
            dialog = PasswordSetupDialog(self._store, username, self)  # noqa
            dialog.exec()  # Kann nicht abgebrochen werden
            user = self._store.get_user(username)
            if user is not None:
                clear_attempts(username)
                try:
                    self._store.update_last_login(username)
                    Session().login(user)
                    AuditLogger().log_action(
                        "USER_LOGIN", {"username": username, "role": user.role}
                    )
                except (OSError, RuntimeError) as exc:
                    log.warning("Post-Login-Aktionen fehlgeschlagen: %s", exc)
                log.info("Ersteinrichtung + Login erfolgreich: %s", username)
                self.accept()
            return

        if not password:
            self._show_error("Bitte Benutzername und Passwort eingeben.")
            return

        try:
            user = self._store.authenticate(username, password)
        except (OSError, RuntimeError, ValueError) as exc:
            log.error("Authentifizierung fehlgeschlagen: %s", exc)
            self._show_error("Anmeldung fehlgeschlagen. Bitte erneut versuchen.")
            self._txt_pw.clear()
            self._txt_pw.setFocus()
            return

        if user is None:
            self._failed_attempts += 1
            record_failed_attempt(username)
            try:
                AuditLogger().log_action("LOGIN_FAILED", {"username": username})
            except (OSError, RuntimeError) as exc:
                log.warning("Audit-Log konnte nicht geschrieben werden: %s", exc)
            log.warning("Fehlgeschlagener Login-Versuch für: %s", username)

            remaining = _MAX_ATTEMPTS - self._failed_attempts
            if remaining > 0:
                # Versuche 1 und 2: Fehlermeldung, Dialog bleibt offen
                self._show_error(
                    f"Falsches Passwort. Bitte erneut versuchen.\n"
                    f"Noch {remaining} Versuch{'e' if remaining > 1 else ''}."
                )
                self._txt_pw.clear()
                self._txt_pw.setFocus()
            else:
                # Letzter Versuch aufgebraucht → Meldung anzeigen, dann App beenden
                log.warning("Maximale Fehlversuche erreicht — Login gesperrt.")
                self._show_error("Zu viele Fehlversuche. App wird beendet.")
                self._btn_login.setEnabled(False)
                self._txt_user.setEnabled(False)
                self._txt_pw.setEnabled(False)
                QTimer.singleShot(_REJECT_DELAY_MS, self.reject)
            return

        # Erfolgreicher Login — persistente Versuchs-Historie loeschen,
        # damit ein User der zwischendurch sein Passwort getippt hat
        # nicht durch Reste-Fehlversuche im Window gesperrt wird.
        clear_attempts(username)
        try:
            self._store.update_last_login(username)
            Session().login(user)
            AuditLogger().log_action(
                "USER_LOGIN", {"username": username, "role": user.role}
            )
        except (OSError, RuntimeError) as exc:
            log.warning("Post-Login-Aktionen fehlgeschlagen: %s", exc)
        log.info("Login erfolgreich: %s", username)
        self.accept()
