"""startup_window — Kombiniertes Lade-/Login-Fenster für den App-Start.

Ein einziges rahmenloses, zentriertes Fenster (NICHT bildschirmfüllend) deckt
den gesamten Startup-Lifecycle ab. Kein Fensterwechsel, kein Flash — eine
kohärente visuelle Erfahrung. Da das Fenster nicht maximiert ist und einen
Taskbar-Eintrag hat (``Qt.Window``), kann der Nutzer vor dem Login jederzeit
per Alt+Tab/Taskleiste zu anderen Apps wechseln.

Phasen
------
Phase 1 — Pre-Login-Ladescreen (Seite 0):
    Logo, App-Name, Progress-Bar (0 → 75 %), Schritt-Text.
    Schritte laufen synchron via ``set_progress`` + ``processEvents``.

Phase 2 — Login (Seite 1):
    Logo (kleiner), Username/Passwort, Login-Button, Fehlermeldung.
    Ausgelöst via ``show_login``. 3-Versuche-Logik ist eingebaut.

Phase 3 — Post-Login-Ladescreen (Seite 0):
    Progress-Bar weiter (80 → 100 %), Schritt-Text.
    Timer-basiert via ``run_post_login_sequence(on_done)``.
    ``on_done``: MainWindow.show → StartupWindow.close.

Signals
-------
login_successful(username: str, role: str)
    Erfolgreich eingeloggt — in ``apps/__init__.py`` mit ``_on_login_success``
    verbunden um den Post-Login-Ladescreen zu starten.
login_cancelled
    3 Fehlversuche aufgebraucht oder X-Button gedrückt — App soll beendet
    werden.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QEventLoop, QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QGuiApplication, QKeyEvent, QMouseEvent, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.audit_log import AuditLogger
from core.auth.session import Session
from core.auth.user_store import UserStore
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.widgets.finlai_progress import FinlaiProgressBar

if TYPE_CHECKING:
    from apps.app_config import AppConfig

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

_MAX_ATTEMPTS = 3
_REJECT_DELAY_MS = 1_500  # Pause zwischen "App wird beendet"-Meldung und Abbruch
_MIN_SICHTBAR_MS = 500  # Post-Login: Mindest-Anzeigezeit der Animation
_SCHRITT_DELAY_MS = 100  # Pause zwischen Post-Login-Schritten
_TIMEOUT_MS = 30_000  # Sicherheits-Timeout für Post-Login-Animation

_PAGE_LOADING = 0
_PAGE_LOGIN = 1

# Feste Fenstergroesse fuer das zentrierte Startfenster. Gross genug,
# um die eingebetteten Startup-Dialoge aufzunehmen (AgreementDialog min 640x520,
# FirstRunWizard/GDPR fixed 640x480) plus etwas Rand fuer das run_embedded-
# Stretch-Layout.
_WINDOW_WIDTH = 760
_WINDOW_HEIGHT = 620

# Kompakte Fenstergroessen fuer Login- und Post-Login-Lade-Seite. Ohne sie
# rahmt das fuer die eingebetteten Startup-Dialoge (Agreement/FirstRun) auf
# 760x620 dimensionierte Fenster die schmale Karte mit einem grossen leeren
# Hintergrund-"Quadrat" ein (wirkt wie zwei Fenster uebereinander).
# (Patrick 2026-06-27): schmaler + hoeher = Hochkant-Karte im Stil eines
# Blizzard-Login-Screens (vorher 380x480). Die Karte (``_LoginPage``) fuellt das
# Fenster und zentriert ihren Inhalt vertikal.
_LOGIN_WIDTH = 340
_LOGIN_HEIGHT = 560

_POST_LOGIN_SCHRITTE: list[tuple[int, str]] = [
    (80, "Benutzeroberfläche wird aufgebaut …"),
    (85, "Tools werden registriert …"),
    (90, "Einstellungen werden geladen …"),
    (100, "Bereit."),
]


# ---------------------------------------------------------------------------
# _LoadingPage — Seite 0: Logo + Progress-Bar + Schritt-Text
# ---------------------------------------------------------------------------


class _LoadingPage(QWidget):
    """Lade-Seite des StartupWindow.

    Zeigt Logo, App-Name, eine 8 px Teal-Progress-Bar und einen Schritt-Text.
    Wird via ``set_progress`` synchron von außen gesteuert (Pre-Login)
    und via ``_advance``-Timer (Post-Login).
    """

    def __init__(self, config: AppConfig) -> None:
        """Initialisiert die Lade-Seite.

        Args:
            config: AppConfig der App (für Logo, App-Name, Slogan).
        """
        super().__init__()
        self._config = config
        self._build_ui()

    def _build_ui(self) -> None:
        """Erstellt zentreirte Karte mit Logo, Balken und Text."""
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._card = QFrame()
        self._card.setObjectName("startup_lade_card")
        self._card.setFixedWidth(420)

        card_layout = QVBoxLayout(self._card)
        card_layout.setContentsMargins(40, 36, 40, 36)
        card_layout.setSpacing(0)
        card_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Logo
        self._lbl_icon = QLabel()
        self._lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_icon.setFixedHeight(64)
        self._lbl_icon.setStyleSheet("background: transparent; border: none;")
        self._load_logo(56)
        card_layout.addWidget(self._lbl_icon)

        # App-Name
        lbl_name = QLabel(self._config.app_name)
        lbl_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_name.setStyleSheet(
            "font-family: 'Raleway'; font-size: 16px; font-weight: 700;"
            " background: transparent; border: none; margin-top: 8px;"
        )
        card_layout.addWidget(lbl_name)

        # Slogan / Subtitle
        slogan = self._config.app_slogan or "wird gestartet …"
        lbl_sub = QLabel(slogan)
        lbl_sub.setObjectName("startup_lade_sub")
        lbl_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_sub.setStyleSheet(
            "font-family: 'Raleway'; font-size: 13px;"
            " background: transparent; border: none; margin-bottom: 20px;"
        )
        card_layout.addWidget(lbl_sub)

        # kanonischer FinlaiProgressBar (8 px aus core/theme.py)
        self._progress = FinlaiProgressBar(total=100)
        card_layout.addWidget(self._progress)
        card_layout.addSpacing(10)

        # Schritt-Text
        self._lbl_schritt = QLabel("Initialisierung …")
        self._lbl_schritt.setObjectName("startup_lade_schritt")
        self._lbl_schritt.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_schritt.setWordWrap(True)
        self._lbl_schritt.setFixedHeight(36)
        card_layout.addWidget(self._lbl_schritt)

        outer.addWidget(self._card)

    def _load_logo(self, size: int) -> None:
        """Lädt das App-Logo in der gewünschten Größe.

        Args:
            size: Seitenlänge in Pixel (quadratisch).
        """
        icon_path = Path(self._config.icon_path)
        if not icon_path.is_absolute():
            icon_path = Path(__file__).parent.parent / icon_path
        if icon_path.exists():
            pix = QPixmap(str(icon_path)).scaled(
                size,
                size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self._lbl_icon.setPixmap(pix)

    def set_progress(self, percent: int, text: str) -> None:
        """Aktualisiert Fortschrittsbalken und Schritt-Text.

        Args:
            percent: Fortschritt in Prozent (0–100); sinkt nie ab.
            text: Beschreibung des aktuellen Schritts.
        """
        self._progress.setValue(max(self._progress.value(), percent))
        self._lbl_schritt.setText(text)

    def apply_theme(self) -> None:
        """Aktualisiert Farben für das aktive Theme."""
        c = theme.get()
        self._card.setStyleSheet(
            f"QFrame#startup_lade_card {{"
            f" background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER};"
            f" border-radius: 12px;"
            f"}}"
        )
        self._lbl_schritt.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 12px;"
            f" font-family: 'Raleway'; background: transparent; border: none;"
        )
        # FinlaiProgressBar erbt sein Aussehen aus dem globalen Theme-
        # Stylesheet (#FinlaiProgressBar) — kein lokaler Override mehr noetig.


# ---------------------------------------------------------------------------
# _LoginPage — Seite 1: Logo (klein) + Felder + Login-Button
# ---------------------------------------------------------------------------


class _LoginPage(QWidget):
    """Login-Seite des StartupWindow.

    Zeigt ein kleineres Logo, Username/Passwort-Felder und den Anmelden-Button.
    Emittiert ``login_attempted`` wenn der User auf "Anmelden" klickt oder
    Enter drückt; emittiert ``cancelled`` wenn der X-Button gedrückt wird.
    Die eigentliche Authentifizierung übernimmt ``StartupWindow._attempt_login``.

    Signals:
        login_attempted(str, str): username, password — emittiert bei Login-Versuch.
        cancelled: X-Button oder Escape — emittiert bei Abbruch.
    """

    login_attempted = Signal(str, str)
    cancelled = Signal()

    def __init__(self, config: AppConfig) -> None:
        """Initialisiert die Login-Seite.

        Args:
            config: AppConfig der App (für Logo, App-Name).
        """
        super().__init__()
        self._config = config
        self._store = UserStore()
        self._build_ui()

    def _build_ui(self) -> None:
        """Erstellt die Login-Karte mit Feldern, Buttons und Fehlermeldung."""
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._card = QFrame()
        self._card.setObjectName("startup_login_card")
        # schmale, hohe Hochkant-Karte (Blizzard-Form). Feste Breite +
        # Mindesthoehe; die Karte fuellt das schmale, hohe Login-Fenster.
        self._card.setFixedWidth(340)
        self._card.setMinimumHeight(524)

        card_layout = QVBoxLayout(self._card)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(0)

        # Titelbalken (nur Schließen-Button)
        card_layout.addWidget(self._build_titlebar())

        # Inhalt — fuellt die Restkarte (stretch=1), Inhalt vertikal zentriert.
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(34, 16, 34, 24)
        content_layout.setSpacing(0)
        content_layout.addStretch(1)  # zentriert den Block vertikal

        # Logo (48 px — kleiner als Ladescreen)
        self._lbl_logo = QLabel()
        self._lbl_logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_logo.setFixedHeight(56)
        self._lbl_logo.setStyleSheet(
            "background: transparent; border: none; margin-top: 4px;"
        )
        self._load_logo(48)
        content_layout.addWidget(self._lbl_logo)

        # App-Name
        self._lbl_name = QLabel(self._config.app_name)
        self._lbl_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_name.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 20px; font-weight: bold;"
            f" color: {theme.get().ACCENT}; margin-top: 4px; background: transparent;"
        )
        content_layout.addWidget(self._lbl_name)

        lbl_anmeldung = QLabel("Anmeldung")
        lbl_anmeldung.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_anmeldung.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {theme.get().TEXT_DIM};"
            f" margin-bottom: 20px; background: transparent;"
        )
        content_layout.addWidget(lbl_anmeldung)

        # Benutzername
        self._txt_user = QLineEdit()
        self._txt_user.setPlaceholderText("Benutzername")
        self._txt_user.setFixedHeight(40)
        _user_action = QAction(get_icon(Icons.PERSON), "", self._txt_user)
        self._txt_user.addAction(_user_action, QLineEdit.ActionPosition.LeadingPosition)
        self._txt_user.textChanged.connect(self._update_last_login_label)
        self._txt_user.returnPressed.connect(self._on_login_clicked)
        content_layout.addWidget(self._txt_user)
        content_layout.addSpacing(10)

        # Passwort + Auge
        pw_row = QHBoxLayout()
        pw_row.setSpacing(0)

        self._txt_pw = QLineEdit()
        self._txt_pw.setPlaceholderText("Passwort")
        self._txt_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._txt_pw.setFixedHeight(40)
        _pw_action = QAction(get_icon(Icons.LOCK), "", self._txt_pw)
        self._txt_pw.addAction(_pw_action, QLineEdit.ActionPosition.LeadingPosition)
        # returnPressed → _on_login_clicked (kein QDialog-Doppelaufruf-Problem hier)
        self._txt_pw.returnPressed.connect(self._on_login_clicked)

        self._btn_eye = QPushButton()
        self._btn_eye.setIcon(get_icon(Icons.VISIBILITY))
        self._btn_eye.setFixedSize(40, 40)
        self._btn_eye.setCheckable(True)
        self._btn_eye.toggled.connect(self._toggle_pw_visibility)

        pw_row.addWidget(self._txt_pw)
        pw_row.addWidget(self._btn_eye)
        content_layout.addLayout(pw_row)
        content_layout.addSpacing(20)

        # Anmelden-Button
        self._btn_login = QPushButton("Anmelden")
        self._btn_login.setFixedHeight(42)
        self._btn_login.clicked.connect(self._on_login_clicked)
        content_layout.addWidget(self._btn_login)
        content_layout.addSpacing(8)

        # „Passwort vergessen?"-Link
        self._btn_forgot = QPushButton("Passwort vergessen?")
        self._btn_forgot.setFlat(True)
        self._btn_forgot.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_forgot.setStyleSheet(
            "QPushButton {"
            f" color: {theme.get().TEXT_DIM}; background: transparent; border: none;"
            " font-family: 'Raleway'; font-size: 12px; text-decoration: underline;"
            "}"
            f"QPushButton:hover {{ color: {theme.get().ACCENT}; }}"
        )
        self._btn_forgot.clicked.connect(self._on_forgot_password)
        content_layout.addWidget(self._btn_forgot, alignment=Qt.AlignmentFlag.AlignCenter)
        content_layout.addSpacing(4)

        # Letzter Login
        self._lbl_last_login = QLabel("")
        self._lbl_last_login.setAlignment(Qt.AlignmentFlag.AlignCenter)
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
        content_layout.addStretch(1)  # untere Haelfte der Zentrierung

        card_layout.addWidget(content, stretch=1)
        outer.addWidget(self._card)

    def _build_titlebar(self) -> QWidget:
        """Erstellt den Titelbalken mit Schließen-Button."""
        bar = QWidget()
        bar.setObjectName("startup_login_titlebar")
        bar.setFixedHeight(36)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 0, 6, 0)
        layout.addStretch()

        btn_close = QPushButton()
        btn_close.setIcon(get_icon(Icons.CLOSE))
        btn_close.setFixedSize(30, 24)
        btn_close.setStyleSheet(
            "QPushButton { background: transparent; border: none; border-radius: 3px; }"
            f"QPushButton:hover {{ background-color: {theme.SEVERITY_SIGNAL_CRITICAL}; }}"
        )
        btn_close.clicked.connect(self._on_close_btn)
        layout.addWidget(btn_close)

        self._titlebar = bar
        return bar

    def _load_logo(self, size: int) -> None:
        """Lädt das App-Logo.

        Args:
            size: Seitenlänge in Pixel.
        """
        icon_path = Path(self._config.icon_path)
        if not icon_path.is_absolute():
            icon_path = Path(__file__).parent.parent / icon_path
        if icon_path.exists():
            pix = QPixmap(str(icon_path)).scaled(
                size,
                size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self._lbl_logo.setPixmap(pix)

    # ------------------------------------------------------------------
    # Öffentliche API (aufgerufen von StartupWindow)
    # ------------------------------------------------------------------

    def set_error(self, text: str) -> None:
        """Zeigt eine Fehlermeldung unter dem Button.

        Args:
            text: Fehlermeldung (leer = ausblenden).
        """
        self._lbl_error.setText(text)

    def clear_password(self) -> None:
        """Leert das Passwort-Feld und fokussiert es."""
        self._txt_pw.clear()
        self._txt_pw.setFocus()

    def disable_login(self) -> None:
        """Deaktiviert alle Login-Eingaben (nach 3. Fehlversuch)."""
        self._btn_login.setEnabled(False)
        self._txt_user.setEnabled(False)
        self._txt_pw.setEnabled(False)

    def focus_username(self) -> None:
        """Fokussiert das Benutzername-Feld."""
        self._txt_user.setFocus()

    def set_username(self, username: str) -> None:
        """Setzt das Benutzername-Feld und setzt den Fokus auf das Passwort.

        Wird vom First-Run-Wizard aufgerufen, damit der frisch angelegte
        Benutzer nicht seinen Namen noch einmal tippen muss.

        Args:
            username: Vorzubelegender Benutzername (leer = kein Prefill).
        """
        self._txt_user.setText(username)
        if username:
            self._txt_pw.setFocus()

    def apply_theme(self) -> None:
        """Aktualisiert Farben für das aktive Theme."""
        c = theme.get()
        self._card.setStyleSheet(
            f"QFrame#startup_login_card {{"
            f" background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER};"
            f" border-radius: 12px;"
            f"}}"
        )
        self._titlebar.setStyleSheet(
            f"QWidget#startup_login_titlebar {{"
            f" background-color: {c.CARD_BG};"
            f" border-bottom: 1px solid {c.BORDER};"
            f" border-top-left-radius: 12px;"
            f" border-top-right-radius: 12px;"
            f"}}"
        )
        self._lbl_name.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 20px; font-weight: bold;"
            f" color: {c.ACCENT}; margin-top: 4px; background: transparent;"
        )
        self._txt_user.setStyleSheet(self._field_style())
        self._txt_pw.setStyleSheet(self._field_style(radius_right=0))
        self._btn_eye.setStyleSheet(self._eye_btn_style())
        self._btn_login.setStyleSheet(self._login_btn_style())
        self._lbl_last_login.setStyleSheet(
            f"font-size: 13px; color: {c.TEXT_DIM}; font-family: 'Raleway';"
        )

    # ------------------------------------------------------------------
    # Interne Methoden
    # ------------------------------------------------------------------

    def _on_login_clicked(self) -> None:
        """Emittiert login_attempted mit den aktuellen Feldinhalten."""
        self.login_attempted.emit(
            self._txt_user.text().strip(),
            self._txt_pw.text(),
        )

    def _on_close_btn(self) -> None:
        """Emittiert cancelled wenn der X-Button gedrückt wird."""
        self.cancelled.emit()

    def _on_forgot_password(self) -> None:
        """Öffnet den „Passwort vergessen?"-Dialog (Recovery-Code-Flow)."""
        from core.auth.forgot_password_dialog import (  # noqa: PLC0415
            ForgotPasswordDialog,
        )

        dialog = ForgotPasswordDialog(parent=self)

        def _prefill(username: str) -> None:
            # Nach erfolgreichem Reset → Username im Login-Feld vorausfüllen
            self._txt_user.setText(username)
            self._txt_pw.clear()
            self._txt_pw.setFocus()

        dialog.password_reset.connect(_prefill)
        dialog.exec()

    def _toggle_pw_visibility(self, checked: bool) -> None:
        """Schaltet Passwort-Sichtbarkeit um.

        Args:
            checked: True = Klartext, False = maskiert.
        """
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self._txt_pw.setEchoMode(mode)
        icon_name = Icons.VISIBILITY_OFF if checked else Icons.VISIBILITY
        self._btn_eye.setIcon(get_icon(icon_name))

    def _update_last_login_label(self, username: str) -> None:
        """Zeigt Datum des letzten Logins für den eingegebenen Benutzernamen.

        Args:
            username: Aktueller Inhalt des Benutzername-Felds.
        """
        if not username.strip():
            self._lbl_last_login.setText("")
            return
        data = self._store._load()
        if username in data and data[username].get("last_login"):
            try:
                dt = datetime.fromisoformat(data[username]["last_login"])
                self._lbl_last_login.setText(
                    f"Letzter Login: {dt.strftime('%d.%m.%Y %H:%M')}"
                )
            except ValueError:
                self._lbl_last_login.setText("")
        else:
            self._lbl_last_login.setText("")

    def _field_style(self, radius_right: int = 6) -> str:
        c = theme.get()
        return (
            f"QLineEdit {{"
            f" background-color: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.ACCENT}; border-radius: 6px;"
            f" border-top-right-radius: {radius_right}px;"
            f" border-bottom-right-radius: {radius_right}px;"
            f" padding: 0 10px;"
            f" font-family: 'Raleway'; font-size: 13px;"
            f"}}"
            f"QLineEdit:focus {{ border-color: {c.ACCENT}; }}"
        )

    def _eye_btn_style(self) -> str:
        c = theme.get()
        return (
            f"QPushButton {{"
            f" background-color: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.ACCENT}; border-left: none;"
            f" border-radius: 0px; border-top-right-radius: 6px;"
            f" border-bottom-right-radius: 6px;"
            f"}}"
            f"QPushButton:hover {{ background-color: {c.BG_BUTTON}; }}"
        )

    def _login_btn_style(self) -> str:
        c = theme.get()
        return (
            f"QPushButton {{"
            f" background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f" border: none; border-radius: 6px;"
            f" font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f"}}"
            f"QPushButton:hover {{ background-color: {c.ACCENT_DIM}; }}"
            f"QPushButton:pressed {{ background-color: {c.ACCENT_DARK}; }}"
            f"QPushButton:disabled {{"
            f" background-color: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED};"
            f"}}"
        )


# ---------------------------------------------------------------------------
# StartupWindow — Haupt-Widget
# ---------------------------------------------------------------------------


class StartupWindow(QWidget):
    """Kombiniertes Lade-/Login-Fenster für den App-Start.

    Ein einziges rahmenloses Vollbild-QWidget mit QStackedWidget:
    - Seite 0: ``_LoadingPage`` (Pre-Login + Post-Login)
    - Seite 1: ``_LoginPage`` (Anmeldung)

    Signals:
        login_successful(str, str): (username, role) — nach erfolgreichem Login.
        login_cancelled: 3 Fehlversuche oder X-Button.
    """

    login_successful = Signal(str, str)
    login_cancelled = Signal()

    def __init__(self, config: AppConfig, parent: QWidget | None = None) -> None:
        """Initialisiert das StartupWindow.

        Args:
            config: AppConfig der App (Logo, Name, Slogan).
            parent: Eltern-Widget (normalerweise None = eigenständiges Fenster).
        """
        super().__init__(parent)
        self._config = config
        self._failed_attempts = 0
        self._store = UserStore()

        # Post-Login-Animation
        self._step_idx = 0
        self._start_time: float = 0.0
        self._on_done: Callable[[], None] | None = None

        self._step_timer = QTimer(self)
        self._step_timer.setSingleShot(True)
        self._step_timer.timeout.connect(self._advance)

        self._safety_timer = QTimer(self)
        self._safety_timer.setSingleShot(True)
        self._safety_timer.setInterval(_TIMEOUT_MS)
        self._safety_timer.timeout.connect(self._finish)

        # Normales, NICHT maximiertes Fenster. ``Qt.Window``
        # erzwingt einen Taskbar-Eintrag + Alt+Tab-Teilnahme (ein reines
        # FramelessWindowHint-Widget bekommt das unter Windows nicht zuverlaessig);
        # ``FramelessWindowHint`` behaelt den Splash-Look. KEIN
        # WindowStaysOnTopHint — der Nutzer muss vor dem Login zu anderen Apps
        # wechseln koennen, besonders auf Single-Monitor-PCs. Angezeigt via
        # ``show_centered`` (760x620, zentriert) statt ``showMaximized``.
        # Startup-Dialoge werden via ``run_embedded`` als Kind-Widget eingehaengt.
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint
        )
        # Frameless-Fenster bieten keinen System-Drag — Position fuer manuelles
        # Verschieben per Maus (siehe mousePressEvent/mouseMoveEvent).
        self._drag_pos: QPoint | None = None

        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt QStackedWidget mit Lade- und Login-Seite."""
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._stack = QStackedWidget()
        outer.addWidget(self._stack)

        self._loading_page = _LoadingPage(self._config)
        self._login_page = _LoginPage(self._config)

        self._stack.addWidget(self._loading_page)  # Index 0
        self._stack.addWidget(self._login_page)  # Index 1

        self._login_page.login_attempted.connect(self._attempt_login)
        self._login_page.cancelled.connect(self._do_cancel)

    # ------------------------------------------------------------------
    # Öffentliche API
    # ------------------------------------------------------------------

    def set_progress(self, percent: int, text: str) -> None:
        """Aktualisiert den Fortschrittsbalken auf der Ladeseite.

        Args:
            percent: Fortschritt (0–100); sinkt nie ab.
            text: Beschreibung des aktuellen Schritts.
        """
        self._loading_page.set_progress(percent, text)

    def show_login(self, prefill_username: str | None = None) -> None:
        """Wechselt zu Seite 1 (Login).

        Args:
            prefill_username: Optionaler Benutzername, der in das Eingabefeld
                vorbelegt wird (z. B. nach First-Run-Wizard). Bei ``None`` wird
                das Benutzername-Feld fokussiert, sonst springt der Fokus
                direkt ins Passwort-Feld.
        """
        self._stack.setCurrentIndex(_PAGE_LOGIN)
        # Auf die Login-Karte schrumpfen — kein grosses leeres "Quadrat" um die
        # Karte (die eingebetteten Startup-Dialoge, die 760x620 brauchen, sind
        # zu diesem Zeitpunkt bereits durchlaufen).
        self._resize_centered(_LOGIN_WIDTH, _LOGIN_HEIGHT)
        if prefill_username:
            self._login_page.set_username(prefill_username)
        else:
            self._login_page.focus_username()

    def show_loading(self) -> None:
        """Wechselt zu Seite 0 (Ladescreen).

        Behaelt die aktuelle (kompakte) Fenstergroesse bei — der Post-Login-
        Ladescreen erbt das schmale Login-Fenster, sodass kein grosses
        Hintergrund-"Quadrat" um die Ladekarte erscheint.
        """
        self._stack.setCurrentIndex(_PAGE_LOADING)

    def show_centered(self) -> None:
        """Zeigt das Startfenster zentriert in kompakter Login-Größe.

        Ersetzt das frühere ``showMaximized``: Der Startscreen darf
        den Bildschirm nicht mehr komplett abdecken, damit der Nutzer vor dem
        Login per Alt+Tab/Taskleiste zu anderen Apps wechseln kann.

 (Patrick-Live-Test 2026-06-27): Das Fenster VOR der Anmeldung hat
        jetzt dieselbe Größe wie das Login-Fenster (``_LOGIN_WIDTH`` ×
        ``_LOGIN_HEIGHT``). Vorher erschien hier kurz das für die eingebetteten
        Startup-Dialoge dimensionierte ``_WINDOW_WIDTH`` × ``_WINDOW_HEIGHT``-
        Fenster und schrumpfte dann auf die Login-Karte — ein sichtbarer
        Größensprung. Eingebettete Startup-Dialoge (Agreement/First-Run)
        vergrößern das Fenster bei Bedarf selbst (:meth:`run_embedded`) und
        ``show_login`` schrumpft danach wieder auf die Login-Größe.
        """
        self._resize_centered(_LOGIN_WIDTH, _LOGIN_HEIGHT)
        self.show()

    def _resize_centered(self, width: int, height: int) -> None:
        """Setzt die Fenstergroesse und zentriert auf dem primaeren Bildschirm.

        Wird genutzt, um das Startfenster fuer die Login-/Lade-Seite auf die
        kompakte Karten-Groesse zu schrumpfen, statt die schmale Karte in dem
        fuer die eingebetteten Startup-Dialoge dimensionierten 760x620-Fenster
        mit einem grossen leeren Hintergrund-"Quadrat" zu umrahmen.

        Args:
            width: Neue Fensterbreite in Pixel.
            height: Neue Fensterhoehe in Pixel.
        """
        self.resize(width, height)
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            geo = screen.availableGeometry()
            self.move(
                geo.x() + (geo.width() - self.width()) // 2,
                geo.y() + (geo.height() - self.height()) // 2,
            )

    def run_embedded(self, dialog: QDialog) -> int:
        """Zeigt einen QDialog als eingebettete, zentrierte Startup-Seite.

        Statt den Dialog als eigenes modales Top-Level-Fenster via ``exec``
        zu öffnen — was hinter dem Startfenster verschwinden oder den ganzen
        Bildschirm überlagern kann — wird er als Seite in den
        ``QStackedWidget`` eingehängt. Ein lokaler ``QEventLoop`` blockiert
        synchron bis der Dialog ``finished`` emittiert, sodass der bestehende
        synchrone Startup-Ablauf in ``apps.launch_app`` unverändert bleibt.

        Die übergebene Klasse bleibt ein QDialog (wird in den Einstellungen
        weiter als Popup genutzt) — hier wird nur die Darstellung eingebettet,
        nicht die Klasse verändert.

        Args:
            dialog: QDialog, dessen ``finished``-Signal das Ergebnis liefert.
                Der Aufrufer behält die Referenz und kann den Dialog nach
                Rückkehr weiter auslesen (z. B. ``was_accepted``).

        Returns:
            Der Result-Code (``QDialog.DialogCode``) als int — ``Accepted``
            oder ``Rejected``.
        """
        # Eingebettete Startup-Dialoge (Agreement/First-Run) brauchen
        # mehr Platz als die kompakte Login-Karte. Das Fenster startet jetzt in
        # Login-Größe (show_centered) -> hier für die Dauer des Dialogs auf die
        # Dialog-Größe vergrößern; ``show_login`` schrumpft danach zurück.
        self._resize_centered(_WINDOW_WIDTH, _WINDOW_HEIGHT)

        # Dialog als zentrierte Karte (NICHT Vollbild): Stretch-Ränder oben/
        # unten und links/rechts absorbieren den freien Platz, der Dialog
        # bleibt bei seiner sizeHint — kompakt wie der Login-Bereich.
        host = QWidget()
        outer = QVBoxLayout(host)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addStretch(1)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        row.addStretch(1)

        # Als reines Kind-Widget reparenten BEVOR es ins Layout kommt: das
        # QDialog-eigene ``Qt.Dialog``-Flag (sowie Frameless/StaysOnTop der
        # Startup-Dialoge) wird entfernt, sonst rendert es trotz Parent als
        # eigenes Fenster.
        dialog.setParent(host, Qt.WindowType.Widget)
        row.addWidget(dialog)
        row.addStretch(1)
        outer.addLayout(row)
        outer.addStretch(1)
        dialog.show()

        previous = self._stack.currentWidget()
        self._stack.addWidget(host)
        self._stack.setCurrentWidget(host)

        loop = QEventLoop()
        result = int(QDialog.DialogCode.Rejected.value)

        def _on_finished(code: int) -> None:
            nonlocal result
            result = code
            loop.quit()

        dialog.finished.connect(_on_finished)
        loop.exec()
        dialog.finished.disconnect(_on_finished)

        # Dialog vom Host lösen, damit der Aufrufer ihn nach Rückkehr noch
        # auslesen kann und er nicht mit dem Host zerstört wird.
        dialog.hide()
        dialog.setParent(None)

        if previous is not None:
            self._stack.setCurrentWidget(previous)
        self._stack.removeWidget(host)
        host.deleteLater()
        return result

    def set_error(self, text: str) -> None:
        """Zeigt eine Fehlermeldung auf der Login-Seite.

        Args:
            text: Fehlermeldung (leer = ausblenden).
        """
        self._login_page.set_error(text)

    def run_post_login_sequence(
        self, on_done: Callable[[], None] | None = None
    ) -> None:
        """Startet die Post-Login-Animation (80 → 100 %).

        Läuft im Qt-Event-Loop via QTimer. ``on_done`` wird nach Abschluss
        aller Schritte + Mindest-Anzeigezeit aufgerufen.

        Args:
            on_done: Callback nach Abschluss — typischerweise MainWindow.show
                     + StartupWindow.close.
        """
        self._on_done = on_done
        self._start_time = time.monotonic()
        self._step_idx = 0
        self._safety_timer.start()
        self._advance()

    # ------------------------------------------------------------------
    # Keyboard-Handling
    # ------------------------------------------------------------------

    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Escape auf der Login-Seite → App beenden.

        Args:
            event: Tastaturevent.
        """
        if (
            event.key() == Qt.Key.Key_Escape
            and self._stack.currentIndex() == _PAGE_LOGIN
        ):
            self._do_cancel()
            event.accept()
            return
        super().keyPressEvent(event)

    # ------------------------------------------------------------------
    # Fenster verschieben (Frameless hat keinen System-Drag)
    # ------------------------------------------------------------------

    def mousePressEvent(self, event: QMouseEvent) -> None:
        """Merkt sich die Startposition für das Verschieben des Fensters.

        Args:
            event: Mausevent. Nur die linke Taste startet das Verschieben.
        """
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        """Verschiebt das Fenster, solange die linke Maustaste gehalten wird.

        Args:
            event: Mausevent mit aktueller globaler Cursor-Position.
        """
        if self._drag_pos is not None and event.buttons() == Qt.MouseButton.LeftButton:
            new_pos = event.globalPosition().toPoint()
            self.move(self.pos() + (new_pos - self._drag_pos))
            self._drag_pos = new_pos
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        """Beendet das Verschieben.

        Args:
            event: Mausevent (Inhalt wird nicht ausgewertet).
        """
        self._drag_pos = None
        super().mouseReleaseEvent(event)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self) -> None:
        """Aktualisiert Hintergrundfarbe und delegiert an Unter-Seiten."""
        c = theme.get()
        self.setStyleSheet(f"QWidget {{ background-color: {c.BG_MAIN}; }}")
        self._loading_page.apply_theme()
        self._login_page.apply_theme()

    # ------------------------------------------------------------------
    # Post-Login-Animation (intern)
    # ------------------------------------------------------------------

    def _advance(self) -> None:
        """Zeigt den nächsten Post-Login-Schritt oder wartet auf Mindest-Anzeigezeit."""
        if self._step_idx >= len(_POST_LOGIN_SCHRITTE):
            elapsed_ms = int((time.monotonic() - self._start_time) * 1000)
            remaining = max(0, _MIN_SICHTBAR_MS - elapsed_ms)
            QTimer.singleShot(remaining, self._finish)
            return
        percent, text = _POST_LOGIN_SCHRITTE[self._step_idx]
        self.set_progress(percent, text)
        self._step_idx += 1
        self._step_timer.start(_SCHRITT_DELAY_MS)

    def _finish(self) -> None:
        """Beendet die Animation und ruft on_done auf."""
        self._step_timer.stop()
        self._safety_timer.stop()
        if self._on_done:
            self._on_done()

    # ------------------------------------------------------------------
    # Login-Logik (intern)
    # ------------------------------------------------------------------

    def _attempt_login(self, username: str, password: str) -> None:
        """Verarbeitet einen Login-Versuch.

        Authentifiziert gegen UserStore, hält die 3-Versuche-Logik
        und emittiert ``login_successful`` oder ``login_cancelled``.

        Args:
            username: Eingegebener Benutzername (bereits getrimmt).
            password: Eingegebenes Passwort (nicht getrimmt).
        """
        from core.auth.password_setup_dialog import (  # noqa: PLC0415
            PasswordSetupDialog,
        )

        if not username:
            self.set_error("Bitte Benutzername und Passwort eingeben.")
            return

        # Ersteinrichtung: kein Passwort gesetzt → Setup-Dialog
        if self._store.requires_password_setup(username):
            dialog = PasswordSetupDialog(self._store, username, self)
            dialog.exec()
            user = self._store.get_user(username)
            if user is not None:
                try:
                    self._store.update_last_login(username)
                    Session().login(user)
                    AuditLogger().log_action(
                        "USER_LOGIN", {"username": username, "role": user.role}
                    )
                except (OSError, RuntimeError) as exc:
                    log.warning("Post-Login-Aktionen fehlgeschlagen: %s", exc)
                log.info("Ersteinrichtung + Login erfolgreich: %s", username)
                self.login_successful.emit(username, user.role)
            return

        if not password:
            self.set_error("Bitte Benutzername und Passwort eingeben.")
            return

        try:
            user = self._store.authenticate(username, password)
        except (OSError, RuntimeError, ValueError) as exc:
            log.error("Authentifizierung fehlgeschlagen: %s", exc)
            self.set_error("Anmeldung fehlgeschlagen. Bitte erneut versuchen.")
            self._login_page.clear_password()
            return

        if user is None:
            self._failed_attempts += 1
            try:
                AuditLogger().log_action("LOGIN_FAILED", {"username": username})
            except (OSError, RuntimeError) as exc:
                log.warning("Audit-Log konnte nicht geschrieben werden: %s", exc)
            log.warning("Fehlgeschlagener Login-Versuch für: %s", username)

            remaining = _MAX_ATTEMPTS - self._failed_attempts
            if remaining > 0:
                self.set_error(
                    f"Falsches Passwort. Bitte erneut versuchen.\n"
                    f"Noch {remaining} Versuch{'e' if remaining > 1 else ''}."
                )
                self._login_page.clear_password()
            else:
                log.warning("Maximale Fehlversuche erreicht — Login gesperrt.")
                self.set_error("Zu viele Fehlversuche. App wird beendet.")
                self._login_page.disable_login()
                QTimer.singleShot(_REJECT_DELAY_MS, self._do_cancel)
            return

        # Erfolgreicher Login
        try:
            self._store.update_last_login(username)
            Session().login(user)
            AuditLogger().log_action(
                "USER_LOGIN", {"username": username, "role": user.role}
            )
        except (OSError, RuntimeError) as exc:
            log.warning("Post-Login-Aktionen fehlgeschlagen: %s", exc)
        log.info("Login erfolgreich: %s", username)
        self.login_successful.emit(username, user.role)

    def _do_cancel(self) -> None:
        """Emittiert login_cancelled."""
        self.login_cancelled.emit()
