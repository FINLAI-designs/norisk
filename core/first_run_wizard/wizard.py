"""First-Run-Wizard — QDialog mit QStackedWidget.

Keine Nutzung von:class:`QWizard`, damit das Look-and-Feel zu
:class:`core.startup_window.StartupWindow` konsistent bleibt
(FramelessWindowHint, Teal-Accent, Raleway).

Flow
----
Aktive Seiten im Stack (in Reihenfolge):
    1. WelcomePage
    2. AdminSetupPage
    3. CompanyScopingPage (optionales Einstiegs-Scoping)
    4. W1ProfilePage (optionales Profil-Gating-Interview)
    5. RecoveryCodeDisplayPage
    6. CompletionPage

Die Datenschutz-Akzeptanz erfolgt beim Start (apps/__init__ AgreementDialog),
nicht mehr als separate Wizard-Seite: die OSS-App macht keine Lizenz-/Update-
Server-Aufrufe mehr -> es gibt keine Heartbeat-Daten-
uebertragung, ueber die ein Art.-13-Vorab-Hinweis aufklaeren muesste.

Weitere Skelett-Seiten (z. B. CompanyInfoPage für Billing) sind importierbar
(``core.first_run_wizard.pages``) und werden später integriert.

Rückgabe
--------
:meth:`run_first_run_wizard` liefert ein:class:`FirstRunResult`:
    * ``completed=True`` + ``username="..."`` bei erfolgreichem Abschluss
    * ``completed=False`` bei Abbruch (X-Button, Escape). Der Aufrufer
      entscheidet dann, ob die App trotzdem starten darf (im Normalfall:
      App beenden).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core.audit_log import AuditLogger
from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog
from core.first_run_wizard.pages.admin_setup_page import AdminSetupPage
from core.first_run_wizard.pages.completion_page import CompletionPage
from core.first_run_wizard.pages.recovery_code_page import RecoveryCodeDisplayPage
from core.first_run_wizard.pages.scoping_page import CompanyScopingPage
from core.first_run_wizard.pages.w1_profile_page import W1ProfilePage
from core.first_run_wizard.pages.welcome_page import WelcomePage
from core.icons import Icons
from core.logger import get_logger
from core.theme import (
    ACCENT_PRESSED,
    BG_PANEL_DARK,
    BG_PANEL_LIGHT,
    DARK_ACCENT,
    DARK_BG_BUTTON_DISABLED,
    DARK_BG_PRIMARY,
    DARK_BG_SECONDARY,
    DARK_BORDER,
    DARK_TEXT_DISABLED,
    DARK_TEXT_PRIMARY,
    DARK_TEXT_SECONDARY,
    TEXT_ON_ACCENT_DEEP,
)

log = get_logger(__name__)


@dataclass(frozen=True)
class FirstRunResult:
    """Rückgabewert von:func:`run_first_run_wizard`."""

    completed: bool
    username: str | None = None


class FirstRunWizard(QDialog):
    """Dialog mit Step-Indikator, Weiter/Zurück/Abbrechen-Navigation."""

    finished_with_username = Signal(str)

    def __init__(
        self,
        app_name: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._app_name = app_name
        self._result: FirstRunResult = FirstRunResult(completed=False)

        self.setWindowTitle(f"{app_name} — Ersteinrichtung")
        self.setFixedSize(640, 480)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
        self.setModal(True)

        self._welcome = WelcomePage(app_name=app_name)
        self._admin_setup = AdminSetupPage()
        self._scoping = CompanyScopingPage()
        self._w1_profile = W1ProfilePage()
        self._recovery_code = RecoveryCodeDisplayPage()
        self._completion = CompletionPage()

        # Scoping + W1-Profil liegen nach dem Admin-Setup (Subjekt + DB existieren
        # dann) und vor dem Recovery-Code, damit der kritische Pfad ungestört
        # bleibt Scoping W1). Beide sind optional (kein Gate).
        self._pages: list[QWidget] = [
            self._welcome,
            self._admin_setup,
            self._scoping,
            self._w1_profile,
            self._recovery_code,
            self._completion,
        ]

        self._build_ui()
        self._connect_signals()
        self._update_navigation()
        AuditLogger().log_action("FIRST_RUN_STARTED", {"app_name": app_name})

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._card = QWidget()
        self._card.setObjectName("first_run_card")
        self._card.setStyleSheet(
            f"QWidget#first_run_card {{"
            f" background-color: {DARK_BG_PRIMARY};"
            f" border: 1px solid {DARK_BORDER};"
            f" border-radius: 12px;"
            f"}}"
        )
        root.addWidget(self._card)

        card_layout = QVBoxLayout(self._card)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(0)

        # TitleBar
        titlebar = QWidget()
        titlebar.setFixedHeight(48)
        titlebar.setStyleSheet(
            f"background-color: {DARK_BG_SECONDARY};"
            f" border-top-left-radius: 12px; border-top-right-radius: 12px;"
            f" border-bottom: 1px solid {DARK_BORDER};"
        )
        tb_layout = QHBoxLayout(titlebar)
        tb_layout.setContentsMargins(16, 0, 16, 0)
        tb_layout.setSpacing(8)

        self._title_label = QLabel("Ersteinrichtung")
        self._title_label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 14px; font-weight: bold;"
            f" color: {DARK_ACCENT}; background: transparent;"
        )
        tb_layout.addWidget(self._title_label)
        tb_layout.addStretch(1)

        self._step_label = QLabel("")
        self._step_label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {DARK_TEXT_SECONDARY};"
            f" background: transparent;"
        )
        tb_layout.addWidget(self._step_label)

        card_layout.addWidget(titlebar)

        # Stack
        self._stack = QStackedWidget()
        for page in self._pages:
            self._stack.addWidget(page)
        card_layout.addWidget(self._stack, stretch=1)

        # Footer
        footer = QWidget()
        footer.setFixedHeight(64)
        footer.setStyleSheet(
            f"background-color: {DARK_BG_SECONDARY};"
            f" border-top: 1px solid {DARK_BORDER};"
            f" border-bottom-left-radius: 12px; border-bottom-right-radius: 12px;"
        )
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(16, 0, 16, 0)
        footer_layout.setSpacing(8)

        self._btn_cancel = QPushButton("Abbrechen")
        self._btn_back = QPushButton("Zurück")
        self._btn_next = QPushButton("Weiter")
        for btn in (self._btn_cancel, self._btn_back, self._btn_next):
            btn.setFixedHeight(36)
            btn.setMinimumWidth(110)

        self._btn_cancel.setStyleSheet(self._button_style(primary=False))
        self._btn_back.setStyleSheet(self._button_style(primary=False))
        self._btn_next.setStyleSheet(self._button_style(primary=True))

        footer_layout.addWidget(self._btn_cancel)
        footer_layout.addStretch(1)
        footer_layout.addWidget(self._btn_back)
        footer_layout.addWidget(self._btn_next)

        card_layout.addWidget(footer)

    def _button_style(self, primary: bool) -> str:
        if primary:
            return (
                "QPushButton {"
                f" background-color: {DARK_ACCENT}; color: {TEXT_ON_ACCENT_DEEP};"
                " border: none; border-radius: 6px;"
                " font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
                " padding: 0 16px;"
                f"}} QPushButton:hover {{ background-color: {ACCENT_PRESSED}; }}"
                f"  QPushButton:disabled {{ background-color: {DARK_BG_BUTTON_DISABLED};"
                f" color: {DARK_TEXT_DISABLED}; }}"
            )
        return (
            "QPushButton {"
            f" background-color: {BG_PANEL_DARK}; color: {DARK_TEXT_PRIMARY};"
            f" border: 1px solid {DARK_BORDER}; border-radius: 6px;"
            " font-family: 'Raleway'; font-size: 13px;"
            " padding: 0 16px;"
            f"}} QPushButton:hover {{ background-color: {BG_PANEL_LIGHT}; }}"
        )

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------

    def _connect_signals(self) -> None:
        self._btn_cancel.clicked.connect(self._on_cancel)
        self._btn_back.clicked.connect(self._on_back)
        self._btn_next.clicked.connect(self._on_next)
        self._admin_setup.completion_changed.connect(
            lambda _: self._update_navigation()
        )
        self._recovery_code.completion_changed.connect(
            lambda _: self._update_navigation()
        )
        self._stack.currentChanged.connect(lambda _: self._update_navigation())

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _update_navigation(self) -> None:
        idx = self._stack.currentIndex()
        total = self._stack.count()
        self._step_label.setText(f"Schritt {idx + 1} von {total}")

        current = self._stack.currentWidget()
        is_complete = bool(current and getattr(current, "is_complete", lambda: True)())
        is_last = idx == total - 1

        self._btn_back.setEnabled(idx > 0 and not is_last)
        self._btn_next.setEnabled(is_complete)
        self._btn_next.setText("Fertigstellen" if is_last else "Weiter")
        # Auf der Abschluss-Seite ist ein Cancel nicht mehr sinnvoll
        self._btn_cancel.setVisible(not is_last)

    def _on_next(self) -> None:
        current_widget = self._stack.currentWidget()
        idx = self._stack.currentIndex()

        # Seite vor dem Wechsel committen (AdminSetup legt den User an)
        if hasattr(current_widget, "commit"):
            try:
                current_widget.commit()
            except RuntimeError as exc:
                FinlaiInfoDialog(
                    title="Fehler bei Einrichtung",
                    message=str(exc),
                    icon_name=Icons.ERROR,
                    parent=self,
                ).exec()
                return
            except Exception:  # noqa: BLE001 -- First-Run-Wizard fail-safe: jede Wizard-Page kann eigene Errors haben, User-Hinweis statt Crash
                log.exception("Unerwarteter Fehler bei Page.commit()")
                FinlaiInfoDialog(
                    title="Fehler bei Einrichtung",
                    message="Unerwarteter Fehler. Bitte Logs prüfen.",
                    icon_name=Icons.ERROR,
                    parent=self,
                ).exec()
                return

        # Wenn AdminSetup gerade committed wurde, Username an nachfolgende
        # Seiten weiterreichen (Recovery-Code-Hash + Completion-Anzeige).
        if current_widget is self._admin_setup:
            username = self._admin_setup.created_username
            if username:
                self._recovery_code.set_username(username)
                self._completion.set_username(username)

        # Letzter Schritt → Dialog schließen
        if idx == self._stack.count() - 1:
            username = self._completion.username
            self._result = FirstRunResult(completed=True, username=username)
            AuditLogger().log_action(
                "FIRST_RUN_COMPLETED", {"username": username or ""}
            )
            if username:
                self.finished_with_username.emit(username)
            self.accept()
            return

        self._stack.setCurrentIndex(idx + 1)

    def _on_back(self) -> None:
        idx = self._stack.currentIndex()
        if idx > 0:
            self._stack.setCurrentIndex(idx - 1)

    def _on_cancel(self) -> None:
        dlg = FinlaiConfirmDialog(
            title="Einrichtung abbrechen?",
            message=(
                "Ohne einen Administrator kann die App nicht gestartet werden.\n\n"
                "Einrichtung wirklich abbrechen?"
            ),
            confirm_text="Einrichtung abbrechen",
            cancel_text="Weiter einrichten",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        AuditLogger().log_action("FIRST_RUN_CANCELLED", {"app_name": self._app_name})
        self._result = FirstRunResult(completed=False)
        self.reject()

    # ------------------------------------------------------------------
    # Keyboard
    # ------------------------------------------------------------------

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self._on_cancel()
            event.accept()
            return
        super().keyPressEvent(event)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def result_info(self) -> FirstRunResult:
        """Gibt das Ergebnis nach:meth:`exec` zurück."""
        return self._result


def run_first_run_wizard(
    app_name: str,
    parent: QWidget | None = None,
    runner: Callable[[QDialog], int] | None = None,
) -> FirstRunResult:
    """Startet den Wizard synchron und gibt das Ergebnis zurück.

    Args:
        app_name: Anzeigename der aktuellen App (z. B. ``"NoRisk by FINLAI"``).
        parent: Optionales Elternfenster — typ. das ``StartupWindow``.
        runner: Optionaler Anzeige-Callback (typ. ``StartupWindow.
                  run_embedded``), der den Wizard als eingebettete Seite statt
                  als Popup zeigt. Ohne ``runner`` fällt die Funktion auf den
                  klassischen modalen ``exec``-Pfad zurück (z. B. in Tests).

    Returns:
:class:`FirstRunResult` mit ``completed`` und optional ``username``.
    """
    assert QApplication.instance() is not None, (
        "run_first_run_wizard benötigt eine laufende QApplication."
    )
    wizard = FirstRunWizard(app_name=app_name, parent=parent)
    if runner is not None:
        runner(wizard)
    else:
        wizard.setWindowModality(Qt.WindowModality.ApplicationModal)
        wizard.raise_()
        wizard.activateWindow()
        wizard.exec()
    return wizard.result_info()
