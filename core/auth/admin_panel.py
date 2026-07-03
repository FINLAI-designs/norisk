"""
admin_panel — Benutzerverwaltungs-Dialog für FINLAI

Nur für Admins zugänglich. Drei Tabs:
  1. Benutzerübersicht (Tabelle mit Aktionen)
  2. Benutzer erstellen / bearbeiten
  3. Eigenes Passwort ändern

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme, ui_constants
from core.auth.models import User
from core.auth.session import Session
from core.auth.user_store import UserStore
from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog, FinlaiSuccessDialog
from core.icons import Icons
from core.logger import get_logger

log = get_logger(__name__)

_FIELD_STYLE = f"""
    QLineEdit {{
        background-color: {theme.BG_PANEL_DARK};
        color: {theme.get().TEXT_MAIN};
        border: 1px solid {theme.get().BORDER};
        border-radius: 4px;
        padding: 4px 8px;
        font-family: 'Raleway';
    }}
    QLineEdit:focus {{ border-color: {theme.get().ACCENT}; }}
"""

_COMBO_STYLE = f"""
    QComboBox {{
        background-color: {theme.BG_PANEL_DARK};
        color: {theme.get().TEXT_MAIN};
        border: 1px solid {theme.get().BORDER};
        border-radius: 4px;
        padding: 4px 8px;
    }}
    QComboBox::drop-down {{ border: none; }}
    QComboBox QAbstractItemView {{
        background-color: {theme.BG_PANEL_DARK};
        color: {theme.get().TEXT_MAIN};
        selection-background-color: {theme.get().BG_SIDEBAR_SELECTED};
    }}
"""


class AdminPanel(QDialog):
    """Benutzerverwaltungs-Dialog — nur für Administratoren.

    Bietet drei Tabs für Benutzerübersicht, Anlegen/Bearbeiten und
    Passwortänderung. Kommuniziert direkt mit UserStore.

    Args:
        available_tools: Liste aller verfügbaren Tool-Namen der App.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        available_tools: list[str],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Benutzerverwaltung")
        self.setMinimumSize(720, 520)
        self.setModal(True)

        self._store = UserStore()
        self._available_tools = available_tools
        self._edit_username: str | None = None  # gesetzter Name = Bearbeiten-Modus

        self._build_ui()

        # ------------------------------------------------------------------
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme.

        Wird bei Theme-Wechsel aufgerufen (register_listener).
        TODO: setStyleSheet-Aufrufe mit theme.get-Farben ersetzen.
        """
        from core import theme  # noqa: PLC0415

        c = theme.get()  # noqa: F841

    def _build_ui(self) -> None:
        """Erstellt die Tab-Struktur des Dialogs."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QLabel("Benutzerverwaltung")
        header.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 15px; font-weight: bold;"
            f" color: {theme.get().ACCENT}; padding: 12px 16px;"
        )
        layout.addWidget(header)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {theme.get().ACCENT};")
        layout.addWidget(sep)

        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {theme.get().BG_MAIN};
            }}
            QTabBar::tab {{
                background-color: {theme.BG_PANEL_DARK};
                color: {theme.get().TEXT_MAIN};
                padding: 8px 16px;
                border: none;
                font-family: 'Raleway';
            }}
            QTabBar::tab:selected {{
                background-color: {theme.get().BG_SIDEBAR_SELECTED};
                color: {theme.get().TEXT_SIDEBAR};
                font-weight: bold;
            }}
            QTabBar::tab:hover:!selected {{
                background-color: {theme.get().BG_SIDEBAR_HOVER};
            }}
        """)

        self._tab_users = self._build_tab_users()
        self._tab_form = self._build_tab_form()
        self._tab_password = self._build_tab_password()

        self._tabs.addTab(self._tab_users, "Benutzer")
        self._tabs.addTab(self._tab_form, "Benutzer anlegen / bearbeiten")
        self._tabs.addTab(self._tab_password, "Passwort ändern")

        layout.addWidget(self._tabs)

        # Schließen-Button unten
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(12, 8, 12, 12)
        btn_row.addStretch()
        btn_close = QPushButton("Schließen")
        btn_close.setFixedWidth(100)
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)

    # ==================================================================
    # Tab 1: Benutzerübersicht
    # ==================================================================
    def _build_tab_users(self) -> QWidget:
        """Erstellt den Benutzerübersicht-Tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 8)

        # Toolbar
        toolbar = QHBoxLayout()
        btn_new = QPushButton("Neuer Benutzer")
        btn_new.setFixedHeight(ui_constants.BUTTON_HEIGHT_LARGE)
        btn_new.setStyleSheet(
            f"QPushButton {{ background-color: {theme.get().ACCENT}; color: {theme.get().BG_DARK};"
            f" border: none; border-radius: 4px; font-weight: bold; }}"
            f"QPushButton:hover {{ background-color: {theme.get().BG_SIDEBAR_HOVER}; }}"
        )
        btn_new.clicked.connect(self._new_user)
        toolbar.addWidget(btn_new)
        toolbar.addStretch()

        btn_refresh = QPushButton("Aktualisieren")
        btn_refresh.setFixedHeight(ui_constants.BUTTON_HEIGHT_LARGE)
        btn_refresh.clicked.connect(self._refresh_user_table)
        toolbar.addWidget(btn_refresh)
        layout.addLayout(toolbar)
        layout.addSpacing(8)

        # Tabelle
        self._tbl_users = QTableWidget()
        self._tbl_users.setColumnCount(6)
        self._tbl_users.setHorizontalHeaderLabels(
            ["Benutzername", "Name", "Rolle", "Letzter Login", "Status", "Aktionen"]
        )
        self._tbl_users.horizontalHeader().setStretchLastSection(True)
        self._tbl_users.setColumnWidth(0, 120)
        self._tbl_users.setColumnWidth(1, 160)
        self._tbl_users.setColumnWidth(2, 70)
        self._tbl_users.setColumnWidth(3, 140)
        self._tbl_users.setColumnWidth(4, 70)
        self._tbl_users.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tbl_users.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._tbl_users.verticalHeader().setVisible(False)
        self._tbl_users.setAlternatingRowColors(True)
        layout.addWidget(self._tbl_users)

        self._refresh_user_table()
        return widget

    def _refresh_user_table(self) -> None:
        """Lädt alle Benutzer und befüllt die Tabelle neu."""
        users = self._store.get_all_users()
        self._tbl_users.setRowCount(len(users))

        for row, user in enumerate(users):
            self._tbl_users.setItem(row, 0, QTableWidgetItem(user.username))
            self._tbl_users.setItem(row, 1, QTableWidgetItem(user.full_name))

            role_text = "Admin" if user.role == "admin" else "Benutzer"
            role_item = QTableWidgetItem(role_text)
            role_item.setForeground(
                Qt.GlobalColor.cyan if user.role == "admin" else Qt.GlobalColor.white
            )
            self._tbl_users.setItem(row, 2, role_item)

            # Letzter Login
            last_login = "—"
            if user.last_login:
                try:
                    dt = datetime.fromisoformat(user.last_login)
                    last_login = dt.strftime("%d.%m.%Y %H:%M")
                except ValueError:
                    last_login = user.last_login
            self._tbl_users.setItem(row, 3, QTableWidgetItem(last_login))

            # Status
            status_text = "Aktiv" if user.is_active else "Gesperrt"
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(
                Qt.GlobalColor.green if user.is_active else Qt.GlobalColor.red
            )
            self._tbl_users.setItem(row, 4, status_item)

            # Aktionen-Buttons
            actions = QWidget()
            actions_layout = QHBoxLayout(actions)
            actions_layout.setContentsMargins(4, 2, 4, 2)
            actions_layout.setSpacing(6)

            # TODO Sprint 2: Action-Button-Color-Set zentralisieren
            # (BG_ACTION_EDIT/FG_ACTION_EDIT/BG_ACTION_DELETE/FG_ACTION_DELETE
            # oder Helper-Funktion). Patrick will Sprint 1 fokussiert halten.
            btn_edit = QPushButton("Bearbeiten")
            btn_edit.setFixedHeight(ui_constants.BUTTON_HEIGHT_SMALL)
            btn_edit.setStyleSheet(
                "QPushButton { background-color: #2a5a2a; color: #90ee90;"  # noqa: hex-color-pending — Edit-Action-Button-Pattern, Sprint 2
                " border: none; border-radius: 3px; padding: 0 8px; font-size: 11px; }"
                "QPushButton:hover { background-color: #3a7a3a; }"  # noqa: hex-color-pending
            )
            btn_edit.clicked.connect(lambda _, u=user: self._edit_user(u))

            btn_del = QPushButton("Löschen")
            btn_del.setFixedHeight(ui_constants.BUTTON_HEIGHT_SMALL)
            btn_del.setStyleSheet(
                "QPushButton { background-color: #5a2a2a; color: #ee9090;"  # noqa: hex-color-pending — Delete-Action-Button-Pattern, Sprint 2
                " border: none; border-radius: 3px; padding: 0 8px; font-size: 11px; }"
                "QPushButton:hover { background-color: #7a3a3a; }"  # noqa: hex-color-pending
            )
            btn_del.clicked.connect(lambda _, u=user: self._delete_user(u))

            # Admin kann sich nicht selbst löschen
            if user.username == Session().current_user.username:
                btn_del.setEnabled(False)
                btn_del.setToolTip("Eigenes Konto kann nicht gelöscht werden.")

            actions_layout.addWidget(btn_edit)
            actions_layout.addWidget(btn_del)
            self._tbl_users.setCellWidget(row, 5, actions)

        self._tbl_users.resizeRowsToContents()

    # ==================================================================
    # Tab 2: Benutzer anlegen / bearbeiten
    # ==================================================================
    def _build_tab_form(self) -> QWidget:
        """Erstellt den Formular-Tab für Anlegen/Bearbeiten."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 16, 20, 12)
        layout.setSpacing(10)

        self._form_title = QLabel("Neuer Benutzer")
        self._form_title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold; color: {theme.get().ACCENT};"
        )
        layout.addWidget(self._form_title)

        # Benutzername
        layout.addWidget(QLabel("Benutzername:"))
        self._form_username = QLineEdit()
        self._form_username.setFixedHeight(ui_constants.FORM_INPUT_HEIGHT)
        self._form_username.setStyleSheet(_FIELD_STYLE)
        layout.addWidget(self._form_username)

        # Vollständiger Name
        layout.addWidget(QLabel("Vollständiger Name:"))
        self._form_fullname = QLineEdit()
        self._form_fullname.setFixedHeight(ui_constants.FORM_INPUT_HEIGHT)
        self._form_fullname.setStyleSheet(_FIELD_STYLE)
        layout.addWidget(self._form_fullname)

        # Passwort
        layout.addWidget(QLabel("Passwort (leer lassen = unverändert):"))
        self._form_pw = QLineEdit()
        self._form_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._form_pw.setFixedHeight(ui_constants.FORM_INPUT_HEIGHT)
        self._form_pw.setStyleSheet(_FIELD_STYLE)
        layout.addWidget(self._form_pw)

        layout.addWidget(QLabel("Passwort wiederholen:"))
        self._form_pw2 = QLineEdit()
        self._form_pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self._form_pw2.setFixedHeight(ui_constants.FORM_INPUT_HEIGHT)
        self._form_pw2.setStyleSheet(_FIELD_STYLE)
        layout.addWidget(self._form_pw2)

        # Rolle
        layout.addWidget(QLabel("Rolle:"))
        self._form_role = QComboBox()
        self._form_role.addItems(["user", "admin"])
        self._form_role.setFixedHeight(ui_constants.FORM_INPUT_HEIGHT)
        self._form_role.setStyleSheet(_COMBO_STYLE)
        layout.addWidget(self._form_role)

        # Konto aktiv — vor den Tools, damit es nicht die Liste überlappt
        self._form_active = QCheckBox("Konto aktiv")
        self._form_active.setChecked(True)
        layout.addWidget(self._form_active)

        # Erlaubte Tools
        layout.addWidget(QLabel("Erlaubte Tools (kein Haken = alle Tools erlaubt):"))
        self._form_tools_list = QListWidget()
        self._form_tools_list.setMinimumHeight(160)
        self._form_tools_list.setStyleSheet(
            f"QListWidget {{"
            f"  background-color: {theme.BG_PANEL_DARK};"
            f"  border: 1px solid {theme.get().BORDER};"
            f"  border-radius: 4px;"
            f"  color: {theme.get().TEXT_MAIN};"
            f"}}"
            f"QListWidget::item {{"
            f"  padding: 4px 6px;"
            f"}}"
            f"QListWidget::item:hover {{"
            f"  background-color: rgba(0,212,255,0.08);"
            f"}}"
            f"QListWidget::item:selected {{"
            f"  background-color: rgba(0,212,255,0.15);"
            f"}}"
            # Indikator-Rahmen sichtbar auf dunklem Hintergrund.
            # Kein image: none — damit bleibt der native Haken (✓) erhalten.
            f"QListWidget::indicator {{"
            f"  width: 16px; height: 16px;"
            f"  border: 2px solid {theme.get().BORDER};"
            f"  border-radius: 3px;"
            f"  background-color: {theme.get().BG_MAIN};"
            f"}}"
            f"QListWidget::indicator:checked {{"
            f"  background-color: {theme.get().ACCENT};"
            f"  border-color: {theme.get().ACCENT};"
            f"}}"
            f"QListWidget::indicator:unchecked:hover {{"
            f"  border-color: {theme.get().ACCENT};"
            f"}}"
        )
        for tool_name in self._available_tools:
            item = QListWidgetItem(tool_name)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            self._form_tools_list.addItem(item)
        layout.addWidget(self._form_tools_list)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self._btn_form_cancel = QPushButton("Abbrechen")
        self._btn_form_cancel.setFixedWidth(130)
        self._btn_form_cancel.clicked.connect(self._reset_form)
        btn_row.addWidget(self._btn_form_cancel)

        self._btn_form_save = QPushButton("Speichern")
        self._btn_form_save.setFixedWidth(130)
        self._btn_form_save.setStyleSheet(
            f"QPushButton {{ background-color: {theme.get().ACCENT}; color: {theme.get().BG_DARK};"
            f" border: none; border-radius: 4px; font-weight: bold; }}"
            f"QPushButton:hover {{ background-color: {theme.get().BG_SIDEBAR_HOVER}; }}"
        )
        self._btn_form_save.clicked.connect(self._save_user_form)
        btn_row.addWidget(self._btn_form_save)
        layout.addLayout(btn_row)

        return widget

    # ==================================================================
    # Tab 3: Passwort ändern
    # ==================================================================
    def _build_tab_password(self) -> QWidget:
        """Erstellt den Passwort-Ändern-Tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 16, 20, 12)
        layout.setSpacing(10)

        lbl_title = QLabel("Passwort ändern")
        lbl_title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold; color: {theme.get().ACCENT};"
        )
        layout.addWidget(lbl_title)

        layout.addWidget(QLabel("Aktuelles Passwort:"))
        self._pw_old = QLineEdit()
        self._pw_old.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_old.setFixedHeight(ui_constants.FORM_INPUT_HEIGHT)
        self._pw_old.setStyleSheet(_FIELD_STYLE)
        layout.addWidget(self._pw_old)

        layout.addWidget(QLabel("Neues Passwort:"))
        self._pw_new = QLineEdit()
        self._pw_new.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_new.setFixedHeight(ui_constants.FORM_INPUT_HEIGHT)
        self._pw_new.setStyleSheet(_FIELD_STYLE)
        self._pw_new.textChanged.connect(self._update_strength_indicator)
        layout.addWidget(self._pw_new)

        # Stärke-Anzeige
        self._lbl_strength = QLabel("")
        self._lbl_strength.setStyleSheet("font-size: 12px; font-family: 'Raleway';")
        layout.addWidget(self._lbl_strength)

        layout.addWidget(QLabel("Neues Passwort wiederholen:"))
        self._pw_new2 = QLineEdit()
        self._pw_new2.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_new2.setFixedHeight(ui_constants.FORM_INPUT_HEIGHT)
        self._pw_new2.setStyleSheet(_FIELD_STYLE)
        layout.addWidget(self._pw_new2)

        self._lbl_pw_error = QLabel("")
        self._lbl_pw_error.setStyleSheet(
            f"color: {theme.ERROR_RED}; font-size: 12px;"
        )
        layout.addWidget(self._lbl_pw_error)

        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_change = QPushButton("Passwort ändern")
        btn_change.setFixedWidth(160)
        btn_change.setStyleSheet(
            f"QPushButton {{ background-color: {theme.get().ACCENT}; color: {theme.get().BG_DARK};"
            f" border: none; border-radius: 4px; font-weight: bold; }}"
            f"QPushButton:hover {{ background-color: {theme.get().BG_SIDEBAR_HOVER}; }}"
        )
        btn_change.clicked.connect(self._change_password)
        btn_row.addWidget(btn_change)
        layout.addLayout(btn_row)

        return widget

    # ------------------------------------------------------------------
    # Passwort-Stärke-Anzeige
    # ------------------------------------------------------------------
    def _update_strength_indicator(self, pw: str) -> None:
        """Berechnet und zeigt die Passwort-Stärke an."""
        score = 0
        if len(pw) >= 8:
            score += 1
        if len(pw) >= 12:
            score += 1
        if any(c.isupper() for c in pw):
            score += 1
        if any(c.isdigit() for c in pw):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pw):
            score += 1

        if not pw:
            self._lbl_strength.setText("")
        elif score <= 2:
            self._lbl_strength.setText("Stärke: ● Schwach")
            self._lbl_strength.setStyleSheet(
                f"color: {theme.ERROR_RED}; font-size: 12px;"
            )
        elif score <= 3:
            self._lbl_strength.setText("Stärke: ●● Mittel")
            self._lbl_strength.setStyleSheet(
                f"color: {theme.WARNING_ORANGE}; font-size: 12px;"
            )
        else:
            self._lbl_strength.setText("Stärke: ●●● Stark")
            self._lbl_strength.setStyleSheet(
                f"color: {theme.SUCCESS_GREEN}; font-size: 12px;"
            )

    # ------------------------------------------------------------------
    # Aktionen
    # ------------------------------------------------------------------
    def _new_user(self) -> None:
        """Wechselt in den Tab 'Benutzer anlegen' mit leerem Formular."""
        self._edit_username = None
        self._reset_form()
        self._form_title.setText("Neuer Benutzer")
        self._form_username.setEnabled(True)
        self._tabs.setCurrentIndex(1)

    def _edit_user(self, user: User) -> None:
        """Befüllt das Formular mit den Daten eines Benutzers zum Bearbeiten."""
        self._edit_username = user.username
        self._form_title.setText(f"Benutzer bearbeiten: {user.username}")
        self._form_username.setText(user.username)
        self._form_username.setEnabled(False)
        self._form_fullname.setText(user.full_name)
        self._form_pw.clear()
        self._form_pw2.clear()

        idx = self._form_role.findText(user.role)
        if idx >= 0:
            self._form_role.setCurrentIndex(idx)

        # Tool-Checkboxen setzen
        for i in range(self._form_tools_list.count()):
            item = self._form_tools_list.item(i)
            state = (
                Qt.CheckState.Checked
                if item.text() in user.allowed_tools
                else Qt.CheckState.Unchecked
            )
            item.setCheckState(state)

        self._form_active.setChecked(user.is_active)
        self._tabs.setCurrentIndex(1)

    def _delete_user(self, user: User) -> None:
        """Löscht einen Benutzer nach Bestätigung."""
        dlg = FinlaiConfirmDialog(
            title="Benutzer löschen",
            message=(
                f"Benutzer '{user.username}' wirklich löschen?\n"
                "Diese Aktion kann nicht rückgängig gemacht werden."
            ),
            confirm_text="Löschen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._store.delete_user(user.username)
            log.info("Benutzer gelöscht: %s", user.username)
            self._refresh_user_table()
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Löschen nicht möglich",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()

    def _reset_form(self) -> None:
        """Setzt das Formular auf Leerzustand zurück."""
        self._edit_username = None
        self._form_title.setText("Neuer Benutzer")
        self._form_username.clear()
        self._form_username.setEnabled(True)
        self._form_fullname.clear()
        self._form_pw.clear()
        self._form_pw2.clear()
        self._form_role.setCurrentIndex(0)
        self._form_active.setChecked(True)
        for i in range(self._form_tools_list.count()):
            self._form_tools_list.item(i).setCheckState(Qt.CheckState.Unchecked)

    def _save_user_form(self) -> None:
        """Speichert das Formular als neuen oder bearbeiteten Benutzer."""
        username = self._form_username.text().strip()
        full_name = self._form_fullname.text().strip()
        password = self._form_pw.text()
        password2 = self._form_pw2.text()
        role = self._form_role.currentText()
        is_active = self._form_active.isChecked()

        allowed_tools = [
            self._form_tools_list.item(i).text()
            for i in range(self._form_tools_list.count())
            if self._form_tools_list.item(i).checkState() == Qt.CheckState.Checked
        ]

        # Validierung
        if not username or not full_name:
            FinlaiInfoDialog(
                title="Eingabe fehlt",
                message="Benutzername und Name sind Pflichtfelder.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return

        if password != password2:
            FinlaiInfoDialog(
                title="Passwort-Fehler",
                message="Die Passwörter stimmen nicht überein.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return

        if self._edit_username is None and not password:
            FinlaiInfoDialog(
                title="Passwort fehlt",
                message="Bitte Passwort für neuen Benutzer eingeben.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return

        try:
            if self._edit_username is None:
                # Neuer Benutzer
                self._store.create_user(
                    username, password, role, full_name, allowed_tools
                )
                FinlaiSuccessDialog(
                    title="Gespeichert",
                    message=f"Benutzer '{username}' erfolgreich angelegt.",
                    parent=self,
                ).exec()
            else:
                # Bestehenden Benutzer aktualisieren
                self._store.update_user(
                    self._edit_username,
                    full_name=full_name,
                    allowed_tools=allowed_tools,
                    is_active=is_active,
                )
                self._store.set_role(self._edit_username, role)
                if password:
                    self._store.set_password_admin(self._edit_username, password)
                FinlaiSuccessDialog(
                    title="Gespeichert",
                    message=f"Benutzer '{self._edit_username}' aktualisiert.",
                    parent=self,
                ).exec()

            self._reset_form()
            self._refresh_user_table()
            self._tabs.setCurrentIndex(0)

        except (ValueError, KeyError) as exc:
            FinlaiInfoDialog(
                title="Fehler",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()

    def _change_password(self) -> None:
        """Führt die Passwortänderung für den aktuellen Benutzer durch."""
        old_pw = self._pw_old.text()
        new_pw = self._pw_new.text()
        new_pw2 = self._pw_new2.text()

        if not old_pw or not new_pw or not new_pw2:
            self._lbl_pw_error.setText("Alle Felder müssen ausgefüllt sein.")
            return

        if new_pw != new_pw2:
            self._lbl_pw_error.setText("Die neuen Passwörter stimmen nicht überein.")
            return

        if len(new_pw) < 6:
            self._lbl_pw_error.setText("Das Passwort muss mindestens 6 Zeichen haben.")
            return

        current_user = Session().current_user
        if current_user is None:
            return

        success = self._store.change_password(current_user.username, old_pw, new_pw)
        if success:
            self._lbl_pw_error.setStyleSheet(
                f"color: {theme.SUCCESS_GREEN}; font-size: 12px;"
            )
            self._lbl_pw_error.setText("OK: Passwort erfolgreich geändert.")
            self._pw_old.clear()
            self._pw_new.clear()
            self._pw_new2.clear()
        else:
            self._lbl_pw_error.setStyleSheet(
                f"color: {theme.ERROR_RED}; font-size: 12px;"
            )
            self._lbl_pw_error.setText("Das aktuelle Passwort ist falsch.")
