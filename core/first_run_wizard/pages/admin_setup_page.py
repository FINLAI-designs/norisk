"""Admin-Einrichtungs-Seite — der Kern des First-Run-Wizards.

Erfasst Vorname, Benutzername, E-Mail, Anzeigename und Passwort (zweimal).
Validiert die Eingaben live und emittiert:attr:`completion_changed`, damit
der Wizard den „Weiter"-Button aktiviert.

Validierungsregeln
------------------
* Vorname: 2–30 Zeichen, nur Buchstaben (inkl. Umlaute/ß), Leerzeichen,
  Bindestriche und Apostrophe.
* Benutzername: 3–30 Zeichen, keine Leerzeichen, nicht reserviert
  (``admin`` / ``administrator`` / ``root`` / ``system``).
  Wird aus dem Vornamen automatisch vorgeschlagen (Umlaute transliteriert),
  sobald der User das Feld nicht bereits manuell editiert hat.
* E-Mail: Standard-Regex, zusätzlich Typo-Warnung für gängige Fehldomains
  (``gmial.com``, ``gmai.com``, ``yaho.com``, ``hotnail.com``).
* Anzeigename: nicht leer.
* Passwort: min. 8 Zeichen, min. 1 Buchstabe, min. 1 Ziffer (NIST-Basis).
* Passwort-Wiederholung: muss übereinstimmen.

Bei:meth:`commit` wird der Benutzer via:class:`UserStore` angelegt
und ein Audit-Event ``FIRST_RUN_USER_CREATED`` geschrieben.
"""

from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QLineEdit, QVBoxLayout, QWidget

from core.audit_log import AuditLogger
from core.auth.user_store import UserStore
from core.exceptions import ValidationError
from core.first_run_wizard.pages.base_page import BasePage
from core.logger import get_logger
from core.theme import (
    ACCENT_HOVER,
    BG_PANEL_DARK,
    DARK_ACCENT,
    DARK_BORDER,
    DARK_ERROR,
    DARK_TEXT_PRIMARY,
    DARK_TEXT_SECONDARY,
    DARK_WARNING,
)

log = get_logger(__name__)

RESERVED_USERNAMES = frozenset({"admin", "administrator", "root", "system"})
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 30
MIN_PASSWORD_LENGTH = 8
MIN_FIRST_NAME_LENGTH = 2
MAX_FIRST_NAME_LENGTH = 30

_FIRST_NAME_RE = re.compile(r"^[A-Za-zÄÖÜäöüß\s\-']{2,30}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

_EMAIL_TYPO_DOMAINS = {
    "gmial.com": "gmail.com",
    "gmai.com": "gmail.com",
    "gnail.com": "gmail.com",
    "yaho.com": "yahoo.com",
    "yahooo.com": "yahoo.com",
    "hotnail.com": "hotmail.com",
    "hotmai.com": "hotmail.com",
    "outlok.com": "outlook.com",
}

_UMLAUT_MAP = str.maketrans(
    {
        "ä": "ae",
        "ö": "oe",
        "ü": "ue",
        "ß": "ss",
        "Ä": "Ae",
        "Ö": "Oe",
        "Ü": "Ue",
    }
)


def suggest_username(first_name: str) -> str:
    """Leitet einen Benutzernamens-Vorschlag aus dem Vornamen ab.

    Umlaute werden transliteriert (``ä``→``ae``, ``ö``→``oe``, ``ü``→``ue``,
    ``ß``→``ss``). Leerzeichen, Bindestriche und Apostrophe werden entfernt,
    der Rest wird klein geschrieben.
    """
    cleaned = first_name.strip().translate(_UMLAUT_MAP)
    cleaned = re.sub(r"[\s\-']", "", cleaned)
    return cleaned.lower()


def validate_first_name(first_name: str) -> str | None:
    """Prüft den Vornamen. Gibt Fehlermeldung oder ``None`` zurück."""
    if not first_name:
        return "Vorname darf nicht leer sein."
    if len(first_name) < MIN_FIRST_NAME_LENGTH:
        return f"Vorname muss mindestens {MIN_FIRST_NAME_LENGTH} Zeichen lang sein."
    if len(first_name) > MAX_FIRST_NAME_LENGTH:
        return f"Vorname darf maximal {MAX_FIRST_NAME_LENGTH} Zeichen lang sein."
    if not _FIRST_NAME_RE.match(first_name):
        return "Vorname enthält ungültige Zeichen."
    return None


def validate_username(username: str) -> str | None:
    """Prüft den Benutzernamen. Gibt Fehlermeldung oder ``None`` zurück."""
    if not username:
        return "Benutzername darf nicht leer sein."
    if " " in username or "\t" in username:
        return "Benutzername darf keine Leerzeichen enthalten."
    if len(username) < MIN_USERNAME_LENGTH:
        return f"Benutzername muss mindestens {MIN_USERNAME_LENGTH} Zeichen lang sein."
    if len(username) > MAX_USERNAME_LENGTH:
        return f"Benutzername darf maximal {MAX_USERNAME_LENGTH} Zeichen lang sein."
    if username.lower() in RESERVED_USERNAMES:
        return f"'{username}' ist reserviert. Bitte einen anderen Namen wählen."
    return None


def validate_email(email: str) -> str | None:
    """Prüft die E-Mail-Adresse. Gibt Fehlermeldung oder ``None`` zurück."""
    if not email:
        return "E-Mail darf nicht leer sein."
    if not _EMAIL_RE.match(email):
        return "Bitte eine gültige E-Mail-Adresse eingeben."
    return None


def email_typo_hint(email: str) -> str | None:
    """Gibt eine Korrekturempfehlung zurück, wenn die Domain nach Typo aussieht."""
    at = email.rfind("@")
    if at == -1 or at == len(email) - 1:
        return None
    domain = email[at + 1 :].lower()
    suggestion = _EMAIL_TYPO_DOMAINS.get(domain)
    if suggestion is None:
        return None
    return f"Meintest du '{email[: at + 1]}{suggestion}'?"


def validate_password(password: str) -> str | None:
    """Prüft das Passwort. Gibt Fehlermeldung oder ``None`` zurück."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Passwort muss mindestens {MIN_PASSWORD_LENGTH} Zeichen lang sein."
    if not any(c.isalpha() for c in password):
        return "Passwort muss mindestens einen Buchstaben enthalten."
    if not any(c.isdigit() for c in password):
        return "Passwort muss mindestens eine Ziffer enthalten."
    return None


class AdminSetupPage(BasePage):
    """Eingabeseite für Admin-Konto."""

    TITLE = "Administrator-Konto"

    def __init__(self, user_store: UserStore | None = None) -> None:
        super().__init__()
        self._user_store = user_store or UserStore()
        self._created_username: str | None = None
        self._created_first_name: str = ""
        self._username_manually_edited = False

        title = QLabel("Administrator-Konto einrichten")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 20px; font-weight: bold;"
            f" color: {DARK_ACCENT};"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hint = QLabel(
            "Lege den ersten Administrator an. Das Passwort wird "
            "ausschließlich lokal als bcrypt-Hash gespeichert."
        )
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {DARK_TEXT_SECONDARY};"
        )

        self._first_name = QLineEdit()
        self._first_name.setPlaceholderText("Vorname (z. B. Max)")
        self._first_name.setFixedHeight(36)

        self._username = QLineEdit()
        self._username.setPlaceholderText("Benutzername (min. 3 Zeichen)")
        self._username.setFixedHeight(36)

        self._email = QLineEdit()
        self._email.setPlaceholderText("E-Mail-Adresse")
        self._email.setFixedHeight(36)

        self._full_name = QLineEdit()
        self._full_name.setPlaceholderText("Anzeigename (z. B. Max Mustermann)")
        self._full_name.setFixedHeight(36)

        self._password = QLineEdit()
        self._password.setPlaceholderText("Passwort (min. 8 Zeichen, Buchstabe + Ziffer)")
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._password.setFixedHeight(36)

        self._password_repeat = QLineEdit()
        self._password_repeat.setPlaceholderText("Passwort wiederholen")
        self._password_repeat.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_repeat.setFixedHeight(36)

        self._error_label = QLabel(" ")
        self._error_label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {DARK_ERROR};"
        )
        self._error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._error_label.setMinimumHeight(18)

        self._hint_label = QLabel(" ")
        self._hint_label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 11px; color: {DARK_WARNING};"
        )
        self._hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._hint_label.setMinimumHeight(16)

        field_style = (
            "QLineEdit {"
            f" background-color: {BG_PANEL_DARK}; border: 1px solid {DARK_BORDER};"
            f" color: {DARK_TEXT_PRIMARY}; border-radius: 6px; padding: 6px 10px;"
            " font-family: 'Raleway'; font-size: 13px;"
            f"}} QLineEdit:focus {{ border: 1px solid {ACCENT_HOVER}; }}"
        )
        for field in (
            self._first_name,
            self._username,
            self._email,
            self._full_name,
            self._password,
            self._password_repeat,
        ):
            field.setStyleSheet(field_style)

        self._first_name.textChanged.connect(self._on_first_name_changed)
        self._username.textEdited.connect(self._on_username_edited)
        self._username.textChanged.connect(self._revalidate)
        self._email.textChanged.connect(self._revalidate)
        self._full_name.textChanged.connect(self._revalidate)
        self._password.textChanged.connect(self._revalidate)
        self._password_repeat.textChanged.connect(self._revalidate)

        form = QWidget()
        form_layout = QVBoxLayout(form)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(10)
        form_layout.addWidget(self._first_name)
        form_layout.addWidget(self._username)
        form_layout.addWidget(self._email)
        form_layout.addWidget(self._full_name)
        form_layout.addWidget(self._password)
        form_layout.addWidget(self._password_repeat)

        self._layout.addStretch(1)
        self._layout.addWidget(title)
        self._layout.addWidget(hint)
        self._layout.addSpacing(12)
        self._layout.addWidget(form)
        self._layout.addWidget(self._hint_label)
        self._layout.addWidget(self._error_label)
        self._layout.addStretch(2)

    # ------------------------------------------------------------------
    # Auto-Suggest
    # ------------------------------------------------------------------

    def _on_first_name_changed(self, text: str) -> None:
        """Aktualisiert den Username-Vorschlag, solange unbearbeitet."""
        if not self._username_manually_edited:
            suggestion = suggest_username(text)
            # Signals blockieren, damit textEdited NICHT triggert.
            self._username.blockSignals(True)
            self._username.setText(suggestion)
            self._username.blockSignals(False)
        self._revalidate()

    def _on_username_edited(self, _text: str) -> None:
        """Markiert den Username als manuell bearbeitet (stoppt Autosuggest)."""
        self._username_manually_edited = True

    # ------------------------------------------------------------------
    # Validierung
    # ------------------------------------------------------------------

    def _current_error(self) -> str | None:
        """Gibt den ersten Validierungsfehler zurück — oder ``None``."""
        first_name = self._first_name.text().strip()
        username = self._username.text().strip()
        email = self._email.text().strip()
        full_name = self._full_name.text().strip()
        password = self._password.text()
        password_repeat = self._password_repeat.text()

        err = validate_first_name(first_name)
        if err is not None:
            return err
        err = validate_username(username)
        if err is not None:
            return err
        err = validate_email(email)
        if err is not None:
            return err
        if not full_name:
            return "Anzeigename darf nicht leer sein."
        err = validate_password(password)
        if err is not None:
            return err
        if password != password_repeat:
            return "Die Passwörter stimmen nicht überein."
        return None

    def _revalidate(self) -> None:
        """Aktualisiert Fehlerlabel und emittiert ``completion_changed``."""
        err = self._current_error()
        any_input = any(
            f.text()
            for f in (
                self._first_name,
                self._username,
                self._email,
                self._full_name,
                self._password,
                self._password_repeat,
            )
        )
        self._error_label.setText(err if err and any_input else " ")

        typo = email_typo_hint(self._email.text().strip())
        self._hint_label.setText(typo if typo else " ")

        self.completion_changed.emit(err is None)

    def is_complete(self) -> bool:
        return self._current_error() is None

    # ------------------------------------------------------------------
    # Persistenz
    # ------------------------------------------------------------------

    def commit(self) -> None:
        """Legt den Admin-Benutzer an und protokolliert das Ereignis."""
        err = self._current_error()
        if err is not None:
            raise ValidationError(err)

        first_name = self._first_name.text().strip()
        username = self._username.text().strip()
        email = self._email.text().strip()
        full_name = self._full_name.text().strip()
        password = self._password.text()

        # Aktive App-Config zur Laufzeit aufloesen, damit der
        # ``created_by_app``-Marker in users.json gesetzt wird (filtert die
        # geteilte ~/.finlai/users.json auf echte Build-User). Lokaler Import
        # vermeidet Zirkular-Abhaengigkeiten zwischen apps/ und core/.
        from apps.app_config import get_active_config  # noqa: PLC0415

        active_config = get_active_config()
        created_by_app = active_config.app_id if active_config else ""

        try:
            self._user_store.create_user(
                username=username,
                password=password,
                role="admin",
                full_name=full_name,
                allowed_tools=[],
                first_name=first_name,
                email=email,
                created_by_app=created_by_app,
            )
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

        self._cleanup_placeholder_admin(new_username=username)

        self._created_username = username
        self._created_first_name = first_name
        AuditLogger().log_action(
            "FIRST_RUN_USER_CREATED",
            {
                "username": username,
                "role": "admin",
                "first_name": first_name,
                "email": email,
            },
        )
        log.info("First-Run-Wizard: Admin-Konto '%s' erstellt.", username)

    def _cleanup_placeholder_admin(self, *, new_username: str) -> None:
        """Entfernt das Default-'admin'-Konto, falls es nur ein Placeholder ist.

        Das Placeholder-Konto wird beim ersten ``UserStore``-Aufruf
        automatisch mit leerem Passwort angelegt. Nachdem die echte
        Ersteinrichtung einen anderen Admin erzeugt hat, ist der
        Platzhalter überflüssig und würde nur Verwirrung stiften
        (z. B. in der Benutzerverwaltung).

        Es wird NUR gelöscht, wenn alle drei Bedingungen erfüllt sind:
            * Der neu angelegte Benutzer heißt nicht 'admin'.
            * Der alte 'admin'-Eintrag existiert.
            * Der alte Eintrag hat leeres ``password_hash`` und
              ``requires_setup=True`` (= Auto-Placeholder).
        """
        if new_username.lower() == "admin":
            return

        placeholder = self._user_store.get_user("admin")
        if placeholder is None:
            return
        if placeholder.password_hash:
            return  # Echter Admin-Account — nicht anfassen.

        # Das ``requires_setup``-Flag steht nicht im User-Dataclass-Modell,
        # daher direkt über den Store-internen Datenzugriff prüfen.
        raw = self._user_store._load().get("admin", {})  # noqa: SLF001
        if not raw.get("requires_setup"):
            return

        try:
            self._user_store.delete_user("admin")
            log.info("First-Run-Wizard: Default-Admin-Platzhalter entfernt.")
        except (ValueError, KeyError) as exc:
            log.warning("Platzhalter-Admin konnte nicht entfernt werden: %s", exc)

    @property
    def created_username(self) -> str | None:
        """Gibt den erfolgreich angelegten Benutzernamen zurück (oder ``None``)."""
        return self._created_username

    @property
    def created_first_name(self) -> str:
        """Gibt den Vornamen des angelegten Benutzers zurück."""
        return self._created_first_name
