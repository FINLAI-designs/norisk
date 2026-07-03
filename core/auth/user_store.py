"""
user_store — Benutzerverwaltung für FINLAI

Liest und schreibt Benutzerkonten aus ``~/.finlai/users.json``.
Passwörter werden ausschließlich als bcrypt-Hash gespeichert.

Beim ersten Start wird ein Administrator-Konto OHNE Passwort angelegt.
Der Benutzer muss beim ersten Login ein sicheres Passwort festlegen
(Ersteinrichtungs-Dialog). Kein hardcodiertes Default-Passwort.

Abhängigkeit:
    pip install bcrypt

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path

import bcrypt

from core.audit_log import AuditLogger
from core.auth.models import User
from core.exceptions import ValidationError
from core.finlai_paths import finlai_dir
from core.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------
_FINLAI_DIR = finlai_dir()
_USERS_FILE = _FINLAI_DIR / "users.json"
_DEFAULT_ADMIN_USER = "admin"

# Rotierende Backups von users.json — verhindert Datenverlust wenn die
# Datei versehentlich geloescht oder von einem Test ueberschrieben wird.
_BACKUP_PREFIX = "users.json.bak."
_BACKUP_KEEP = 5


# Felder die über update_user geändert werden dürfen.
# NIEMALS über update_user änderbar:
# role → nur über set_role
# password_hash → nur über change_password / set_password_admin
# username → unveränderlich
# created_at → unveränderlich
_UPDATEABLE_FIELDS: frozenset[str] = frozenset(
    {"display_name", "email", "full_name", "allowed_tools", "is_active"}
)


class UserStore:
    """Verwaltet Benutzerkonten in ``~/.finlai/users.json``.

    Passwörter werden niemals im Klartext gespeichert — ausschließlich
    als bcrypt-Hash. Beim ersten Aufruf wird das Verzeichnis und ein
    Standard-Administratorkonto automatisch erstellt.

    Beispiel::

        store = UserStore
        user = store.authenticate("admin", "finLai2026!")
        if user:
            log.info("Angemeldet: %s", user.full_name)
    """

    def __init__(self) -> None:
        """Initialisiert den UserStore und erstellt bei Bedarf den Admin-Account.

        Existiert keine ``users.json``, wird ein Placeholder-Admin angelegt.
        Falls dabei Backups gefunden werden, wird eine Warnung geloggt mit
        Hinweis auf die Wiederherstellungs-Pfade — die Datei wird nicht
        automatisch wiederhergestellt, der Benutzer entscheidet selbst.
        """
        _FINLAI_DIR.mkdir(parents=True, exist_ok=True)
        if not _USERS_FILE.exists():
            backups = self._list_backups()
            if backups:
                log.warning(
                    "users.json fehlt, aber %d Backup(s) gefunden — "
                    "neuester: %s. Restore manuell via "
                    "'cp %s ~/.finlai/users.json'.",
                    len(backups),
                    backups[0].name,
                    backups[0].name,
                )
            else:
                log.info("Keine Benutzerdatei gefunden — erstelle Standard-Admin.")
            self._create_default_admin()

    # ------------------------------------------------------------------
    # Interne Hilfsmethoden
    # ------------------------------------------------------------------
    def _load(self) -> dict[str, dict]:
        """Lädt alle Benutzer aus der JSON-Datei.

        Sec-3-Fix (Code-Review 2026-05-19): vorher nacktes ``except Exception``
        — das verschluckte auch KeyboardInterrupt + MemoryError + Programm-
        Bugs. Jetzt nur die zwei realistischen Failure-Modes (Datei nicht
        lesbar, JSON kaputt). Andere Exceptions propagieren.
        """
        if not _USERS_FILE.exists():
            return {}
        try:
            return json.loads(_USERS_FILE.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Benutzerdatei konnte nicht geladen werden: %s", exc)
            return {}

    def _save(self, data: dict[str, dict]) -> None:
        """Schreibt alle Benutzer in die JSON-Datei.

        Vor jedem Schreibvorgang wird die bestehende Datei als rotierendes
        Backup gesichert (``users.json.bak.<timestamp>``). Die letzten
        ``_BACKUP_KEEP`` Backups bleiben erhalten, aeltere werden geloescht.
        So kann ein versehentlich geloeschter User aus einem Backup
        wiederhergestellt werden.
        """
        self._rotate_backups()
        try:
            _USERS_FILE.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            log.error("Benutzerdatei konnte nicht gespeichert werden: %s", exc)
            raise

    def _rotate_backups(self) -> None:
        """Erzeugt ein Backup der aktuellen users.json und haelt max. ``_BACKUP_KEEP``."""
        if not _USERS_FILE.exists():
            return
        try:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup = _FINLAI_DIR / f"{_BACKUP_PREFIX}{stamp}"
            if not backup.exists():
                shutil.copy2(_USERS_FILE, backup)
            backups = sorted(
                _FINLAI_DIR.glob(f"{_BACKUP_PREFIX}*"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in backups[_BACKUP_KEEP:]:
                try:
                    old.unlink()
                except OSError as exc:
                    log.warning("Altes Backup konnte nicht geloescht werden: %s", exc)
        except OSError as exc:
            log.warning("Backup von users.json fehlgeschlagen: %s", exc)

    @staticmethod
    def _list_backups() -> list[Path]:
        """Listet vorhandene Backups sortiert nach mtime (neueste zuerst)."""
        if not _FINLAI_DIR.exists():
            return []
        return sorted(
            _FINLAI_DIR.glob(f"{_BACKUP_PREFIX}*"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

    def _dict_to_user(self, d: dict) -> User:
        """Konvertiert ein Dictionary in ein User-Objekt.

        Backward-Compat: Alt-User ohne ``first_name``/``email``/
        ``recovery_code_hash`` bekommen leere Strings — kein None.
        """
        return User(
            username=d["username"],
            password_hash=d["password_hash"],
            role=d["role"],
            full_name=d["full_name"],
            allowed_tools=d.get("allowed_tools", []),
            last_login=d.get("last_login"),
            created_at=d.get("created_at", ""),
            is_active=d.get("is_active", True),
            first_name=d.get("first_name", "") or "",
            email=d.get("email", "") or "",
            recovery_code_hash=d.get("recovery_code_hash", "") or "",
            created_by_app=d.get("created_by_app", "") or "",
        )

    def _user_to_dict(self, user: User) -> dict:
        """Konvertiert ein User-Objekt in ein Dictionary."""
        return {
            "username": user.username,
            "password_hash": user.password_hash,
            "role": user.role,
            "full_name": user.full_name,
            "allowed_tools": user.allowed_tools,
            "last_login": user.last_login,
            "created_at": user.created_at,
            "is_active": user.is_active,
            "first_name": user.first_name,
            "email": user.email,
            "recovery_code_hash": user.recovery_code_hash,
            "created_by_app": user.created_by_app,
        }

    def _create_default_admin(self) -> None:
        """Erstellt Admin-Konto ohne Passwort beim ersten Start.

        Setzt ``requires_setup=True`` — der Benutzer muss beim ersten
        Login ein sicheres Passwort festlegen. Kein Default-Passwort.
        """
        try:
            initial_user: dict = {
                "username": _DEFAULT_ADMIN_USER,
                "password_hash": "",
                "role": "admin",
                "full_name": "Administrator",
                "allowed_tools": [],
                "last_login": None,
                "is_active": True,
                "requires_setup": True,
                "created_at": datetime.now().isoformat(timespec="seconds"),
            }
            self._save({_DEFAULT_ADMIN_USER: initial_user})
            log.info("Admin-Konto erstellt. Passwort wird beim ersten Login gesetzt.")
        except Exception as exc:
            log.error("Admin-Konto konnte nicht erstellt werden: %s", exc)

    # ------------------------------------------------------------------
    # Öffentliche API
    # ------------------------------------------------------------------
    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        full_name: str,
        allowed_tools: list[str],
        first_name: str = "",
        email: str = "",
        recovery_code_hash: str = "",
        created_by_app: str = "",
    ) -> User:
        """Erstellt ein neues Benutzerkonto.

        Args:
            username: Eindeutiger Benutzername.
            password: Passwort im Klartext (wird sofort gehasht).
            role: ``"admin"`` oder ``"user"``.
            full_name: Vollständiger Anzeigename.
            allowed_tools: Liste erlaubter Tool-Namen, leer = alle.
            first_name: Vorname — seit First-Run-Wizard v2 gepflegt.
            email: E-Mail-Adresse — seit First-Run-Wizard v2 gepflegt.
            recovery_code_hash: bcrypt-Hash des einmaligen Recovery-Codes.
                                Leerer String = kein Reset per Recovery-Code möglich.
            created_by_app: — app_id der anlegenden App. Markiert den
                                User in der geteilten ``users.json`` als echten
                                Build-User (Default leer für Legacy-Aufrufer).

        Returns:
            Das neu erstellte User-Objekt.

        Raises:
            ValueError: Falls der Benutzername bereits vergeben ist.
        """
        data = self._load()
        if username in data:
            raise ValidationError(f"Benutzername '{username}' ist bereits vergeben.")

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )

        user = User(
            username=username,
            password_hash=pw_hash,
            role=role,
            full_name=full_name,
            allowed_tools=allowed_tools,
            last_login=None,
            created_at=datetime.now().isoformat(timespec="seconds"),
            is_active=True,
            first_name=first_name,
            email=email,
            recovery_code_hash=recovery_code_hash,
            created_by_app=created_by_app,
        )
        data[username] = self._user_to_dict(user)
        self._save(data)
        log.info("Benutzer erstellt: %s (%s)", username, role)
        return user

    def authenticate(self, username: str, password: str) -> User | None:
        """Authentifiziert einen Benutzer mit Benutzername und Passwort.

        Args:
            username: Benutzername.
            password: Passwort im Klartext.

        Returns:
            Das User-Objekt bei Erfolg, None bei falschem Passwort oder
            gesperrtem Konto.
        """
        data = self._load()
        if username not in data:
            return None

        user_data = data[username]
        if not user_data.get("is_active", True):
            log.warning("Login-Versuch für gesperrtes Konto: %s", username)
            return None

        stored_hash_str = user_data.get("password_hash", "")
        if not stored_hash_str:
            # Kein Passwort gesetzt — Ersteinrichtung erforderlich
            log.warning("Login ohne gesetztes Passwort: %s", username)
            return None

        if bcrypt.checkpw(password.encode("utf-8"), stored_hash_str.encode("utf-8")):
            log.info("Authentifizierung erfolgreich: %s", username)
            return self._dict_to_user(user_data)

        return None

    def get_all_users(self) -> list[User]:
        """Gibt alle Benutzerkonten zurück.

        Returns:
            Liste aller User-Objekte.
        """
        return [self._dict_to_user(d) for d in self._load().values()]

    def update_user(self, username: str, **kwargs) -> User:
        """Aktualisiert erlaubte Felder eines Benutzerkontos.

        Args:
            username: Benutzername des zu aktualisierenden Kontos.
            **kwargs: Nur Felder aus ``_UPDATEABLE_FIELDS`` erlaubt.
                Sensible Felder wie ``role`` und ``password_hash``
                werden hier niemals akzeptiert.

        Returns:
            Das aktualisierte User-Objekt.

        Raises:
            ValueError: Bei unerlaubten Feldern.
            KeyError: Falls der Benutzer nicht existiert.
        """
        invalid = set(kwargs.keys()) - _UPDATEABLE_FIELDS
        if invalid:
            raise ValidationError(
                f"Nicht erlaubte Felder: {invalid}. Erlaubt: {_UPDATEABLE_FIELDS}"
            )
        data = self._load()
        if username not in data:
            raise KeyError(f"Benutzer '{username}' nicht gefunden.")
        for field, value in kwargs.items():
            data[username][field] = value
        self._save(data)
        AuditLogger().log_action(
            "USER_UPDATED",
            {"username": username, "fields": list(kwargs.keys())},
        )
        log.debug("Benutzer aktualisiert: %s", username)
        return self._dict_to_user(data[username])

    def delete_user(self, username: str) -> None:
        """Löscht ein Benutzerkonto.

        Args:
            username: Benutzername des zu löschenden Kontos.

        Raises:
            KeyError: Falls der Benutzer nicht existiert.
            ValueError: Falls versucht wird den letzten Admin zu löschen.
        """
        data = self._load()
        if username not in data:
            raise KeyError(f"Benutzer '{username}' nicht gefunden.")

        # Sicherstellen dass mindestens ein Admin übrig bleibt
        remaining_admins = sum(
            1
            for u in data.values()
            if u["role"] == "admin" and u["username"] != username
        )
        if data[username]["role"] == "admin" and remaining_admins == 0:
            raise ValidationError("Der letzte Administrator kann nicht gelöscht werden.")

        del data[username]
        self._save(data)
        log.info("Benutzer gelöscht: %s", username)

    def change_password(self, username: str, old_pw: str, new_pw: str) -> bool:
        """Ändert das Passwort eines Benutzers nach Prüfung des alten Passworts.

        Args:
            username: Benutzername.
            old_pw: Aktuelles Passwort im Klartext.
            new_pw: Neues Passwort im Klartext (min. 8 Zeichen).

        Returns:
            True bei Erfolg, False wenn das alte Passwort falsch ist.

        Raises:
            ValueError: Falls ``new_pw`` kürzer als 8 Zeichen ist.
        """
        data = self._load()
        if username not in data:
            return False

        stored_hash_str = data[username].get("password_hash", "")
        if not stored_hash_str:
            return False  # Kein Passwort gesetzt — Ersteinrichtung verwenden

        if not bcrypt.checkpw(old_pw.encode("utf-8"), stored_hash_str.encode("utf-8")):
            log.warning(
                "Passwortänderung fehlgeschlagen (falsches altes Passwort): %s",
                username,
            )
            return False

        if len(new_pw) < 8:
            raise ValidationError("Passwort zu kurz (min. 8 Zeichen).")

        new_hash = bcrypt.hashpw(new_pw.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )
        data[username]["password_hash"] = new_hash
        self._save(data)
        log.info("Passwort geändert für: %s", username)
        return True

    def set_password_admin(self, username: str, new_pw: str) -> None:
        """Setzt das Passwort eines Benutzers ohne Prüfung des alten Passworts.

        Nur für Administratoren gedacht.

        Args:
            username: Benutzername.
            new_pw: Neues Passwort im Klartext (min. 8 Zeichen).

        Raises:
            ValueError: Falls ``new_pw`` kürzer als 8 Zeichen ist.
            KeyError: Falls der Benutzer nicht existiert.
        """
        data = self._load()
        if username not in data:
            raise KeyError(f"Benutzer '{username}' nicht gefunden.")
        if len(new_pw) < 8:
            raise ValidationError("Passwort zu kurz (min. 8 Zeichen).")
        new_hash = bcrypt.hashpw(new_pw.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )
        data[username]["password_hash"] = new_hash
        self._save(data)
        log.info("Passwort (Admin) gesetzt für: %s", username)

    def set_recovery_code_hash(self, username: str, code_hash: str) -> None:
        """Speichert den bcrypt-Hash des Recovery-Codes für einen Benutzer.

        Der Klartext-Code wird im First-Run-Wizard erzeugt und dem Benutzer
        einmalig angezeigt — nur der Hash landet hier.

        Args:
            username: Benutzername.
            code_hash: bcrypt-Hash (bereits mit Cost-Factor 12 gehashed).

        Raises:
            KeyError: Falls der Benutzer nicht existiert.
            ValueError: Falls ``code_hash`` leer ist oder kein bcrypt-Hash.
        """
        if not code_hash or not code_hash.startswith("$2"):
            raise ValidationError("Ungültiger bcrypt-Hash für Recovery-Code.")
        data = self._load()
        if username not in data:
            raise KeyError(f"Benutzer '{username}' nicht gefunden.")
        data[username]["recovery_code_hash"] = code_hash
        self._save(data)
        log.info("Recovery-Code-Hash gespeichert für: %s", username)

    def set_role(self, username: str, role: str) -> None:
        """Ändert die Benutzerrolle.

        Dies ist die einzige Methode die ``role`` ändern darf.

        Args:
            username: Benutzername.
            role: ``"admin"`` oder ``"user"``.

        Raises:
            ValueError: Falls die Rolle ungültig oder der User nicht
                gefunden wurde.
        """
        if role not in {"admin", "user"}:
            raise ValidationError(f"Ungültige Rolle: {role!r}. Erlaubt: 'admin', 'user'.")
        data = self._load()
        if username not in data:
            raise ValidationError(f"User '{username}' nicht gefunden.")
        data[username]["role"] = role
        self._save(data)
        AuditLogger().log_action(
            "ROLE_CHANGED", {"username": username, "new_role": role}
        )
        log.info("Rolle geändert: %s → %s", username, role)

    def get_user(self, username: str) -> User | None:
        """Gibt ein User-Objekt zurück ohne Passwort-Prüfung.

        Args:
            username: Benutzername.

        Returns:
            Das User-Objekt oder None wenn nicht gefunden.
        """
        data = self._load()
        if username not in data:
            return None
        return self._dict_to_user(data[username])

    def requires_password_setup(self, username: str) -> bool:
        """Prüft ob der User ein Passwort festlegen muss.

        Returns:
            True wenn ``requires_setup`` gesetzt oder ``password_hash`` leer ist.
        """
        users = self._load()
        if username not in users:
            return False
        user = users[username]
        return bool(
            user.get("requires_setup", False) or not user.get("password_hash", "")
        )

    def complete_setup(self, username: str, new_password: str) -> None:
        """Schließt die Ersteinrichtung ab und setzt das Passwort.

        Args:
            username: Benutzername.
            new_password: Neues Passwort (min. 10 Zeichen, 1 Zahl,
                          1 Sonderzeichen).

        Raises:
            ValueError: Bei zu schwachem Passwort oder unbekanntem User.
        """
        self._validate_password_strength(new_password)
        users = self._load()
        if username not in users:
            raise ValidationError(f"User '{username}' nicht gefunden.")
        pw_hash = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt(rounds=12)
        ).decode("utf-8")
        users[username]["password_hash"] = pw_hash
        users[username]["requires_setup"] = False
        self._save(users)
        AuditLogger().log_action("INITIAL_PASSWORD_SET", {"username": username})  # noqa
        log.info("Ersteinrichtung abgeschlossen: %s", username)

    def _validate_password_strength(self, password: str) -> None:
        """Prüft Passwort-Stärke für die Ersteinrichtung.

        Raises:
            ValueError: Falls das Passwort die Anforderungen nicht erfüllt.
        """
        import re  # noqa: PLC0415

        errors = []
        if len(password) < 10:
            errors.append("Mindestens 10 Zeichen")
        if not re.search(r"\d", password):
            errors.append("Mindestens eine Zahl")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Mindestens ein Sonderzeichen")
        if errors:
            raise ValidationError("Passwort zu schwach:\n• " + "\n• ".join(errors))

    def update_last_login(self, username: str) -> None:
        """Aktualisiert den Zeitstempel des letzten Logins.

        Args:
            username: Benutzername.
        """
        data = self._load()
        if username in data:
            data[username]["last_login"] = datetime.now().isoformat(timespec="seconds")
            self._save(data)
