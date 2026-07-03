"""
models — Datenmodelle für das Auth-System von FINLAI

Enthält die User-Dataclass, die alle relevanten Informationen
zu einem Benutzer hält. Passwörter werden ausschließlich als
bcrypt-Hash gespeichert, niemals im Klartext.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class User:
    """Repräsentiert einen FINLAI-Benutzer.

    Attributes:
        username: Eindeutiger Anmeldename.
        password_hash: bcrypt-Hash des Passworts — niemals Klartext.
        role: Benutzerrolle: ``"admin"`` oder ``"user"``.
        full_name: Vollständiger Anzeigename.
        allowed_tools: Liste der erlaubten Tool-Namen. Leere Liste bedeutet
                       alle Tools sind erlaubt.
        last_login: ISO-Datetime des letzten Logins, oder ``None``.
        created_at: ISO-Datetime der Kontoerstellung.
        is_active: False = Konto gesperrt, kein Login möglich.
        created_by_app: — app_id der App, die diesen User angelegt hat.
                       Filtert die geteilte ``users.json`` auf echte Build-User
                       (Backward-Compat: leerer String für Alt-/Fremd-User).
    """

    username: str
    password_hash: str
    role: str
    full_name: str
    allowed_tools: list[str] = field(default_factory=list)
    last_login: str | None = None
    created_at: str = ""
    is_active: bool = True
    # Ab First-Run-Wizard v2 gepflegt (Backward-Compat: leerer String für Alt-User).
    first_name: str = ""
    email: str = ""
    # bcrypt-Hash des Recovery-Codes. Wird im Wizard generiert und ausschließlich
    # gehasht persistiert — der Klartext-Code wird dem Nutzer einmalig angezeigt.
    recovery_code_hash: str = ""
    # App-Marker (app_id). Leer = Alt-User oder fremder FINLAI-Build.
    created_by_app: str = ""
