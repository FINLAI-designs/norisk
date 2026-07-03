"""
password_reset — Zurücksetzen eines vergessenen Admin-Passworts.

Unterstützt zwei Wege:

    * **Recovery-Code (offline):** Vollständig implementiert. Der Benutzer
      gibt seinen beim Wizard gesicherten Code ein, zusammen mit dem neuen
      Passwort. Erfolgreicher Vergleich → bcrypt-Passwort-Hash wird ersetzt.

    * **E-Mail-Reset:** Nur Stub. Wirft:class:`NotImplementedError` mit
      Hinweis auf den Pro-Launch.

Rate-Limiting greift für BEIDE Wege: pro Benutzer werden maximal drei
Versuche innerhalb eines rollenden 60-Minuten-Fensters zugelassen. Die
Versuche werden in ``~/.finlai/reset_attempts.json`` gespeichert.

Audit-Events:
    ``PASSWORD_RESET_ATTEMPT`` — jede Anfrage (erfolgreich oder nicht).
    ``PASSWORD_RESET_SUCCESS`` — nach erfolgreichem Reset.
    ``RESET_RATE_LIMITED`` — wenn das Limit überschritten ist.
    ``EMAIL_RESET_ATTEMPTED`` — bei Aufruf des noch nicht implementierten Pfads.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

import bcrypt

from core.audit_log import AuditLogger
from core.auth.recovery_code import verify_recovery_code
from core.auth.user_store import UserStore
from core.finlai_paths import finlai_dir
from core.logger import get_logger

log = get_logger(__name__)

_FINLAI_DIR = finlai_dir()
_ATTEMPTS_FILE = _FINLAI_DIR / "reset_attempts.json"

MAX_ATTEMPTS_PER_WINDOW = 3
WINDOW_MINUTES = 60

_EMAIL_RESET_MESSAGE = (
    "E-Mail-Reset verfügbar ab Pro-Launch (voraussichtlich 15.05.2026)"
)


class ResetStatus(StrEnum):
    """Status-Codes des Reset-Vorgangs."""

    SUCCESS = "success"
    INVALID_CODE = "invalid_code"
    USER_NOT_FOUND = "user_not_found"
    RATE_LIMITED = "rate_limited"
    EMAIL_NOT_IMPLEMENTED = "email_not_implemented"
    INVALID_PASSWORD = "invalid_password"


@dataclass(frozen=True)
class ResetResult:
    """Rückgabewert eines Reset-Versuchs."""

    status: ResetStatus
    message: str
    retry_after_minutes: int | None = None


class PasswordResetService:
    """Service für Passwort-Reset mit Rate-Limiting."""

    def __init__(
        self,
        user_store: UserStore | None = None,
        *,
        attempts_file: Path | None = None,
    ) -> None:
        """Initialisiert den Service.

        Args:
            user_store: Optionaler UserStore (Tests).
            attempts_file: Pfad der Rate-Limit-Datei (Tests können umleiten).
        """
        self._user_store = user_store or UserStore()
        self._attempts_file = attempts_file or _ATTEMPTS_FILE

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def request_reset_via_recovery_code(
        self, username: str, code: str, new_password: str
    ) -> ResetResult:
        """Versucht einen Reset über den Recovery-Code.

        Args:
            username: Benutzername.
            code: Vom Benutzer eingegebener Recovery-Code.
            new_password: Neues Passwort (min. 8 Zeichen, Buchstabe + Ziffer).

        Returns:
:class:`ResetResult` mit Status und Nutzer-freundlicher Nachricht.
        """
        AuditLogger().log_action(
            "PASSWORD_RESET_ATTEMPT",
            {"username": username, "via": "recovery_code"},
        )

        rate = self._check_rate_limit(username)
        if rate is not None:
            return rate

        password_err = _validate_password(new_password)
        if password_err is not None:
            self._record_attempt(username)
            return ResetResult(ResetStatus.INVALID_PASSWORD, password_err)

        user = self._user_store.get_user(username)
        if user is None:
            self._record_attempt(username)
            return ResetResult(
                ResetStatus.USER_NOT_FOUND,
                "Benutzer nicht gefunden oder ungültiger Code.",
            )

        if not user.recovery_code_hash or not verify_recovery_code(
            code, user.recovery_code_hash
        ):
            self._record_attempt(username)
            return ResetResult(
                ResetStatus.INVALID_CODE,
                "Benutzer nicht gefunden oder ungültiger Code.",
            )

        try:
            self._user_store.set_password_admin(username, new_password)
        except (ValueError, KeyError) as exc:
            log.warning("Passwort-Reset fehlgeschlagen: %s", exc)
            self._record_attempt(username)
            return ResetResult(
                ResetStatus.INVALID_PASSWORD,
                f"Passwort konnte nicht gesetzt werden: {exc}",
            )

        # Recovery-Code ist einmalig — nach Erfolg invalidieren.
        try:
            self._user_store.set_recovery_code_hash(
                username, _burnt_recovery_placeholder()
            )
        except (ValueError, KeyError):
            log.warning(
                "Recovery-Code-Hash konnte nach Reset nicht invalidiert werden."
            )

        self._reset_attempts(username)
        AuditLogger().log_action(
            "PASSWORD_RESET_SUCCESS",
            {"username": username, "via": "recovery_code"},
        )
        log.info("Passwort-Reset erfolgreich für '%s' via Recovery-Code.", username)
        return ResetResult(
            ResetStatus.SUCCESS,
            "Passwort erfolgreich zurückgesetzt. Du kannst dich jetzt anmelden.",
        )

    def request_reset_via_email(self, username: str) -> ResetResult:
        """E-Mail-Reset — noch nicht implementiert.

        Args:
            username: Benutzername (wird nur fürs Audit geloggt).

        Raises:
            NotImplementedError: Immer — Feature ab Pro-Launch verfügbar.
        """
        AuditLogger().log_action(
            "EMAIL_RESET_ATTEMPTED",
            {"username": username},
        )
        raise NotImplementedError(_EMAIL_RESET_MESSAGE)

    # ------------------------------------------------------------------
    # Rate-Limit
    # ------------------------------------------------------------------

    def _check_rate_limit(self, username: str) -> ResetResult | None:
        """Prüft ob das Limit für ``username`` überschritten ist.

        Returns:
            Einen:class:`ResetResult` mit Status ``RATE_LIMITED`` oder
            ``None``, wenn weitere Versuche erlaubt sind.
        """
        attempts = self._load_attempts_for(username)
        if len(attempts) < MAX_ATTEMPTS_PER_WINDOW:
            return None

        oldest = min(attempts)
        retry_at = oldest + timedelta(minutes=WINDOW_MINUTES)
        # TM-6 (Code-Review 2026-05-19, P1): UTC-aware Vergleich. Vorher
        # ``datetime.now`` naive — DST-Wechsel oder Zeitzonen-Drift haette
        # den Rate-Limit-Counter um eine Stunde verspringen lassen.
        remaining = max(
            1,
            int((retry_at - datetime.now(UTC)).total_seconds() // 60),
        )
        AuditLogger().log_action(
            "RESET_RATE_LIMITED",
            {"username": username, "retry_after_minutes": remaining},
        )
        return ResetResult(
            ResetStatus.RATE_LIMITED,
            f"Zu viele Versuche. Bitte in {remaining} Minuten erneut probieren.",
            retry_after_minutes=remaining,
        )

    def _record_attempt(self, username: str) -> None:
        """Fügt einen Versuch zum Rolling-Window hinzu."""
        data = self._load_raw()
        entries = data.get(username, [])
        # TM-6 (Code-Review 2026-05-19, P1): UTC-aware ISO mit ``+00:00``-Suffix.
        entries.append(datetime.now(UTC).isoformat(timespec="seconds"))
        data[username] = entries[-20:]  # defensive cap
        self._save_raw(data)

    def _reset_attempts(self, username: str) -> None:
        """Löscht die Versuchs-Liste für einen Benutzer (nach Erfolg)."""
        data = self._load_raw()
        if username in data:
            del data[username]
            self._save_raw(data)

    def _load_attempts_for(self, username: str) -> list[datetime]:
        """Liefert alle Versuchs-Zeitstempel innerhalb des Fensters.

        TM-6 (Code-Review 2026-05-19, P1): UTC-aware Vergleich. Bestehende
        naive ISO-Strings aus alten reset_attempts.json-Dateien werden
        beim Parsen auf UTC promotet — Datenmigration ohne expliziten
        Migrate-Schritt.
        """
        data = self._load_raw()
        raw_entries = data.get(username, [])
        cutoff = datetime.now(UTC) - timedelta(minutes=WINDOW_MINUTES)
        active: list[datetime] = []
        for ts in raw_entries:
            try:
                parsed = datetime.fromisoformat(ts)
            except ValueError:
                continue
            # Legacy-Eintraege ohne TZ-Suffix als UTC interpretieren.
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            if parsed >= cutoff:
                active.append(parsed)
        return active

    def _load_raw(self) -> dict[str, list[str]]:
        """Liest die Attempts-Datei (oder leeres Dict)."""
        if not self._attempts_file.exists():
            return {}
        try:
            raw = json.loads(self._attempts_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return raw
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("reset_attempts.json unlesbar: %s", exc)
        return {}

    def _save_raw(self, data: dict[str, list[str]]) -> None:
        """Schreibt die Attempts-Datei zurück."""
        self._attempts_file.parent.mkdir(parents=True, exist_ok=True)
        self._attempts_file.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )


def _validate_password(password: str) -> str | None:
    """Prüft das neue Passwort (gleiche Regeln wie im Wizard)."""
    if len(password) < 8:
        return "Passwort muss mindestens 8 Zeichen lang sein."
    if not any(c.isalpha() for c in password):
        return "Passwort muss mindestens einen Buchstaben enthalten."
    if not any(c.isdigit() for c in password):
        return "Passwort muss mindestens eine Ziffer enthalten."
    return None


def _burnt_recovery_placeholder() -> str:
    """Liefert einen bcrypt-Hash, der zu keiner realen Eingabe passt.

    Wird nach einem erfolgreichen Reset in ``recovery_code_hash`` geschrieben,
    damit der Code nicht erneut funktioniert. Der Benutzer muss im nächsten
    Schritt einen frischen Code generieren (Aufgabe für den Einstellungs-Dialog).
    """
    import secrets  # noqa: PLC0415

    placeholder = secrets.token_urlsafe(32)
    return bcrypt.hashpw(placeholder.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode(
        "utf-8"
    )
