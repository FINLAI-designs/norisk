"""Tests für:mod:`core.auth.password_reset`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from core.auth.password_reset import (
    MAX_ATTEMPTS_PER_WINDOW,
    WINDOW_MINUTES,
    PasswordResetService,
    ResetStatus,
)
from core.auth.recovery_code import generate_recovery_code, hash_recovery_code
from core.auth.user_store import UserStore


@pytest.fixture
def isolated_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> UserStore:
    """Isoliert ``users.json`` in einem tmp-Verzeichnis."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)
    finlai_dir = fake_home / ".finlai"
    users_file = finlai_dir / "users.json"
    monkeypatch.setattr("core.auth.user_store._FINLAI_DIR", finlai_dir)
    monkeypatch.setattr("core.auth.user_store._USERS_FILE", users_file)
    return UserStore()


@pytest.fixture
def service(
    isolated_store: UserStore,
    tmp_path: Path,
) -> PasswordResetService:
    return PasswordResetService(
        user_store=isolated_store,
        attempts_file=tmp_path / "reset_attempts.json",
    )


def _create_admin_with_code(
    store: UserStore, username: str = "patrick"
) -> tuple[str, str]:
    """Erzeugt einen Admin mit gehashtem Recovery-Code und gibt Klartext zurück."""
    code = generate_recovery_code()
    store.create_user(
        username=username,
        password="initial1",
        role="admin",
        full_name="Patrick Test",
        allowed_tools=[],
        first_name="Patrick",
        email="patrick@example.com",
        recovery_code_hash=hash_recovery_code(code),
    )
    return username, code


class TestRecoveryCodeReset:
    def test_success_flow(
        self, service: PasswordResetService, isolated_store: UserStore
    ) -> None:
        username, code = _create_admin_with_code(isolated_store)

        result = service.request_reset_via_recovery_code(
            username=username, code=code, new_password="brandNew1"
        )

        assert result.status is ResetStatus.SUCCESS
        # Neues Passwort funktioniert
        user = isolated_store.authenticate(username, "brandNew1")
        assert user is not None

    def test_invalidates_code_after_success(
        self, service: PasswordResetService, isolated_store: UserStore
    ) -> None:
        username, code = _create_admin_with_code(isolated_store)

        service.request_reset_via_recovery_code(
            username=username, code=code, new_password="brandNew1"
        )

        # Erneuter Versuch mit demselben Code muss scheitern
        result2 = service.request_reset_via_recovery_code(
            username=username, code=code, new_password="yetAnother1"
        )
        assert result2.status is ResetStatus.INVALID_CODE

    def test_invalid_code_rejected(
        self, service: PasswordResetService, isolated_store: UserStore
    ) -> None:
        username, _ = _create_admin_with_code(isolated_store)

        result = service.request_reset_via_recovery_code(
            username=username,
            code="ZZZZ-ZZZZ-ZZZZ-ZZZZ",
            new_password="brandNew1",
        )
        assert result.status is ResetStatus.INVALID_CODE

    def test_unknown_user_rejected(self, service: PasswordResetService) -> None:
        result = service.request_reset_via_recovery_code(
            username="unknown",
            code="ABCD-EFGH-IJKL-MNPQ",
            new_password="brandNew1",
        )
        assert result.status is ResetStatus.USER_NOT_FOUND

    def test_invalid_password_rejected(
        self, service: PasswordResetService, isolated_store: UserStore
    ) -> None:
        username, code = _create_admin_with_code(isolated_store)

        result = service.request_reset_via_recovery_code(
            username=username, code=code, new_password="short"
        )
        assert result.status is ResetStatus.INVALID_PASSWORD


class TestRateLimiting:
    def test_rate_limited_after_max_attempts(
        self, service: PasswordResetService, isolated_store: UserStore
    ) -> None:
        username, _ = _create_admin_with_code(isolated_store)

        # 3 fehlgeschlagene Versuche
        for _ in range(MAX_ATTEMPTS_PER_WINDOW):
            service.request_reset_via_recovery_code(
                username=username,
                code="ZZZZ-ZZZZ-ZZZZ-ZZZZ",
                new_password="brandNew1",
            )

        result = service.request_reset_via_recovery_code(
            username=username,
            code="ZZZZ-ZZZZ-ZZZZ-ZZZZ",
            new_password="brandNew1",
        )
        assert result.status is ResetStatus.RATE_LIMITED
        assert result.retry_after_minutes is not None
        assert result.retry_after_minutes <= WINDOW_MINUTES

    def test_success_resets_counter(
        self, service: PasswordResetService, isolated_store: UserStore
    ) -> None:
        username, code = _create_admin_with_code(isolated_store)

        # 2 fehlgeschlagene Versuche
        for _ in range(2):
            service.request_reset_via_recovery_code(
                username=username,
                code="ZZZZ-ZZZZ-ZZZZ-ZZZZ",
                new_password="brandNew1",
            )

        # Erfolgreicher Versuch
        ok = service.request_reset_via_recovery_code(
            username=username, code=code, new_password="brandNew1"
        )
        assert ok.status is ResetStatus.SUCCESS

        # Attempts-File sollte leer sein
        raw = service._load_raw()  # noqa: SLF001
        assert username not in raw

    def test_expired_attempts_are_ignored(
        self,
        service: PasswordResetService,
        isolated_store: UserStore,
        tmp_path: Path,
    ) -> None:
        username, _ = _create_admin_with_code(isolated_store)

        # Alte Versuche (> Fenster) manuell in Datei schreiben.
        # TM-6: seit dem UTC-aware-Fix in password_reset.py
        # parsed das Modul ISO-Strings als UTC. Test nutzt entsprechend
        # ``datetime.now(UTC)``, damit der Vergleich nicht durch
        # Lokale-Zeit-Offset verspringt.
        old_ts = (
            datetime.now(UTC) - timedelta(minutes=WINDOW_MINUTES + 5)
        ).isoformat(timespec="seconds")
        service._save_raw(  # noqa: SLF001
            {username: [old_ts, old_ts, old_ts]}
        )

        # Neuer fehlgeschlagener Versuch darf nicht RATE_LIMITED sein
        result = service.request_reset_via_recovery_code(
            username=username,
            code="ZZZZ-ZZZZ-ZZZZ-ZZZZ",
            new_password="brandNew1",
        )
        assert result.status is ResetStatus.INVALID_CODE


class TestEmailResetStub:
    def test_raises_not_implemented(self, service: PasswordResetService) -> None:
        with pytest.raises(NotImplementedError) as exc_info:
            service.request_reset_via_email("patrick")
        assert "Pro-Launch" in str(exc_info.value)
