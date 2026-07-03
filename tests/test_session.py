"""
Tests für Session und UserStore.

Testet Sitzungsverwaltung, Berechtigungsprüfungen,
Benutzer-CRUD und Passwort-Handling.

Author: Patrick Riederich
Version: 1.0
"""

import pytest

from core.auth.models import User
from core.auth.session import Session
from core.auth.user_store import UserStore


# -----------------------------------------------------------------------
# Session
# -----------------------------------------------------------------------
class TestSession:
    """Tests für die Sitzungsverwaltung."""

    def setup_method(self):
        # Singleton zurücksetzen für isolierte Tests
        Session._instance = None
        Session._initialized = False

    def teardown_method(self):
        Session._instance = None
        Session._initialized = False

    def _make_user(self, **kwargs) -> User:
        defaults = {
            "username": "testuser",
            "password_hash": "$2b$12$dummy",
            "role": "user",
            "full_name": "Test User",
            "allowed_tools": [],
        }
        defaults.update(kwargs)
        return User(**defaults)

    def test_singleton(self):
        s1 = Session()
        s2 = Session()
        assert s1 is s2

    def test_initial_not_logged_in(self):
        session = Session()
        assert session.is_logged_in() is False
        assert session.current_user is None

    def test_login(self):
        session = Session()
        user = self._make_user()
        session.login(user)
        assert session.is_logged_in() is True
        assert session.current_user is user

    def test_logout(self):
        session = Session()
        session.login(self._make_user())
        session.logout()
        assert session.is_logged_in() is False
        assert session.current_user is None

    def test_is_admin_true(self):
        session = Session()
        session.login(self._make_user(role="admin"))
        assert session.is_admin() is True

    def test_is_admin_false(self):
        session = Session()
        session.login(self._make_user(role="user"))
        assert session.is_admin() is False

    def test_is_admin_not_logged_in(self):
        session = Session()
        assert session.is_admin() is False

    def test_can_access_tool_not_logged_in(self):
        session = Session()
        assert session.can_access_tool("Datenvergleich") is False

    def test_can_access_einstellungen_always(self):
        """Einstellungen ist immer zugänglich."""
        session = Session()
        session.login(self._make_user(allowed_tools=["SomeOtherTool"]))
        assert session.can_access_tool("Einstellungen") is True

    def test_can_access_cockpit_landing_always(self):
        """Das Cockpit/„Übersicht" ist als Landing-Seite immer zugänglich.

        Ein Nutzer mit eingeschränktem ``allowed_tools`` (ohne „Übersicht")
        soll nicht vor einer leeren Landing-Seite stehen 3c)."""
        from tools.norisk_dashboard.tool import NoRiskDashboardTool

        session = Session()
        session.login(self._make_user(allowed_tools=["SomeOtherTool"]))
        assert session.can_access_tool(NoRiskDashboardTool.name) is True
        assert session.can_access_tool("Übersicht") is True

    def test_can_access_all_tools_empty_list(self):
        """Leere allowed_tools = alle Tools erlaubt."""
        session = Session()
        session.login(self._make_user(allowed_tools=[]))
        assert session.can_access_tool("Datenvergleich") is True
        assert session.can_access_tool("Robotic") is True

    def test_can_access_restricted(self):
        """Nur erlaubte Tools sind zugänglich."""
        session = Session()
        session.login(self._make_user(allowed_tools=["Datenvergleich"]))
        assert session.can_access_tool("Datenvergleich") is True
        assert session.can_access_tool("Robotic") is False

    def test_can_access_multiple_tools(self):
        session = Session()
        session.login(
            self._make_user(allowed_tools=["Datenvergleich", "Robotic", "XML Reader"])
        )
        assert session.can_access_tool("Datenvergleich") is True
        assert session.can_access_tool("Robotic") is True
        assert session.can_access_tool("XML Reader") is True
        assert session.can_access_tool("Buchprüfung") is False


# -----------------------------------------------------------------------
# UserStore
# -----------------------------------------------------------------------
class TestUserStore:
    """Tests für die Benutzerverwaltung."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.tmp = tmp_path
        users_file = tmp_path / "users.json"
        finlai_dir = tmp_path

        monkeypatch.setattr("core.auth.user_store._FINLAI_DIR", finlai_dir)
        monkeypatch.setattr("core.auth.user_store._USERS_FILE", users_file)

    def test_default_admin_created(self):
        """Beim ersten Start wird ein Admin-Account erstellt."""
        store = UserStore()
        users = store.get_all_users()
        assert len(users) == 1
        assert users[0].username == "admin"
        assert users[0].role == "admin"

    def test_authenticate_default_admin(self):
        store = UserStore()
        # Kein Default-Passwort mehr — Setup zuerst abschließen
        store.complete_setup("admin", "Sicher!2026#")
        user = store.authenticate("admin", "Sicher!2026#")
        assert user is not None
        assert user.username == "admin"

    def test_authenticate_wrong_password(self):
        store = UserStore()
        store.complete_setup("admin", "Sicher!2026#")
        assert store.authenticate("admin", "wrong") is None

    def test_authenticate_nonexistent_user(self):
        store = UserStore()
        assert store.authenticate("nobody", "pass") is None

    def test_create_user(self):
        store = UserStore()
        user = store.create_user(
            username="testuser",
            password="TestPass123!",
            role="user",
            full_name="Test User",
            allowed_tools=["Datenvergleich"],
        )
        assert user.username == "testuser"
        assert user.role == "user"
        assert user.allowed_tools == ["Datenvergleich"]
        assert user.is_active is True

    def test_create_user_duplicate_raises(self):
        store = UserStore()
        with pytest.raises(ValueError, match="bereits vergeben"):
            store.create_user(
                username="admin",
                password="pass",
                role="user",
                full_name="Dup",
                allowed_tools=[],
            )

    def test_authenticate_created_user(self):
        store = UserStore()
        store.create_user(
            username="jane",
            password="SecureP@ss1",
            role="user",
            full_name="Jane Doe",
            allowed_tools=[],
        )
        user = store.authenticate("jane", "SecureP@ss1")
        assert user is not None
        assert user.full_name == "Jane Doe"

    def test_authenticate_inactive_user(self):
        """Gesperrte Konten können sich nicht anmelden."""
        store = UserStore()
        store.create_user(
            username="locked",
            password="pass",
            role="user",
            full_name="Locked",
            allowed_tools=[],
        )
        store.update_user("locked", is_active=False)
        assert store.authenticate("locked", "pass") is None

    def test_get_all_users(self):
        store = UserStore()
        store.create_user("user2", "pass", "user", "User 2", [])
        users = store.get_all_users()
        assert len(users) == 2

    def test_update_user(self):
        store = UserStore()
        updated = store.update_user("admin", full_name="Super Admin")
        assert updated.full_name == "Super Admin"

    def test_update_nonexistent_raises(self):
        store = UserStore()
        with pytest.raises(KeyError, match="nicht gefunden"):
            store.update_user("nobody", full_name="X")

    def test_delete_user(self):
        store = UserStore()
        store.create_user("temp", "pass", "user", "Temp", [])
        store.delete_user("temp")
        assert store.authenticate("temp", "pass") is None

    def test_delete_nonexistent_raises(self):
        store = UserStore()
        with pytest.raises(KeyError, match="nicht gefunden"):
            store.delete_user("nobody")

    def test_delete_last_admin_raises(self):
        """Der letzte Admin darf nicht gelöscht werden."""
        store = UserStore()
        with pytest.raises(ValueError, match="letzte Administrator"):
            store.delete_user("admin")

    def test_delete_admin_with_other_admin(self):
        """Admin-Löschung erlaubt wenn ein anderer Admin existiert."""
        store = UserStore()
        store.create_user("admin2", "pass", "admin", "Admin 2", [])
        store.delete_user("admin")
        users = store.get_all_users()
        assert len(users) == 1
        assert users[0].username == "admin2"

    def test_change_password(self):
        store = UserStore()
        store.complete_setup("admin", "Sicher!2026#")
        assert store.change_password("admin", "Sicher!2026#", "NewPass!1") is True
        assert store.authenticate("admin", "Sicher!2026#") is None
        assert store.authenticate("admin", "NewPass!1") is not None

    def test_change_password_wrong_old(self):
        store = UserStore()
        assert store.change_password("admin", "wrong", "new") is False

    def test_change_password_nonexistent(self):
        store = UserStore()
        assert store.change_password("nobody", "old", "new") is False

    def test_set_password_admin(self):
        store = UserStore()
        store.set_password_admin("admin", "ResetPass!")
        assert store.authenticate("admin", "ResetPass!") is not None

    def test_set_password_admin_nonexistent_raises(self):
        store = UserStore()
        with pytest.raises(KeyError, match="nicht gefunden"):
            store.set_password_admin("nobody", "pass")

    def test_update_last_login(self):
        store = UserStore()
        store.complete_setup("admin", "Sicher!2026#")
        store.update_last_login("admin")
        user = store.authenticate("admin", "Sicher!2026#")
        assert user.last_login is not None

    def test_password_never_stored_plaintext(self):
        """Passwort darf niemals im Klartext gespeichert werden."""
        store = UserStore()
        store.create_user("secure", "MySecret123!", "user", "Secure", [])

        users_file = self.tmp / "users.json"
        content = users_file.read_text(encoding="utf-8")
        assert "MySecret123!" not in content
        assert "$2b$" in content  # bcrypt-Hash
