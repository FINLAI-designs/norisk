"""Skin-Tests fuer ``core.exceptions`` — Vertrag der Exception-Hierarchie.

Foundation des R-Exc-Sprints (Run 2). Sichert die strukturelle
Integritaet der Hierarchie ab, damit Tools beim Migrieren von
nackten ``RuntimeError``/``ValueError`` darauf verlassen koennen.
"""

from __future__ import annotations

import pytest

from core.exceptions import (
    AuthError,
    ConfigurationError,
    CryptoError,
    DatabaseError,
    ExternalToolError,
    FileSystemError,
    FinLaiError,
    LicenseError,
    NetworkError,
    StorageError,
    ValidationError,
)


class TestRootHierarchy:
    """``FinLaiError`` ist die Wurzel der Hierarchie und erbt von
    ``Exception``. Subklassen erben **zusaetzlich** von Stdlib-Klassen
    (``ValueError``, ``RuntimeError``, ``OSError``) damit existierender
    ``except ValueError``-Code waehrend der Migration nicht bricht.
    """

    def test_finlai_error_extends_exception(self) -> None:
        assert issubclass(FinLaiError, Exception)

    def test_finlai_error_root_does_not_extend_stdlib_subtypes(self) -> None:
        # FinLaiError selbst ist sauber — nur Subklassen erben Stdlib-Klassen.
        assert not issubclass(FinLaiError, RuntimeError)
        assert not issubclass(FinLaiError, ValueError)
        assert not issubclass(FinLaiError, OSError)

    def test_finlai_error_carries_message(self) -> None:
        err = FinLaiError("etwas ist schief gelaufen")
        assert str(err) == "etwas ist schief gelaufen"


@pytest.mark.parametrize(
    "subclass",
    [
        ConfigurationError,
        ValidationError,
        StorageError,
        NetworkError,
        CryptoError,
        LicenseError,
        AuthError,
        ExternalToolError,
    ],
)
class TestDirectSubclasses:
    """Alle direkten Top-Level-Kategorien erben von:class:`FinLaiError`."""

    def test_extends_finlai_error(self, subclass: type[Exception]) -> None:
        assert issubclass(subclass, FinLaiError)

    def test_extends_exception(self, subclass: type[Exception]) -> None:
        assert issubclass(subclass, Exception)

    def test_carries_message(self, subclass: type[Exception]) -> None:
        err = subclass("test message")
        assert str(err) == "test message"


class TestStorageSubHierarchy:
    """``DatabaseError`` und ``FileSystemError`` sind Subklassen von
    ``StorageError`` — und damit transitiv von ``FinLaiError``.
    """

    def test_database_error_extends_storage_error(self) -> None:
        assert issubclass(DatabaseError, StorageError)
        assert issubclass(DatabaseError, FinLaiError)

    def test_filesystem_error_extends_storage_error(self) -> None:
        assert issubclass(FileSystemError, StorageError)
        assert issubclass(FileSystemError, FinLaiError)

    def test_database_and_filesystem_are_disjoint(self) -> None:
        # Beide sind Storage-Subklassen, aber NICHT voneinander abgeleitet.
        assert not issubclass(DatabaseError, FileSystemError)
        assert not issubclass(FileSystemError, DatabaseError)


class TestExceptionChaining:
    """``raise X from err`` — Phase 4 enforcet B904, hier verifizieren wir
    nur, dass die Hierarchie das ``__cause__``-Attribut respektiert.
    """

    def test_explicit_cause_preserved(self) -> None:
        original = ValueError("original")
        try:
            raise ValidationError("wrapped") from original
        except ValidationError as err:
            assert err.__cause__ is original
            assert isinstance(err, FinLaiError)

    def test_implicit_cause_via_during_handling(self) -> None:
        try:
            try:
                raise ValueError("original")
            except ValueError as err:
                raise NetworkError("wrapped") from err
        except NetworkError as final:
            assert final.__cause__ is not None
            assert isinstance(final.__cause__, ValueError)


class TestStdlibCompatibility:
    """Mehrfach-Vererbung mit Stdlib-Exceptions Phase-1-Anpassung
    2026-05-07): bestehende ``except ValueError``-/``except RuntimeError``-
    /``except OSError``-Pfade fangen die FINLAI-Subklassen weiter, damit
    Migration aus 128 nackten Raises in tools/+core/ additiv ist.
    """

    def test_validation_error_is_value_error(self) -> None:
        assert issubclass(ValidationError, ValueError)
        # Bidirektionaler Sanity-Check: instanceof-Pfad.
        try:
            raise ValidationError("test")
        except ValueError as caught:
            assert isinstance(caught, ValidationError)
            assert isinstance(caught, FinLaiError)

    def test_configuration_error_is_runtime_error(self) -> None:
        assert issubclass(ConfigurationError, RuntimeError)
        try:
            raise ConfigurationError("test")
        except RuntimeError as caught:
            assert isinstance(caught, ConfigurationError)

    def test_storage_error_is_os_error(self) -> None:
        assert issubclass(StorageError, OSError)
        try:
            raise StorageError("test")
        except OSError as caught:
            assert isinstance(caught, StorageError)

    def test_database_error_is_os_error_transitively(self) -> None:
        # DatabaseError → StorageError → OSError-Chain
        assert issubclass(DatabaseError, OSError)
        try:
            raise DatabaseError("test")
        except OSError as caught:
            assert isinstance(caught, DatabaseError)

    def test_filesystem_error_is_os_error_transitively(self) -> None:
        assert issubclass(FileSystemError, OSError)

    def test_network_error_is_os_error(self) -> None:
        # ConnectionError-Pattern: HTTP/Socket-Fehler sind OSError im Stdlib.
        assert issubclass(NetworkError, OSError)

    def test_crypto_error_is_runtime_error(self) -> None:
        assert issubclass(CryptoError, RuntimeError)

    def test_license_error_is_runtime_error(self) -> None:
        assert issubclass(LicenseError, RuntimeError)

    def test_auth_error_is_runtime_error(self) -> None:
        assert issubclass(AuthError, RuntimeError)

    def test_external_tool_error_is_runtime_error(self) -> None:
        assert issubclass(ExternalToolError, RuntimeError)


class TestCatchmentRules:
    """Use-Case-Doku via Tests: zeigen, wie Caller die Hierarchie
    nutzen koennen.
    """

    def test_catch_finlai_error_catches_all_subclasses(self) -> None:
        for subclass in (
            ConfigurationError,
            ValidationError,
            StorageError,
            DatabaseError,
            FileSystemError,
            NetworkError,
            CryptoError,
            LicenseError,
            AuthError,
            ExternalToolError,
        ):
            try:
                raise subclass("test")
            except FinLaiError as caught:
                assert isinstance(caught, subclass)

    def test_catch_storage_error_catches_database_and_filesystem(
        self,
    ) -> None:
        for subclass in (DatabaseError, FileSystemError):
            try:
                raise subclass("test")
            except StorageError as caught:
                assert isinstance(caught, subclass)

    def test_catch_network_error_does_not_catch_external_tool(
        self,
    ) -> None:
        # Subprocess-Fehler sind explizit NICHT Network — Caller muss
        # beide separat behandeln wenn beide moeglich sind.
        with pytest.raises(ExternalToolError):
            try:
                raise ExternalToolError("winget exit=1")
            except NetworkError:
                pytest.fail("ExternalToolError sollte nicht von NetworkError gefangen werden")


class TestPublicApi:
    """``__all__`` deckt alle exponierten Klassen ab."""

    def test_all_lists_all_public_classes(self) -> None:
        from core import exceptions as mod

        expected = {
            "AuthError",
            "ConfigurationError",
            "CryptoError",
            "DatabaseError",
            "ExternalToolError",
            "FileSystemError",
            "FinLaiError",
            "LicenseError",
            "NetworkError",
            "StorageError",
            "ValidationError",
        }
        assert set(mod.__all__) == expected
