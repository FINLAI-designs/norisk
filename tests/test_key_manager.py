"""test_key_manager — Tests fuer ``core/database/key_manager.py``.

Stand Schritt 1.6: + ``get_key_metadata`` (read-only Diagnose, kein
Key-Material, kein DEK-Zugriff). ``TestSkeletonStubs`` hat noch genau
einen Stub (``migrate_legacy_db``, kommt in Subtask 3) und kann am Ende
von Schritt 1.7 vollstaendig geloescht werden, sobald
``rotate_master_key`` als bewusster Stub eigene Tests hat (statt im
SkeletonStub-Pool zu leben).

Test-ID-Familien:
    K-N: KeyManager-Lifecycle (init, wipe, rotate, permissions, atomic
          write, DEK-Eigenschaften)
    L-N: load_master_key-Verhalten (Cache, Disk-Read, Error-Pfade)
    D-N: Eigenschaften der Schluessel-Ableitung (domain separation,
          determinism, stability across instances, edge cases)
    M-N: get_key_metadata-Verhalten (Schema, kein Key-Material,
          read-only ohne DEK-Zugriff)
    Mig-N: Bestandsdaten-Migration (Subtask 3, geplant)

Test-IDs gemaess MIGRATION_TEST_PLAN §3.1 + 1.4-Review:
    K-1: DEK-Generierung produziert 256-bit (Schritt 1.2)
    K-2: DEK-Entropie 1000 Samples alle unique (Schritt 1.8 nachgereicht)
    K-3: Wrap+Unwrap-Roundtrip (InMemoryDPAPIBackend) (Schritt 1.1)
    K-5: initialize ist idempotent (Schritt 1.2)
    K-6: Existierende, unlesbare Datei → Corrupt (Schritt 1.2 + 1.3)
    K-9: rotate_master_key bleibt NotImplemented (Schritt 1.1, reserviert)
    K-11: master.key.wrapped Permissions 0600 (Schritt 1.2, POSIX)
    K-12: Atomare Schreib-Eigenschaft (write-tmp+replace) (Schritt 1.2)
    load_master_key liefert DEK nach initialize (Schritt 1.3)
    load_master_key == initialize-DEK (Roundtrip) (Schritt 1.3)
    Final-Cache (zweiter Call liest nicht von Disk) (Schritt 1.3)
    NotInitialized wenn Datei fehlt (Schritt 1.3)
    Corrupt wenn Backend-Unwrap fehlschlaegt (Schritt 1.3)
    D-1: Domain-Separation derive_secondary_key (Schritt 1.4)
    D-2: Determinismus derive_secondary_key (Schritt 1.4)
    D-3: ValueError bei leerem purpose (Schritt 1.4)
    D-4: ValueError bei whitespace-only purpose (Schritt 1.4)
    D-5: Stabilitaet ueber Instanzen hinweg (Schritt 1.4)
    D-6: Unicode-purposes funktionieren (Schritt 1.4)
    D-7: Output ist 32 Byte (256 bit) (Schritt 1.4)
    K-13: wipe ueberschreibt Cache + setzt None (Schritt 1.5)
    K-14a: wipe ohne prev load → no-op (Schritt 1.5)
    K-14b: wipe nach load → Cache leer (Schritt 1.5)
    K-14c: wipe nach wipe → no-op (Schritt 1.5)
    K-15: load_after_wipe → ein neuer Disk-Read (Schritt 1.5)
    M-1: get_key_metadata exponiert keine Key-Daten (Schritt 1.6)
    M-2: get_key_metadata Schema konsistent (Schritt 1.6)
    M-3: get_key_metadata kein DEK-Zugriff/Cache-Pop (Schritt 1.6)
    M-4: schema_version-Feld vorhanden + stabil (Schritt 1.7)
    M-5: backend_type via BackendKind-Enum stabil (Schritt 1.7)
    weitere K-Tests in spaeteren Schritten

Hinweis: Im 1.4-Review wurden die ehemaligen K-7/K-8/K-9 (Schluessel-
Ableitungs-Eigenschaften) zu D-1/D-2/D-5 umbenannt — sie gehoeren
strukturell zur D-Familie, nicht zum K-Lifecycle. K-9 bleibt damit fuer
``rotate_master_key`` reserviert (im aktuellen Stand
:class:`TestRotateMasterKeyStub`). Numerische Loecher in der K-Familie
(K-2/4/7/8/10) entsprechen Tests, die in spaeteren Schritten kommen oder
direkt durch andere ID-Familien abgedeckt werden — nicht entfernt.

Author: Patrick Riederich
Version: 0.5 (Subtask 1, Schritt 1.4-Review-Anpassungen)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from core.database.key_manager import (
    _DEK_LENGTH_BYTES,
    _HKDF_SALT_V1,
    _HKDF_SALT_VERSION,
    _MASTER_KEY_FILE,
    KeyManager,
    KeyManagerCorruptError,
    KeyManagerError,
    KeyManagerNotInitializedError,
    KeyManagerPermissionError,
)
from core.database.key_manager_platform import (
    BackendKind,
    InMemoryDPAPIBackend,
    LinuxLibsecretBackend,
    MacOSKeychainBackend,
    WindowsDPAPIBackend,
    select_backend,
)

# Subtask 2: Diese Tests verwalten den KeyManager-Modul-State
# selbst (eigene Instanzen, eigene `isolated_master_key_file`-Fixture).
# Der globale conftest-Bootstrap (siehe tests/conftest.py) wird per
# Marker deaktiviert.
pytestmark = pytest.mark.no_key_manager_bootstrap

# ---------------------------------------------------------------------------
# Shared Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_master_key_file(tmp_path, monkeypatch):
    """Isoliert ``_MASTER_KEY_FILE`` auf ``tmp_path/master.key.wrapped``.

    Effekt: Tests koennen ``KeyManager.initialize`` aufrufen, ohne die
    echte ``~/.finlai/master.key.wrapped`` von Patrick anzufassen.
    pytest haengt das Cleanup an den Test-Scope.
    """
    test_dir = tmp_path / "finlai_test"
    test_dir.mkdir()
    test_file = test_dir / "master.key.wrapped"
    monkeypatch.setattr(
        "core.database.key_manager._MASTER_KEY_FILE",
        test_file,
    )
    return test_file

# ---------------------------------------------------------------------------
# Modul-Konstanten + Smoke
# ---------------------------------------------------------------------------


class TestKeyManagerSmoke:
    """Smoke: Modul importiert, Konstanten haben sinnvolle Werte."""

    def test_module_imports(self) -> None:
        # Wenn die Imports am Datei-Anfang funktioniert haben, ist dieser
        # Test trivial wahr — er existiert primaer als sichtbares Signal,
        # dass das Skeleton importierbar ist.
        assert KeyManager is not None

    def test_dek_length_is_256_bit(self) -> None:
        assert _DEK_LENGTH_BYTES == 32  # 256 / 8 = 32 Byte

    def test_hkdf_salt_v1_has_expected_size(self) -> None:
        assert isinstance(_HKDF_SALT_V1, bytes)
        assert len(_HKDF_SALT_V1) == 32

    def test_hkdf_salt_version_is_v1(self) -> None:
        assert _HKDF_SALT_VERSION == "v1"

    def test_master_key_file_path_in_finlai_dir(self) -> None:
        # Pfad-Form (nicht Existenz!) verifizieren.
        assert _MASTER_KEY_FILE.name == "master.key.wrapped"
        assert _MASTER_KEY_FILE.parent.name == ".finlai"


# ---------------------------------------------------------------------------
# Exception-Hierarchie
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Alle drei Subtypen muessen ``KeyManagerError`` sein.

    Effekt: Caller koennen breit ``except KeyManagerError`` schreiben
    UND spezifisch ``except KeyManagerCorruptError`` — beide Patterns
    funktionieren.
    """

    def test_not_initialized_is_subclass(self) -> None:
        assert issubclass(KeyManagerNotInitializedError, KeyManagerError)

    def test_corrupt_is_subclass(self) -> None:
        assert issubclass(KeyManagerCorruptError, KeyManagerError)

    def test_permission_is_subclass(self) -> None:
        assert issubclass(KeyManagerPermissionError, KeyManagerError)

    def test_subtypes_are_distinct(self) -> None:
        # Drei verschiedene Klassen — kein Alias, keine Doppelung.
        types = {
            KeyManagerNotInitializedError,
            KeyManagerCorruptError,
            KeyManagerPermissionError,
        }
        assert len(types) == 3

    def test_base_is_exception(self) -> None:
        assert issubclass(KeyManagerError, Exception)


# ---------------------------------------------------------------------------
# Backend-Stubs verifizieren NotImplementedError
# ---------------------------------------------------------------------------


class TestPlatformStubs:
    """macOS/Linux-Backends sollen ``NotImplementedError`` werfen.

    Effekt: kein Silent-Skip, kein Klartext-Fallback. Sobald NoRisk fuer
    diese Plattformen gebaut wird, schlaegt die Tests-Sammlung gegen den
    Stub und zwingt zur Implementation.
    """

    def test_macos_backend_wrap_raises(self) -> None:
        backend = MacOSKeychainBackend()
        with pytest.raises(NotImplementedError, match="macOS-Backend"):
            backend.wrap(b"x")

    def test_macos_backend_unwrap_raises(self) -> None:
        backend = MacOSKeychainBackend()
        with pytest.raises(NotImplementedError, match="macOS-Backend"):
            backend.unwrap(b"x")

    def test_linux_backend_wrap_raises(self) -> None:
        backend = LinuxLibsecretBackend()
        with pytest.raises(NotImplementedError, match="Linux-Backend"):
            backend.wrap(b"x")

    def test_linux_backend_unwrap_raises(self) -> None:
        backend = LinuxLibsecretBackend()
        with pytest.raises(NotImplementedError, match="Linux-Backend"):
            backend.unwrap(b"x")


# ---------------------------------------------------------------------------
# K-3 — InMemoryDPAPIBackend Roundtrip
# ---------------------------------------------------------------------------


class TestInMemoryDPAPIBackend:
    """Test-Backend funktioniert deterministisch."""

    def test_wrap_unwrap_roundtrip_simple(self) -> None:
        backend = InMemoryDPAPIBackend()
        plaintext = b"hello world"
        ciphertext = backend.wrap(plaintext)
        assert ciphertext != plaintext  # zumindest praefixiert
        assert backend.unwrap(ciphertext) == plaintext

    def test_wrap_unwrap_roundtrip_empty(self) -> None:
        backend = InMemoryDPAPIBackend()
        assert backend.unwrap(backend.wrap(b"")) == b""

    def test_wrap_unwrap_roundtrip_32_bytes(self) -> None:
        # Realer Use-Case: DEK-Groesse.
        backend = InMemoryDPAPIBackend()
        dek = bytes(range(32))
        assert backend.unwrap(backend.wrap(dek)) == dek

    def test_unwrap_without_header_raises(self) -> None:
        # Ciphertext, der nicht von InMemoryDPAPIBackend stammt:
        backend = InMemoryDPAPIBackend()
        with pytest.raises(RuntimeError, match="Header-Praefix"):
            backend.unwrap(b"foreign_ciphertext_without_header")


# ---------------------------------------------------------------------------
# Backend-Auswahl per Platform
# ---------------------------------------------------------------------------


class TestSelectBackend:
    """``select_backend`` waehlt anhand ``sys.platform``."""

    def test_returns_backend_instance(self) -> None:
        backend = select_backend()
        # auf jeder unterstuetzten Plattform: irgendein Backend-Objekt.
        assert backend is not None

    def test_windows_returns_windows_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "win32")
        backend = select_backend()
        assert isinstance(backend, WindowsDPAPIBackend)

    def test_darwin_returns_macos_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "darwin")
        backend = select_backend()
        assert isinstance(backend, MacOSKeychainBackend)

    def test_linux_returns_linux_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "linux")
        backend = select_backend()
        assert isinstance(backend, LinuxLibsecretBackend)

    def test_unknown_platform_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "freebsd")
        with pytest.raises(RuntimeError, match="freebsd"):
            select_backend()


# ---------------------------------------------------------------------------
# WindowsDPAPIBackend Roundtrip (nur unter win32)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="WindowsDPAPI-Test nur unter Windows aussagekraeftig",
)
class TestWindowsDPAPIBackend:
    """Echter DPAPI-Roundtrip — nur auf Windows.

    Effekt: Verifiziert, dass ``win32crypt.CryptProtectData`` und
    ``CryptUnprotectData`` mit den hier gewaehlten Parametern (Default-
    Scope = ``CurrentUser``) funktionieren. Auf CI-Linux wird der Block
    skipped.
    """

    def test_wrap_unwrap_roundtrip_dek_size(self) -> None:
        backend = WindowsDPAPIBackend()
        dek = bytes(range(32))
        ciphertext = backend.wrap(dek)
        assert ciphertext != dek
        assert backend.unwrap(ciphertext) == dek

    def test_unwrap_foreign_bytes_raises(self) -> None:
        # Bytes, die nicht von DPAPI stammen — CryptUnprotectData
        # sollte fehlschlagen.
        backend = WindowsDPAPIBackend()
        with pytest.raises(RuntimeError, match="DPAPI CryptUnprotectData"):
            backend.unwrap(b"\x00" * 64)


# ---------------------------------------------------------------------------
# K-9 — rotate_master_key ist Post-Beta-Stub
# ---------------------------------------------------------------------------


class TestRotateMasterKeyStub:
    """``rotate_master_key`` ist bewusst Stub fuer Post-Beta.

    Begruendung (siehe §2.5 + §K-5):
        Rotation des DEK invalidiert alle abgeleiteten Sekundaer-
        schluessel und alle DB-Schluessel. Sie erfordert daher eine
        vollstaendige Re-Encryption aller bestehenden DBs +
        ``secure_store.enc`` mit dem neuen DEK. Das ist eine eigene
        Migrations-Mechanik, die im Rahmen des v1.0-Sprints nicht
        implementiert wird K-5: "DEK-Rotation invalidiert alle
        abgeleiteten Schluessel").

        Eskalations-Trigger:
            Wenn ein Key-Rotation-Bedarf entsteht (z. B. Compliance-
            Anforderung, Sicherheits-Vorfall), wandert dieser Stub-Test
            in einen produktiven Test-Block. Dazu gehoert dann auch
            eine Migration der ``secure_store.enc`` und aller DBs auf
            den neuen DEK — analog zu Subtask 3 (Bestandsdaten-
            Migration).

    K-9-ID stammt aus:file:`MIGRATION_TEST_PLAN.md` §3.1; dort als
    "rotate_master_key bleibt NotImplemented" reserviert.
    """

    def test_K9_raises_not_implemented(self) -> None:
        """``rotate_master_key`` triggert ``NotImplementedError`` mit
        ``Post-Beta``-Hinweis."""
        km = KeyManager(backend=InMemoryDPAPIBackend())
        with pytest.raises(NotImplementedError, match="Post-Beta"):
            km.rotate_master_key()


# ---------------------------------------------------------------------------
# Skeleton-Methoden werfen NotImplementedError mit Schritt-Hinweis
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# K-1, K-5, K-6, K-11, K-12 — initialize
# ---------------------------------------------------------------------------


class TestKeyManagerInitialize:
    """Schritt 1.2 — ``initialize`` schreibt ``master.key.wrapped`` atomar.

    Tests verwenden ``InMemoryDPAPIBackend``, damit das Verhalten
    plattformunabhaengig prueftbar ist. Echter DPAPI-Roundtrip lebt in
    ``TestWindowsDPAPIBackend`` (oben).
    """

    def test_K1_dek_is_256_bit(
        self, isolated_master_key_file
    ) -> None:
        """Der gewrappte DEK ist nach Unwrap 32 Byte (256 bit) lang."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        wrapped = isolated_master_key_file.read_bytes()
        dek = backend.unwrap(wrapped)
        assert len(dek) == 32

    def test_K1_dek_uses_secrets_token_bytes(
        self, isolated_master_key_file, monkeypatch
    ) -> None:
        """``initialize`` ruft ``secrets.token_bytes(32)``, nicht
        ``random.*`` oder andere Quellen mit niedrigerer Entropie."""
        called_with = []

        def fake_token_bytes(n: int) -> bytes:
            called_with.append(n)
            return b"\xab" * n  # deterministisch fuer Test

        monkeypatch.setattr(
            "core.database.key_manager.secrets.token_bytes",
            fake_token_bytes,
        )

        km = KeyManager(backend=InMemoryDPAPIBackend())
        km.initialize()

        assert called_with == [32]

    def test_K2_dek_high_entropy(self) -> None:
        """1000 mit ``secrets.token_bytes(32)`` generierte DEKs sind unique.

        Defense-in-depth gegen versehentliche Generator-Substitution
        (z. B. Monkeypatch im falschen Scope, der ``secrets.token_bytes``
        durch ``random.randbytes`` ersetzt — was schwaechere Entropie
        haette und Kollisionen produzieren wuerde).

        Testet die DEK-Quelle (``secrets.token_bytes``) selbst, nicht die
        File-IO-Pipeline drumherum (das deckt K-1 ab).

        Statistik (32-Byte aus CSPRNG):
            Kollisions-Wahrscheinlichkeit bei 1000 Samples ist
            ``1000^2 / 2 / 2^256`` ≈ ``10^-71``. Bei einem Test-Failure
            ist die Wahrscheinlichkeit fuer "echte Kollision" praktisch
            null — ein Failure deutet auf Generator-Substitution hin.
        """
        import secrets  # noqa: PLC0415

        deks = {secrets.token_bytes(32) for _ in range(1000)}
        # Alle 1000 DEKs unique — kein Kollisions-Bug im Generator.
        assert len(deks) == 1000

        # Bytes-Min-Check: bei 1000 * 32 = 32_000 Bytes aus CSPRNG sollten
        # praktisch alle 256 moeglichen Byte-Werte vorkommen.
        # 200 ist konservativer Threshold (siehe MIGRATION_TEST_PLAN §3.1).
        all_byte_values: set[int] = set()
        for dek in deks:
            all_byte_values.update(dek)
        assert len(all_byte_values) >= 200

    def test_K5_idempotent_does_not_overwrite(
        self, isolated_master_key_file
    ) -> None:
        """Zweiter ``initialize``-Aufruf liest die Datei nur, schreibt
        nicht neu. Erkennbar am byte-identischen File-Inhalt."""
        backend = InMemoryDPAPIBackend()

        km1 = KeyManager(backend=backend)
        km1.initialize()
        first_bytes = isolated_master_key_file.read_bytes()
        first_mtime = isolated_master_key_file.stat().st_mtime_ns

        km2 = KeyManager(backend=backend)
        km2.initialize()
        second_bytes = isolated_master_key_file.read_bytes()
        second_mtime = isolated_master_key_file.stat().st_mtime_ns

        assert first_bytes == second_bytes
        # mtime darf sich nicht geaendert haben (kein Schreibzugriff)
        assert first_mtime == second_mtime

    def test_I4_dek_byte_identical_across_initialize_calls(
        self, isolated_master_key_file  # noqa: ARG002 -- Fixture-Setup ist Pflicht
    ) -> None:
        """I-4 (MIGRATION_TEST_PLAN §3.4): DEK ist nach erstem
        ``initialize`` stabil — zweiter ``load_master_key`` ueber
        zweite KM-Instanz liefert byte-identischen DEK.

        K-5 verifiziert nur, dass die wrapped-Datei byte-identisch
        bleibt. I-4 ist die End-to-End-Variante: zwei Backends erzeugen
        zwei KMs, beide initialize, beide load_master_key — die
        zurueckgelieferten DEK-Bytes muessen identisch sein. Damit ist
        die Kombination "wrap stabil" + "unwrap deterministisch" als
        ganzheitliche Eigenschaft verifiziert.
        """
        backend = InMemoryDPAPIBackend()

        km1 = KeyManager(backend=backend)
        km1.initialize()
        dek_first = km1.load_master_key()

        # Zweite Instanz liest dieselbe Datei (initialize ist no-op).
        km2 = KeyManager(backend=backend)
        km2.initialize()
        dek_second = km2.load_master_key()

        assert dek_first == dek_second
        assert len(dek_first) == 32

    def test_K6_corrupt_raises_no_overwrite(
        self, isolated_master_key_file
    ) -> None:
        """Existierende Datei ohne valides Wrap-Format triggert
        ``KeyManagerCorruptError``. Datei bleibt UNANGETASTET — kein
        Auto-Reset, sonst gefaehrlich (siehe THREAT_MODEL.md R-8)."""
        # Bytes ohne InMemoryDPAPIBackend-Header → unwrap failt
        corrupted = b"corrupted_no_header_just_random_bytes_xxxxxxxxxxxxxxxx"
        isolated_master_key_file.write_bytes(corrupted)

        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)

        with pytest.raises(KeyManagerCorruptError, match="Recovery"):
            km.initialize()

        # Datei wurde nicht ueberschrieben.
        assert isolated_master_key_file.read_bytes() == corrupted

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX-Permissions — Windows ignoriert chmod 0o600 leise.",
    )
    def test_K11_permissions_0600_on_posix(
        self, isolated_master_key_file
    ) -> None:
        """Auf POSIX hat ``master.key.wrapped`` mode 0600 nach Init."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        mode = isolated_master_key_file.stat().st_mode & 0o777
        assert mode == 0o600

    def test_K12_atomic_write_no_partial_state(
        self, isolated_master_key_file, monkeypatch
    ) -> None:
        """Wenn ``os.replace`` mid-write fehlschlaegt:
        - keine ``master.key.wrapped`` (kein Halb-Zustand)
        - keine ``master.key.wrapped.tmp`` (Cleanup hat gegriffen)
        - ``KeyManagerPermissionError`` propagiert
        """
        original_replace = os.replace

        def failing_replace(src, dst, *args, **kwargs):
            # Erst aufgerufen sein, damit.tmp wirklich existiert.
            raise OSError("Simulierter os.replace-Fehler in K-12")

        monkeypatch.setattr(
            "core.database.key_manager.os.replace",
            failing_replace,
        )

        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)

        with pytest.raises(KeyManagerPermissionError):
            km.initialize()

        # Hauptdatei wurde nie via replace finalisiert.
        assert not isolated_master_key_file.exists()

        #.tmp darf nicht uebrig bleiben — Cleanup-Pfad in initialize
        # muss die Datei entfernt haben.
        tmp_path = isolated_master_key_file.with_name(
            isolated_master_key_file.name + ".tmp"
        )
        assert not tmp_path.exists()

        # Sanity: ohne den Mock funktioniert es wieder (zeigt, dass der
        # Mock der einzige Ausloeser war).
        monkeypatch.setattr(
            "core.database.key_manager.os.replace",
            original_replace,
        )
        km.initialize()
        assert isolated_master_key_file.exists()


# ---------------------------------------------------------------------------
# — load_master_key
# ---------------------------------------------------------------------------


class TestKeyManagerLoadMasterKey:
    """Schritt 1.3 — ``load_master_key`` liest DEK, cached final im RAM.

    Cache-Strategie A (siehe §2.5 + Code-Doc): final innerhalb
    einer KeyManager-Instanz. File-Replacement zur Laufzeit erfordert
    explizit eine neue Instanz.
    """

    def test_L1_returns_dek_after_initialize(
        self, isolated_master_key_file
    ) -> None:
        """Nach ``initialize`` liefert ``load_master_key`` 32 Bytes."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        dek = km.load_master_key()
        assert isinstance(dek, bytes)
        assert len(dek) == 32

    def test_L2_dek_matches_what_initialize_wrote(
        self, isolated_master_key_file
    ) -> None:
        """``load_master_key`` liefert exakt den DEK, den
        ``initialize`` in die Datei geschrieben hat."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        # Direkt-Auslese der Datei + Unwrap zum Vergleich.
        wrapped = isolated_master_key_file.read_bytes()
        expected_dek = backend.unwrap(wrapped)

        actual_dek = km.load_master_key()
        assert actual_dek == expected_dek

    def test_L3_final_cache_no_second_disk_read(
        self, isolated_master_key_file, monkeypatch
    ) -> None:
        """Zweiter ``load_master_key``-Call liest NICHT erneut von Disk.

        Verifiziert, dass nach dem ersten Aufruf der Path-Read-Hook nicht
        mehr ausgeloest wird — Cache-Strategie A ist Final.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        # Erster Call (warmt Cache).
        first_dek = km.load_master_key()

        # Ab jetzt: Path.read_bytes wuerde fail-en, falls erneut versucht.
        read_count = {"calls": 0}
        original_read_bytes = Path.read_bytes

        def counting_read(self_path: Path) -> bytes:
            read_count["calls"] += 1
            return original_read_bytes(self_path)

        monkeypatch.setattr("pathlib.Path.read_bytes", counting_read)

        # Zweiter Call — sollte Cache treffen.
        second_dek = km.load_master_key()

        assert read_count["calls"] == 0  # kein Disk-Read
        assert second_dek == first_dek  # gleicher DEK

    def test_L3_returned_bytes_are_immutable_copy(
        self, isolated_master_key_file
    ) -> None:
        """Caller bekommt ``bytes``, nicht den ``bytearray``-Cache.

        Effekt: Caller kann das Ergebnis nicht versehentlich modifizieren
        und damit die wipe-Strategie aushebeln.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        dek = km.load_master_key()
        assert isinstance(dek, bytes)
        assert not isinstance(dek, bytearray)

    def test_L4_not_initialized_when_file_missing(
        self, isolated_master_key_file  # noqa: ARG002 — Fixture rein fuer Pfad-Setup
    ) -> None:
        """Ohne ``initialize`` triggert ``load_master_key``
        ``KeyManagerNotInitializedError`` mit klarem Recovery-Hinweis."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)

        # initialize wurde nicht aufgerufen → Datei existiert nicht.
        with pytest.raises(
            KeyManagerNotInitializedError,
            match="initialize",
        ):
            km.load_master_key()

    def test_L5_corrupt_when_backend_unwrap_fails(
        self, isolated_master_key_file
    ) -> None:
        """Existierende, aber via Backend nicht entschluesselbare Datei
        triggert ``KeyManagerCorruptError``."""
        # Bytes ohne Header → InMemoryDPAPIBackend.unwrap failt.
        isolated_master_key_file.write_bytes(b"corrupted_bytes_no_header_xx")

        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)

        with pytest.raises(KeyManagerCorruptError, match="Recovery"):
            km.load_master_key()


# ---------------------------------------------------------------------------
# K-7, K-8, K-9, D-1, D-2, D-3, D-4 — derive_secondary_key
# ---------------------------------------------------------------------------


class TestKeyManagerDeriveSecondaryKey:
    """Schritt 1.4 — ``derive_secondary_key`` mit HKDF + Domain-Separation.

    Tests verwenden ``InMemoryDPAPIBackend``, weil HKDF unabhaengig vom
    Backend ist (HKDF arbeitet auf dem entwrappten DEK).
    """

    def test_D1_domain_separation(self, isolated_master_key_file) -> None:
        """``derive("a") != derive("b")`` — Domain-Separation via info-Param.

        Verwendet eine Sammlung typischer Purposes (heutige + geplante)
        plus zwei Test-Strings — alle 5 Schluessel sind unique.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        purposes = [
            "secure_storage",   # Subtask 2
            "audit_log_hmac",   # Reserve
            "future_xyz",       # Hypothetisch
            "test_purpose_1",
            "test_purpose_2",
        ]
        keys = {km.derive_secondary_key(p) for p in purposes}
        assert len(keys) == len(purposes)  # alle unique

    def test_D2_determinism_within_instance(
        self, isolated_master_key_file
    ) -> None:
        """``derive("secure_storage")`` 10x → byte-identisch."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        results = [km.derive_secondary_key("secure_storage") for _ in range(10)]
        # Alle Aufrufe liefern dasselbe Ergebnis.
        assert all(r == results[0] for r in results)
        assert len(results[0]) == 32

    def test_D5_stability_across_instances(
        self, isolated_master_key_file
    ) -> None:
        """Zwei KeyManager-Instanzen mit gleichem Backend, gleicher Datei
        liefern fuer denselben purpose denselben Schluessel.

        Verhindert, dass jemand versehentlich eine instance-spezifische
        Komponente in den info-String einbaut (z. B. ``id(self)``).
        purpose ist die einzige Variable.
        """
        backend = InMemoryDPAPIBackend()

        km1 = KeyManager(backend=backend)
        km1.initialize()
        key1 = km1.derive_secondary_key("test_stability")

        # Zweite Instanz: gleicher Backend, gleiche bestehende Datei.
        km2 = KeyManager(backend=backend)
        km2.initialize()  # idempotent — liest existierende Datei nur
        key2 = km2.derive_secondary_key("test_stability")

        assert key1 == key2

    def test_D3_empty_purpose_raises_value_error(
        self, isolated_master_key_file
    ) -> None:
        """Leerer purpose-String triggert ``ValueError``."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        with pytest.raises(ValueError, match="non-empty"):
            km.derive_secondary_key("")

    def test_D4_whitespace_only_purpose_raises_value_error(
        self, isolated_master_key_file
    ) -> None:
        """Nur-Whitespace-purpose triggert ``ValueError``."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        whitespace_strings = ["   ", "\t\t", "\n", " \t \n ", "   \r\n  "]
        for ws in whitespace_strings:
            with pytest.raises(ValueError, match="non-empty"):
                km.derive_secondary_key(ws)

    def test_D6_unicode_purpose_works(
        self, isolated_master_key_file
    ) -> None:
        """UTF-8-encoded Unicode-Purposes funktionieren — info-Param ist
        ``str.encode("utf-8")``.

        Damit ist auch Domain-Separation fuer Unicode-Purposes intakt.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        # Deutsch + Emoji + CJK
        for purpose in [
            "schluessel_speicher",
            "schlüssel_speicher",  # Umlaut-Variante
            "🔐_storage",
            "鍵_格納",
        ]:
            key = km.derive_secondary_key(purpose)
            assert isinstance(key, bytes)
            assert len(key) == 32

        # Domain-Separation auch fuer Unicode:
        key_a = km.derive_secondary_key("schlüssel_speicher")
        key_b = km.derive_secondary_key("schluessel_speicher")
        assert key_a != key_b

    def test_D7_returns_32_bytes(self, isolated_master_key_file) -> None:
        """Output ist immer 32 Byte (256 bit)."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        key = km.derive_secondary_key("test")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_propagates_not_initialized_error(
        self, isolated_master_key_file  # noqa: ARG002
    ) -> None:
        """Ohne ``initialize``: KeyManagerNotInitializedError ueber
        ``load_master_key`` propagiert nach aussen.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)

        # initialize wurde nicht aufgerufen
        with pytest.raises(KeyManagerNotInitializedError):
            km.derive_secondary_key("test")


# ---------------------------------------------------------------------------
# K-13, K-14a/b/c, K-15 — wipe
# ---------------------------------------------------------------------------


class TestKeyManagerWipe:
    """Schritt 1.5 — ``wipe`` ueberschreibt RAM-DEK best-effort.

    Tests verifizieren das vollstaendige Cache-Lifecycle:
    load → wipe → load erzeugt genau einen Disk-Read.
    """

    def test_K13_wipe_clears_dek_from_cache(
        self, isolated_master_key_file
    ) -> None:
        """Pre-Condition: Cache enthaelt DEK. Post-Condition: ``_dek``
        ist ``None``. Pre-wipe-bytes-Kopie bleibt unangetastet (eigener
        Heap-Slot)."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        # Pre-Condition: Cache fuellen.
        dek_before = km.load_master_key()
        assert km._dek is not None  # noqa: SLF001
        assert len(km._dek) == 32  # noqa: SLF001
        assert bytes(km._dek) == dek_before  # noqa: SLF001

        km.wipe()

        # Post-Condition: Cache leer (None).
        assert km._dek is None  # noqa: SLF001

        # Pre-wipe-Kopie ist NICHT betroffen — bytes ist immutable und
        # liegt in eigenem Heap-Slot. Verifiziert die bewusste Trennung
        # zwischen Cache (mutable) und Caller-Kopie (immutable). Falls
        # jemand spaeter versehentlich auf den bytearray-Cache-Slot
        # direkt referenzieren wuerde (statt ``bytes``-Kopie), wuerde
        # dieser Test brechen.
        assert dek_before is not None
        assert len(dek_before) == 32

    def test_K13_internal_bytearray_zeroed_after_wipe(
        self, isolated_master_key_file
    ) -> None:
        """Vor ``self._dek = None`` werden alle Bytes auf ``0x00`` gesetzt.

        Wir halten eine Referenz auf den bytearray-Slot vor dem wipe,
        damit wir die Ueberschreibung sehen koennen — ``self._dek = None``
        droppt nur die Klasse-Attribut-Referenz, der bytearray bleibt
        ueber unsere Variable lesbar.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()
        km.load_master_key()

        # Referenz auf bytearray vor wipe holen.
        cache_ref = km._dek  # noqa: SLF001
        assert isinstance(cache_ref, bytearray)
        # Pre-Condition: nicht schon Nullen (32-Byte-DEK ist
        # statistisch fast garantiert nicht all-Zero).
        assert any(b != 0 for b in cache_ref)

        km.wipe()

        # Die alte Referenz zeigt auf dasselbe bytearray-Objekt, das
        # wipe in-place ueberschrieben hat. Bytearray ist mutable —
        # wir sehen die Ueberschreibung.
        assert all(b == 0 for b in cache_ref)

    def test_K14a_wipe_without_prev_load_is_noop(
        self, isolated_master_key_file
    ) -> None:
        """``wipe`` ohne vorherigen ``load_master_key`` darf nicht
        failen. Cache ist noch ``None``, bleibt ``None``."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        # Cache wurde NIE gefuellt.
        assert km._dek is None  # noqa: SLF001

        km.wipe()  # darf nicht crashen

        assert km._dek is None  # noqa: SLF001 — immer noch None

    def test_K14b_wipe_after_load_clears_cache(
        self, isolated_master_key_file
    ) -> None:
        """``wipe`` nach ``load_master_key`` setzt Cache auf ``None``."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()
        km.load_master_key()
        assert km._dek is not None  # noqa: SLF001

        km.wipe()

        assert km._dek is None  # noqa: SLF001

    def test_K14c_wipe_after_wipe_is_noop(
        self, isolated_master_key_file
    ) -> None:
        """Doppelter ``wipe``-Aufruf schadet nicht."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()
        km.load_master_key()

        km.wipe()
        km.wipe()  # darf nicht crashen

        assert km._dek is None  # noqa: SLF001

    def test_K15_load_after_wipe_reads_from_disk(
        self, isolated_master_key_file, monkeypatch
    ) -> None:
        """Cache-Lifecycle vollstaendig: load → wipe → load erzeugt
        genau einen NEUEN Disk-Read.

        Verifikation der Cache-Strategie A (:meth:`KeyManager.load_master_key` Doc): nach ``wipe`` muss
        der naechste ``load_master_key`` frisch von Disk lesen, nicht
        aus einem alten Cache.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        # Erster Load — waermt Cache.
        dek_before = km.load_master_key()

        km.wipe()
        assert km._dek is None  # noqa: SLF001

        # Counter installieren NACH wipe, damit nur der refill-Read
        # gezaehlt wird.
        read_count = {"calls": 0}
        original_read = Path.read_bytes

        def counted_read(self_path: Path) -> bytes:
            read_count["calls"] += 1
            return original_read(self_path)

        monkeypatch.setattr("pathlib.Path.read_bytes", counted_read)

        # Refill-Load nach wipe.
        dek_after = km.load_master_key()

        assert dek_before == dek_after  # gleicher DEK von Disk
        assert read_count["calls"] == 1  # genau ein Disk-Read


# ---------------------------------------------------------------------------
# M-1, M-2, M-3 — get_key_metadata
# ---------------------------------------------------------------------------


class TestKeyManagerGetKeyMetadata:
    """Schritt 1.6 — ``get_key_metadata`` liefert read-only Diagnose."""

    def test_M1_no_key_material_in_result(
        self, isolated_master_key_file
    ) -> None:
        """Result-Dict enthaelt KEINE Key-Daten — weder DEK noch wrapped
        Bytes noch abgeleitetes Material.

        Verifiziert in zwei Stufen:
        1. Keine Key-Bytes (alle Werte sind str/int/bool/None).
        2. Keine "verdaechtigen" Schluessel-Namen ("dek", "secret",...).
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        metadata = km.get_key_metadata()

        # Stufe 1: Werte sind alle nicht-bytes.
        for key, value in metadata.items():
            assert not isinstance(value, bytes), (
                f"Field '{key}' enthaelt bytes-Wert (potenzielles "
                f"Schluessel-Material)"
            )
            assert not isinstance(value, bytearray), (
                f"Field '{key}' enthaelt bytearray-Wert (potenzielles "
                f"Schluessel-Material)"
            )
            # Erlaubte Typen: str, int, bool, None (str ist hier kein
            # Hex-Hash-Verdacht, weil wir auf Field-Namen filtern).
            assert isinstance(value, str | int | bool | type(None)), (
                f"Field '{key}' hat unerwarteten Typ {type(value).__name__}"
            )

        # Stufe 2: Keine "verdaechtigen" Schluessel-Namen.
        forbidden_substrings = (
            "dek",
            "secret",
            "private",
            "wrapped_bytes",  # waere ein Schluessel-Inhalt
            "ciphertext",
            "plaintext",
            "raw_key",
        )
        for key in metadata:
            lowered = key.lower()
            for substring in forbidden_substrings:
                assert substring not in lowered, (
                    f"Key '{key}' enthaelt verbotenes Substring "
                    f"'{substring}'"
                )

    def test_M2_schema_complete_when_initialized(
        self, isolated_master_key_file
    ) -> None:
        """Alle dokumentierten Felder im Result; konkrete Werte konsistent."""
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        metadata = km.get_key_metadata()

        expected_keys = {
            "schema_version",
            "wrapped_path",
            "wrapped_exists",
            "wrapped_created_at",
            "wrapped_size_bytes",
            "backend_type",
            "hkdf_salt_version",
            "kdf_algorithm",
            "key_length_bits",
            "rotation_supported",
        }
        assert set(metadata.keys()) == expected_keys

        # Konkrete Werte:
        assert metadata["schema_version"] == "1"
        assert metadata["backend_type"] == BackendKind.IN_MEMORY.value
        assert metadata["hkdf_salt_version"] == "v1"
        assert metadata["kdf_algorithm"] == "HKDF-SHA256"
        assert metadata["key_length_bits"] == 256
        assert metadata["rotation_supported"] is False
        assert metadata["wrapped_exists"] is True
        assert metadata["wrapped_size_bytes"] > 0
        # ISO-8601-UTC-Format: "2026-05-04T13:55:12+00:00"-aehnlich.
        assert isinstance(metadata["wrapped_created_at"], str)
        assert "T" in metadata["wrapped_created_at"]
        assert (
            "+00:00" in metadata["wrapped_created_at"]
            or "Z" in metadata["wrapped_created_at"]
        )

    def test_M2_schema_when_not_initialized(
        self, isolated_master_key_file  # noqa: ARG002 — fixture nur fuer Pfad-Setup
    ) -> None:
        """Schema bleibt konsistent auch wenn ``master.key.wrapped`` fehlt.

        Diagnose-Werkzeug muss in nicht-initialisiertem Zustand laufen.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        # KEIN initialize — Datei existiert nicht.

        metadata = km.get_key_metadata()

        assert metadata["schema_version"] == "1"
        assert metadata["wrapped_exists"] is False
        assert metadata["wrapped_size_bytes"] == 0
        assert metadata["wrapped_created_at"] is None

        # Andere Felder weiterhin korrekt:
        assert metadata["backend_type"] == BackendKind.IN_MEMORY.value
        assert metadata["hkdf_salt_version"] == "v1"
        assert metadata["kdf_algorithm"] == "HKDF-SHA256"
        assert metadata["key_length_bits"] == 256
        assert metadata["rotation_supported"] is False

    def test_M2_backend_type_matches_actual_backend(
        self, isolated_master_key_file
    ) -> None:
        """``backend_type`` matcht den:class:`BackendKind`-Wert des
        injizierten Backends.

        Pruefen ueber alle 4 Backends — wenn jemand einen neuen Backend
        hinzufuegt, MUSS er ein ``KIND``-Class-Attribut deklarieren,
        sonst faellt schon der Import auf (Protocol-Verletzung).
        """
        backends_and_kinds = [
            (InMemoryDPAPIBackend(), BackendKind.IN_MEMORY),
            (WindowsDPAPIBackend(), BackendKind.WINDOWS_DPAPI),
            (MacOSKeychainBackend(), BackendKind.MACOS_KEYCHAIN),
            (LinuxLibsecretBackend(), BackendKind.LINUX_LIBSECRET),
        ]
        for backend, expected_kind in backends_and_kinds:
            km = KeyManager(backend=backend)
            metadata = km.get_key_metadata()
            assert metadata["backend_type"] == expected_kind.value
            # Stabile snake_case-Form, nicht Klassen-Name:
            assert "_" in metadata["backend_type"] or metadata["backend_type"] == "in_memory"
            assert metadata["backend_type"].islower()

    def test_M4_schema_version_is_string_one(
        self, isolated_master_key_file  # noqa: ARG002
    ) -> None:
        """``schema_version`` ist genau ``"1"`` (str).

        Erlaubt zukuenftige Schema-Erweiterungen ohne Konsumenten zu
        brechen — sie sehen ein unerwartetes ``"2"`` und koennen klar
        fail-en statt missverstaendlich Werte zu ignorieren.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        # Funktioniert auch ohne initialize.

        metadata = km.get_key_metadata()
        assert metadata["schema_version"] == "1"
        assert isinstance(metadata["schema_version"], str)

    def test_M5_backend_kind_enum_is_stable_api(
        self, isolated_master_key_file
    ) -> None:
        """Der ``backend_type``-Wert ist der stabile:class:`BackendKind`-
        Enum-Wert, NICHT der Klassen-Name.

        Verifiziert die Architektur-Entscheidung aus 1.7-Review: bei einer
        Klassen-Umbenennung darf sich der Diagnose-Output NICHT aendern.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        metadata = km.get_key_metadata()

        # NICHT der Klassen-Name:
        assert metadata["backend_type"] != "InMemoryDPAPIBackend"
        # Stattdessen der Enum-Wert:
        assert metadata["backend_type"] == "in_memory"
        # Und identisch zum Class-Attribut:
        assert metadata["backend_type"] == backend.KIND.value

    def test_M3_no_dek_access_no_cache_population(
        self, isolated_master_key_file
    ) -> None:
        """``get_key_metadata`` befuellt den DEK-Cache NICHT.

        Wichtig: Methode ist read-only auf Disk-Metadaten + Konstanten.
        Diagnose-Werkzeug muss auch im "nichts geladen"-Zustand sicher
        sein.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        # Pre-Condition: Cache ist None (kein load_master_key).
        assert km._dek is None  # noqa: SLF001

        km.get_key_metadata()

        # Post-Condition: Cache ist immer noch None.
        assert km._dek is None  # noqa: SLF001

    def test_M3_works_after_wipe(self, isolated_master_key_file) -> None:
        """``get_key_metadata`` funktioniert auch nach ``wipe``.

        Diagnose-Werkzeug muss bei Fehlerdiagnose laufen koennen.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()
        km.load_master_key()
        km.wipe()
        assert km._dek is None  # noqa: SLF001

        # get_key_metadata muss trotzdem funktionieren.
        metadata = km.get_key_metadata()
        assert metadata["wrapped_exists"] is True
        # Cache wurde NICHT erneut befuellt.
        assert km._dek is None  # noqa: SLF001

    def test_M3_does_not_call_backend_unwrap(
        self, isolated_master_key_file, monkeypatch
    ) -> None:
        """``get_key_metadata`` ruft den Backend NICHT auf.

        Verifiziert, dass die Methode wirklich Disk-Metadaten + Konstanten
        konsumiert, nicht den DEK-Pfad.
        """
        backend = InMemoryDPAPIBackend()
        km = KeyManager(backend=backend)
        km.initialize()

        unwrap_call_count = {"calls": 0}
        original_unwrap = backend.unwrap

        def counting_unwrap(ciphertext: bytes) -> bytes:
            unwrap_call_count["calls"] += 1
            return original_unwrap(ciphertext)

        monkeypatch.setattr(backend, "unwrap", counting_unwrap)

        km.get_key_metadata()

        assert unwrap_call_count["calls"] == 0


# ---------------------------------------------------------------------------
# migrate_legacy_db — Smoke-Test (echte Mig-Familie in tests/database/)
# ---------------------------------------------------------------------------
#
# TestSkeletonStubs wurde am 2026-05-04 (Schritt 1.7) aufgeloest — alle
# KeyManager-Lifecycle-Methoden sind seit den Schritten 1.2 bis 1.6
# produktiv (initialize, load_master_key, derive_secondary_key, wipe,
# get_key_metadata). ``rotate_master_key`` lebt als bewusster Post-Beta-
# Stub in:class:`TestRotateMasterKeyStub` mit eigener Begruendung.
#
# ``migrate_legacy_db`` wurde in Subtask 3 Schritt 3.3 produktiv
# implementiert. Die echten Migrations-Tests (Mig-/I-/B-Familien aus
# MIGRATION_TEST_PLAN) leben in
#:file:`tests/database/test_migrate_to_envelope.py`. Der Test hier ist
# nur ein API-Smoke: ``migrate_legacy_db`` returns
#:class:`MigrationStatus`-Enum auch fuer eine nicht-existente DB
# (Pfad-Fall, der den Failure-Pfad triggert).


def test_migrate_legacy_db_returns_failed_for_invalid_db_file(
    isolated_master_key_file, tmp_path  # noqa: ARG001 -- Fixture-Setup ist Pflicht
) -> None:
    """API-Smoke: ``migrate_legacy_db`` returns:class:`MigrationStatus`
    fuer eine existierende Datei, die keine valide SQLCipher-DB ist.

    Verifiziert lediglich den API-Vertrag — die echten Migrations-
    Szenarien (M-1..M-4, I-1..I-4) sind in
:file:`tests/database/test_migrate_to_envelope.py` gedeckt.
    """
    from core.database.key_manager import MigrationStatus  # noqa: PLC0415

    km = KeyManager(backend=InMemoryDPAPIBackend())
    km.initialize()
    fake_db = tmp_path / "fake.db"
    # Random Bytes — kein gueltiger SQLite/SQLCipher-Header.
    fake_db.write_bytes(b"this is definitely not a database file" * 10)
    status = km.migrate_legacy_db(fake_db, lambda: "00" * 32)
    assert status == MigrationStatus.FAILED
