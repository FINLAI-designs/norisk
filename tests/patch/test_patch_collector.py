"""
test_patch_collector — pytest-Tests fuer core/patch_collector.py.

PM-1.1a. Deckt die 6 Akzeptanzkriterien aus dem Task-Spec:

1. SoftwareItem ist frozen dataclass
2. collect_winget bei Timeout/Parse-Fehler -> leere Liste, kein Crash
3. collect_registry bei Fehler -> leere Liste, kein Crash
4. collect_all Deduplizierung funktioniert
5. Windows-Guard: auf non-Windows-Plattformen leere Liste
6. (implizit) Kein UI-Import — pure Funktionen

Strategie:
- ``subprocess.run`` wird per monkeypatch durch eine Lambda ersetzt,
  die ein vorbereitetes ``CompletedProcess``-Mock liefert.
- ``winreg`` existiert auf Linux/macOS nicht — wir injizieren ein
  Fake-Modul via ``monkeypatch.setitem(sys.modules, "winreg",...)``,
  damit die ``import winreg``-Stelle innerhalb des Sammlers das Fake
  bekommt.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.patch_collector import (
    SoftwareItem,
    collect_all,
    collect_registry,
    collect_winget,
)

_WINGET_JSON_ARGS = [
    "winget", "list", "--output", "json",
    "--accept-source-agreements", "--disable-interactivity",
]
_WINGET_TEXT_ARGS = [
    "winget", "list",
    "--accept-source-agreements", "--disable-interactivity",
]


def _patch_winget_args(monkeypatch, *, args=_WINGET_JSON_ARGS):
    """Umgeht die Version-Detection in:func:`_get_winget_args` und
    liefert die uebergebenen ``args`` direkt zurueck — fuer Tests, die
    nur den ``winget list``-Aufruf interessiert.
    """
    monkeypatch.setattr(
        "core.patch_collector._get_winget_args", lambda: args
    )

# ===========================================================================
# Akzeptanz 1 — SoftwareItem ist frozen dataclass
# ===========================================================================


class TestSoftwareItem:
    def test_alle_felder_setzbar(self):
        item = SoftwareItem(
            name="Mozilla Firefox",
            version="120.0",
            winget_id="Mozilla.Firefox",
            source="winget",
        )
        assert item.name == "Mozilla Firefox"
        assert item.version == "120.0"
        assert item.winget_id == "Mozilla.Firefox"
        assert item.source == "winget"

    def test_winget_id_optional(self):
        item = SoftwareItem(
            name="X", version="1.0", winget_id=None, source="registry"
        )
        assert item.winget_id is None

    def test_frozen_verhindert_zuweisung(self):
        item = SoftwareItem(
            name="X", version="1.0", winget_id=None, source="registry"
        )
        with pytest.raises(FrozenInstanceError):
            item.name = "Y"  # type: ignore[misc]

    def test_gleichheit_basiert_auf_feldern(self):
        a = SoftwareItem(name="X", version="1.0", winget_id=None, source="registry")
        b = SoftwareItem(name="X", version="1.0", winget_id=None, source="registry")
        assert a == b

    def test_hashbar(self):
        a = SoftwareItem(name="X", version="1.0", winget_id=None, source="registry")
        # frozen=True macht dataclass hashbar
        assert hash(a) == hash(a)


# ===========================================================================
# Akzeptanz 2 — collect_winget
# ===========================================================================


class TestCollectWingetWindowsGuard:
    def test_non_windows_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        assert collect_winget() == []


class TestCollectWingetHappyPath:
    def test_parst_korrekte_softwareitems(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_winget_args(monkeypatch)
        winget_json = json.dumps(
            [
                {
                    "Id": "Mozilla.Firefox",
                    "Name": "Mozilla Firefox",
                    "Version": "120.0.1",
                    "Source": "winget",
                },
                {
                    "Id": "Microsoft.PowerToys",
                    "Name": "PowerToys",
                    "Version": "0.75.1",
                    "Source": "winget",
                },
            ]
        )
        completed = MagicMock(returncode=0, stdout=winget_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_winget()

        assert items == [
            SoftwareItem(
                name="Mozilla Firefox",
                version="120.0.1",
                winget_id="Mozilla.Firefox",
                source="winget",
            ),
            SoftwareItem(
                name="PowerToys",
                version="0.75.1",
                winget_id="Microsoft.PowerToys",
                source="winget",
            ),
        ]

    def test_eintrag_ohne_id_setzt_winget_id_none(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_winget_args(monkeypatch)
        winget_json = json.dumps(
            [{"Name": "Hand-installiert", "Version": "1.0"}]
        )
        completed = MagicMock(returncode=0, stdout=winget_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_winget()

        assert len(items) == 1
        assert items[0].winget_id is None

    def test_eintraege_ohne_name_oder_version_uebersprungen(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_winget_args(monkeypatch)
        winget_json = json.dumps(
            [
                {"Id": "ok", "Name": "OK", "Version": "1.0"},
                {"Id": "leerer-name", "Name": "", "Version": "1.0"},
                {"Id": "leere-version", "Name": "Z", "Version": ""},
                {"Id": "fehlende-version", "Name": "M"},
            ]
        )
        completed = MagicMock(returncode=0, stdout=winget_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_winget()

        assert len(items) == 1
        assert items[0].name == "OK"


class TestCollectWingetFehler:
    def test_timeout_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_winget_args(monkeypatch)

        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="winget", timeout=30)

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        assert collect_winget() == []

    def test_winget_nicht_installiert_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_winget_args(monkeypatch)

        def raise_fnf(*a, **kw):
            raise FileNotFoundError("winget not in PATH")

        monkeypatch.setattr(subprocess, "run", raise_fnf)
        assert collect_winget() == []

    def test_oserror_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_winget_args(monkeypatch)

        def raise_oserror(*a, **kw):
            raise OSError("permission denied")

        monkeypatch.setattr(subprocess, "run", raise_oserror)
        assert collect_winget() == []

    def test_returncode_nicht_null_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_winget_args(monkeypatch)
        completed = MagicMock(returncode=1, stdout="", stderr="error")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_winget() == []

    def test_json_parse_fehler_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_winget_args(monkeypatch)
        completed = MagicMock(returncode=0, stdout="kein valides json", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_winget() == []

    def test_json_kein_array_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_winget_args(monkeypatch)
        completed = MagicMock(
            returncode=0, stdout=json.dumps({"unerwartet": "object"}), stderr=""
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_winget() == []


# ===========================================================================
# Akzeptanz 3 — collect_registry
# ===========================================================================


class _FakeRoot:
    """Fake-Handle fuer einen Uninstall-Root-Pfad mit Sub-Eintraegen."""

    def __init__(self, entries: list[tuple[str, str | None, str | None]]) -> None:
        # entries: list of (sub_key_name, display_name, display_version)
        self._entries = entries


class _FakeSub:
    """Fake-Handle fuer einen einzelnen Uninstall-Sub-Key."""

    def __init__(self, dn: str | None, dv: str | None) -> None:
        self.dn = dn
        self.dv = dv

    def __enter__(self) -> _FakeSub:
        return self

    def __exit__(self, *a: object) -> None:
        return None


def _make_fake_winreg(
    paths: dict[str, list[tuple[str, str | None, str | None]]],
) -> SimpleNamespace:
    """Baut ein Fake-winreg-Modul, das die nur die 4 benutzten Calls
    bedient (OpenKey, EnumKey, QueryValueEx, CloseKey).

    HKLM- und HKCU-Pfade werden im selben ``paths``-Dict gehalten.
    Da HKLM-Pfade in der Praxis ``SOFTWARE\\...`` (uppercase) und
    HKCU-Pfade ``Software\\...`` (mixed case) sind, kollidieren die
    String-Keys nicht.
    """
    fake = SimpleNamespace()
    fake.HKEY_LOCAL_MACHINE = object()  # Sentinel
    fake.HKEY_CURRENT_USER = object()   # Sentinel

    _hive_sentinels = (fake.HKEY_LOCAL_MACHINE, fake.HKEY_CURRENT_USER)

    def open_key(parent: object, name: str) -> object:
        if parent in _hive_sentinels:
            if name in paths:
                return _FakeRoot(paths[name])
            raise OSError(f"path not found: {name}")
        # Sub-Key-Open: parent ist _FakeRoot
        assert isinstance(parent, _FakeRoot)
        for sub_name, dn, dv in parent._entries:
            if sub_name == name:
                return _FakeSub(dn, dv)
        raise OSError(f"sub-key not found: {name}")

    def enum_key(handle: object, idx: int) -> str:
        assert isinstance(handle, _FakeRoot)
        if idx >= len(handle._entries):
            raise OSError("no more sub-keys")
        return handle._entries[idx][0]

    def query_value_ex(handle: object, name: str) -> tuple[str, int]:
        assert isinstance(handle, _FakeSub)
        if name == "DisplayName":
            if handle.dn is None:
                raise FileNotFoundError("DisplayName fehlt")
            return (handle.dn, 1)
        if name == "DisplayVersion":
            if handle.dv is None:
                raise FileNotFoundError("DisplayVersion fehlt")
            return (handle.dv, 1)
        raise FileNotFoundError(name)

    def close_key(handle: object) -> None:
        return None

    fake.OpenKey = open_key
    fake.EnumKey = enum_key
    fake.QueryValueEx = query_value_ex
    fake.CloseKey = close_key
    return fake


_PATH_HKLM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
_PATH_WOW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
_PATH_HKCU = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"


class TestCollectRegistryWindowsGuard:
    def test_non_windows_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        assert collect_registry() == []


class TestCollectRegistryHappyPath:
    def test_liest_alle_drei_pfade(self, monkeypatch):
        # HKLM + WOW6432Node + HKCU (Per-User-Installs wie Slack)
        monkeypatch.setattr(sys, "platform", "win32")
        fake = _make_fake_winreg(
            {
                _PATH_HKLM: [
                    ("{firefox-guid}", "Mozilla Firefox", "120.0.1"),
                ],
                _PATH_WOW: [
                    ("{7zip-guid}", "7-Zip 23.01", "23.01"),
                ],
                _PATH_HKCU: [
                    ("{slack-guid}", "Slack", "4.36.140"),
                    ("{discord-guid}", "Discord", "1.0.9034"),
                ],
            }
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_registry()

        assert items == [
            SoftwareItem(
                name="Mozilla Firefox", version="120.0.1",
                winget_id=None, source="registry",
            ),
            SoftwareItem(
                name="7-Zip 23.01", version="23.01",
                winget_id=None, source="registry",
            ),
            SoftwareItem(
                name="Slack", version="4.36.140",
                winget_id=None, source="registry",
            ),
            SoftwareItem(
                name="Discord", version="1.0.9034",
                winget_id=None, source="registry",
            ),
        ]

    def test_hkcu_per_user_install_wird_erfasst(self, monkeypatch):
        """Per-User-Installationen (Slack/Discord/Teams/Zoom) liegen
        nur in HKCU, nicht in HKLM. Mit dem HKCU-Pfad in
        ``_REGISTRY_PATHS`` fallen sie nicht mehr durchs Raster."""
        monkeypatch.setattr(sys, "platform", "win32")
        fake = _make_fake_winreg(
            {
                _PATH_HKLM: [],
                _PATH_WOW: [],
                _PATH_HKCU: [
                    ("{teams-guid}", "Microsoft Teams", "1.6.00.4472"),
                ],
            }
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_registry()

        assert len(items) == 1
        assert items[0].name == "Microsoft Teams"
        assert items[0].source == "registry"

    def test_eintraege_ohne_displayname_uebersprungen(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        fake = _make_fake_winreg(
            {
                _PATH_HKLM: [
                    ("{kb12345}", None, "1.0"),  # Kernel-Update ohne UI
                    ("{firefox-guid}", "Mozilla Firefox", "120.0.1"),
                ],
                _PATH_WOW: [],
                _PATH_HKCU: [],
            }
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_registry()

        assert len(items) == 1
        assert items[0].name == "Mozilla Firefox"

    def test_fehlende_displayversion_setzt_unbekannt(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        fake = _make_fake_winreg(
            {
                _PATH_HKLM: [
                    ("{x}", "Software ohne Version", None),
                ],
                _PATH_WOW: [],
                _PATH_HKCU: [],
            }
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_registry()

        assert len(items) == 1
        assert items[0].version == "unbekannt"

    def test_fehlender_pfad_uebergeht_diesen(self, monkeypatch):
        # Kein WOW6432Node + kein HKCU — typisch auf 32-Bit-Systemen
        # bzw. wenn der User-Hive nicht freigegeben ist.
        monkeypatch.setattr(sys, "platform", "win32")
        fake = _make_fake_winreg(
            {
                _PATH_HKLM: [
                    ("{firefox-guid}", "Mozilla Firefox", "120.0.1"),
                ],
                # WOW + HKCU absichtlich nicht eingetragen → OSError pro
                # Pfad, wird verworfen und der naechste Pfad probiert.
            }
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_registry()

        assert len(items) == 1
        assert items[0].name == "Mozilla Firefox"


class TestCollectRegistryFehler:
    def test_winreg_nicht_importierbar_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        # Fake-winreg, das beim Import einen ImportError ausloest.
        # Trick: setze sys.modules["winreg"] auf None — Python's import
        # raised dann ImportError fuer "import winreg".
        monkeypatch.setitem(sys.modules, "winreg", None)
        assert collect_registry() == []


# ===========================================================================
# Akzeptanz 4 — collect_all Deduplizierung
# ===========================================================================


def _patch_subprocess_dispatch(monkeypatch, *, winget_json=None,
                                appx_json=None,
                                winget_exc=None, appx_exc=None,
                                winget_version="v1.10.10661"):
    """Routet ``subprocess.run`` nach argv: winget oder powershell.

    ``winget --version`` (Version-Detection) wird **separat** mit
    ``winget_version`` (Default ``"v1.10.10661"`` → JSON-Pfad)
    bedient — ``winget_exc`` / ``winget_json`` betreffen nur den
    nachfolgenden ``winget list``-Call. Damit bleiben die TestCollectAll-
    Tests fokussiert auf die List-Logik.
    """

    def fake_run(argv, *args, **kwargs):
        if isinstance(argv, list) and len(argv) >= 2 and argv[0] == "winget":
            if argv[1] == "--version":
                return MagicMock(
                    returncode=0, stdout=winget_version, stderr=""
                )
            # winget list...
            if winget_exc is not None:
                raise winget_exc
            return MagicMock(
                returncode=0, stdout=winget_json or "[]", stderr=""
            )
        cmd = argv[0] if isinstance(argv, list) and argv else ""
        if cmd == "powershell":
            # Mehrere Sammler nutzen powershell (Get-AppxPackage,
            # Windows-Update-COM, Get-PnpDevice). Nur der AppX-Call wird mit
            # ``appx_json`` bedient; Windows-Update + Treiber liefern hier
            # leer (ihr Parser braucht andere Felder als das AppX-JSON, sie
            # blieben sonst still mit AppX-Daten gefuettert). So bleibt die
            # collect_all-Dedup-Erwartung der bestehenden Tests stabil.
            script = argv[3] if isinstance(argv, list) and len(argv) > 3 else ""
            if "Get-PnpDevice" in script or "Microsoft.Update.Session" in script:
                return MagicMock(returncode=0, stdout="", stderr="")
            if appx_exc is not None:
                raise appx_exc
            return MagicMock(
                returncode=0, stdout=appx_json or "[]", stderr=""
            )
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)


class TestCollectAll:
    def test_dedupliziert_gleichen_namen(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        winget_json = json.dumps(
            [
                {
                    "Id": "Mozilla.Firefox",
                    "Name": "Mozilla Firefox",
                    "Version": "120.0.1",
                    "Source": "winget",
                },
                {
                    "Id": "Microsoft.PowerToys",
                    "Name": "PowerToys",
                    "Version": "0.75.1",
                    "Source": "winget",
                },
            ]
        )
        appx_json = json.dumps(
            [
                # MSIX-Eintrag fuer PowerToys = Doppel zu winget
                {"Name": "PowerToys", "Version": "0.75.1"},
                # Neuer MSIX-Eintrag (Store-App)
                {"Name": "Microsoft.Photos",
                 "Version": {"Major": 2024, "Minor": 11050,
                             "Build": 24001, "Revision": 0}},
            ]
        )
        _patch_subprocess_dispatch(
            monkeypatch, winget_json=winget_json, appx_json=appx_json
        )

        # Registry liefert Firefox (Doppel zu winget), 7-Zip (neu)
        fake = _make_fake_winreg(
            {
                _PATH_HKLM: [
                    ("{firefox-guid}", "Mozilla Firefox", "120.0.1"),
                    ("{7zip-guid}", "7-Zip 23.01", "23.01"),
                ],
                _PATH_WOW: [],
                _PATH_HKCU: [],
            }
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_all()

        # Erwartet: 2 winget + 1 Registry-Extra (7-Zip)
        # + 1 MSIX-Extra (Photos). Firefox-Dup + PowerToys-Dup raus.
        assert len(items) == 4
        assert items[0].source == "winget"  # Firefox
        assert items[1].source == "winget"  # PowerToys
        assert items[2].source == "registry"
        assert items[2].name == "7-Zip 23.01"
        assert items[3].source == "msix"
        assert items[3].name == "Microsoft.Photos"

    def test_case_insensitive_dedup_alle_quellen(self, monkeypatch):
        """Dedup schaut ueber alle drei Quellen, case-insensitiv."""
        monkeypatch.setattr(sys, "platform", "win32")
        winget_json = json.dumps(
            [{"Id": "x", "Name": "Mozilla Firefox", "Version": "120.0"}]
        )
        appx_json = json.dumps(
            [{"Name": "MOZILLA FIREFOX", "Version": "120.0"}]
        )
        _patch_subprocess_dispatch(
            monkeypatch, winget_json=winget_json, appx_json=appx_json
        )
        fake = _make_fake_winreg(
            {
                _PATH_HKLM: [
                    # Anderer Casing — soll trotzdem als Doppel erkannt werden
                    ("{ff-guid}", "mozilla firefox", "120.0"),
                ],
                _PATH_WOW: [],
                _PATH_HKCU: [],
            }
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_all()

        assert len(items) == 1
        assert items[0].source == "winget"

    def test_non_windows_alle_quellen_leer(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        # collect_dotnet_runtimes laeuft (dotnet-CLI ist
        # plattformuebergreifend) — fuer diesen Linux-Quellen-leer-Test
        # die CLI als nicht vorhanden simulieren, sonst koennte eine echte
        # dotnet-Installation Eintraege liefern.
        def _raise_fnf(*a, **kw):
            raise FileNotFoundError("dotnet not in PATH")

        monkeypatch.setattr(subprocess, "run", _raise_fnf)
        assert collect_all() == []

    def test_registry_und_msix_bekommen_synthetische_id(self, monkeypatch):
        """Registry-/MSIX-Items (winget_id=None) bekommen in collect_all
        eine stabile synthetische Id (regid:/msix:), winget-Items bleiben
        unveraendert. Store-Items (store_id gesetzt) bleiben ebenfalls
        unangetastet — sie sind via msstore upgradebar."""
        import core.patch_collector as pc  # noqa: PLC0415

        monkeypatch.setattr(
            pc,
            "collect_winget_inventory",
            lambda: [
                SoftwareItem(
                    name="Mozilla Firefox",
                    version="120.0",
                    winget_id="Mozilla.Firefox",
                    source="winget",
                ),
                # Store-App: kein winget_id, aber store_id -> nicht synthetisch
                SoftwareItem(
                    name="KeePassXC",
                    version="2.7",
                    winget_id=None,
                    source="msix",
                    store_id="XP8K2L36VP0QMB",
                ),
            ],
        )
        monkeypatch.setattr(
            pc,
            "collect_registry",
            lambda: [
                SoftwareItem(
                    name="7-Zip 23.01",
                    version="23.01",
                    winget_id=None,
                    source="registry",
                ),
            ],
        )
        monkeypatch.setattr(
            pc,
            "collect_appx",
            lambda: [
                SoftwareItem(
                    name="Microsoft.Photos",
                    version="2024.1",
                    winget_id=None,
                    source="msix",
                ),
            ],
        )

        by_name = {item.name: item for item in collect_all()}

        # winget-Item unveraendert
        assert by_name["Mozilla Firefox"].winget_id == "Mozilla.Firefox"
        # Registry -> regid: mit normalisiertem Namen (ohne Version)
        assert by_name["7-Zip 23.01"].winget_id == "regid:7-zip"
        # MSIX -> msix: mit Paketnamen
        assert by_name["Microsoft.Photos"].winget_id == "msix:Microsoft.Photos"
        # Store-App: store_id bleibt, keine synthetische winget_id
        assert by_name["KeePassXC"].winget_id is None
        assert by_name["KeePassXC"].store_id == "XP8K2L36VP0QMB"

    def test_synthetische_id_ist_stabil_ueber_versionswechsel(self, monkeypatch):
        """Die regid:-Id bleibt ueber Versions-Updates stabil — dieselbe
        App aktualisiert dieselbe PK-Zeile statt zu duplizieren."""
        import core.patch_collector as pc  # noqa: PLC0415

        monkeypatch.setattr(pc, "collect_winget_inventory", list)
        monkeypatch.setattr(pc, "collect_appx", list)
        monkeypatch.setattr(
            pc,
            "collect_registry",
            lambda: [
                SoftwareItem(
                    name="7-Zip 24.08 (x64)",
                    version="24.08",
                    winget_id=None,
                    source="registry",
                ),
            ],
        )
        items = collect_all()
        # Trotz anderer Version + Architektur-Suffix dieselbe Id wie 23.01.
        assert items[0].winget_id == "regid:7-zip"

    def test_nur_registry_wenn_winget_und_msix_leer(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_subprocess_dispatch(
            monkeypatch,
            winget_exc=subprocess.TimeoutExpired(cmd="winget", timeout=30),
            appx_json="[]",
        )
        fake = _make_fake_winreg(
            {
                _PATH_HKLM: [("{x}", "Nur Registry", "1.0")],
                _PATH_WOW: [],
                _PATH_HKCU: [],
            }
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_all()

        assert len(items) == 1
        assert items[0].source == "registry"
        assert items[0].name == "Nur Registry"

    def test_gleicher_name_unterschiedliche_versionen_beide_kommen_durch(
        self, monkeypatch
    ):
        """FIX 1 — Dedup-Schluessel (name, version): parallele
        Mehrfachinstallationen wie ``Python 3.11`` + ``Python 3.12``
        bleiben beide erhalten."""
        monkeypatch.setattr(sys, "platform", "win32")
        winget_json = json.dumps(
            [
                {"Id": "Python.3.11", "Name": "Python", "Version": "3.11.9"},
                {"Id": "Python.3.12", "Name": "Python", "Version": "3.12.5"},
            ]
        )
        _patch_subprocess_dispatch(
            monkeypatch, winget_json=winget_json, appx_json="[]"
        )
        fake = _make_fake_winreg(
            {_PATH_HKLM: [], _PATH_WOW: [], _PATH_HKCU: []}
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_all()

        assert len(items) == 2
        assert {i.version for i in items} == {"3.11.9", "3.12.5"}

    def test_gleicher_name_gleiche_version_winget_gewinnt(self, monkeypatch):
        """FIX 1 — bei echtem Duplikat (Name + Version identisch) ueber
        winget + Registry bleibt **nur** der winget-Eintrag erhalten
        (winget hat die ``Id`` fuer downstream-Schritte)."""
        monkeypatch.setattr(sys, "platform", "win32")
        winget_json = json.dumps(
            [{"Id": "Mozilla.Firefox", "Name": "Mozilla Firefox",
              "Version": "120.0.1"}]
        )
        _patch_subprocess_dispatch(
            monkeypatch, winget_json=winget_json, appx_json="[]"
        )
        fake = _make_fake_winreg(
            {
                _PATH_HKLM: [
                    ("{ff}", "Mozilla Firefox", "120.0.1"),  # gleicher Name+Ver
                ],
                _PATH_WOW: [],
                _PATH_HKCU: [],
            }
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_all()

        assert len(items) == 1
        assert items[0].source == "winget"
        assert items[0].winget_id == "Mozilla.Firefox"

    def test_msix_architektur_duplikate_werden_gefiltert(self, monkeypatch):
        """FIX 1 — Get-AppxPackage liefert pro Framework-Paket je einen
        Eintrag pro Architektur (x86/x64/arm), aber Select-Object
        Name+Version reduziert sie auf identische Tuples. Mit
        Dedup-Schluessel ``(name, version)`` ueberlebt nur einer."""
        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps(
            [
                {"Name": "SomeApp", "Version": "1.0.0.0"},
                {"Name": "SomeApp", "Version": "1.0.0.0"},
                {"Name": "SomeApp", "Version": "1.0.0.0"},
            ]
        )
        _patch_subprocess_dispatch(
            monkeypatch, winget_json="[]", appx_json=appx_json
        )
        fake = _make_fake_winreg(
            {_PATH_HKLM: [], _PATH_WOW: [], _PATH_HKCU: []}
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)

        items = collect_all()

        assert len(items) == 1
        assert items[0].source == "msix"


# ===========================================================================
# FIX 2 — MSIX Noise-Filter (System-Frameworks ausblenden)
# ===========================================================================


class TestMsixNoiseFilter:
    def test_native_framework_wird_gefiltert(self, monkeypatch):
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps(
            [
                {"Name": "Microsoft.NET.Native.Framework.2.2",
                 "Version": "2.2.29512.0"},
                {"Name": "Microsoft.WindowsTerminal",
                 "Version": "1.21.10351.0"},  # legitim, bleibt
            ]
        )
        completed = MagicMock(returncode=0, stdout=appx_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_appx()

        assert len(items) == 1
        assert items[0].name == "Microsoft.WindowsTerminal"

    def test_alle_ignore_prefixes_filtern(self, monkeypatch):
        """Stichproben-Test fuer mehrere Eintraege aus
:data:`_MSIX_IGNORE_PREFIXES`."""
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps(
            [
                {"Name": "Microsoft.VCLibs.140.00", "Version": "14.0.0.0"},
                {"Name": "Microsoft.UI.Xaml.2.7", "Version": "7.2208.0.0"},
                {"Name": "Microsoft.WindowsAppRuntime.1.5",
                 "Version": "5000.0.0.0"},
                {"Name": "Microsoft.XboxGameOverlay", "Version": "1.0.0.0"},
                {"Name": "Microsoft.ZuneMusic", "Version": "11.0.0.0"},
                {"Name": "Windows.CBSPreview", "Version": "1.0.0.0"},
                # Lowercase-Variante:
                {"Name": "windows.immersivecontrolpanel",
                 "Version": "1.0.0.0"},
            ]
        )
        completed = MagicMock(returncode=0, stdout=appx_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_appx()

        assert items == []  # alle gefiltert

    def test_legitime_apps_kommen_durch(self, monkeypatch):
        """Apps, deren Name nicht mit einem Ignore-Prefix beginnt,
        werden NICHT gefiltert — auch wenn sie ``Microsoft.``-prefixed
        sind (z.B. Microsoft.WindowsCalculator, Microsoft.Photos)."""
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps(
            [
                {"Name": "Microsoft.WindowsTerminal",
                 "Version": "1.21.10351.0"},
                {"Name": "Microsoft.WindowsCalculator",
                 "Version": "11.2401.0.0"},
                {"Name": "Microsoft.Photos", "Version": "2024.0.0.0"},
                {"Name": "Microsoft.GamingApp", "Version": "100.0.0.0"},
                {"Name": "SpotifyAB.SpotifyMusic", "Version": "1.0.0.0"},
            ]
        )
        completed = MagicMock(returncode=0, stdout=appx_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_appx()

        assert {i.name for i in items} == {
            "Microsoft.WindowsTerminal",
            "Microsoft.WindowsCalculator",
            "Microsoft.Photos",
            "Microsoft.GamingApp",
            "SpotifyAB.SpotifyMusic",
        }

    def test_case_insensitive_match(self, monkeypatch):
        """Auch wenn die Prefix-Konstante z.B. ``"Microsoft.NET.Native"``
        mit grossem M lautet, sollen Items mit anderer Schreibweise
        (``microsoft.net.native.runtime.x86``) trotzdem gefiltert
        werden — Defense-in-Depth."""
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps(
            [
                {"Name": "microsoft.net.native.runtime.2.2.x86",
                 "Version": "2.2.0.0"},
                {"Name": "MICROSOFT.VCLIBS.140.00", "Version": "14.0.0.0"},
            ]
        )
        completed = MagicMock(returncode=0, stdout=appx_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_appx()

        assert items == []


# ===========================================================================
# collect_appx — MSIX/Store-Apps
# ===========================================================================


class TestCollectAppxWindowsGuard:
    def test_non_windows_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        from core.patch_collector import collect_appx

        assert collect_appx() == []


class TestCollectAppxHappyPath:
    def test_parst_string_version(self, monkeypatch):
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps(
            [
                {"Name": "Microsoft.WindowsTerminal", "Version": "1.21.10351.0"},
                {"Name": "Microsoft.SkypeApp", "Version": "15.110.0.0"},
            ]
        )
        completed = MagicMock(returncode=0, stdout=appx_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_appx()

        assert items == [
            SoftwareItem(
                name="Microsoft.WindowsTerminal",
                version="1.21.10351.0",
                winget_id=None,
                source="msix",
            ),
            SoftwareItem(
                name="Microsoft.SkypeApp",
                version="15.110.0.0",
                winget_id=None,
                source="msix",
            ),
        ]

    def test_parst_object_version_aus_powershell(self, monkeypatch):
        """PowerShell ConvertTo-Json serialisiert ``System.Version`` als
        Object mit Major/Minor/Build/Revision."""
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps(
            [
                {
                    "Name": "Microsoft.Photos",
                    "Version": {
                        "Major": 2024, "Minor": 11050,
                        "Build": 24001, "Revision": 0,
                    },
                },
            ]
        )
        completed = MagicMock(returncode=0, stdout=appx_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_appx()

        assert len(items) == 1
        assert items[0].version == "2024.11050.24001.0"
        assert items[0].source == "msix"

    def test_einzel_objekt_statt_liste(self, monkeypatch):
        """ConvertTo-Json liefert bei einer einzigen Zeile ein Objekt
        statt einer Liste — das muss der Parser auch akzeptieren."""
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps(
            {"Name": "Microsoft.Photos", "Version": "2024.0.0.0"}
        )
        completed = MagicMock(returncode=0, stdout=appx_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_appx()

        assert len(items) == 1
        assert items[0].name == "Microsoft.Photos"

    def test_eintrag_ohne_name_uebersprungen(self, monkeypatch):
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps(
            [
                {"Version": "1.0"},  # kein Name
                {"Name": "OK", "Version": "1.0"},
            ]
        )
        completed = MagicMock(returncode=0, stdout=appx_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_appx()

        assert len(items) == 1
        assert items[0].name == "OK"

    def test_fehlende_version_setzt_unbekannt(self, monkeypatch):
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps([{"Name": "App ohne Version"}])
        completed = MagicMock(returncode=0, stdout=appx_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_appx()

        assert len(items) == 1
        assert items[0].version == "unbekannt"


class TestCollectAppxFehler:
    def test_timeout_gibt_leere_liste(self, monkeypatch):
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")

        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="powershell", timeout=20)

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        assert collect_appx() == []

    def test_powershell_nicht_im_path_gibt_leere_liste(self, monkeypatch):
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")

        def raise_fnf(*a, **kw):
            raise FileNotFoundError("powershell not in PATH")

        monkeypatch.setattr(subprocess, "run", raise_fnf)
        assert collect_appx() == []

    def test_returncode_nicht_null_gibt_leere_liste(self, monkeypatch):
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=1, stdout="", stderr="error")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_appx() == []

    def test_leere_stdout_ist_kein_fehler(self, monkeypatch):
        """User hat keine MSIX-Apps — leere stdout ist keine Warning,
        einfach leere Liste."""
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=0, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_appx() == []

    def test_json_parse_fehler_gibt_leere_liste(self, monkeypatch):
        from core.patch_collector import collect_appx

        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=0, stdout="kein valides json", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_appx() == []


# ===========================================================================
# FIX 2 (Erweiterung) — UUID-Filter + zusaetzliche Prefixes
# ===========================================================================


class TestMsixUuidFilter:
    def test_uuid_name_wird_gefiltert(self, monkeypatch):
        from core.patch_collector import _is_msix_noise, collect_appx

        # Direkter Helper-Check
        assert _is_msix_noise("1527c705-839a-4832-9118-54d4Bd6a0c89")
        assert _is_msix_noise("E2A4F912-2574-4A75-9BB0-0D023378592B")
        assert _is_msix_noise("aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000")
        # Negativ: kein UUID-Match
        assert not _is_msix_noise("Microsoft.WindowsTerminal")
        assert not _is_msix_noise("12345-not-uuid")

        # Integration via collect_appx
        monkeypatch.setattr(sys, "platform", "win32")
        appx_json = json.dumps(
            [
                {"Name": "1527c705-839a-4832-9118-54d4bd6a0c89",
                 "Version": "10.0.19640.1000"},
                {"Name": "Microsoft.Photos", "Version": "2024.0.0.0"},
            ]
        )
        completed = MagicMock(returncode=0, stdout=appx_json, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_appx()

        assert len(items) == 1
        assert items[0].name == "Microsoft.Photos"


class TestMsixZusaetzlichePrefixes:
    def test_capturepicker_wird_gefiltert(self, monkeypatch):
        from core.patch_collector import _is_msix_noise

        assert _is_msix_noise("Microsoft.Windows.CapturePicker")
        assert _is_msix_noise("Microsoft.CredDialogHost")
        assert _is_msix_noise("Microsoft.AAD.BrokerPlugin")
        assert _is_msix_noise("Microsoft.AccountsControl")
        assert _is_msix_noise("Microsoft.AsyncTextService")
        assert _is_msix_noise("Microsoft.capabilityaccessmanager")
        assert _is_msix_noise("Microsoft.Windows.CloudExperienceHost")
        assert _is_msix_noise(
            "Microsoft.Windows.OOBENetworkCaptivePortal"
        )
        assert _is_msix_noise("Microsoft.Windows.PeopleExperienceHost")
        assert _is_msix_noise("Microsoft.Windows.PrintQueueActionCenter")


# ===========================================================================
# FIX 3 — winget Version-Detection
# ===========================================================================


class TestGetWingetArgs:
    def test_winget_nicht_installiert_gibt_none(self, monkeypatch):
        """FileNotFoundError bei ``winget --version`` → None,
        collect_winget faellt sauber auf [] zurueck."""
        from core.patch_collector import _get_winget_args

        def raise_fnf(*a, **kw):
            raise FileNotFoundError("winget not found")

        monkeypatch.setattr(subprocess, "run", raise_fnf)
        assert _get_winget_args() is None

    def test_neue_version_liefert_json_args(self, monkeypatch):
        from core.patch_collector import _get_winget_args

        completed = MagicMock(returncode=0, stdout="v1.10.10661\n", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        args = _get_winget_args()
        assert args is not None
        assert "--output" in args
        assert "json" in args

    def test_alte_version_liefert_text_args(self, monkeypatch):
        """winget < 1.6 unterstuetzt --output json nicht — Text-Pfad."""
        from core.patch_collector import _get_winget_args

        completed = MagicMock(returncode=0, stdout="v1.4.10173\n", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        args = _get_winget_args()
        assert args is not None
        assert "--output" not in args
        assert "json" not in args
        assert "list" in args

    def test_genau_1_6_liefert_json(self, monkeypatch):
        """Boundary: 1.6.0 ist die erste Version mit --output json."""
        from core.patch_collector import _get_winget_args

        completed = MagicMock(returncode=0, stdout="v1.6.0\n", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        args = _get_winget_args()
        assert args is not None
        assert "json" in args

    def test_unparsbare_version_faellt_auf_text_zurueck(self, monkeypatch):
        from core.patch_collector import _get_winget_args

        completed = MagicMock(returncode=0, stdout="seltsamer-output", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        args = _get_winget_args()
        assert args is not None
        assert "json" not in args

    def test_returncode_nicht_null_gibt_none(self, monkeypatch):
        from core.patch_collector import _get_winget_args

        completed = MagicMock(returncode=1, stdout="", stderr="error")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert _get_winget_args() is None

    def test_timeout_gibt_none(self, monkeypatch):
        from core.patch_collector import _get_winget_args

        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="winget", timeout=5)

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        assert _get_winget_args() is None


class TestParseWingetText:
    def test_parst_winget_text_tabelle(self, monkeypatch):
        """Echtes winget-list-Text-Output-Format (winget < 1.6)."""
        from core.patch_collector import _parse_winget_text

        sample = (
            "Name                                Id                       "
            "Version       Available    Source\n"
            "-------------------------------------------------------------"
            "----------------------------------\n"
            "Mozilla Firefox                     Mozilla.Firefox          "
            "120.0.1       121.0        winget\n"
            "PowerToys                           Microsoft.PowerToys      "
            "0.75.1                     winget\n"
        )
        items = _parse_winget_text(sample)
        assert len(items) == 2
        assert items[0] == SoftwareItem(
            name="Mozilla Firefox", version="120.0.1",
            winget_id="Mozilla.Firefox", source="winget",
        )
        assert items[1] == SoftwareItem(
            name="PowerToys", version="0.75.1",
            winget_id="Microsoft.PowerToys", source="winget",
        )

    def test_text_ohne_header_gibt_leere_liste(self):
        from core.patch_collector import _parse_winget_text

        assert _parse_winget_text("nur garbage ohne tabelle") == []

    def test_collect_winget_nutzt_text_pfad_bei_alter_version(
        self, monkeypatch
    ):
        """End-to-End: alte winget-Version → _get_winget_args liefert
        Text-Args → subprocess.run gibt Text-Tabelle → korrekte Items."""
        monkeypatch.setattr(sys, "platform", "win32")

        text_table = (
            "Name              Id                   Version  Available  Source\n"
            "-------------------------------------------------------------\n"
            "Firefox           Mozilla.Firefox      120.0    121.0      winget\n"
        )

        def fake_run(argv, *args, **kwargs):
            if "--version" in argv:
                return MagicMock(
                    returncode=0, stdout="v1.4.10173", stderr=""
                )
            # winget list (Text-Pfad, kein --output json)
            assert "--output" not in argv
            return MagicMock(returncode=0, stdout=text_table, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        items = collect_winget()
        assert len(items) == 1
        assert items[0].name == "Firefox"
        assert items[0].version == "120.0"
        assert items[0].winget_id == "Mozilla.Firefox"

    def test_collect_winget_winget_komplett_nicht_verfuegbar(
        self, monkeypatch
    ):
        """End-to-End: winget komplett nicht installiert
        (FileNotFoundError bei --version) → leere Liste."""
        monkeypatch.setattr(sys, "platform", "win32")

        def raise_fnf(*a, **kw):
            raise FileNotFoundError("winget not in PATH")

        monkeypatch.setattr(subprocess, "run", raise_fnf)
        assert collect_winget() == []


# ===========================================================================
# Bug 3 / Option C — collect_winget_module (Microsoft.WinGet.Client PowerShell)
# ===========================================================================

from core.patch_collector import collect_winget_module  # noqa: E402

_PWSH_ARGS_PREFIX = ["powershell", "-NoProfile", "-Command"]


def _patch_pwsh_subprocess(monkeypatch, *, returncode=0, stdout="[]", stderr=""):
    """Mockt subprocess.run fuer PowerShell-Subprocess-Aufrufe."""
    completed = MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
    return completed


class TestCollectWingetModule:
    """Tests fuer ``collect_winget_module`` (PowerShell-Modul-Pfad)."""

    def test_non_windows_returns_empty(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        assert collect_winget_module() == []

    def test_subprocess_timeout_returns_empty(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        def boom(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="powershell", timeout=30)

        monkeypatch.setattr(subprocess, "run", boom)
        assert collect_winget_module() == []

    def test_powershell_not_in_path_returns_empty(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        def boom(*args, **kwargs):
            raise FileNotFoundError("powershell.exe")

        monkeypatch.setattr(subprocess, "run", boom)
        assert collect_winget_module() == []

    def test_returncode_nonzero_returns_empty(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_pwsh_subprocess(
            monkeypatch, returncode=1, stdout="", stderr="Module not found"
        )
        assert collect_winget_module() == []

    def test_invalid_json_returns_empty(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_pwsh_subprocess(monkeypatch, stdout="not-json{{")
        assert collect_winget_module() == []

    def test_empty_stdout_returns_empty(self, monkeypatch):
        # Get-WinGetPackage liefert "" wenn kein einzelnes Paket — wir
        # tolerieren das ohne JSON-Parse-Versuch.
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_pwsh_subprocess(monkeypatch, stdout="")
        assert collect_winget_module() == []

    def test_empty_array_returns_empty(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_pwsh_subprocess(monkeypatch, stdout="[]")
        assert collect_winget_module() == []

    # -- Edge-Case-Tests aus C-0.2-Schema-Bericht --

    def test_edge_case_winget_source_with_winget_id(self, monkeypatch):
        """Source='winget' → SoftwareItem.source='winget', winget_id gesetzt.

        Plus: is_update_available=True, latest_available='4.71.0'.
        """
        monkeypatch.setattr(sys, "platform", "win32")
        stdout = json.dumps([{
            "Name": "Docker Desktop",
            "Id": "Docker.DockerDesktop",
            "InstalledVersion": "4.69.0",
            "AvailableVersions": ["4.71.0", "4.70.0"],
            "IsUpdateAvailable": True,
            "Source": "winget",
        }])
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        assert len(items) == 1
        assert items[0].name == "Docker Desktop"
        assert items[0].version == "4.69.0"
        assert items[0].winget_id == "Docker.DockerDesktop"
        assert items[0].source == "winget"
        assert items[0].is_update_available is True
        assert items[0].latest_available == "4.71.0"

    def test_edge_case_arp_app_source_null_no_winget_id(self, monkeypatch):
        """Source=null (ARP) → source='registry', winget_id=None.

        ARP-Id ist Backslash-Pfad — taugt nicht fuer CPE.
        Plus: AvailableVersions=[] → latest_available=None,
        is_update_available=False (ARP-Standard).
        """
        monkeypatch.setattr(sys, "platform", "win32")
        stdout = json.dumps([{
            "Name": "Bitdefender Antivirus Plus",
            "Id": "ARP\\Machine\\X64\\Bitdefender",
            "InstalledVersion": "27.0.50.256",
            "AvailableVersions": [],
            "IsUpdateAvailable": False,
            "Source": None,
        }])
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        assert len(items) == 1
        assert items[0].source == "registry"
        assert items[0].winget_id is None
        assert items[0].is_update_available is False
        assert items[0].latest_available is None

    def test_edge_case_msstore_app(self, monkeypatch):
        """Source='msstore' → source='msix', winget_id=None.

        msstore-Apps haben Store-Identifier (kein winget-Catalog-Format),
        deshalb winget_id=None.
        """
        monkeypatch.setattr(sys, "platform", "win32")
        stdout = json.dumps([{
            "Name": "KeePassXC",
            "Id": "XP8K2L36VP0QMB",
            "InstalledVersion": "2.7.10",
            "AvailableVersions": [],
            "IsUpdateAvailable": True,
            "Source": "msstore",
        }])
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        assert len(items) == 1
        assert items[0].source == "msix"
        assert items[0].winget_id is None

    def test_edge_case_installed_version_as_timestamp(self, monkeypatch):
        """InstalledVersion als ISO-Timestamp (Mesh-Agent-Pattern).

        Tolerant als string, NICHT als SemVer parsen versuchen.
        """
        monkeypatch.setattr(sys, "platform", "win32")
        stdout = json.dumps([{
            "Name": "Mesh Agent",
            "Id": "ARP\\Machine\\X64\\Mesh Agent",
            "InstalledVersion": "2025-03-06 22:44:07.000+01:00",
            "AvailableVersions": [],
            "IsUpdateAvailable": False,
            "Source": None,
        }])
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        assert len(items) == 1
        assert items[0].version == "2025-03-06 22:44:07.000+01:00"

    def test_edge_case_unicode_name_arabic(self, monkeypatch):
        """Unicode in Display-Names (z.B. arabische Office-Variante).

        UTF-8-Encoding muss durchgeschleift sein.
        """
        monkeypatch.setattr(sys, "platform", "win32")
        unicode_name = "Microsoft 365 Apps for business - ar-sa مكتب"
        stdout = json.dumps([{
            "Name": unicode_name,
            "Id": "ARP\\Machine\\X64\\O365 - ar-sa",
            "InstalledVersion": "16.0.19929.20106",
            "AvailableVersions": [],
            "IsUpdateAvailable": False,
            "Source": None,
        }], ensure_ascii=False)
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        assert len(items) == 1
        assert items[0].name == unicode_name

    def test_edge_case_available_versions_older_with_no_update(
        self, monkeypatch
    ):
        """AvailableVersions enthaelt aeltere Version, IsUpdateAvailable=false.

        Bitdefender-Pattern: installiert 27.1.1.38, verfuegbar nur
        ["26.0.1.233"]. Wir nutzen IsUpdateAvailable **autoritativ** —
        das Item wird mit ``is_update_available=False`` aufgenommen,
        ``latest_available="26.0.1.233"`` als Diagnose-Wert.
        """
        monkeypatch.setattr(sys, "platform", "win32")
        stdout = json.dumps([{
            "Name": "BitDefender Agent",
            "Id": "Bitdefender.Bitdefender",
            "InstalledVersion": "27.1.1.38",
            "AvailableVersions": ["26.0.1.233"],
            "IsUpdateAvailable": False,
            "Source": "winget",
        }])
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        assert len(items) == 1
        assert items[0].source == "winget"
        assert items[0].version == "27.1.1.38"
        # Autoritativer Bool aus IsUpdateAvailable — NICHT aus
        # latest_available != version abgeleitet!
        assert items[0].is_update_available is False
        # latest_available bleibt als Diagnose-Wert befuellt.
        assert items[0].latest_available == "26.0.1.233"

    # -- Schema-Toleranz-Tests --

    def test_single_dict_output_tolerated(self, monkeypatch):
        """ConvertTo-Json bei einzelnem Element liefert dict, nicht Array.

        Wir tolerieren beides.
        """
        monkeypatch.setattr(sys, "platform", "win32")
        stdout = json.dumps({
            "Name": "Single App",
            "Id": "Test.Single",
            "InstalledVersion": "1.0.0",
            "AvailableVersions": [],
            "IsUpdateAvailable": False,
            "Source": "winget",
        })
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        assert len(items) == 1
        assert items[0].name == "Single App"

    def test_entry_without_name_skipped(self, monkeypatch):
        """Eintraege ohne Name oder InstalledVersion werden uebersprungen."""
        monkeypatch.setattr(sys, "platform", "win32")
        stdout = json.dumps([
            {"Name": "Valid", "InstalledVersion": "1.0", "Source": "winget"},
            {"Name": "", "InstalledVersion": "2.0", "Source": "winget"},  # leerer Name
            {"InstalledVersion": "3.0", "Source": "winget"},  # kein Name
            {"Name": "NoVersion", "Source": "winget"},  # keine Version
        ])
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        assert len(items) == 1
        assert items[0].name == "Valid"

    def test_top_level_non_list_non_dict_returns_empty(self, monkeypatch):
        """Ungueltige JSON-Struktur (z.B. string oder number) → leere Liste."""
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_pwsh_subprocess(monkeypatch, stdout='"unexpected"')
        assert collect_winget_module() == []

    def test_aggregated_distribution_of_sources(self, monkeypatch):
        """Gemischter Output mit allen 3 Source-Typen aggregiert korrekt."""
        monkeypatch.setattr(sys, "platform", "win32")
        stdout = json.dumps([
            {"Name": "A", "Id": "A.A", "InstalledVersion": "1", "Source": "winget", "AvailableVersions": [], "IsUpdateAvailable": False},
            {"Name": "B", "Id": "ARP\\X\\B", "InstalledVersion": "2", "Source": None, "AvailableVersions": [], "IsUpdateAvailable": False},
            {"Name": "C", "Id": "STORE_ID", "InstalledVersion": "3", "Source": "msstore", "AvailableVersions": [], "IsUpdateAvailable": False},
        ])
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        sources = sorted(i.source for i in items)
        assert sources == ["msix", "registry", "winget"]
        # winget_id nur bei Source='winget' gesetzt
        winget_ids = {i.name: i.winget_id for i in items}
        assert winget_ids == {"A": "A.A", "B": None, "C": None}

    # -- Update-Info-Mapping (C-1.5: SoftwareItem-Erweiterung) --

    def test_update_info_field_missing_defaults_to_false_none(
        self, monkeypatch
    ):
        """Wenn IsUpdateAvailable/AvailableVersions fehlen → Defaults.

        Tolerant gegenueber Schema-Drift: fehlende Update-Felder im
        JSON-Output ergeben ``is_update_available=False``,
        ``latest_available=None``.
        """
        monkeypatch.setattr(sys, "platform", "win32")
        stdout = json.dumps([{
            "Name": "Minimal",
            "Id": "Min.Min",
            "InstalledVersion": "1.0",
            "Source": "winget",
            # IsUpdateAvailable und AvailableVersions fehlen
        }])
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        assert items[0].is_update_available is False
        assert items[0].latest_available is None

    def test_available_versions_null_value_tolerant(self, monkeypatch):
        """``AvailableVersions: null`` (statt leerer Liste) → latest_available=None."""
        monkeypatch.setattr(sys, "platform", "win32")
        stdout = json.dumps([{
            "Name": "NullVer",
            "Id": "Test.Null",
            "InstalledVersion": "1.0",
            "AvailableVersions": None,
            "IsUpdateAvailable": False,
            "Source": "winget",
        }])
        _patch_pwsh_subprocess(monkeypatch, stdout=stdout)
        items = collect_winget_module()
        assert items[0].latest_available is None


class TestSoftwareItemUpdateFieldsBackwardsCompat:
    """Verifiziert dass existing Caller (Tabular/Registry/MSIX) ohne
    Update-Info weiter funktionieren — Default-Werte greifen."""

    def test_existing_winget_tabular_path_default_is_update_available(
        self, monkeypatch
    ):
        """``collect_winget`` (Tabular-Pfad) liefert ``is_update_available=False``."""
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_winget_args(monkeypatch, args=_WINGET_TEXT_ARGS)

        text_table = (
            "Name             Id                Version  Available  Source\n"
            "------------------------------------------------------------\n"
            "Mozilla Firefox  Mozilla.Firefox   120.0    126.0      winget\n"
        )
        completed = MagicMock(returncode=0, stdout=text_table, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_winget()
        assert len(items) == 1
        # Tabular-Pfad liefert keine Update-Info → Defaults greifen.
        assert items[0].is_update_available is False
        assert items[0].latest_available is None

    def test_software_item_construction_keyword_only_defaults(self):
        """SoftwareItem mit nur den 4 Pflicht-Feldern (keyword-only)
        hat Defaults fuer Update-Info."""
        item = SoftwareItem(
            name="X", version="1.0", winget_id=None, source="registry"
        )
        assert item.is_update_available is False
        assert item.latest_available is None


# ===========================================================================
# C-2: Detection-Logik + Fallback-Pfad
# ===========================================================================

from core import patch_collector as _pc_mod  # noqa: E402
from core import patch_module_detection as _pmd_mod  # noqa: E402
from core.patch_collector import (  # noqa: E402
    ModuleStatus,
    ModuleStatusDetail,
    collect_winget_inventory,
    detect_winget_module,
    get_winget_module_status,
)


@pytest.fixture(autouse=True)
def _reset_module_status_cache():
    """Reset des Modul-Status-Caches zwischen Tests.

    Cache lebt seit (C-6) in:mod:`core.patch_module_detection`
    (vorher in:mod:`core.patch_collector`). Ohne Reset wuerde der erste
    Test der ``detect_winget_module`` triggert das Ergebnis fuer alle
    folgenden Tests einfrieren (Pollution).
    """
    _pmd_mod._module_status_cache = None
    yield
    _pmd_mod._module_status_cache = None


def _patch_ps_subprocess(monkeypatch, *, returncode=0, stdout="", stderr=""):
    """Mockt ``subprocess.run`` fuer PowerShell-Aufrufe."""
    completed = MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
    return completed


def _patch_ps_subprocess_sequence(monkeypatch, *responses):
    """Mockt subprocess.run mit Sequenz von Responses (fuer multi-stage detect)."""
    iter_responses = iter(responses)

    def _run(*args, **kwargs):
        spec = next(iter_responses)
        if isinstance(spec, BaseException):
            raise spec
        rc, out, err = spec
        return MagicMock(returncode=rc, stdout=out, stderr=err)

    monkeypatch.setattr(subprocess, "run", _run)


class TestDetectWingetModule:
    def test_non_windows_returns_blocked(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        result = detect_winget_module()
        assert result.status == ModuleStatus.BLOCKED
        assert result.reason == "non-windows-platform"
        assert result.can_attempt_install is False

    def test_powershell_filenotfound_returns_blocked(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        def boom(*args, **kwargs):
            raise FileNotFoundError("powershell.exe")

        monkeypatch.setattr(subprocess, "run", boom)
        result = detect_winget_module()
        assert result.status == ModuleStatus.BLOCKED
        assert result.reason == "powershell-subprocess-unavailable"

    def test_get_module_returncode_nonzero_returns_blocked(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_ps_subprocess(
            monkeypatch, returncode=1, stdout="", stderr="ParseError"
        )
        result = detect_winget_module()
        assert result.status == ModuleStatus.BLOCKED
        assert result.reason == "get-module-failed"
        # Privacy-Filter (C-5): stderr-Excerpt nur in reason_detail, nicht in
        # reason. Caller muss sich aktiv fuer Diagnose-Anzeige entscheiden.
        assert result.reason_detail == "ParseError"

    def test_module_installed_probe_ok_returns_available(self, monkeypatch):
        """Modul installiert + Probe-Aufruf OK → AVAILABLE."""
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_ps_subprocess_sequence(
            monkeypatch,
            (0, "INSTALLED", ""),  # _MODULE_LIST_CMD
            (0, "OK", ""),         # _MODULE_PROBE_CMD
        )
        result = detect_winget_module()
        assert result.status == ModuleStatus.AVAILABLE
        assert result.reason == "probe-succeeded"
        assert result.can_attempt_install is False

    def test_module_installed_probe_fails_returns_blocked(self, monkeypatch):
        """Modul installiert ABER Probe schlaegt fehl → BLOCKED."""
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_ps_subprocess_sequence(
            monkeypatch,
            (0, "INSTALLED", ""),
            (1, "", "Cmdlet not found"),
        )
        result = detect_winget_module()
        assert result.status == ModuleStatus.BLOCKED
        assert result.reason == "probe-failed"
        # Privacy-Filter (C-5): stderr-Excerpt steckt in reason_detail.
        assert result.reason_detail == "Cmdlet not found"

    def test_module_not_installed_remotesigned_returns_needs_install(
        self, monkeypatch
    ):
        """Modul fehlt, ExecPolicy=RemoteSigned → NEEDS_INSTALL."""
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_ps_subprocess_sequence(
            monkeypatch,
            (0, "NOT_INSTALLED", ""),
            (0, "RemoteSigned", ""),
        )
        result = detect_winget_module()
        assert result.status == ModuleStatus.NEEDS_INSTALL
        assert result.reason == "module-not-found"
        assert result.can_attempt_install is True

    def test_module_not_installed_unrestricted_returns_needs_install(
        self, monkeypatch
    ):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_ps_subprocess_sequence(
            monkeypatch,
            (0, "NOT_INSTALLED", ""),
            (0, "Unrestricted", ""),
        )
        assert detect_winget_module().status == ModuleStatus.NEEDS_INSTALL

    def test_module_not_installed_restricted_returns_blocked(
        self, monkeypatch
    ):
        """Modul fehlt + ExecPolicy=Restricted → BLOCKED (Install nicht moeglich)."""
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_ps_subprocess_sequence(
            monkeypatch,
            (0, "NOT_INSTALLED", ""),
            (0, "Restricted", ""),
        )
        result = detect_winget_module()
        assert result.status == ModuleStatus.BLOCKED
        assert result.reason == "execution-policy-restricted"
        assert result.can_attempt_install is False
        # Klassen-Status ohne stderr — reason_detail bleibt None.
        assert result.reason_detail is None

    def test_module_not_installed_allsigned_returns_blocked(
        self, monkeypatch
    ):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_ps_subprocess_sequence(
            monkeypatch,
            (0, "NOT_INSTALLED", ""),
            (0, "AllSigned", ""),
        )
        result = detect_winget_module()
        assert result.status == ModuleStatus.BLOCKED
        assert result.reason == "execution-policy-allsigned"
        assert result.reason_detail is None

    def test_subprocess_timeout_returns_blocked(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        def boom(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="powershell", timeout=10)

        monkeypatch.setattr(subprocess, "run", boom)
        result = detect_winget_module()
        assert result.status == ModuleStatus.BLOCKED


class TestModuleReasonClasses:
    """Privacy-Filter (Bug-Fix-Sprint C-5): reason ist klassen-basiert.

    Pflichtkriterien:
    1. Jeder von ``detect_winget_module`` gesetzte ``reason``-Wert ist
       in:data:`MODULE_REASON_CLASSES`.
    2. ``reason`` enthaelt nie stderr-Excerpts oder andere Free-Form-Daten.
    3. ``reason_detail`` ist ``None`` bei reinen Klassen-Pfaden und enthaelt
       nur stderr-Excerpts bei tatsaechlichen Subprocess-Fehlern.
    """

    def test_alle_detection_pfade_liefern_klassen_basierte_reason(
        self, monkeypatch
    ):
        from core.patch_collector import MODULE_REASON_CLASSES

        # Sammle reason-Werte aus allen 8 Detection-Pfaden.
        observed: set[str] = set()

        # 1. non-windows-platform
        monkeypatch.setattr(sys, "platform", "linux")
        observed.add(detect_winget_module().reason)
        monkeypatch.setattr(sys, "platform", "win32")

        # 2. powershell-subprocess-unavailable
        def boom(*_a, **_kw):
            raise FileNotFoundError("ps")

        monkeypatch.setattr(subprocess, "run", boom)
        observed.add(detect_winget_module().reason)

        # 3. get-module-failed
        _patch_ps_subprocess(
            monkeypatch, returncode=1, stdout="", stderr="x"
        )
        observed.add(detect_winget_module().reason)

        # 4. probe-succeeded
        _patch_ps_subprocess_sequence(
            monkeypatch, (0, "INSTALLED", ""), (0, "OK", "")
        )
        observed.add(detect_winget_module().reason)

        # 5. probe-failed
        _patch_ps_subprocess_sequence(
            monkeypatch, (0, "INSTALLED", ""), (1, "", "boom")
        )
        observed.add(detect_winget_module().reason)

        # 6. module-not-found
        _patch_ps_subprocess_sequence(
            monkeypatch, (0, "NOT_INSTALLED", ""), (0, "RemoteSigned", "")
        )
        observed.add(detect_winget_module().reason)

        # 7. execution-policy-restricted
        _patch_ps_subprocess_sequence(
            monkeypatch, (0, "NOT_INSTALLED", ""), (0, "Restricted", "")
        )
        observed.add(detect_winget_module().reason)

        # 8. execution-policy-allsigned
        _patch_ps_subprocess_sequence(
            monkeypatch, (0, "NOT_INSTALLED", ""), (0, "AllSigned", "")
        )
        observed.add(detect_winget_module().reason)

        assert observed <= MODULE_REASON_CLASSES, (
            f"reason-Werte ausserhalb des Vokabulars: "
            f"{observed - MODULE_REASON_CLASSES}"
        )
        assert observed == MODULE_REASON_CLASSES, (
            f"nicht alle Klassen erreicht — fehlend: "
            f"{MODULE_REASON_CLASSES - observed}"
        )

    def test_reason_detail_nur_bei_subprocess_fehlern(self, monkeypatch):
        """Klassen-Status ohne stderr → reason_detail ist None."""
        monkeypatch.setattr(sys, "platform", "win32")

        # module-not-found
        _patch_ps_subprocess_sequence(
            monkeypatch, (0, "NOT_INSTALLED", ""), (0, "RemoteSigned", "")
        )
        assert detect_winget_module().reason_detail is None

        # probe-succeeded
        _patch_ps_subprocess_sequence(
            monkeypatch, (0, "INSTALLED", ""), (0, "OK", "")
        )
        assert detect_winget_module().reason_detail is None

    def test_reason_keine_stderr_excerpts(self, monkeypatch):
        """Auch bei Subprocess-Fehler: reason bleibt klassen-basiert."""
        monkeypatch.setattr(sys, "platform", "win32")

        # Stderr enthaelt sensiblen Inhalt (User-Profile, Domain).
        sensitive = "C:\\Users\\patrick auf CONTOSO domain failed"
        _patch_ps_subprocess(
            monkeypatch, returncode=1, stdout="", stderr=sensitive
        )
        result = detect_winget_module()
        # reason darf NICHTS davon enthalten.
        assert "patrick" not in result.reason
        assert "CONTOSO" not in result.reason
        assert "C:\\" not in result.reason
        # reason_detail darf den Excerpt enthalten (Admin-Diagnose-Opt-in).
        assert result.reason_detail == sensitive


class TestGetWingetModuleStatusCache:
    def test_cache_hit_returns_same_instance(self, monkeypatch):
        """Zweiter Aufruf liefert dasselbe Objekt — kein 2x Subprocess-Call."""
        monkeypatch.setattr(sys, "platform", "win32")
        call_count = {"n": 0}

        def counting_run(*args, **kwargs):
            call_count["n"] += 1
            return MagicMock(returncode=0, stdout="INSTALLED", stderr="")

        monkeypatch.setattr(subprocess, "run", counting_run)

        first = get_winget_module_status()
        second = get_winget_module_status()
        assert first is second
        # Nur die initiale Detection-Sequenz, nicht erneut.
        # (LIST + PROBE = 2 calls, NICHT 4)
        assert call_count["n"] == 2

    def test_force_refresh_invalidates_cache(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        _patch_ps_subprocess_sequence(
            monkeypatch,
            (0, "INSTALLED", ""), (0, "OK", ""),  # 1. detect
            (0, "INSTALLED", ""), (0, "OK", ""),  # 2. detect (force)
        )
        first = get_winget_module_status()
        second = get_winget_module_status(force_refresh=True)
        assert first is not second
        # Beide sollten AVAILABLE sein (gleiche Mocks)
        assert first.status == ModuleStatus.AVAILABLE
        assert second.status == ModuleStatus.AVAILABLE


class TestCollectWingetInventoryFallback:
    def test_module_available_uses_module_path(self, monkeypatch):
        """ModuleStatus.AVAILABLE → ruft collect_winget_module auf."""
        monkeypatch.setattr(sys, "platform", "win32")
        # Cache direkt setzen (bypass Detection-Subprocess).
        _pmd_mod._module_status_cache = ModuleStatusDetail(
            status=ModuleStatus.AVAILABLE,
            reason="probe-succeeded",
            can_attempt_install=False,
        )
        # collect_winget_module mocken, dass es eine bekannte Liste liefert.
        sentinel_items = [
            SoftwareItem(
                name="ModulePath",
                version="1.0",
                winget_id="Module.Test",
                source="winget",
                is_update_available=True,
                latest_available="2.0",
            )
        ]
        monkeypatch.setattr(
            _pc_mod, "collect_winget_module", lambda: sentinel_items
        )
        # collect_winget (Tabular) darf NICHT aufgerufen werden.
        called_tabular = {"n": 0}

        def fail_tabular():
            called_tabular["n"] += 1
            return []

        monkeypatch.setattr(_pc_mod, "collect_winget", fail_tabular)

        result = collect_winget_inventory()
        assert result == sentinel_items
        assert called_tabular["n"] == 0

    def test_module_needs_install_uses_tabular_fallback(self, monkeypatch):
        """ModuleStatus.NEEDS_INSTALL → ruft collect_winget (Tabular)."""
        monkeypatch.setattr(sys, "platform", "win32")
        _pmd_mod._module_status_cache = ModuleStatusDetail(
            status=ModuleStatus.NEEDS_INSTALL,
            reason="module-not-found",
            can_attempt_install=True,
        )
        sentinel_items = [
            SoftwareItem(
                name="TabularPath",
                version="1.0",
                winget_id="Tabular.Test",
                source="winget",
            )
        ]
        monkeypatch.setattr(_pc_mod, "collect_winget", lambda: sentinel_items)
        called_module = {"n": 0}

        def fail_module():
            called_module["n"] += 1
            return []

        monkeypatch.setattr(_pc_mod, "collect_winget_module", fail_module)

        result = collect_winget_inventory()
        assert result == sentinel_items
        assert called_module["n"] == 0

    def test_module_blocked_uses_tabular_fallback(self, monkeypatch):
        """ModuleStatus.BLOCKED → ebenfalls Tabular-Fallback."""
        monkeypatch.setattr(sys, "platform", "win32")
        _pmd_mod._module_status_cache = ModuleStatusDetail(
            status=ModuleStatus.BLOCKED,
            reason="execution-policy-restricted",
            can_attempt_install=False,
        )
        monkeypatch.setattr(_pc_mod, "collect_winget", lambda: ["sentinel"])
        result = collect_winget_inventory()
        assert result == ["sentinel"]


# ===========================================================================
# Windows-Update-Inventar — collect_windows_update (WUA-COM, OFFLINE/cached)
# ===========================================================================

from core.patch_collector import (  # noqa: E402
    _with_synthetic_id,
    collect_windows_update,
)
from core.patch_id_utils import is_synthetic_id  # noqa: E402

# Echtes WUA-Output: ein Update mit KB im Titel + KB-Feld, eines ohne KB
# (z.B. ein Treiber-/Defender-Definitions-Update).
_WU_JSON_TWO = json.dumps(
    [
        {
            "Title": "2024-06 Cumulative Update for Windows 11 (KB5039212)",
            "KB": "5039212",
            "Severity": "Important",
        },
        {
            "Title": "Intel - Display - 31.0.101.5333",
            "KB": "",
            "Severity": None,
        },
    ]
)


class TestCollectWindowsUpdateWindowsGuard:
    def test_non_windows_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        assert collect_windows_update() == []


class TestCollectWindowsUpdateHappyPath:
    def test_parst_ausstehende_updates(self, monkeypatch):
        """Zwei Updates (eines mit KB, eines ohne) -> zwei SoftwareItems
        mit source='windows_update', is_update_available=True."""
        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=0, stdout=_WU_JSON_TWO, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_windows_update()

        assert len(items) == 2
        assert all(i.source == "windows_update" for i in items)
        assert all(i.is_update_available is True for i in items)
        assert all(i.version == "ausstehend" for i in items)
        assert all(i.winget_id is None for i in items)
        # KB-Update: latest_available = "KB" + Nummer.
        assert items[0].name.startswith("2024-06 Cumulative")
        assert items[0].latest_available == "KB5039212"
        # Update ohne KB: latest_available faellt auf den Titel zurueck.
        assert items[1].latest_available == "Intel - Display - 31.0.101.5333"

    def test_einzel_objekt_statt_liste(self, monkeypatch):
        """ConvertTo-Json liefert bei einem einzigen Update ein Objekt
        statt einer Liste — muss toleriert werden."""
        monkeypatch.setattr(sys, "platform", "win32")
        single = json.dumps(
            {"Title": "Nur ein Update (KB5000001)", "KB": "5000001"}
        )
        completed = MagicMock(returncode=0, stdout=single, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_windows_update()

        assert len(items) == 1
        assert items[0].latest_available == "KB5000001"

    def test_eintrag_ohne_title_uebersprungen(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        payload = json.dumps(
            [
                {"Title": "", "KB": "1"},  # leerer Titel
                {"KB": "2"},  # gar kein Titel
                {"Title": "Echtes Update (KB3)", "KB": "3"},
            ]
        )
        completed = MagicMock(returncode=0, stdout=payload, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_windows_update()

        assert len(items) == 1
        assert items[0].name == "Echtes Update (KB3)"

    def test_synthetische_wu_id_kb_basiert_und_stabil(self, monkeypatch):
        """Nach _with_synthetic_id tragen WU-Items eine wu:KB...-Id.

        KB-basiert wenn der Titel ein KB traegt; stabil ueber Re-Scans."""
        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=0, stdout=_WU_JSON_TWO, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = [_with_synthetic_id(it) for it in collect_windows_update()]

        # KB im Titel -> wu:KB<nummer> (Uppercase, stabil).
        assert items[0].winget_id == "wu:KB5039212"
        # Kein KB -> wu:<normalisierter Titel>.
        assert items[1].winget_id.startswith("wu:")
        assert items[1].winget_id != "wu:KB5039212"
        # Alle WU-Ids sind synthetisch -> aus winget-Gates ausgeschlossen.
        assert all(is_synthetic_id(i.winget_id) for i in items)

    def test_wu_id_stabil_ueber_rescan(self, monkeypatch):
        """Derselbe KB-Patch ergibt bei jedem Scan dieselbe wu:-Id."""
        kb_item = SoftwareItem(
            name="2024-06 Cumulative Update for Windows 11 (KB5039212)",
            version="ausstehend",
            winget_id=None,
            source="windows_update",
            is_update_available=True,
            latest_available="KB5039212",
        )
        first = _with_synthetic_id(kb_item)
        second = _with_synthetic_id(kb_item)
        assert first.winget_id == second.winget_id == "wu:KB5039212"


class TestSyntheticIdWingetOhneKatalogId:
    """B (Live-Test 2026-07-01): eine winget-Quelle OHNE Katalog-Id (leeres
    ``Id``-Feld, z.B. KeePassXC) bekommt eine stabile ``wgname:``-Id, damit sie
    in ``full_scan`` nicht verworfen wird und aus der DB verschwindet."""

    def test_winget_ohne_id_bekommt_wgname_id(self):
        item = SoftwareItem(
            name="KeePassXC", version="2.7.9", winget_id=None, source="winget"
        )
        result = _with_synthetic_id(item)
        # Nicht None / nicht leer -> full_scan verwirft die Zeile nicht mehr.
        assert result.winget_id
        assert result.winget_id.startswith("wgname:")
        # fail-closed: synthetische Id wird NIE an ein winget-Kommando gereicht.
        assert is_synthetic_id(result.winget_id) is True

    def test_winget_ohne_id_stabil_ueber_rescan(self):
        item = SoftwareItem(
            name="KeePassXC", version="2.7.9", winget_id=None, source="winget"
        )
        assert _with_synthetic_id(item).winget_id == _with_synthetic_id(item).winget_id

    def test_echte_winget_id_bleibt_unveraendert(self):
        item = SoftwareItem(
            name="Mozilla Firefox",
            version="123.0",
            winget_id="Mozilla.Firefox",
            source="winget",
        )
        result = _with_synthetic_id(item)
        assert result.winget_id == "Mozilla.Firefox"
        assert is_synthetic_id(result.winget_id) is False


class TestCollectWindowsUpdateFehler:
    def test_timeout_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="powershell", timeout=90)

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        assert collect_windows_update() == []

    def test_powershell_nicht_im_path_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        def raise_fnf(*a, **kw):
            raise FileNotFoundError("powershell not in PATH")

        monkeypatch.setattr(subprocess, "run", raise_fnf)
        assert collect_windows_update() == []

    def test_oserror_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        def raise_oserror(*a, **kw):
            raise OSError("com error")

        monkeypatch.setattr(subprocess, "run", raise_oserror)
        assert collect_windows_update() == []

    def test_returncode_nicht_null_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=1, stdout="", stderr="error")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_windows_update() == []

    def test_leere_stdout_gibt_leere_liste(self, monkeypatch):
        """Leerer Output (keine Updates ODER catch-Leerstring) -> []."""
        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=0, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_windows_update() == []

    def test_json_parse_fehler_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=0, stdout="kein valides json", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_windows_update() == []


class TestWindowsUpdateGate:
    """Sicherheits-Invariante: WU-Items sind nie upgradebar via winget."""

    def test_wu_id_ist_synthetisch(self):
        assert is_synthetic_id("wu:KB5012345") is True

    def test_wu_item_nie_upgradeable_und_kein_upgrade_request(self):
        """Reuse der bestehenden Gate-Logik: ein WU-PatchScanResult mit
        wu:-Id ist nicht _is_upgradeable und erzeugt keinen UpgradeRequest."""
        from core.patch_result import PatchScanResult
        from tools.patch_monitor.gui.patch_console_widget import (
            _is_upgradeable,
            _to_upgrade_request,
        )

        result = PatchScanResult(
            name="2024-06 Cumulative Update for Windows 11 (KB5039212)",
            normalized_name="2024-06 cumulative update for windows 11",
            vendor=None,
            winget_id="wu:KB5039212",
            source="windows_update",
            installed_version="ausstehend",
            available_version="KB5039212",
            channel="notify_only",
            policy_source="default",
            cve_ids=(),
            cvss_max=None,
            exploit_available=False,
            eol=False,
            confidence_score=0.0,
            recommendation="update_available",
        )
        # Trotz Update-Klasse: synthetische Id -> nicht selektierbar.
        assert _is_upgradeable(result) is False
        # Defense-in-depth: ein Upgrade-Request zu erzeugen wird verweigert.
        with pytest.raises(ValueError):
            _to_upgrade_request(result)


class TestCollectAllIncludesWindowsUpdate:
    def test_collect_all_enthaelt_wu_items(self, monkeypatch):
        """collect_all haengt die WU-Items (mit wu:-Id) hinten an —
        nach winget/registry/msix, durch denselben Dedup-Pass."""
        monkeypatch.setattr(
            _pc_mod,
            "collect_winget_inventory",
            lambda: [
                SoftwareItem(
                    name="Mozilla Firefox",
                    version="120.0",
                    winget_id="Mozilla.Firefox",
                    source="winget",
                ),
            ],
        )
        monkeypatch.setattr(
            _pc_mod,
            "collect_registry",
            lambda: [
                SoftwareItem(
                    name="7-Zip 23.01",
                    version="23.01",
                    winget_id=None,
                    source="registry",
                ),
            ],
        )
        monkeypatch.setattr(_pc_mod, "collect_appx", list)
        monkeypatch.setattr(
            _pc_mod,
            "collect_windows_update",
            lambda: [
                SoftwareItem(
                    name="2024-06 Cumulative Update (KB5039212)",
                    version="ausstehend",
                    winget_id=None,
                    source="windows_update",
                    is_update_available=True,
                    latest_available="KB5039212",
                ),
            ],
        )
        #.NET- und Treiber-Sammler hier ausblenden, damit dieser Test
        # isoliert das WU-Verhalten prueft (sonst haengt collect_all auf der
        # Test-Maschine echte dotnet-/Treiber-Items hintenan -> ``items[-1]``
        # waere kein WU-Item).
        monkeypatch.setattr(_pc_mod, "collect_dotnet_runtimes", list)
        monkeypatch.setattr(_pc_mod, "collect_drivers", list)

        items = collect_all()
        by_name = {i.name: i for i in items}

        # WU-Item ist enthalten und steht hinten (nach winget + registry).
        assert items[-1].source == "windows_update"
        wu = by_name["2024-06 Cumulative Update (KB5039212)"]
        assert wu.winget_id == "wu:KB5039212"
        assert wu.is_update_available is True
        # Die anderen Quellen bleiben unveraendert vorhanden.
        assert by_name["Mozilla Firefox"].winget_id == "Mozilla.Firefox"
        assert by_name["7-Zip 23.01"].winget_id == "regid:7-zip"


# ===========================================================================
#.NET-Laufzeit-Inventar — collect_dotnet_runtimes (Registry + dotnet-CLI)
# ===========================================================================

from core.patch_collector import (  # noqa: E402
    _parse_dotnet_runtimes,
    collect_dotnet_runtimes,
)

# Echtes ``dotnet --list-runtimes``-Output: drei Familien, ein Major in zwei
# Familien parallel (6.0 + 8.0 NETCore) sowie ASP.NET + Desktop.
_DOTNET_LIST = (
    "Microsoft.AspNetCore.App 8.0.11 [C:\\Program Files\\dotnet\\shared\\X]\n"
    "Microsoft.NETCore.App 6.0.33 [C:\\Program Files\\dotnet\\shared\\Y]\n"
    "Microsoft.NETCore.App 8.0.11 [C:\\Program Files\\dotnet\\shared\\Z]\n"
    "Microsoft.WindowsDesktop.App 8.0.11 [C:\\Program Files\\dotnet\\shared\\W]\n"
)


class TestParseDotnetRuntimes:
    def test_parst_familien_und_majors_distinkt(self):
        """Jede Familie+Major.Minor wird ein eigener SoftwareItem."""
        items = _parse_dotnet_runtimes(_DOTNET_LIST)
        by_name = {i.name: i for i in items}

        # 4 distinkte Eintraege: ASP.NET 8.0, NETCore 6.0, NETCore 8.0, Desktop 8.0.
        assert set(by_name) == {
            ".NET ASP.NET Core 8.0",
            ".NET Runtime 6.0",
            ".NET Runtime 8.0",
            ".NET Desktop 8.0",
        }
        assert all(i.source == "dotnet" for i in items)
        assert all(i.is_update_available is False for i in items)
        assert all(i.winget_id is None for i in items)
        # Volle Version steckt im version-Feld.
        assert by_name[".NET Runtime 8.0"].version == "8.0.11"
        assert by_name[".NET Runtime 6.0"].version == "6.0.33"

    def test_unbekannte_family_uebersprungen(self):
        """Zukuenftige/unbekannte Family-Ids werden konservativ ignoriert."""
        items = _parse_dotnet_runtimes(
            "Microsoft.SomeFutureThing.App 9.0.0 [C:\\x]\n"
        )
        assert items == []

    def test_unparsbare_zeilen_uebersprungen(self):
        items = _parse_dotnet_runtimes("kein valides Format\n\n   \n")
        assert items == []

    def test_patch_version_kollabiert_auf_einen_eintrag(self):
        """Zwei Patch-Versionen derselben Familie+Major.Minor -> ein Eintrag
        (Id bleibt ueber Patch-Updates stabil)."""
        listing = (
            "Microsoft.NETCore.App 8.0.10 [C:\\a]\n"
            "Microsoft.NETCore.App 8.0.11 [C:\\b]\n"
        )
        items = _parse_dotnet_runtimes(listing)
        assert len(items) == 1
        assert items[0].name == ".NET Runtime 8.0"


class TestCollectDotnetCore:
    def test_dotnet_cli_liefert_core_runtimes_plattformunabhaengig(
        self, monkeypatch
    ):
        """Auch auf non-win32 liefert die dotnet-CLI die Core-Laufzeiten —
        collect_dotnet_runtimes ist teil-plattformuebergreifend."""
        monkeypatch.setattr(sys, "platform", "linux")
        completed = MagicMock(returncode=0, stdout=_DOTNET_LIST, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_dotnet_runtimes()

        # Auf Linux faellt der Framework-Teil weg, der Core-Teil bleibt.
        assert {i.name for i in items} == {
            ".NET ASP.NET Core 8.0",
            ".NET Runtime 6.0",
            ".NET Runtime 8.0",
            ".NET Desktop 8.0",
        }
        assert all(i.source == "dotnet" for i in items)

    def test_dotnet_nicht_installiert_gibt_leere_liste(self, monkeypatch):
        """FileNotFoundError (dotnet nicht im PATH) + leere Registry -> []."""
        monkeypatch.setattr(sys, "platform", "linux")  # ueberspringt Framework

        def raise_fnf(*a, **kw):
            raise FileNotFoundError("dotnet not in PATH")

        monkeypatch.setattr(subprocess, "run", raise_fnf)
        assert collect_dotnet_runtimes() == []

    def test_timeout_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")

        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="dotnet", timeout=15)

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        assert collect_dotnet_runtimes() == []

    def test_returncode_nicht_null_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        completed = MagicMock(returncode=1, stdout="", stderr="boom")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_dotnet_runtimes() == []

    def test_kaputter_output_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        completed = MagicMock(returncode=0, stdout="voelliger Unsinn", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_dotnet_runtimes() == []


class TestCollectDotnetFramework:
    """.NET-Framework-Teil via gemocktem winreg (nur win32-Pfad)."""

    def _fake_winreg(self, *, v4_version=None, v35_install=None, v35_version=None):
        """Baut ein Fake-winreg-Modul, das je Pfad einen Kontext liefert.

        ``v4_version``/``v35_install`` steuern, welche Schluessel "existieren":
        ``None`` -> OpenKey wirft OSError (Schluessel fehlt).
        """
        v4_path = r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
        v35_path = r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5"

        class _Key:
            def __init__(self, values):
                self._values = values

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def open_key(_hive, path):
            if path == v4_path and v4_version is not None:
                return _Key({"Version": v4_version})
            if path == v35_path and v35_install is not None:
                vals = {"Install": v35_install}
                if v35_version is not None:
                    vals["Version"] = v35_version
                return _Key(vals)
            raise OSError("key not found")

        def query_value_ex(key, name):
            if name in key._values:
                return (key._values[name], 1)
            raise OSError("value not found")

        return SimpleNamespace(
            HKEY_LOCAL_MACHINE=0,
            OpenKey=open_key,
            QueryValueEx=query_value_ex,
        )

    def test_framework_4x_und_35_erkannt(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        fake = self._fake_winreg(
            v4_version="4.8.09037", v35_install=1, v35_version="3.5.30729.4926"
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)
        # dotnet-CLI hier nicht relevant: leere Core-Liste.
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **kw: MagicMock(
                returncode=0, stdout="", stderr=""
            )
        )

        items = collect_dotnet_runtimes()
        by_name = {i.name: i for i in items}

        assert by_name[".NET Framework 4.x"].version == "4.8.09037"
        assert by_name[".NET Framework 4.x"].source == "dotnet"
        assert by_name[".NET Framework 4.x"].is_update_available is False
        assert by_name[".NET Framework 3.5"].version == "3.5.30729.4926"

    def test_framework_35_nicht_installiert_uebersprungen(self, monkeypatch):
        """Install != 1 -> kein 3.5-Eintrag."""
        monkeypatch.setattr(sys, "platform", "win32")
        fake = self._fake_winreg(v4_version="4.8.0", v35_install=0)
        monkeypatch.setitem(sys.modules, "winreg", fake)
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **kw: MagicMock(
                returncode=0, stdout="", stderr=""
            )
        )

        names = {i.name for i in collect_dotnet_runtimes()}
        assert ".NET Framework 4.x" in names
        assert ".NET Framework 3.5" not in names

    def test_registry_leer_und_kein_dotnet_gibt_leere_liste(self, monkeypatch):
        """Beide Framework-Schluessel fehlen + dotnet nicht da -> []."""
        monkeypatch.setattr(sys, "platform", "win32")
        fake = self._fake_winreg()  # nichts existiert
        monkeypatch.setitem(sys.modules, "winreg", fake)

        def raise_fnf(*a, **kw):
            raise FileNotFoundError("dotnet not in PATH")

        monkeypatch.setattr(subprocess, "run", raise_fnf)
        assert collect_dotnet_runtimes() == []


class TestDotnetSyntheticIdAndGate:
    def test_synthetische_dotnet_id_distinkt_pro_major(self):
        """_with_synthetic_id -> dotnet:<normalisierter Name>, distinkt pro
        Major (der Name traegt die Versions-Familie)."""
        items = [_with_synthetic_id(it) for it in _parse_dotnet_runtimes(
            _DOTNET_LIST
        )]
        ids = {i.name: i.winget_id for i in items}

        # Verschiedene Majors -> verschiedene Ids.
        assert ids[".NET Runtime 6.0"] != ids[".NET Runtime 8.0"]
        # Alle dotnet:-Praefix.
        assert all(v.startswith("dotnet:") for v in ids.values())
        # Alle synthetisch -> aus winget-Gates ausgeschlossen.
        assert all(is_synthetic_id(v) for v in ids.values())

    def test_dotnet_id_stabil_ueber_patch_update(self):
        """8.0.11 -> 8.0.12 (gleiche Familie) behaelt dieselbe dotnet:-Id."""
        base = SoftwareItem(
            name=".NET Runtime 8.0",
            version="8.0.11",
            winget_id=None,
            source="dotnet",
        )
        import dataclasses  # noqa: PLC0415

        patched = dataclasses.replace(base, version="8.0.12")
        assert (
            _with_synthetic_id(base).winget_id
            == _with_synthetic_id(patched).winget_id
        )

    def test_dotnet_id_ist_synthetisch(self):
        assert is_synthetic_id("dotnet:.net runtime 8.0") is True

    def test_dotnet_item_nie_upgradeable(self):
        """Ein dotnet-PatchScanResult mit dotnet:-Id ist nicht
        _is_upgradeable (synthetische Id -> nie an winget)."""
        from core.patch_result import PatchScanResult
        from tools.patch_monitor.gui.patch_console_widget import _is_upgradeable

        result = PatchScanResult(
            name=".NET Runtime 8.0",
            normalized_name=".net runtime 8.0",
            vendor=None,
            winget_id="dotnet:.net runtime 8.0",
            source="dotnet",
            installed_version="8.0.11",
            available_version=None,
            channel="notify_only",
            policy_source="default",
            cve_ids=(),
            cvss_max=None,
            exploit_available=False,
            eol=False,
            confidence_score=0.0,
            recommendation="up_to_date",
        )
        assert _is_upgradeable(result) is False


class TestSourceLabelDotnet:
    def test_source_label_dotnet(self):
        from tools.patch_monitor.gui.patch_console_widget import _source_label

        assert _source_label("dotnet") == ".NET"


class TestCollectAllIncludesDotnet:
    def test_collect_all_haengt_dotnet_items_hinten_an(self, monkeypatch):
        """collect_all enthaelt die dotnet-Items mit dotnet:-Id, nach
        winget/registry/msix/windows_update."""
        monkeypatch.setattr(
            _pc_mod,
            "collect_winget_inventory",
            lambda: [
                SoftwareItem(
                    name="Mozilla Firefox",
                    version="120.0",
                    winget_id="Mozilla.Firefox",
                    source="winget",
                ),
            ],
        )
        monkeypatch.setattr(_pc_mod, "collect_registry", list)
        monkeypatch.setattr(_pc_mod, "collect_appx", list)
        monkeypatch.setattr(_pc_mod, "collect_windows_update", list)
        monkeypatch.setattr(
            _pc_mod,
            "collect_dotnet_runtimes",
            lambda: [
                SoftwareItem(
                    name=".NET Runtime 8.0",
                    version="8.0.11",
                    winget_id=None,
                    source="dotnet",
                ),
            ],
        )
        # Treiber-Sammler hier ausblenden, damit dieser Test isoliert das
        # dotnet-Verhalten als LETZTE Quelle prueft (sonst haengt collect_all
        # auf der Test-Maschine echte Treiber hinten an -> items[-1] waere
        # kein dotnet-Item mehr).
        monkeypatch.setattr(_pc_mod, "collect_drivers", list)

        items = collect_all()
        by_name = {i.name: i for i in items}

        assert items[-1].source == "dotnet"
        dn = by_name[".NET Runtime 8.0"]
        assert dn.winget_id == "dotnet:.net runtime 8.0"
        assert dn.is_update_available is False
        assert by_name["Mozilla Firefox"].winget_id == "Mozilla.Firefox"


# ===========================================================================
# Treiber-Inventar — collect_drivers (Get-PnpDevice, kuratierte Klassen)
# ===========================================================================

from core.patch_collector import collect_drivers  # noqa: E402

# Echtes Get-PnpDevice-Output: eine GPU (Display) + eine NIC (Net), beide
# mit Treiber-Version, sowie ein virtuelles Geraet ohne Version (Version=
# null), das uebersprungen werden muss.
_DRIVER_JSON_THREE = json.dumps(
    [
        {
            "Name": "NVIDIA GeForce RTX 4070",
            "Class": "Display",
            "Version": "31.0.15.3667",
        },
        {
            "Name": "Intel(R) Ethernet Connection I219-V",
            "Class": "Net",
            "Version": "12.19.2.50",
        },
        {
            "Name": "Microsoft Virtual Drive Enumerator",
            "Class": "DiskDrive",
            "Version": None,
        },
    ]
)


class TestCollectDriversWindowsGuard:
    def test_non_windows_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        assert collect_drivers() == []


class TestCollectDriversHappyPath:
    def test_parst_kuratierte_treiber(self, monkeypatch):
        """GPU + NIC -> zwei SoftwareItems; das versionslose Geraet wird
        uebersprungen."""
        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=0, stdout=_DRIVER_JSON_THREE, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_drivers()

        assert len(items) == 2  # versionsloses Geraet uebersprungen
        assert all(i.source == "driver" for i in items)
        assert all(i.is_update_available is False for i in items)
        assert all(i.winget_id is None for i in items)
        assert all(i.version for i in items)
        by_name = {i.name: i for i in items}
        assert by_name["NVIDIA GeForce RTX 4070"].version == "31.0.15.3667"
        assert (
            by_name["Intel(R) Ethernet Connection I219-V"].version
            == "12.19.2.50"
        )
        # Das versionslose virtuelle Geraet taucht NICHT auf.
        assert "Microsoft Virtual Drive Enumerator" not in by_name

    def test_einzel_objekt_statt_liste(self, monkeypatch):
        """ConvertTo-Json liefert bei einem einzigen Geraet ein Objekt
        statt einer Liste — muss toleriert werden."""
        monkeypatch.setattr(sys, "platform", "win32")
        single = json.dumps(
            {"Name": "Realtek PCIe GbE", "Class": "Net", "Version": "10.0.1"}
        )
        completed = MagicMock(returncode=0, stdout=single, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_drivers()

        assert len(items) == 1
        assert items[0].name == "Realtek PCIe GbE"
        assert items[0].source == "driver"

    def test_eintrag_ohne_name_uebersprungen(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        payload = json.dumps(
            [
                {"Name": "", "Class": "Net", "Version": "1.0"},  # leerer Name
                {"Class": "Display", "Version": "2.0"},  # gar kein Name
                {"Name": "Echte GPU", "Class": "Display", "Version": "3.0"},
            ]
        )
        completed = MagicMock(returncode=0, stdout=payload, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = collect_drivers()

        assert len(items) == 1
        assert items[0].name == "Echte GPU"


class TestCollectDriversFehler:
    def test_timeout_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="powershell", timeout=30)

        monkeypatch.setattr(subprocess, "run", raise_timeout)
        assert collect_drivers() == []

    def test_powershell_nicht_im_path_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        def raise_fnf(*a, **kw):
            raise FileNotFoundError("powershell not in PATH")

        monkeypatch.setattr(subprocess, "run", raise_fnf)
        assert collect_drivers() == []

    def test_oserror_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        def raise_oserror(*a, **kw):
            raise OSError("pnp error")

        monkeypatch.setattr(subprocess, "run", raise_oserror)
        assert collect_drivers() == []

    def test_returncode_nicht_null_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=1, stdout="", stderr="error")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_drivers() == []

    def test_leere_stdout_gibt_leere_liste(self, monkeypatch):
        """Leerer Output (keine Geraete ODER catch-Leerstring) -> []."""
        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=0, stdout="", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_drivers() == []

    def test_json_parse_fehler_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=0, stdout="kein valides json", stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
        assert collect_drivers() == []


class TestDriverSyntheticIdAndGate:
    def test_synthetische_drv_id_distinkt_pro_geraet(self, monkeypatch):
        """_with_synthetic_id -> drv:<leicht normalisierter Name>, distinkt
        pro Geraet (verschiedene FriendlyNames bleiben distinkt)."""
        monkeypatch.setattr(sys, "platform", "win32")
        completed = MagicMock(returncode=0, stdout=_DRIVER_JSON_THREE, stderr="")
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)

        items = [_with_synthetic_id(it) for it in collect_drivers()]
        ids = {i.name: i.winget_id for i in items}

        # Verschiedene Geraete -> verschiedene Ids.
        assert (
            ids["NVIDIA GeForce RTX 4070"]
            != ids["Intel(R) Ethernet Connection I219-V"]
        )
        # Leicht normalisiert (lowercase + Whitespace-Kollaps).
        assert ids["NVIDIA GeForce RTX 4070"] == "drv:nvidia geforce rtx 4070"
        # Alle drv:-Praefix + synthetisch -> aus winget-Gates ausgeschlossen.
        assert all(v.startswith("drv:") for v in ids.values())
        assert all(is_synthetic_id(v) for v in ids.values())

    def test_drv_id_stabil_ueber_treiber_update(self):
        """Treiber-Versions-Update (gleicher FriendlyName) behaelt dieselbe
        drv:-Id — dieselbe PK-Zeile statt Duplikat."""
        base = SoftwareItem(
            name="NVIDIA GeForce RTX 4070",
            version="31.0.15.3667",
            winget_id=None,
            source="driver",
        )
        import dataclasses  # noqa: PLC0415

        updated = dataclasses.replace(base, version="31.0.15.4000")
        assert (
            _with_synthetic_id(base).winget_id
            == _with_synthetic_id(updated).winget_id
        )

    def test_drv_id_ist_synthetisch(self):
        assert is_synthetic_id("drv:nvidia geforce rtx 4070") is True

    def test_driver_item_nie_upgradeable(self):
        """Ein driver-PatchScanResult mit drv:-Id ist nicht _is_upgradeable
        (synthetische Id -> nie an winget)."""
        from core.patch_result import PatchScanResult
        from tools.patch_monitor.gui.patch_console_widget import _is_upgradeable

        result = PatchScanResult(
            name="NVIDIA GeForce RTX 4070",
            normalized_name="nvidia geforce rtx 4070",
            vendor=None,
            winget_id="drv:nvidia geforce rtx 4070",
            source="driver",
            installed_version="31.0.15.3667",
            available_version=None,
            channel="notify_only",
            policy_source="default",
            cve_ids=(),
            cvss_max=None,
            exploit_available=False,
            eol=False,
            confidence_score=0.0,
            recommendation="up_to_date",
        )
        assert _is_upgradeable(result) is False


class TestSourceLabelDriver:
    def test_source_label_driver(self):
        from tools.patch_monitor.gui.patch_console_widget import _source_label

        assert _source_label("driver") == "Treiber"


class TestCollectAllIncludesDriver:
    def test_collect_all_haengt_treiber_items_hinten_an(self, monkeypatch):
        """collect_all enthaelt die Treiber-Items mit drv:-Id, als LETZTE
        Quelle (nach winget/registry/msix/windows_update/dotnet)."""
        monkeypatch.setattr(
            _pc_mod,
            "collect_winget_inventory",
            lambda: [
                SoftwareItem(
                    name="Mozilla Firefox",
                    version="120.0",
                    winget_id="Mozilla.Firefox",
                    source="winget",
                ),
            ],
        )
        monkeypatch.setattr(_pc_mod, "collect_registry", list)
        monkeypatch.setattr(_pc_mod, "collect_appx", list)
        monkeypatch.setattr(_pc_mod, "collect_windows_update", list)
        monkeypatch.setattr(_pc_mod, "collect_dotnet_runtimes", list)
        monkeypatch.setattr(
            _pc_mod,
            "collect_drivers",
            lambda: [
                SoftwareItem(
                    name="NVIDIA GeForce RTX 4070",
                    version="31.0.15.3667",
                    winget_id=None,
                    source="driver",
                ),
            ],
        )

        items = collect_all()
        by_name = {i.name: i for i in items}

        assert items[-1].source == "driver"
        drv = by_name["NVIDIA GeForce RTX 4070"]
        assert drv.winget_id == "drv:nvidia geforce rtx 4070"
        assert drv.is_update_available is False
        assert by_name["Mozilla Firefox"].winget_id == "Mozilla.Firefox"
