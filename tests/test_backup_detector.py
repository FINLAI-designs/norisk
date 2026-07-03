"""
test_backup_detector.

Tests fuer den optionalen ``BackupDetector``. Wir mocken die Windows-
Registry damit der Test offline + plattform-unabhaengig laeuft.
"""

from __future__ import annotations

import sys
from unittest.mock import patch

from tools.customer_audit.application.backup_detector import (
    _DETECT_PATTERNS,
    BackupDetector,
)


def test_detect_disabled_returns_empty() -> None:
    """Detection AUS → leere Liste, kein Scan."""
    detector = BackupDetector()
    assert detector.detect(enabled=False) == []


def test_detect_match_canonical_names() -> None:
    """Match-Logik fuer bekannte Tool-Strings."""
    detector = BackupDetector()
    cases = {
        "Veeam Agent for Microsoft Windows 12.1": "Veeam Agent",
        "Acronis Cyber Protect Home Office": "Acronis Cyber Protect",
        "Macrium Reflect Free Edition": "Macrium Reflect",
        "Backblaze 9.0": "Backblaze",
        "Microsoft Office 365": None,  # kein Backup-Tool
        "OpenSSH Client": None,
    }
    for display_name, expected in cases.items():
        assert detector._match(display_name) == expected, display_name  # noqa: SLF001


def test_guess_version_from_display_name() -> None:
    detector = BackupDetector()
    assert detector._guess_version("Veeam Agent 12.1.0") == "12.1.0"  # noqa: SLF001
    assert detector._guess_version("Macrium Reflect Free") == ""  # noqa: SLF001
    assert detector._guess_version("Backblaze 9.0") == "9.0"  # noqa: SLF001


def test_detect_patterns_decken_bekannte_familien_ab() -> None:
    """Alle BEKANNTE_BACKUP_TOOLS aus der Domain sollten im Detector
    erwaehnt sein (sonst werden sie nie erkannt)."""
    from tools.customer_audit.domain.entities import BEKANNTE_BACKUP_TOOLS

    canonical_values = set(_DETECT_PATTERNS.values())
    for tool in BEKANNTE_BACKUP_TOOLS:
        # Mindestens irgendein Marker matchet diesen kanonischen Namen
        assert (
            tool in canonical_values
            or any(tool.lower().split()[0] in m for m in _DETECT_PATTERNS)
        ), f"BEKANNTE_BACKUP_TOOLS-Eintrag '{tool}' hat kein Detect-Pattern"


def test_detect_nicht_windows_liefert_leer(monkeypatch) -> None:
    """Auf nicht-Windows-Hosts soll der Detector eine leere Liste
    liefern (NoRisk-Hauptplattform ist Windows, aber Tests laufen
    auch auf Linux-CI)."""
    detector = BackupDetector()
    monkeypatch.setattr(
        "tools.customer_audit.application.backup_detector.platform.system",
        lambda: "Linux",
    )
    assert detector.detect(enabled=True) == []


def test_detect_windows_mocked_registry() -> None:
    """Simuliert einen Windows-Registry-Scan mit zwei Treffern."""
    if sys.platform != "win32":
        # Auf Linux: winreg ist Stub, wir patchen den Code-Pfad nicht
        return

    detector = BackupDetector()
    with patch.object(
        detector, "_scan_windows", return_value=[]
    ) as scan_mock:
        detector.detect(enabled=True)
        assert scan_mock.called


def test_scan_windows_sammelt_treffer(monkeypatch) -> None:
    """Direct-Test des ``_scan_windows``-Codepfades mit gemocktem
    ``winreg``-Modul. Funktioniert auf jedem OS solange das Modul
    importierbar ist."""
    if sys.platform != "win32":
        return

    import winreg

    detector = BackupDetector()

    # Simuliere zwei Treffer in HKLM/Uninstall:
    fake_entries = [
        ("Some_Veeam_Subkey", {"DisplayName": "Veeam Agent for Windows", "DisplayVersion": "12.1.0"}),
        ("EaseUS_Subkey", {"DisplayName": "EaseUS Todo Backup", "DisplayVersion": "13.5"}),
        ("Random_Subkey", {"DisplayName": "Notepad++", "DisplayVersion": "8.0"}),
    ]

    class _FakeKey:
        def __init__(self, items: list) -> None:
            self._items = items

        def __enter__(self):
            return self

        def __exit__(self, *_a) -> None:
            return None

    class _FakeSubKey(_FakeKey):
        def __init__(self, values: dict) -> None:
            super().__init__([])
            self._values = values

    def fake_open_key(hive, sub):  # noqa: ANN001
        # Nur HKLM-uninstall liefern, andere → FileNotFoundError
        if "Uninstall" not in sub:
            raise FileNotFoundError
        # Sub-Key-Aufruf: liefer entweder Top-Container oder Untereintrag
        if sub.endswith("Uninstall"):
            return _FakeKey(fake_entries)
        raise FileNotFoundError

    def fake_enum_key(key, i):  # noqa: ANN001
        return fake_entries[i][0]

    def fake_query_info_key(key):  # noqa: ANN001
        return (len(key._items), 0, 0)  # noqa: SLF001

    def fake_query_value_ex(key, name):  # noqa: ANN001
        if name in key._values:  # noqa: SLF001
            return (key._values[name], 1)  # noqa: SLF001
        raise FileNotFoundError

    # Open auf Sub: liefert _FakeSubKey
    def fake_open_subkey(parent, name):  # noqa: ANN001
        # Map: erster Aufruf = Veeam, zweiter = EaseUS, dritter = Notepad
        for sub_name, values in fake_entries:
            if sub_name == name:
                return _FakeSubKey(values)
        raise FileNotFoundError

    monkeypatch.setattr(winreg, "OpenKey", lambda *a, **kw: (
        fake_open_subkey(a[0], a[1]) if isinstance(a[0], _FakeKey)
        else fake_open_key(a[0], a[1])
    ))
    monkeypatch.setattr(winreg, "EnumKey", fake_enum_key)
    monkeypatch.setattr(winreg, "QueryInfoKey", fake_query_info_key)
    monkeypatch.setattr(winreg, "QueryValueEx", fake_query_value_ex)

    results = detector._scan_windows()  # noqa: SLF001
    names = {r.canonical_name for r in results}
    assert "Veeam Agent" in names
    assert "EaseUS Todo Backup" in names
    # Notepad++ ist kein Backup-Tool → nicht im Result
    assert all("Notepad" not in r.canonical_name for r in results)
