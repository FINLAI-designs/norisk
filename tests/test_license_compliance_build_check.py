"""Tests für den GPLv2-Sperrlisten-Build-Check F-G).

Verifiziert: (1) der echte Repo-Stand ist sauber, (2) der Check ist fail-closed
(eingeschleustes pyshark/Npcap/QtCharts wird in jeder der vier Ebenen gefangen),
(3) das THIRD_PARTY_NOTICES-Register existiert und nennt die Pflicht-Punkte,
(4) die Spec ruft das Gate auf.
"""

from __future__ import annotations

from pathlib import Path

import license_compliance as lc
import pytest
from license_compliance import (
    LicenseComplianceError,
    assert_build_compliant,
    check_build_compliance,
    scan_bundle,
    scan_installed_distributions,
    scan_source_imports,
    scan_text,
)

_REPO_ROOT = Path(lc.__file__).resolve().parent


# ── 1) Echter Stand ist sauber ──────────────────────────────────────────────


class TestRealRepoClean:
    def test_repo_ist_compliant(self) -> None:
        violations = check_build_compliance(_REPO_ROOT, check_installed=True)
        assert violations == [], f"Unerwartete Verstöße: {violations}"

    def test_assert_wirft_nicht(self) -> None:
        assert_build_compliant(_REPO_ROOT)  # darf nicht werfen

    def test_echte_spec_sauber(self) -> None:
        from license_compliance import scan_spec_text

        spec = _REPO_ROOT / "build_specs" / "build_norisk.spec"
        assert spec.is_file()
        assert scan_spec_text(spec) == []

    def test_eigener_code_kein_qtcharts(self) -> None:
        # bandwidth_chart nutzt reinen QPainter, kein QtCharts.
        assert scan_source_imports(_REPO_ROOT) == []


# ── 2) Fail-closed: jede Ebene fängt eine Einschleusung ─────────────────────


class TestSpecTextScan:
    def test_hiddenimport_pyshark_gefangen(self) -> None:
        assert scan_text('hiddenimports=["pyshark"]', source="spec")

    def test_npcap_binary_gefangen(self) -> None:
        assert scan_text('binaries=[("npcap.dll", ".")]', source="spec")

    def test_wireshark_gefangen(self) -> None:
        assert scan_text('datas=[("tshark.exe", ".")]', source="spec")

    def test_kommentar_loest_nicht_aus(self) -> None:
        # Erklärende Kommentare nennen die Namen zwangsläufig — kein Verstoß.
        assert scan_text("# wir bündeln kein pyshark/wireshark/npcap", source="spec") == []

    def test_qtcharts_ausschluss_loest_nicht_aus(self) -> None:
        # Die Spec schließt QtCharts via excludes aus — das ist KEIN Verstoß.
        assert scan_text('excludes=["PySide6.QtCharts"]', source="spec") == []


class TestInstalledScan:
    def test_eingeschleuste_dist_gefangen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _FakeDist:
            def __init__(self, name: str) -> None:
                self.metadata = {"Name": name}

        monkeypatch.setattr(
            "importlib.metadata.distributions",
            lambda: [_FakeDist("pyshark"), _FakeDist("requests")],
        )
        violations = scan_installed_distributions()
        assert any("pyshark" in v for v in violations)

    def test_echte_umgebung_ohne_sniffer(self) -> None:
        # In der Dev-/CI-Umgebung darf kein Sniffer-Paket installiert sein.
        assert scan_installed_distributions() == []

    def test_pep503_normalisierung_gefangen(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Review F-G P3: Underscore/Punkt-Schreibweise darf nicht umgehen.
        class _FakeDist:
            def __init__(self, name: str) -> None:
                self.metadata = {"Name": name}

        monkeypatch.setattr(
            "importlib.metadata.distributions",
            lambda: [_FakeDist("PCAPY_NG")],  # == pcapy-ng nach PEP-503
        )
        assert scan_installed_distributions()


class TestSourceImportScan:
    def test_qtcharts_import_gefangen(self, tmp_path: Path) -> None:
        (tmp_path / "apps").mkdir()
        (tmp_path / "apps" / "bad.py").write_text(
            "from PySide6.QtCharts import QChart\n", encoding="utf-8"
        )
        violations = scan_source_imports(tmp_path)
        assert any("QtCharts" in v for v in violations)

    def test_pyshark_import_gefangen(self, tmp_path: Path) -> None:
        (tmp_path / "core").mkdir()
        (tmp_path / "core" / "bad.py").write_text("import pyshark\n", encoding="utf-8")
        assert any("pyshark" in v for v in scan_source_imports(tmp_path))

    def test_from_pyside6_import_qtcharts_gefangen(self, tmp_path: Path) -> None:
        # Review F-G P2: die idiomatischste QtCharts-Importform.
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "bad.py").write_text(
            "from PySide6 import QtCharts\n", encoding="utf-8"
        )
        assert any("QtCharts" in v for v in scan_source_imports(tmp_path))

    def test_sauberer_code_kein_verstoss(self, tmp_path: Path) -> None:
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "ok.py").write_text(
            "from PySide6.QtGui import QPainter\nimport requests\n", encoding="utf-8"
        )
        assert scan_source_imports(tmp_path) == []


class TestBundleScan:
    def test_npcap_dll_gefangen(self, tmp_path: Path) -> None:
        internal = tmp_path / "_internal"
        internal.mkdir()
        (internal / "npcap.dll").write_bytes(b"x")
        assert any("npcap" in v.lower() for v in scan_bundle(tmp_path))

    def test_qt6charts_dll_gefangen(self, tmp_path: Path) -> None:
        (tmp_path / "Qt6Charts.dll").write_bytes(b"x")
        assert scan_bundle(tmp_path)

    def test_qtcharts_pyd_binding_gefangen(self, tmp_path: Path) -> None:
        # Review F-G P3: das PySide6-Binding-Modul (QtCharts.pyd), nicht nur die DLL.
        (tmp_path / "QtCharts.pyd").write_bytes(b"x")
        assert scan_bundle(tmp_path)

    def test_sauberes_bundle(self, tmp_path: Path) -> None:
        (tmp_path / "Qt6Core.dll").write_bytes(b"x")
        (tmp_path / "_ssl.pyd").write_bytes(b"x")
        assert scan_bundle(tmp_path) == []


class TestAssertFailClosed:
    def test_assert_wirft_bei_verstoss(self, tmp_path: Path) -> None:
        (tmp_path / "apps").mkdir()
        (tmp_path / "apps" / "bad.py").write_text("import pyshark\n", encoding="utf-8")
        with pytest.raises(LicenseComplianceError):
            assert_build_compliant(tmp_path, check_installed=False)


# ── 3) THIRD_PARTY_NOTICES-Register ─────────────────────────────────────────


class TestNoticeRegister:
    def test_existiert_und_nennt_pflichtpunkte(self) -> None:
        notice = _REPO_ROOT / "THIRD_PARTY_NOTICES.md"
        assert notice.is_file()
        text = notice.read_text(encoding="utf-8")
        assert "PySide6" in text
        assert "LGPL" in text  # Qt als LGPL eingeordnet
        assert "Onedir" in text or "ersetzbar" in text  # Replaceable-DLL-Konformität
        # Verbotene-Sektion nennt den GPL-Sniffer-Stack:
        assert "Wireshark" in text or "wireshark" in text
        assert "pyshark" in text
        assert "Qt Charts" in text or "QtCharts" in text


# ── 4) Spec ruft das Gate auf ───────────────────────────────────────────────


class TestSpecIntegration:
    def test_spec_ruft_assert_build_compliant(self) -> None:
        spec = (_REPO_ROOT / "build_specs" / "build_norisk.spec").read_text(
            encoding="utf-8"
        )
        assert "assert_build_compliant" in spec
        assert "license_compliance" in spec
