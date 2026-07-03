"""
test_patch_cpe — pytest-Tests fuer core/patch_cpe.py.

PM-1.2. Deckt:

* Override-Tabelle hat Vorrang vor Heuristik.
* winget-Id-Heuristik (``Vendor.Product``-Split).
* Display-Name-Heuristik nur bei Single-Token (sonst ``None``).
* Versions-Normalisierung integriert (Trailing-Zeros, Java-Suffix,
  Sentinels).
* Sonder-Strings im CPE (``+`` escaped, ``-``-Vendor wie
  ``"notepad-plus-plus"``).
"""

from __future__ import annotations

from core.patch_collector import SoftwareItem
from core.patch_cpe import build_cpe


def _item(name, version, winget_id=None, source="winget"):
    return SoftwareItem(
        name=name, version=version, winget_id=winget_id, source=source
    )


# ===========================================================================
# Override-Tabelle hat Vorrang
# ===========================================================================


class TestCpeOverride:
    def test_firefox_override(self):
        cpe = build_cpe(
            _item("Mozilla Firefox", "121.0", "Mozilla.Firefox")
        )
        assert (
            cpe
            == "cpe:2.3:a:mozilla:firefox:121.0:*:*:*:*:windows:*:*"
        )

    def test_chrome_override(self):
        cpe = build_cpe(_item("Google Chrome", "120.0", "Google.Chrome"))
        assert (
            cpe == "cpe:2.3:a:google:chrome:120.0:*:*:*:*:windows:*:*"
        )

    def test_vscode_override_underscore_im_product(self):
        cpe = build_cpe(
            _item(
                "Visual Studio Code",
                "1.85.0",
                "Microsoft.VisualStudioCode",
            )
        )
        assert cpe == (
            "cpe:2.3:a:microsoft:visual_studio_code:1.85.0:"
            "*:*:*:*:windows:*:*"
        )

    def test_python_versionsspezifische_winget_id_override(self):
        cpe = build_cpe(
            _item("Python 3.12.0", "3.12.0", "Python.Python.3.12")
        )
        assert (
            cpe == "cpe:2.3:a:python:python:3.12.0:*:*:*:*:windows:*:*"
        )

    def test_notepad_plus_plus_escaping(self):
        cpe = build_cpe(
            _item("Notepad++", "8.6.5", "Notepad++.Notepad++")
        )
        # CPE 2.3 escaped + als \\+ (in Python-String: r"\+\+")
        assert cpe == (
            r"cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.6.5:"
            r"*:*:*:*:windows:*:*"
        )

    def test_keepass_override_mit_unterstrichen(self):
        cpe = build_cpe(
            _item("KeePass", "2.55", "KeePass.KeePass")
        )
        assert cpe == (
            "cpe:2.3:a:dominik_reichl:keepass_password_safe:2.55:"
            "*:*:*:*:windows:*:*"
        )


# ===========================================================================
# winget-Id-Heuristik (kein Override-Eintrag)
# ===========================================================================


class TestCpeWingetIdHeuristic:
    def test_unbekannte_winget_id_split_an_punkt(self):
        # "SomeVendor.SomeProduct" ist nicht im Override → Heuristik
        cpe = build_cpe(
            _item("SomeProduct", "1.0", "SomeVendor.SomeProduct")
        )
        assert cpe == (
            "cpe:2.3:a:somevendor:someproduct:1.0:*:*:*:*:windows:*:*"
        )

    def test_drei_teilige_winget_id(self):
        # "A.B.C" → vendor=A, product=B (nur die ersten zwei Parts)
        cpe = build_cpe(_item("Whatever", "2.5.0", "Foo.Bar.Baz"))
        assert cpe == (
            "cpe:2.3:a:foo:bar:2.5.0:*:*:*:*:windows:*:*"
        )

    def test_single_part_winget_id(self):
        # winget_id "Foo" ohne Punkt → vendor=product=foo
        cpe = build_cpe(_item("Foo App", "1.0", "Foo"))
        assert cpe == "cpe:2.3:a:foo:foo:1.0:*:*:*:*:windows:*:*"


# ===========================================================================
# Display-Name-Heuristik (nur Single-Token)
# ===========================================================================


class TestCpeDisplayNameHeuristic:
    def test_7zip_ohne_winget_id_single_token(self):
        # "7-Zip 24.08" → normalize_name → "7-zip" (single token)
        # → vendor=product="7-zip"
        cpe = build_cpe(
            _item("7-Zip 24.08", "24.08", winget_id=None, source="registry")
        )
        assert cpe == (
            "cpe:2.3:a:7-zip:7-zip:24.08:*:*:*:*:windows:*:*"
        )

    def test_unknown_multi_token_gibt_none(self):
        # "Unknown App 1.0" → normalize_name → "unknown app" (2 tokens)
        # → zu fuzzy → None
        cpe = build_cpe(
            _item(
                "Unknown App 1.0", "1.0", winget_id=None, source="registry"
            )
        )
        assert cpe is None

    def test_msix_single_token_funktioniert(self):
        # "VLC" als reiner MSIX-Eintrag ohne winget-Id
        cpe = build_cpe(_item("VLC", "3.0.20", winget_id=None, source="msix"))
        assert cpe == "cpe:2.3:a:vlc:vlc:3.0.20:*:*:*:*:windows:*:*"


# ===========================================================================
# Versions-Behandlung
# ===========================================================================


class TestCpeVersion:
    def test_version_unbekannt_wird_zu_stern(self):
        cpe = build_cpe(
            _item(
                "Mozilla Firefox", "unbekannt", "Mozilla.Firefox"
            )
        )
        assert cpe == "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:windows:*:*"

    def test_version_normalisierung_integriert(self):
        # "3.12.0.0" → "3.12.0" (trailing zero stripped)
        cpe = build_cpe(
            _item("Python", "3.12.0.0", "Python.Python.3.12")
        )
        assert cpe == (
            "cpe:2.3:a:python:python:3.12.0:*:*:*:*:windows:*:*"
        )

    def test_java_style_version_suffix_abgeschnitten(self):
        cpe = build_cpe(
            _item("Some Java", "11.0.2+9", "Foo.Bar")
        )
        assert "11.0.2:" in cpe
        assert "+9" not in cpe

    def test_leere_version_zu_stern(self):
        cpe = build_cpe(_item("Mozilla Firefox", "", "Mozilla.Firefox"))
        assert "*:*:*:*:*:windows" in cpe


# ===========================================================================
# Edge Cases
# ===========================================================================


class TestCpeEdgeCases:
    def test_kein_winget_id_und_leerer_name_gibt_none(self):
        cpe = build_cpe(_item("", "1.0", winget_id=None, source="registry"))
        assert cpe is None

    def test_multi_token_normalize_strippt_version_dann_single_token(self):
        # "PowerShell 7.4.0" → normalize → "powershell" (single)
        cpe = build_cpe(
            _item(
                "PowerShell 7.4.0", "7.4.0", winget_id=None, source="registry"
            )
        )
        assert cpe == (
            "cpe:2.3:a:powershell:powershell:7.4.0:*:*:*:*:windows:*:*"
        )

    def test_override_gewinnt_auch_wenn_heuristik_anders_waere(self):
        # Ohne Override haette die winget-Id-Heuristik
        # vendor="mozilla", product="firefox" geliefert (wuerde
        # zufaellig korrekt sein). Override liefert dasselbe.
        # Test: bei Override-Treffer wird die Override-Form verwendet,
        # selbst wenn ein Punkt im Product-String ist
        # (z.B. visual_studio_code mit Underscore statt einfach "code").
        cpe = build_cpe(
            _item("VS Code", "1.85", "Microsoft.VisualStudioCode")
        )
        assert "visual_studio_code" in cpe

    def test_wireguard_override_passt(self):
        cpe = build_cpe(_item("WireGuard", "0.5.3", "WireGuard.WireGuard"))
        assert cpe == (
            "cpe:2.3:a:wireguard:wireguard:0.5.3:*:*:*:*:windows:*:*"
        )

    def test_cpe_format_struktur(self):
        # CPE 2.3 hat exakt 13 mit Kolons getrennte Komponenten:
        # cpe:2.3:a:vendor:product:version:*:*:*:*:windows:*:*
        cpe = build_cpe(_item("Mozilla Firefox", "1.0", "Mozilla.Firefox"))
        parts = cpe.split(":")
        assert parts[0] == "cpe"
        assert parts[1] == "2.3"
        assert parts[2] == "a"  # application
        assert parts[3] == "mozilla"
        assert parts[4] == "firefox"
        assert parts[5] == "1.0"
        assert parts[10] == "windows"
        assert len(parts) == 13
