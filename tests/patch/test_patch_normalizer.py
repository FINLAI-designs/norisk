"""
test_patch_normalizer — pytest-Tests fuer core/patch_normalizer.py.

Verbesserung 2 (PM-1.1a Nachbesserung). Deckt:

*:func:`normalize_name` — alle Doctest-Beispiele aus dem Modul-
  Docstring + Kollisions-Edge-Cases (WebView2 vs Edge, VirtualBox
  vs Box, Visual C++ vs Visual Studio).
*:func:`normalize_version` — Java-Suffix, 4-Komponenten-Zeros,
  Sentinels.
*:func:`is_runtime_noise` — True/False-Faelle.
*:func:`find_policy_key` — Exact, Substring (beide Richtungen),
  Longest-Match-Wins, Hard-Overrides, kein Match.
"""

from __future__ import annotations

from core.patch_normalizer import (
    find_policy_key,
    is_runtime_noise,
    normalize_for_matching,
    normalize_name,
    normalize_version,
)

# ===========================================================================
# normalize_name — alle Doctest-Beispiele aus dem Modul
# ===========================================================================


class TestNormalizeName:
    def test_python_mit_version_und_arch(self):
        assert normalize_name("Python 3.12.0 (64-bit)") == "python"

    def test_visual_cpp_redistributable(self):
        assert (
            normalize_name(
                "Microsoft Visual C++ 2015-2022 Redistributable (x64)"
            )
            == "microsoft visual c++"
        )

    def test_google_chrome_unveraendert(self):
        assert normalize_name("Google Chrome") == "google chrome"

    def test_firefox_mit_lokalcode(self):
        assert normalize_name("Mozilla Firefox (x64 de)") == "mozilla firefox"

    def test_java_tm_konservativ(self):
        # (TM) ohne fuehrendes Leerzeichen bleibt unangetastet
        assert (
            normalize_name("Java(TM) SE Runtime Environment")
            == "java(tm) se"
        )

    def test_7zip_mit_edition(self):
        assert normalize_name("7-Zip 24.08 (x64 edition)") == "7-zip"

    def test_webview2_runtime_NICHT_microsoft_edge(self):
        # KRITISCH: WebView2 darf NICHT zu "microsoft edge" verkuerzen
        result = normalize_name("Microsoft Edge WebView2 Runtime")
        assert result == "microsoft edge webview2"

    def test_leerer_input_gibt_leeren_string(self):
        assert normalize_name("") == ""

    def test_only_whitespace(self):
        assert normalize_name("   ") == ""

    def test_lowercase_passiert_immer(self):
        assert normalize_name("FIREFOX") == "firefox"

    def test_mehrfach_whitespace_kollabiert(self):
        assert normalize_name("foo    bar     baz") == "foo bar baz"

    def test_jahresangabe_einzeln_entfernt(self):
        assert normalize_name("Some App 2024") == "some app"

    def test_v_prefix_version_entfernt(self):
        assert normalize_name("App v123") == "app"

    def test_dotnet_runtime_pattern(self):
        # ".NET" wird nicht als Noise oder Version erkannt — es bleibt
        # erhalten. Aber "Runtime" wird entfernt.
        result = normalize_name("Microsoft .NET Runtime 8.0.10")
        # "8.0.10" → version, "Runtime" → noise
        assert result == "microsoft .net"


# ===========================================================================
# normalize_version
# ===========================================================================


class TestNormalizeVersion:
    def test_4_komponenten_trailing_zero_entfernt(self):
        assert normalize_version("3.12.0.0") == "3.12.0"

    def test_4_komponenten_ohne_trailing_zero_bleibt(self):
        assert normalize_version("121.0.6167.85") == "121.0.6167.85"

    def test_java_style_plus_suffix_abgeschnitten(self):
        assert normalize_version("11.0.2+9") == "11.0.2"

    def test_unknown_gibt_none(self):
        assert normalize_version("unknown") is None

    def test_unbekannt_gibt_none(self):
        assert normalize_version("unbekannt") is None

    def test_leerer_string_gibt_none(self):
        assert normalize_version("") is None

    def test_none_input_gibt_none(self):
        assert normalize_version(None) is None

    def test_n_a_dash_none_dash(self):
        # Verschiedene Sentinel-Schreibweisen
        assert normalize_version("n/a") is None
        assert normalize_version("none") is None
        assert normalize_version("-") is None

    def test_einfache_version_unveraendert(self):
        assert normalize_version("3.12.0") == "3.12.0"

    def test_whitespace_getrimmt(self):
        assert normalize_version("  3.12.0  ") == "3.12.0"


# ===========================================================================
# is_runtime_noise
# ===========================================================================


class TestIsRuntimeNoise:
    def test_visual_cpp_redistributable(self):
        assert is_runtime_noise(
            "Microsoft Visual C++ 2022 Redistributable"
        )

    def test_directx(self):
        assert is_runtime_noise("DirectX for Windows")

    def test_dotnet_runtime(self):
        assert is_runtime_noise("Microsoft .NET Runtime 8.0")

    def test_normaler_browser_keine_runtime(self):
        assert not is_runtime_noise("Mozilla Firefox")

    def test_leerer_input_ist_keine_runtime(self):
        assert not is_runtime_noise("")

    def test_vc_plus_plus_inline(self):
        # "Microsoft VC++ 2022 Update 5" enthaelt "vc++" → True
        assert is_runtime_noise("Microsoft VC++ 2022 Update 5")

    def test_windows_app_runtime(self):
        assert is_runtime_noise("Microsoft.WindowsAppRuntime.1.5")


# ===========================================================================
# find_policy_key — Hard-Overrides + Exact + Substring
# ===========================================================================


class TestFindPolicyKeyExact:
    def test_exakter_match_gibt_confidence_0_9(self):
        keys = ["firefox", "chrome", "vscode"]
        assert find_policy_key("firefox", keys) == ("firefox", 0.9)

    def test_kein_match_gibt_none(self):
        keys = ["firefox", "chrome"]
        assert find_policy_key("notepad", keys) is None

    def test_leerer_normalized_gibt_none(self):
        assert find_policy_key("", ["firefox"]) is None


class TestFindPolicyKeySubstring:
    def test_key_in_normalized(self):
        keys = ["firefox"]
        result = find_policy_key("mozilla firefox 120", keys)
        assert result is not None
        matched, _conf = result
        assert matched == "firefox"

    def test_normalized_in_key(self):
        # Normalisierter Name kuerzer als der Key — beide Richtungen ok
        keys = ["mozilla firefox extended support release"]
        result = find_policy_key("firefox", keys)
        assert result is not None
        matched, _conf = result
        assert matched == "mozilla firefox extended support release"

    def test_laengster_match_gewinnt(self):
        keys = ["firefox", "mozilla firefox", "browser"]
        result = find_policy_key("mozilla firefox 120", keys)
        assert result is not None
        matched, _conf = result
        # "mozilla firefox" (15) vs "firefox" (7) — laengerer wins
        assert matched == "mozilla firefox"

    def test_tie_break_alphabetisch(self):
        # beide Keys gleich lang, beide matchen "aa bb" via Substring
        result = find_policy_key("aa bb", ["aa", "bb"])
        # tuple-key (len, name) → bei gleicher Laenge alphabetisch
        # aufsteigend → max nimmt das alphabetisch GROESSERE
        assert result is not None
        matched, _conf = result
        assert matched == "bb"


class TestFindPolicyKeyKollisionen:
    def test_microsoft_edge_webview2_NICHT_edge(self):
        # KRITISCHER Kollisions-Test
        keys = ["microsoft edge", "microsoft edge webview2", "edge"]
        result = find_policy_key("microsoft edge webview2", keys)
        assert result is not None
        matched, _conf = result
        # Hard-Override ODER Exakter Match — beide picken webview2
        assert matched == "microsoft edge webview2"

    def test_oracle_virtualbox_NICHT_box(self):
        keys = ["box", "virtualbox", "oracle"]
        result = find_policy_key("oracle virtualbox", keys)
        assert result is not None
        matched, _conf = result
        # "virtualbox" (10) > "box" (3) > "oracle" (6 mit substring "oracle"
        # in "oracle virtualbox" — ja). Aber laengster gewinnt.
        assert matched == "virtualbox"

    def test_microsoft_visual_cpp_NICHT_visual_studio(self):
        keys = ["visualstudio", "visual studio code", "microsoft visual c++"]
        result = find_policy_key("microsoft visual c++", keys)
        assert result is not None
        matched, _conf = result
        # Exakter Match
        assert matched == "microsoft visual c++"


class TestFindPolicyKeyHardOverrides:
    def test_hard_override_webview2(self):
        keys = ["microsoft edge", "microsoft edge webview2", "some.app.thing"]
        result = find_policy_key("some.app.webview2", keys)
        assert result is not None
        matched, conf = result
        assert matched == "microsoft edge webview2"
        assert conf == 0.85

    def test_hard_override_vcredist(self):
        keys = ["microsoft visual c++", "vcredist2022"]
        result = find_policy_key("vcredist", keys)
        assert result is not None
        matched, conf = result
        # Hard-Override greift VOR Exakt-Match, daher target gewinnt
        assert matched == "microsoft visual c++"
        assert conf == 0.85

    def test_hard_override_dotnet(self):
        keys = ["microsoft .net", "dotnetruntime"]
        result = find_policy_key("dotnet 8.0", keys)
        assert result is not None
        matched, conf = result
        assert matched == "microsoft .net"
        assert conf == 0.85

    def test_hard_override_java(self):
        keys = ["java runtime", "java"]
        result = find_policy_key("java(tm) se", keys)
        assert result is not None
        matched, conf = result
        assert matched == "java runtime"
        assert conf == 0.85

    def test_hard_override_target_fehlt_keine_anwendung(self):
        # Wenn target NICHT in policy_keys ist, faellt Hard-Override
        # auf normalen Match zurueck.
        keys = ["webview2"]  # "microsoft edge webview2" fehlt
        result = find_policy_key("foo webview2 bar", keys)
        assert result is not None
        matched, conf = result
        assert matched == "webview2"  # Substring-Match auf "webview2"
        assert conf < 0.85  # nicht der Hard-Override-Wert


class TestFindPolicyKeyConfidence:
    def test_confidence_kleiner_match_kuerzer_als_normalized(self):
        keys = ["fox"]
        result = find_policy_key("firefox box", keys)
        assert result is not None
        matched, conf = result
        assert matched == "fox"
        # FIX A — score = 0.7 * substring_ratio + 0.3 * token_ratio
        # substring_ratio = 3/11 = 0.273
        # token_ratio = |{} ∩ {fox}| / max(2, 1) = 0
        # score = 0.273 * 0.7 + 0 = 0.19
        assert conf == 0.19

    def test_confidence_groesser_1_wenn_key_laenger_als_normalized(self):
        # User-Spec erlaubt Werte > 1.0 (key kann laenger als
        # normalized sein, wenn `normalized in key` matcht).
        keys = ["mozilla firefox extended"]
        result = find_policy_key("firefox", keys)
        assert result is not None
        _matched, conf = result
        assert conf > 1.0


class TestNormalizeForMatching:
    """FIX B — normalize_for_matching entfernt zusaetzlich
:data:`_SEMANTIC_TOKENS` (sdk/jdk/jre/server/client/...)."""

    def test_dotnet_runtime_und_sdk_kollabieren_zum_gleichen_key(self):
        assert normalize_for_matching("Microsoft .NET Runtime 8.0") == \
               normalize_for_matching("Microsoft .NET SDK 8.0") == \
               "microsoft .net"

    def test_apache_server_strippt_server(self):
        assert (
            normalize_for_matching("Apache HTTP Server 2.4")
            == "apache http"
        )

    def test_driver_token_entfernt(self):
        assert (
            normalize_for_matching("Realtek Audio Driver 6.0")
            == "realtek audio"
        )

    def test_plugin_token_entfernt(self):
        assert (
            normalize_for_matching("Some Awesome Plugin 1.0")
            == "some awesome"
        )

    def test_fallback_bei_zu_kurzem_ergebnis(self):
        # "eM Client" → normalize_name → "em client" → strip "client"
        # = "em" (2 Zeichen) → Fallback: behaelt "em client".
        assert normalize_for_matching("eM Client 10.4.5326.0") == "em client"

    def test_normalize_name_unveraendert(self):
        # FIX B: normalize_name darf nicht beruehrt werden — nur
        # normalize_for_matching entfernt Semantik-Tokens.
        assert (
            normalize_name("Microsoft .NET SDK 8.0")
            == "microsoft .net sdk"
        )
        assert (
            normalize_name("Apache HTTP Server 2.4")
            == "apache http server"
        )

    def test_runtime_token_redundant_aber_konsistent(self):
        # "runtime" ist sowohl in Noise- als auch in
        # Semantik-Tokens — beides funktioniert.
        assert (
            normalize_for_matching("Microsoft .NET Runtime")
            == "microsoft .net"
        )

    def test_leerer_input(self):
        assert normalize_for_matching("") == ""

    def test_nur_semantik_token_fuehrt_zu_fallback(self):
        # "Driver" allein → normalize_name = "driver" → strip = ""
        # (3 Zeichen Threshold greift NICHT bei leerem stripped).
        # Fallback liefert "driver" zurueck.
        assert normalize_for_matching("Driver") == "driver"


class TestFindPolicyKeyTokenOverlap:
    """FIX A — Token-Overlap-Score in find_policy_key. Regressions-
    Schutz fuer die in:class:`TestFindPolicyKeyKollisionen` bereits
    geprueften Faelle nach dem Score-Refactor."""

    def test_runtime_kollision_bleibt_aufgeloest(self):
        # Regressions-Schutz: WebView2 darf nach FIX A weiter NICHT
        # auf "edge"-Browser verkuerzt werden.
        keys = [
            "microsoft edge",
            "microsoft edge webview2",
            "edge",
        ]
        result = find_policy_key("microsoft edge webview2", keys)
        matched, _conf = result
        assert matched == "microsoft edge webview2"

    def test_oracle_virtualbox_bleibt_stable(self):
        keys = ["box", "virtualbox", "oracle"]
        result = find_policy_key("oracle virtualbox", keys)
        matched, _conf = result
        assert matched == "virtualbox"
