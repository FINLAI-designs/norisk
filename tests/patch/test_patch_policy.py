"""
test_patch_policy — pytest-Tests fuer core/patch_policy.py.

PM-1.3. Deckt:

* PatchPolicy frozen dataclass + VALID_CHANNELS-Set
* Default-Policy:
    - korrekter Kanal pro Brand-Name + winget-Id-Format
    - case-insensitive Substring-Match
    - Schluessel-Mindestlaenge filtert "r" und "go"
    - notify_only-Fallback fuer unbekannte Software
* User-Override:
    - speichert / liest / loescht / listet
    - hat Vorrang vor Default
    - ungueltiger Kanal -> ValueError
    - leerer software_name -> ValueError

Strategie: ``EncryptedDatabase`` wird per ``monkeypatch`` durch ein
in-memory sqlite3-Wrapper ersetzt — kein Disk-Write, keine SQLCipher-
Abhaengigkeit, jeder Test bekommt eine frische DB.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

import pytest

from core import patch_policy
from core.patch_policy import (
    DEFAULT_POLICY,
    VALID_CHANNELS,
    PatchPolicy,
    PolicyDB,
    _build_default_policy,
)

# ---------------------------------------------------------------------------
# Fake-EncryptedDatabase: in-memory sqlite3, ueberlebt mehrere connection-
# Aufrufe innerhalb einer PolicyDB-Instanz.
# ---------------------------------------------------------------------------


class _FakeEncryptedDB:
    """In-memory sqlite3-Wrapper mit gleicher API wie EncryptedDatabase."""

    def __init__(self, db_name: str) -> None:
        # check_same_thread=False ist fuer unsere Tests irrelevant, aber
        # entkoppelt unnoetige Thread-Affinitaet.
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._db_name = db_name

    @contextmanager
    def connection(self):
        try:
            yield self._conn
            self._conn.commit()
        except Exception:  # noqa: BLE001
            self._conn.rollback()
            raise


@pytest.fixture
def policy_db(monkeypatch):
    """Liefert eine frische PolicyDB-Instanz mit in-memory Backend."""
    fake = _FakeEncryptedDB("patch_policy")
    # patch_policy.py importiert ``EncryptedDatabase`` als Modul-Name —
    # wir tauschen die Klasse durch eine Factory aus, die immer dieselbe
    # Fake-Instanz zurueckliefert.
    monkeypatch.setattr(
        patch_policy, "EncryptedDatabase", lambda name: fake
    )
    return PolicyDB()


# ---------------------------------------------------------------------------
# PatchPolicy & VALID_CHANNELS
# ---------------------------------------------------------------------------


class TestPatchPolicyDataclass:
    def test_alle_felder_setzbar(self):
        p = PatchPolicy(channel="latest", reason="X", source="default")
        assert p.channel == "latest"
        assert p.reason == "X"
        assert p.source == "default"

    def test_frozen(self):
        from dataclasses import FrozenInstanceError

        p = PatchPolicy(channel="latest", reason="X", source="default")
        with pytest.raises(FrozenInstanceError):
            p.channel = "stable"  # type: ignore[misc]

    def test_gleichheit(self):
        a = PatchPolicy(channel="latest", reason="X", source="default")
        b = PatchPolicy(channel="latest", reason="X", source="default")
        assert a == b


class TestValidChannels:
    def test_enthaelt_alle_vier_kanale(self):
        for channel in ("latest", "stable", "patch_only", "pinned"):
            assert channel in VALID_CHANNELS
        assert len(VALID_CHANNELS) == 4

    def test_notify_only_ist_kein_user_kanal(self):
        # Sentinel fuer DEFAULT_POLICY, aber NICHT in den User-erlaubten
        # Kanaelen — sonst koennte ein User versehentlich "notify_only"
        # setzen, was inhaltlich keinen Override ausdrueckt.
        assert "notify_only" not in VALID_CHANNELS

    def test_default_policy_konstanten(self):
        assert DEFAULT_POLICY.channel == "notify_only"
        assert DEFAULT_POLICY.source == "default"
        assert "Unbekannte Software" in DEFAULT_POLICY.reason


# ---------------------------------------------------------------------------
# _build_default_policy: Filter & Konsistenz
# ---------------------------------------------------------------------------


class TestBuildDefaultPolicy:
    def test_filter_kurzer_keys(self):
        """Schluessel < 3 Zeichen ('r', 'go') werden aussortiert."""
        entries = _build_default_policy()
        keys = {key for key, _policy in entries}
        # Aussortiert:
        assert "r" not in keys
        assert "go" not in keys
        # Behalten (Aliase fuer dieselben Programme):
        assert "rust" in keys
        assert "rustlang.rust" in keys
        assert "golang" in keys
        assert "google.go" in keys
        assert "r-project.r" in keys
        assert "r project" in keys

    def test_alle_kanale_korrekt_zugeordnet(self):
        entries = _build_default_policy()
        per_channel: dict[str, set[str]] = {}
        for key, policy in entries:
            per_channel.setdefault(policy.channel, set()).add(key)

        # Brand-Name + Winget-Id muessen beide drin sein:
        assert "firefox" in per_channel["latest"]
        assert "mozilla.firefox" in per_channel["latest"]
        assert "vscode" in per_channel["stable"]
        assert "microsoft.visualstudiocode" in per_channel["stable"]
        assert "python" in per_channel["patch_only"]
        assert "python 3.12" in per_channel["patch_only"]

        # Gefilterte Tokens sind nirgends:
        for ch in per_channel:
            assert "r" not in per_channel[ch]
            assert "go" not in per_channel[ch]

    def test_keine_doppelten_keys_innerhalb_kanal(self):
        """Innerhalb eines Kanals dedupliziert ``_build_default_policy``."""
        entries = _build_default_policy()
        per_channel: dict[str, list[str]] = {}
        for key, policy in entries:
            per_channel.setdefault(policy.channel, []).append(key)
        for ch, keys in per_channel.items():
            assert len(keys) == len(set(keys)), (
                f"Doppelte Keys in {ch}: "
                f"{[k for k in keys if keys.count(k) > 1]}"
            )

    def test_mindestens_200_eintraege(self):
        """Erweiterte Default-Policy hat ~400 Eintraege (LATEST + STABLE +
        PATCH_ONLY zusammen). Sanity-Check, keine genaue Zahl."""
        entries = _build_default_policy()
        assert len(entries) >= 200

    def test_alle_keys_lowercase(self):
        for key, _policy in _build_default_policy():
            assert key == key.lower(), f"Key nicht lowercase: {key!r}"

    def test_alle_keys_min_3_zeichen(self):
        for key, _policy in _build_default_policy():
            assert len(key) >= 3, f"Key zu kurz: {key!r}"


# ---------------------------------------------------------------------------
# PolicyDB.get — Default-Matching
# ---------------------------------------------------------------------------


class TestGetDefault:
    def test_bekannte_software_latest(self, policy_db):
        p = policy_db.get("Mozilla Firefox 120.0.1")
        assert p.channel == "latest"
        assert p.source == "default"

    def test_bekannte_software_stable(self, policy_db):
        # vscode ist in stable (nicht latest)
        p = policy_db.get("Microsoft Visual Studio Code 1.85.0")
        assert p.channel == "stable"
        assert p.source == "default"

    def test_bekannte_software_patch_only(self, policy_db):
        p = policy_db.get("Python 3.12.10 Core Interpreter (64-bit)")
        assert p.channel == "patch_only"
        assert p.source == "default"

    def test_unbekannte_software_notify_only(self, policy_db):
        p = policy_db.get("Some Random Tool 1.0")
        assert p == DEFAULT_POLICY
        assert p.channel == "notify_only"

    def test_case_insensitive(self, policy_db):
        p = policy_db.get("PYTHON 3.12 STANDARD LIBRARY")
        assert p.channel == "patch_only"

    def test_substring_match(self, policy_db):
        # "firefox" muss nur als Substring drin sein
        p = policy_db.get("Mozilla Firefox ESR 115.0 (x64)")
        assert p.channel == "latest"

    def test_winget_id_format_match(self, policy_db):
        # winget-Id-Format mit Punkt als Schluessel
        p = policy_db.get("Microsoft.VisualStudioCode")
        assert p.channel == "stable"

    def test_brand_name_alias(self, policy_db):
        p = policy_db.get("Brave Browser 1.50.0")
        assert p.channel == "latest"

    def test_webview2_ist_patch_only(self, policy_db):
        # WebView2 ist Runtime-Komponente — Apps wie Teams/Office
        # haengen davon ab, deshalb patch_only (kein latest).
        p = policy_db.get("Microsoft Edge WebView2 Runtime")
        assert p.channel == "patch_only"

    def test_versionierter_dotnet_runtime_match(self, policy_db):
        p = policy_db.get("Microsoft.DotNet.DesktopRuntime.8 8.0.10")
        assert p.channel == "patch_only"

    def test_em_client_ist_latest(self, policy_db):
        p = policy_db.get("eM Client 10.4.5326.0")
        assert p.channel == "latest"

    def test_virtualbox_ist_stable(self, policy_db):
        p = policy_db.get("Oracle VM VirtualBox 7.0.20")
        assert p.channel == "stable"

    def test_cloudflare_warp_ist_latest(self, policy_db):
        p = policy_db.get("Cloudflare WARP 2024.6.415.0")
        assert p.channel == "latest"

    def test_microsoft_365_apps_for_business_match(self, policy_db):
        # Real-Windows-DisplayName aus dem Live-Inventar
        p = policy_db.get("Microsoft 365 Apps for business - en-us")
        assert p.channel == "latest"

    def test_kurze_keys_loesen_keine_false_positives_aus(self, policy_db):
        """'r' wuerde Substring-Match auf JEDE Software mit 'r' im Namen
        produzieren. Test: Software, die NICHT in der Default-Policy ist
        und keinen anderen Match hat, faellt auf notify_only."""
        # "Adobe Photoshop" enthaelt viele "r" — ohne Filter waere das
        # patch_only (wegen "r"-Key) — wir wollen aber notify_only.
        p = policy_db.get("Adobe Photoshop CC 2025")
        assert p == DEFAULT_POLICY

    def test_leerer_name_gibt_default_policy(self, policy_db):
        p = policy_db.get("")
        assert p == DEFAULT_POLICY

    def test_whitespace_name_gibt_default_policy(self, policy_db):
        p = policy_db.get("   ")
        assert p == DEFAULT_POLICY


# ---------------------------------------------------------------------------
# PolicyDB.set_user_override
# ---------------------------------------------------------------------------


class TestSetUserOverride:
    def test_speichert_korrekt(self, policy_db):
        policy_db.set_user_override(
            "Some Tool 1.0", "pinned", reason="vor Audit"
        )
        p = policy_db.get("Some Tool 1.0")
        assert p.channel == "pinned"
        assert p.source == "user"
        assert p.reason == "vor Audit"

    def test_user_override_hat_vorrang_vor_default(self, policy_db):
        # Default fuer Firefox waere latest
        assert policy_db.get("Mozilla Firefox 120").channel == "latest"
        # User setzt pinned
        policy_db.set_user_override("Mozilla Firefox 120", "pinned")
        p = policy_db.get("Mozilla Firefox 120")
        assert p.channel == "pinned"
        assert p.source == "user"

    def test_ueberschreibt_bestehenden_override(self, policy_db):
        policy_db.set_user_override("Tool", "latest", reason="r1")
        policy_db.set_user_override("Tool", "pinned", reason="r2")
        p = policy_db.get("Tool")
        assert p.channel == "pinned"
        assert p.reason == "r2"

    def test_case_insensitive_lookup_nach_set(self, policy_db):
        policy_db.set_user_override("MyTool", "stable")
        assert policy_db.get("mytool").channel == "stable"
        assert policy_db.get("MYTOOL").channel == "stable"
        assert policy_db.get("MyTool").channel == "stable"

    def test_ungueltiger_kanal_loest_valueerror_aus(self, policy_db):
        with pytest.raises(ValueError, match="Ungueltiger Kanal"):
            policy_db.set_user_override("Tool", "schnell")

    def test_notify_only_ist_gueltiger_user_override(self, policy_db):
        # notify_only ist jetzt ein zulaessiger expliziter Override
        # ("App bewusst nicht patchen"), nicht mehr nur der Fallback-Sentinel.
        policy_db.set_user_override("Tool", "notify_only")
        p = policy_db.get("Tool")
        assert p.channel == "notify_only"
        assert p.source == "user"

    def test_leerer_name_loest_valueerror_aus(self, policy_db):
        with pytest.raises(ValueError, match="darf nicht leer sein"):
            policy_db.set_user_override("", "latest")

    def test_whitespace_name_loest_valueerror_aus(self, policy_db):
        with pytest.raises(ValueError, match="darf nicht leer sein"):
            policy_db.set_user_override("   ", "latest")

    def test_default_reason_ist_leer(self, policy_db):
        policy_db.set_user_override("Tool", "stable")
        assert policy_db.get("Tool").reason == ""


# ---------------------------------------------------------------------------
# PolicyDB.remove_user_override
# ---------------------------------------------------------------------------


class TestRemoveUserOverride:
    def test_entfernt_korrekt(self, policy_db):
        # "MyUniqueApp" — bewusst kein Substring-Match auf einen
        # Default-Policy-Key (vermeidet Kollision mit z.B. "tool" in
        # "jetbrains toolbox" via bidirektionalem Substring-Match).
        policy_db.set_user_override("MyUniqueApp", "pinned")
        assert policy_db.get("MyUniqueApp").channel == "pinned"
        policy_db.remove_user_override("MyUniqueApp")
        assert policy_db.get("MyUniqueApp") == DEFAULT_POLICY

    def test_entfernt_dann_default_greift_wieder(self, policy_db):
        policy_db.set_user_override("Mozilla Firefox 120", "pinned")
        policy_db.remove_user_override("Mozilla Firefox 120")
        # Default-Match laeuft wieder
        p = policy_db.get("Mozilla Firefox 120")
        assert p.channel == "latest"
        assert p.source == "default"

    def test_remove_ohne_existierenden_override_ist_noop(self, policy_db):
        # Darf nicht crashen
        policy_db.remove_user_override("Doesnt Exist")
        # Default-Lookup muss weiter funktionieren
        assert policy_db.get("Doesnt Exist") == DEFAULT_POLICY

    def test_remove_case_insensitive(self, policy_db):
        policy_db.set_user_override("MyTool", "pinned")
        policy_db.remove_user_override("mytool")
        assert policy_db.get("MyTool") == DEFAULT_POLICY

    def test_remove_leerer_name_ist_noop(self, policy_db):
        policy_db.remove_user_override("")  # darf nicht crashen


# ---------------------------------------------------------------------------
# PolicyDB.list_user_overrides
# ---------------------------------------------------------------------------


class TestListUserOverrides:
    def test_leer_initial(self, policy_db):
        assert policy_db.list_user_overrides() == {}

    def test_listet_alle_user_overrides(self, policy_db):
        policy_db.set_user_override("Tool A", "pinned", reason="r1")
        policy_db.set_user_override("Tool B", "stable", reason="r2")

        overrides = policy_db.list_user_overrides()

        assert set(overrides.keys()) == {"Tool A", "Tool B"}
        assert overrides["Tool A"].channel == "pinned"
        assert overrides["Tool A"].reason == "r1"
        assert overrides["Tool A"].source == "user"
        assert overrides["Tool B"].channel == "stable"

    def test_listet_nur_user_overrides_keine_defaults(self, policy_db):
        # Auch wenn Firefox einen Default hat, darf list_user_overrides
        # ihn NICHT zurueckgeben (er ist kein User-Override).
        assert policy_db.list_user_overrides() == {}

    def test_alphabetisch_sortiert(self, policy_db):
        policy_db.set_user_override("Zeta", "pinned")
        policy_db.set_user_override("Alpha", "pinned")
        policy_db.set_user_override("Mike", "pinned")

        overrides = policy_db.list_user_overrides()

        assert list(overrides.keys()) == ["Alpha", "Mike", "Zeta"]

    def test_originale_schreibweise_bleibt_erhalten(self, policy_db):
        # Storage-Key ist normalisierter lowercase, aber
        # list_user_overrides zeigt die Original-Schreibweise an.
        policy_db.set_user_override("MyApp 2.0", "stable")
        overrides = policy_db.list_user_overrides()
        assert "MyApp 2.0" in overrides


# ---------------------------------------------------------------------------
# Integration mit core.patch_normalizer (PM-1.3 + Verbesserung 2)
# ---------------------------------------------------------------------------


class TestNormalizerIntegration:
    def test_python_mit_version_und_arch_mappt_auf_patch_only(self, policy_db):
        # "Python 3.12.0 (64-bit)" → normalize → "python"
        # → exakter Match auf Default-Policy-Key "python" → patch_only
        p = policy_db.get("Python 3.12.0 (64-bit)")
        assert p.channel == "patch_only"
        assert p.source == "default"

    def test_webview2_runtime_mappt_auf_patch_only_nicht_edge(self, policy_db):
        # KRITISCHE Kollision: "Microsoft Edge WebView2 Runtime" darf
        # NICHT als "Microsoft Edge"-Browser (latest) klassifiziert
        # werden — WebView2 ist Runtime-Komponente.
        p = policy_db.get("Microsoft Edge WebView2 Runtime")
        assert p.channel == "patch_only"
        assert p.source == "default"

    def test_virtualbox_mit_arch_mappt_auf_stable_nicht_box(self, policy_db):
        # "Oracle VirtualBox 7.0 (x64)" → "oracle virtualbox"
        # Substring-Match: "virtualbox" (stable) gewinnt ueber
        # "box" (latest, eigentlich rausgefiltert wegen <3 chars).
        p = policy_db.get("Oracle VirtualBox 7.0 (x64)")
        assert p.channel == "stable"
        assert p.source == "default"

    def test_user_override_unter_normalisiertem_namen(self, policy_db):
        # Override auf "Python 3.12.0" gilt auch fuer "Python 3.11.5"
        # — beide normalisieren zu "python".
        policy_db.set_user_override("Python 3.12.0", "pinned")
        assert policy_db.get("Python 3.11.5").channel == "pinned"
        assert policy_db.get("Python 3.12.0 (64-bit)").channel == "pinned"

    def test_visual_cpp_redistributable_via_hard_override(self, policy_db):
        # "Microsoft Visual C++ 2022 Redistributable (x64)"
        # → normalize → "microsoft visual c++"
        # → exakter Match auf Hard-Override-Ziel-Key (patch_only)
        p = policy_db.get("Microsoft Visual C++ 2022 Redistributable (x64)")
        assert p.channel == "patch_only"

    def test_dotnet_runtime_via_hard_override(self, policy_db):
        # "Microsoft.NET Runtime 8.0.10" → normalize → "microsoft.net"
        # → exakter Match (Hard-Override-Ziel) → patch_only
        p = policy_db.get("Microsoft .NET Runtime 8.0.10")
        assert p.channel == "patch_only"


# ---------------------------------------------------------------------------
# Globaler Default-Kanal fuer unbekannte Software
# ---------------------------------------------------------------------------


class TestDefaultChannel:
    """Globaler Default-Kanal: unbekannte Software erbt ihn."""

    _UNKNOWN = "ZzzVoelligUnbekanntesTool 9.9 (x64)"

    def test_werks_default_ist_notify_only(self, policy_db):
        assert policy_db.get_default_channel() == "notify_only"
        # Unbekannte Software -> notify_only (Verhalten wie vor).
        assert policy_db.get(self._UNKNOWN).channel == "notify_only"

    def test_set_default_channel_wirkt_auf_unbekannte(self, policy_db):
        policy_db.set_default_channel("stable")
        assert policy_db.get_default_channel() == "stable"
        p = policy_db.get(self._UNKNOWN)
        # Unbekannte Software ist jetzt 'stable' -> upgradebar statt Dead-End.
        assert p.channel == "stable"
        assert p.source == "default"

    def test_set_default_channel_aendert_kuratierte_nicht(self, policy_db):
        policy_db.set_default_channel("latest")
        # Curated patch_only (Python) bleibt patch_only — Default greift NUR
        # bei unbekannter Software.
        assert policy_db.get("Python 3.12.0 (64-bit)").channel == "patch_only"

    def test_user_override_schlaegt_default_channel(self, policy_db):
        policy_db.set_default_channel("stable")
        policy_db.set_user_override(self._UNKNOWN, "pinned")
        p = policy_db.get(self._UNKNOWN)
        assert p.channel == "pinned"
        assert p.source == "user"

    def test_set_default_channel_validiert(self, policy_db):
        with pytest.raises(ValueError, match="Default-Kanal"):
            policy_db.set_default_channel("turbo")

    def test_default_channel_persistiert(self, policy_db, monkeypatch):
        policy_db.set_default_channel("patch_only")
        # Neue Instanz auf derselben (Fake-)DB -> Wert ueberlebt.
        fresh = PolicyDB()
        assert fresh.get_default_channel() == "patch_only"
