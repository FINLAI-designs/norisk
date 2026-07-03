"""
test_patch_channel_resolver — pytest-Tests fuer
core/patch_channel_resolver.py.

PM-1.4. Deckt:

*:class:`ChannelDecision` ist frozen dataclass mit Pflicht-Feldern.
* Aufloesungs-Hierarchie: user > runtime_force > policy > default.
* Confidence-Heuristik (1.0 / 0.90 / policy / 0.0).
* Reason ist immer nicht-leer + menschenlesbar.
* CPE ist gefuellt fuer Apps mit winget-Id, sonst evtl. None.
*:meth:`resolve_batch` (leere Liste, gemischte Items, Reihenfolge).
* Defensive Fail-Open: Resolver-Exception → ``"default"``-Decision
  ohne Crash.

Strategie: ``EncryptedDatabase`` wird wie in
``test_patch_policy.py`` durch einen in-memory sqlite3-Wrapper
ersetzt. Die:class:`PolicyDB` wird in den Resolver injiziert.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import FrozenInstanceError

import pytest

from core import patch_policy
from core.patch_channel_resolver import (
    ChannelDecision,
    ChannelResolver,
)
from core.patch_collector import SoftwareItem
from core.patch_policy import PolicyDB


class _FakeEncryptedDB:
    def __init__(self, db_name: str) -> None:
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
def resolver(monkeypatch):
    fake = _FakeEncryptedDB("patch_policy")
    monkeypatch.setattr(
        patch_policy, "EncryptedDatabase", lambda name: fake
    )
    db = PolicyDB()
    return ChannelResolver(policy=db), db


def _item(name, version="1.0", winget_id=None, source="winget"):
    return SoftwareItem(
        name=name, version=version, winget_id=winget_id, source=source
    )


# ===========================================================================
# ChannelDecision Dataclass
# ===========================================================================


class TestChannelDecisionDataclass:
    def test_frozen(self):
        d = ChannelDecision(
            item=_item("X"),
            channel="latest",
            policy_source="policy",
            confidence=0.9,
            normalized_name="x",
            cpe=None,
            reason="ok",
        )
        with pytest.raises(FrozenInstanceError):
            d.channel = "stable"  # type: ignore[misc]


# ===========================================================================
# Aufloesungs-Hierarchie: user > runtime > policy > default
# ===========================================================================


class TestResolveUser:
    def test_user_override_gewinnt_ueber_alles(self, resolver):
        r, db = resolver
        # Firefox waere normal "latest" (Default-Policy)
        db.set_user_override("Mozilla Firefox 121.0", "pinned")
        decision = r.resolve(_item(
            "Mozilla Firefox 121.0", "121.0", "Mozilla.Firefox"
        ))
        assert decision.channel == "pinned"
        assert decision.policy_source == "user"
        assert decision.confidence == 1.0
        assert "User-Override" in decision.reason


class TestResolveRuntimeForce:
    def test_runtime_force_fuer_redistributable(self, resolver):
        r, _ = resolver
        decision = r.resolve(_item(
            "Microsoft Visual C++ 2022 Redistributable (x64)",
            "14.50.0", None, "registry",
        ))
        assert decision.channel == "patch_only"
        assert decision.policy_source == "runtime_force"
        assert decision.confidence == 0.90
        assert "Runtime-Komponente erkannt" in decision.reason

    def test_runtime_force_fuer_directx(self, resolver):
        r, _ = resolver
        decision = r.resolve(_item(
            "DirectX for Windows", "9.29", None, "registry"
        ))
        assert decision.channel == "patch_only"
        assert decision.policy_source == "runtime_force"


class TestResolvePolicyMatch:
    def test_firefox_mit_winget_id_high_confidence(self, resolver):
        r, _ = resolver
        decision = r.resolve(_item(
            "Mozilla Firefox", "121.0", "Mozilla.Firefox"
        ))
        assert decision.channel == "latest"
        assert decision.policy_source == "policy"
        # winget-Id-Bonus: confidence >= 0.9
        assert decision.confidence >= 0.9
        assert "Policy-Match" in decision.reason
        assert "Mozilla.Firefox" in decision.reason

    def test_webview2_runtime_landet_auf_patch_only(self, resolver):
        r, _ = resolver
        decision = r.resolve(_item(
            "Microsoft Edge WebView2 Runtime",
            "121.0.2277.83",
            "Microsoft.EdgeWebView2Runtime",
        ))
        # WebView2 ist KEINE _RUNTIME_NOISE_TOKENS-Substring (nur
        # spezifische Phrasen wie "vc++"/"directx" etc) — daher
        # geht es ueber den normalen Policy-Match-Pfad und landet
        # via exact-match "microsoft edge webview2" auf patch_only.
        assert decision.channel == "patch_only"
        assert decision.policy_source == "policy"
        assert decision.confidence >= 0.9

    def test_substring_match_ohne_winget_id(self, resolver):
        r, _ = resolver
        decision = r.resolve(_item(
            "Mozilla Firefox 121.0",
            "121.0",
            winget_id=None,
            source="registry",
        ))
        assert decision.channel == "latest"
        assert decision.policy_source == "policy"
        # Ohne winget-Id: kein +0.10 Bonus, Reason ist "Substring-Match"
        assert "Substring-Match" in decision.reason


class TestResolveDefault:
    def test_unbekannte_app_default(self, resolver):
        r, _ = resolver
        decision = r.resolve(_item(
            "Some Unknown Tool", "1.0", winget_id=None, source="registry"
        ))
        assert decision.channel == "notify_only"
        assert decision.policy_source == "default"
        assert decision.confidence == 0.0
        assert "Kein Policy-Match" in decision.reason


# ===========================================================================
# Confidence-Heuristik
# ===========================================================================


class TestConfidence:
    def test_user_override_immer_1_0(self, resolver):
        r, db = resolver
        db.set_user_override("MyApp", "stable")
        d = r.resolve(_item("MyApp", "1.0"))
        assert d.confidence == 1.0

    def test_runtime_force_0_90(self, resolver):
        r, _ = resolver
        d = r.resolve(_item(
            "Microsoft Visual C++ Redistributable", "14.0",
        ))
        assert d.confidence == 0.90

    def test_policy_mit_winget_id_gedeckelt_bei_0_95(self, resolver):
        r, _ = resolver
        # Exact-Match → match_conf 0.9, +0.1 = 1.0, gedeckelt 0.95.
        d = r.resolve(_item(
            "Mozilla Firefox", "121.0", "Mozilla.Firefox"
        ))
        assert d.confidence <= 0.95

    def test_policy_ohne_winget_id_kein_bonus(self, resolver):
        r, _ = resolver
        d_ohne = r.resolve(_item(
            "Mozilla Firefox 121", "121", winget_id=None, source="registry"
        ))
        d_mit = r.resolve(_item(
            "Mozilla Firefox 121", "121", "Mozilla.Firefox", "winget"
        ))
        # Mit winget-Id ist Confidence systematisch >= ohne.
        assert d_mit.confidence >= d_ohne.confidence

    def test_default_0_0(self, resolver):
        r, _ = resolver
        d = r.resolve(_item("Random Unknown App"))
        assert d.confidence == 0.0


# ===========================================================================
# Reason
# ===========================================================================


class TestReason:
    def test_reason_immer_nicht_leer(self, resolver):
        r, db = resolver
        for item in [
            _item("Mozilla Firefox", "121", "Mozilla.Firefox"),
            _item("Microsoft Visual C++ Redistributable", "14.0"),
            _item("Random Unknown App", "1.0", source="registry"),
        ]:
            d = r.resolve(item)
            assert d.reason
            assert d.reason.strip()

        db.set_user_override("MyApp", "pinned")
        d = r.resolve(_item("MyApp"))
        assert d.reason

    def test_reason_enthaelt_channel(self, resolver):
        r, _ = resolver
        d = r.resolve(_item(
            "Mozilla Firefox", "121", "Mozilla.Firefox"
        ))
        assert d.channel in d.reason


# ===========================================================================
# CPE-Integration
# ===========================================================================


class TestCpeIntegration:
    def test_cpe_gefuellt_bei_winget_id(self, resolver):
        r, _ = resolver
        d = r.resolve(_item(
            "Mozilla Firefox", "121.0", "Mozilla.Firefox"
        ))
        assert d.cpe is not None
        assert d.cpe.startswith("cpe:2.3:a:mozilla:firefox:121.0")

    def test_cpe_none_bei_unbekannter_registry_app(self, resolver):
        r, _ = resolver
        d = r.resolve(_item(
            "Unknown Multi Token App", "1.0", winget_id=None, source="registry"
        ))
        assert d.cpe is None


# ===========================================================================
# normalized_name
# ===========================================================================


class TestNormalizedName:
    def test_normalized_name_korrekt_gesetzt(self, resolver):
        r, _ = resolver
        d = r.resolve(_item(
            "Python 3.12.0 (64-bit)", "3.12.0", "Python.Python.3.12"
        ))
        assert d.normalized_name == "python"


# ===========================================================================
# resolve_batch
# ===========================================================================


class TestResolveBatch:
    def test_leere_liste_gibt_leere_liste(self, resolver):
        r, _ = resolver
        assert r.resolve_batch([]) == []

    def test_gemischte_items_werden_alle_entschieden(self, resolver):
        r, _ = resolver
        items = [
            _item("Mozilla Firefox", "121", "Mozilla.Firefox"),
            _item("Python", "3.12.0", "Python.Python.3.12"),
            _item("Random Unknown App", "1.0", source="registry"),
        ]
        decisions = r.resolve_batch(items)
        assert len(decisions) == 3
        assert decisions[0].channel == "latest"
        assert decisions[1].channel == "patch_only"
        assert decisions[2].channel == "notify_only"

    def test_reihenfolge_bleibt_erhalten(self, resolver):
        r, _ = resolver
        items = [_item(f"App {i}", "1.0") for i in range(5)]
        decisions = r.resolve_batch(items)
        for i, d in enumerate(decisions):
            assert d.item.name == f"App {i}"


# ===========================================================================
# Fail-Open: Exception → default-Decision
# ===========================================================================


class TestFailOpen:
    def test_resolver_crashet_nicht_bei_kaputter_db(
        self, resolver, monkeypatch
    ):
        r, db = resolver

        # PolicyDB.get auf Exception zwingen
        def boom(name: str):
            raise RuntimeError("DB is on fire")

        monkeypatch.setattr(db, "get", boom)
        d = r.resolve(_item("Mozilla Firefox", "121", "Mozilla.Firefox"))
        # Statt Crash → default-Decision
        assert d.channel == "notify_only"
        assert d.policy_source == "default"
        assert d.confidence == 0.0
        assert "Resolver-Fehler" in d.reason
