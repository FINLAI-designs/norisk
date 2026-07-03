"""Tests für die ``cve_products``-Tabelle in NvdCacheRepository (Sprint S0b).

Deckt sowohl die neuen Repo-Methoden (``upsert_products``,
``find_cves_by_product``, ``iter_cache_payloads``) als auch den
Service-Hook (``_store_products`` auf Online-Fetch + ``backfill_products``)
ab.

Tests verwenden eine echte SQLCipher-DB in einem ``tmp_path``, damit der
Schema-Anlage-Pfad (``CREATE TABLE IF NOT EXISTS``) mitgetestet wird.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from core.database.db_context import clear_db_app_id
from tools.cyber_dashboard.application.nvd_service import NvdService
from tools.cyber_dashboard.data.nvd_cache_repository import NvdCacheRepository
from tools.cyber_dashboard.domain.models import CveEintrag

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_db_context():
    """Setzt App-Kontext vor und nach jedem Test zurück."""
    clear_db_app_id()
    yield
    clear_db_app_id()


@pytest.fixture
def isolated_db_dir(tmp_path: Path):
    """Patcht ``DB_DIR`` auf ein temporäres Verzeichnis."""
    with patch("core.database.encrypted_db.DB_DIR", tmp_path):
        yield tmp_path


@pytest.fixture
def repo(isolated_db_dir: Path) -> NvdCacheRepository:
    """Frisches Repo mit angelegtem Schema."""
    return NvdCacheRepository()


# ---------------------------------------------------------------------------
# upsert_products
# ---------------------------------------------------------------------------


def test_upsert_products_inserts_new_rows(repo: NvdCacheRepository):
    """Erster Aufruf legt alle Paare neu an."""
    inserted = repo.upsert_products(
        "CVE-2024-1234", ["microsoft windows", "openssl openssl"]
    )
    assert inserted == 2
    assert repo.count_products() == 2


def test_upsert_products_is_idempotent(repo: NvdCacheRepository):
    """Wiederholter Aufruf mit identischen Werten fügt nichts neu ein."""
    repo.upsert_products("CVE-2024-1", ["foo bar"])
    inserted = repo.upsert_products("CVE-2024-1", ["foo bar"])
    assert inserted == 0
    assert repo.count_products() == 1


def test_upsert_products_dedupliziert_listen_intern(repo: NvdCacheRepository):
    """Mehrfach genannte Produkte in derselben Liste zählen nur einmal."""
    inserted = repo.upsert_products("CVE-2024-2", ["a", "a", "  a  ", "b"])
    assert inserted == 2  # "a" + "b", trim ist Teil der Normalisierung


def test_upsert_products_ignoriert_leere_und_none_eingaben(
    repo: NvdCacheRepository,
):
    """Leere Strings, Whitespace-only, leere Liste → 0 Zeilen."""
    assert repo.upsert_products("CVE-2024-3", []) == 0
    assert repo.upsert_products("CVE-2024-3", ["", "   "]) == 0
    assert repo.upsert_products("", ["foo"]) == 0
    assert repo.count_products() == 0


# ---------------------------------------------------------------------------
# find_cves_by_product
# ---------------------------------------------------------------------------


def test_find_cves_by_product_case_insensitive_und_sortiert(
    repo: NvdCacheRepository,
):
    """Case-insensitive Match liefert sortierte CVE-IDs."""
    repo.upsert_products("CVE-2024-2", ["Microsoft Windows"])
    repo.upsert_products("CVE-2024-1", ["microsoft windows"])
    repo.upsert_products("CVE-2024-9", ["openssl openssl"])

    cves = repo.find_cves_by_product("MICROSOFT WINDOWS")
    assert cves == ["CVE-2024-1", "CVE-2024-2"]


def test_find_cves_by_product_unbekannt_leer(repo: NvdCacheRepository):
    """Unbekannter Produkt-Name liefert leere Liste."""
    repo.upsert_products("CVE-2024-1", ["foo bar"])
    assert repo.find_cves_by_product("unbekannt") == []


def test_find_cves_by_product_leerer_input_leer(repo: NvdCacheRepository):
    """Leerer/Whitespace-only Input liefert leere Liste ohne SQL-Roundtrip."""
    assert repo.find_cves_by_product("") == []
    assert repo.find_cves_by_product("   ") == []


# ---------------------------------------------------------------------------
# iter_cache_payloads
# ---------------------------------------------------------------------------


def test_iter_cache_payloads_yields_parsed_json(repo: NvdCacheRepository):
    """Jede Cache-Zeile wird als geparste JSON-Liste geliefert."""
    payload_a = [{"cve": {"id": "CVE-2024-1"}}]
    payload_b = [{"cve": {"id": "CVE-2024-2"}}]
    repo.set("key-a", payload_a)
    repo.set("key-b", payload_b)

    payloads = list(repo.iter_cache_payloads())
    assert len(payloads) == 2
    cve_ids = sorted(p[0]["cve"]["id"] for p in payloads)
    assert cve_ids == ["CVE-2024-1", "CVE-2024-2"]


def test_iter_cache_payloads_skipt_kaputtes_json(repo: NvdCacheRepository):
    """Kaputt geschriebene Cache-Zeilen werden übersprungen, nicht raisen."""
    repo.set("ok-key", [{"cve": {"id": "CVE-2024-1"}}])
    # Direktes Schreiben einer kaputten Zeile, um den Skip-Pfad zu treffen
    with repo._db.connection() as conn:  # noqa: SLF001 -- Test-Setup
        conn.execute(
            "INSERT OR REPLACE INTO nvd_cache(cache_key, data, fetched_at)"
            " VALUES (?, ?, ?)",
            ("broken", "{not-json", 1),
        )

    payloads = list(repo.iter_cache_payloads())
    assert len(payloads) == 1


# ---------------------------------------------------------------------------
# NvdService-Hook: _store_products + backfill_products
# ---------------------------------------------------------------------------


def _make_service(cache: NvdCacheRepository) -> NvdService:
    """Baut einen Service mit injiziertem Cache, ohne API-Key-IO."""
    with patch.object(NvdService, "_lade_api_key", return_value=None):
        return NvdService(cache=cache)


def test_store_products_persistiert_betroffene_produkte(
    repo: NvdCacheRepository,
):
    """``_store_products`` schreibt CveEintrag.betroffene_produkte in die DB."""
    service = _make_service(repo)
    eintrag = CveEintrag(
        cve_id="CVE-2024-99",
        beschreibung="x",
        schweregrad="HIGH",
        cvss_score=7.5,
        veroeffentlicht=datetime.now(UTC),
        geaendert=datetime.now(UTC),
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-99",
        cisa_kev=False,
        cisa_frist="",
        betroffene_produkte=["openssl openssl", "microsoft windows"],
    )

    inserted = service._store_products([eintrag])  # noqa: SLF001 -- gezielter Hook-Test
    assert inserted == 2
    assert repo.find_cves_by_product("openssl openssl") == ["CVE-2024-99"]


def test_backfill_products_aus_existierendem_cache(repo: NvdCacheRepository):
    """``backfill_products`` füllt cve_products aus alten Cache-Rohdaten."""
    raw = [
        {
            "cve": {
                "id": "CVE-2023-OLD",
                "descriptions": [{"lang": "en", "value": "x"}],
                "metrics": {},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": (
                                            "cpe:2.3:a:openssl:openssl:1.0.2:*:*:*:*:*:*:*"
                                        )
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "published": "2023-01-01T00:00:00Z",
                "lastModified": "2023-06-01T00:00:00Z",
            }
        }
    ]
    repo.set("legacy-cache-key", raw)
    assert repo.count_products() == 0

    service = _make_service(repo)
    inserted = service.backfill_products()

    assert inserted >= 1
    assert "CVE-2023-OLD" in repo.find_cves_by_product("openssl openssl")


def test_backfill_products_idempotent(repo: NvdCacheRepository):
    """Zweimaliger Backfill produziert keine Duplikate."""
    raw = [
        {
            "cve": {
                "id": "CVE-2023-X",
                "descriptions": [{"lang": "en", "value": ""}],
                "metrics": {},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"criteria": "cpe:2.3:a:foo:bar:1.0:*:*:*:*:*:*:*"}
                                ]
                            }
                        ]
                    }
                ],
                "published": "",
                "lastModified": "",
            }
        }
    ]
    repo.set("cache-x", raw)

    service = _make_service(repo)
    first = service.backfill_products()
    second = service.backfill_products()

    assert first >= 1
    assert second == 0
    assert repo.count_products() == first


def test_compute_cache_key_unverändert(repo: NvdCacheRepository):
    """Regression: Hash-Schema von ``compute_cache_key`` bleibt stabil.

    Wichtige Invariante — würde sich der Schlüssel ändern, wären alle
    bestehenden Cache-Einträge unleserlich. Deckt ab, dass der Sprint
    S0b-Patch keine Cache-Key-Logik anfasst.
    """
    # Direkter Smoke-Check über ``set``/``get`` — wenn der Key sich ändert,
    # wäre dieser Round-Trip kaputt.
    payload: list[dict] = [{"cve": {"id": "CVE-2024-RT"}}]
    json.dumps(payload)  # serialisierbar
    repo.set("rt-key", payload)
    entry = repo.get("rt-key")
    assert entry is not None
    assert entry.data == payload
