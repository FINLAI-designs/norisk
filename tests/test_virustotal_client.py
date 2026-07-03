"""
test_virustotal_client.

Tests fuer den VT-Hash-Lookup. Wir mocken ``httpx.get`` damit der
Test keinen Netzwerk-Call macht und auch ohne API-Key oder VT-
Service-Verfuegbarkeit grun ist.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from core.security import virustotal_client
from core.security.virustotal_client import (
    VtResult,
    has_api_key,
    lookup_hash,
)

_GOOD_HASH = "a" * 64


def test_invalider_hash_liefert_error() -> None:
    result = lookup_hash("zu_kurz")
    assert result.status == "error"
    assert "Hash" in result.message


def test_kein_key_liefert_key_missing(monkeypatch) -> None:
    monkeypatch.setattr(virustotal_client, "_load_api_key", lambda: None)
    result = lookup_hash(_GOOD_HASH)
    assert result.status == "key_missing"
    assert "API-Key" in result.message


def test_has_api_key_true_wenn_storage_liefert(monkeypatch) -> None:
    monkeypatch.setattr(virustotal_client, "_load_api_key", lambda: "deadbeef")
    assert has_api_key() is True


def test_has_api_key_false_wenn_storage_leer(monkeypatch) -> None:
    monkeypatch.setattr(virustotal_client, "_load_api_key", lambda: None)
    assert has_api_key() is False


class _FakeResponse:
    def __init__(self, status_code: int, body: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._body = body or {}

    def json(self) -> dict[str, Any]:
        return self._body


def test_clean_hash(monkeypatch) -> None:
    monkeypatch.setattr(virustotal_client, "_load_api_key", lambda: "key")
    fake_body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 70,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 4,
                }
            }
        }
    }
    with patch("httpx.get", return_value=_FakeResponse(200, fake_body)):
        result = lookup_hash(_GOOD_HASH)
    assert result.status == "clean"
    assert result.harmless == 70
    assert result.malicious == 0
    assert "virustotal.com/gui/file" in result.permalink


def test_malicious_hash(monkeypatch) -> None:
    monkeypatch.setattr(virustotal_client, "_load_api_key", lambda: "key")
    fake_body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 5,
                    "malicious": 30,
                    "suspicious": 2,
                    "undetected": 10,
                }
            }
        }
    }
    with patch("httpx.get", return_value=_FakeResponse(200, fake_body)):
        result = lookup_hash(_GOOD_HASH)
    assert result.status == "malicious"
    assert result.malicious == 30
    assert "30" in result.message


def test_404_liefert_unknown(monkeypatch) -> None:
    monkeypatch.setattr(virustotal_client, "_load_api_key", lambda: "key")
    with patch("httpx.get", return_value=_FakeResponse(404)):
        result = lookup_hash(_GOOD_HASH)
    assert result.status == "unknown"
    assert "unbekannt" in result.message.lower()


def test_401_liefert_error_mit_key_hinweis(monkeypatch) -> None:
    monkeypatch.setattr(virustotal_client, "_load_api_key", lambda: "key")
    with patch("httpx.get", return_value=_FakeResponse(401)):
        result = lookup_hash(_GOOD_HASH)
    assert result.status == "error"
    assert "401" in result.message


def test_rate_limit_429(monkeypatch) -> None:
    monkeypatch.setattr(virustotal_client, "_load_api_key", lambda: "key")
    with patch("httpx.get", return_value=_FakeResponse(429)):
        result = lookup_hash(_GOOD_HASH)
    assert result.status == "error"
    assert "Rate-Limit" in result.message


def test_vtresult_dataclass_default() -> None:
    """Default-Konstruktor laesst alle Counter auf 0."""
    r = VtResult(status="clean")
    assert r.malicious == 0
    assert r.suspicious == 0
    assert r.harmless == 0
    assert r.undetected == 0
