"""test_nvd_circuit_breaker/.

Der NVD-API-Key wird beim Speichern UND Laden getrimmt (Copy-Paste-
Whitespace fuehrte sonst zu 403 'ungueltiger Key', obwohl der Key korrekt ist).

Circuit-Breaker. Nach ``_CIRCUIT_THRESHOLD`` aufeinanderfolgenden
Fehlversuchen stellt der Service automatische HINTERGRUND-Abrufe ein (kein
weiterer Timeout-Lauf), liefert aus dem Cache und setzt Status CIRCUIT_OPEN.
Erfolg / neuer API-Key / reset_circuit schliessen die Leitung; User-Suchen
(retry_on_timeout=True) duerfen sie trotz offenem Circuit testen.

Author: Patrick Riederich
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from tools.cyber_dashboard.application.nvd_service import (
    _CIRCUIT_THRESHOLD,
    NvdService,
    NvdStatus,
)

_HTTP = "tools.cyber_dashboard.application.nvd_service.get_http_client"


def _ok_response() -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = {"vulnerabilities": []}
    resp.raise_for_status.return_value = None
    return resp


def _service_no_cache() -> NvdService:
    cache = MagicMock()
    cache.get.return_value = None
    svc = NvdService(cache=cache)
    svc._api_key = "test-key"  # noqa: SLF001
    return svc


# ---------------------------------------------------------------------------
# API-Key-Trim
# ---------------------------------------------------------------------------


def test_setze_api_key_trimmt_whitespace_und_reset_circuit() -> None:
    svc = NvdService(cache=MagicMock())
    storage = MagicMock()
    svc._storage = storage  # noqa: SLF001
    svc._consecutive_failures = 5  # noqa: SLF001 — Circuit offen

    svc.setze_api_key("  abc-123-def  \n")

    storage.set.assert_called_once_with("nvd_api_key", "abc-123-def")
    assert svc._api_key == "abc-123-def"  # noqa: SLF001
    assert svc.circuit_open is False  # neuer Key -> Circuit zu


def test_lade_api_key_trimmt_und_leer_wird_none() -> None:
    svc = NvdService(cache=MagicMock())
    storage = MagicMock()
    svc._storage = storage  # noqa: SLF001

    storage.get.return_value = "  key-mit-rand  "
    assert svc._lade_api_key() == "key-mit-rand"  # noqa: SLF001

    storage.get.return_value = "   "
    assert svc._lade_api_key() is None  # noqa: SLF001 — nur Whitespace -> None


# ---------------------------------------------------------------------------
# Circuit-Breaker
# ---------------------------------------------------------------------------


def test_circuit_oeffnet_nach_schwelle_und_stoppt_hintergrund_abrufe() -> None:
    svc = _service_no_cache()
    with patch(_HTTP) as mc:
        mc.return_value.get.side_effect = requests.Timeout("timeout")
        for _ in range(_CIRCUIT_THRESHOLD):
            svc.lade_neueste_cves(tage=7)
        assert svc.circuit_open is True
        assert svc.last_status == NvdStatus.OFFLINE_NO_CACHE

        # Naechster HINTERGRUND-Abruf: Circuit offen -> KEIN weiterer Netz-Call.
        calls_before = mc.return_value.get.call_count
        svc.lade_neueste_cves(tage=7)
        assert mc.return_value.get.call_count == calls_before
        assert svc.last_status == NvdStatus.CIRCUIT_OPEN
        assert svc.is_offline() is True


def test_erfolg_schliesst_circuit() -> None:
    svc = _service_no_cache()
    with patch(_HTTP) as mc:
        mc.return_value.get.side_effect = requests.Timeout("timeout")
        for _ in range(_CIRCUIT_THRESHOLD - 1):
            svc.lade_neueste_cves(tage=7)
        assert svc.circuit_open is False
        # Erfolgreicher Abruf setzt den Fehler-Zaehler zurueck.
        mc.return_value.get.side_effect = None
        mc.return_value.get.return_value = _ok_response()
        svc.lade_neueste_cves(tage=7)
        assert svc._consecutive_failures == 0  # noqa: SLF001
        assert svc.circuit_open is False
        assert svc.last_status == NvdStatus.ONLINE


def test_reset_circuit_schliesst_leitung() -> None:
    svc = _service_no_cache()
    svc._consecutive_failures = _CIRCUIT_THRESHOLD + 2  # noqa: SLF001
    assert svc.circuit_open is True
    svc.reset_circuit()
    assert svc.circuit_open is False


def test_user_suche_umgeht_offenen_circuit() -> None:
    svc = _service_no_cache()
    svc._consecutive_failures = _CIRCUIT_THRESHOLD  # noqa: SLF001 — Circuit offen
    with patch(_HTTP) as mc:
        mc.return_value.get.return_value = _ok_response()
        svc.suche_produkt("nginx", tage=30)  # User-Aktion, retry_on_timeout=True
        # Trotz offenem Circuit wurde NVD angefragt (Half-Open)...
        assert mc.return_value.get.called
        #... und der Erfolg hat die Leitung wieder geschlossen.
        assert svc.circuit_open is False
        assert svc.last_status == NvdStatus.ONLINE
