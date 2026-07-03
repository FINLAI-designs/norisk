"""
apply_plan — Plan-Binding fuer den elevated Apply-Round-Trip (R5).

Sicherheits-Kern der Trust-Boundary: die GUI ist NICHT vertrauenswuerdig. Der
bestaetigte Plan wird an EINEN elevated Lauf gebunden:
- ``token``: Single-Use-uuid4 (vom Caller erzeugt; Plan-Datei wird nach dem
  Lesen geloescht → Replay-Schutz).
- ``hmac``: HMAC-SHA256 ueber token + sortierte Tweak-IDs + Katalog-Signatur,
  Schluessel = prozess-uebergreifendes Geheimnis (DEK aus dem Key-Manager).

Der elevated Prozess lehnt jeden Plan ab, dessen HMAC nicht passt, dessen Token
schon verbraucht ist, oder dessen Tweak-IDs nicht im **signierten** Katalog
stehen (Re-Resolve gegen den Katalog passiert im Orchestrator).

Reine Logik (stdlib ``hmac``) — der Secret wird injiziert (Tests) bzw. vom
Key-Manager geholt (Produktion). Kein I/O hier.

Schichtzugehoerigkeit: application/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

_HMAC_FIELD = "hmac"


@dataclass(frozen=True, slots=True)
class BoundPlan:
    """Serialisierbarer, an einen elevated Lauf gebundener Plan."""

    token: str
    tweak_ids: tuple[str, ...]
    catalog_sig: str
    hmac_hex: str

    def to_dict(self) -> dict[str, object]:
        return {
            "token": self.token,
            "tweak_ids": list(self.tweak_ids),
            "catalog_sig": self.catalog_sig,
            _HMAC_FIELD: self.hmac_hex,
        }


def _compute_hmac(
    token: str, tweak_ids: tuple[str, ...], catalog_sig: str, secret: bytes
) -> str:
    """HMAC-SHA256 ueber token + sortierte IDs + Katalog-Signatur."""
    payload = "\n".join([token, *sorted(tweak_ids), catalog_sig]).encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def bind_plan(
    token: str,
    tweak_ids: list[str],
    catalog_sig: str,
    *,
    secret: bytes,
) -> BoundPlan:
    """Bindet einen bestaetigten Plan an den Lauf (GUI-Seite)."""
    ids = tuple(tweak_ids)
    return BoundPlan(
        token=token,
        tweak_ids=ids,
        catalog_sig=catalog_sig,
        hmac_hex=_compute_hmac(token, ids, catalog_sig, secret),
    )


def verify_plan(
    payload: dict[str, object],
    *,
    secret: bytes,
    expected_catalog_sig: str,
    used_tokens: frozenset[str] = frozenset(),
) -> list[str] | None:
    """Verifiziert einen Plan im elevated Prozess (fail-closed).

    Returns:
        Liste der Tweak-IDs bei gueltigem Plan; ``None`` bei jedem Defekt
        (HMAC-Mismatch, verbrauchter Token, falsche/fehlende Katalog-Signatur,
        Schema-Fehler).
    """
    token = payload.get("token")
    raw_ids = payload.get("tweak_ids")
    catalog_sig = payload.get("catalog_sig")
    given_hmac = payload.get(_HMAC_FIELD)
    if not isinstance(token, str) or not isinstance(raw_ids, list):
        return None
    if not isinstance(catalog_sig, str) or not isinstance(given_hmac, str):
        return None
    if token in used_tokens:
        return None
    # Der elevated Lauf akzeptiert nur den aktuell signierten Katalog.
    if not hmac.compare_digest(catalog_sig, expected_catalog_sig):
        return None
    ids = tuple(str(i) for i in raw_ids)
    expected = _compute_hmac(token, ids, catalog_sig, secret)
    if not hmac.compare_digest(given_hmac, expected):
        return None
    return list(ids)
