"""
edition_gate — Windows-Edition erkennen + Telemetrie-Ehrlichkeit (R4).

Microsoft (policy-csp-system): ``AllowTelemetry=0`` ("Aus") wirkt NUR auf
Enterprise/Education/IoT/Server. Auf **Pro/Home wird ein gesetztes 0 als 1
behandelt**. Der Edition-Gate erkennt die SKU (read-only Registry) und liefert
eine ehrliche Klartext-Aussage — der Differentiator gegenueber jedem Debloater.

Schichtzugehoerigkeit: application/ (nutzt den read-only core-Probe-Port).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re

from core.logger import get_logger
from core.probes.hardening_probe import HIVE_HKLM, IHardeningProbe
from tools.system_tuner.domain.scan_entities import EditionInfo

log = get_logger(__name__)

_CV_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

#: Edition-Marker (lowercase-Substring in EditionID), bei denen
#: ``AllowTelemetry=0`` tatsaechlich greift.
_TELEMETRY_ZERO_MARKERS: tuple[str, ...] = (
    "enterprise",
    "education",
    "iot",
    "server",
)


#: Ab diesem CurrentBuild ist es Windows 11 — die Registry-``ProductName``
#: meldet aber weiterhin "Windows 10" (Microsoft hat den Wert nie aktualisiert).
_WIN11_MIN_BUILD = 22000


def _normalize_product(product: str | None, current_build: str | None) -> str | None:
    """Korrigiert "Windows 10" → "Windows 11", wenn der Build es verraet.

    ``ProductName`` bleibt auf Windows-11-Systemen bei "Windows 10 …" stehen;
    nur ``CurrentBuild >= 22000`` unterscheidet die Generationen zuverlaessig.
    Ist der Build unbekannt/nicht parsebar, bleibt ``product`` unveraendert
    (fail-soft — keine falsche Korrektur).
    """
    if not product or "windows 10" not in product.lower():
        return product
    try:
        build = int((current_build or "").strip())
    except (ValueError, TypeError):
        return product
    if build >= _WIN11_MIN_BUILD:
        return re.sub(r"(?i)windows 10", "Windows 11", product)
    return product


def _telemetry_zero_supported(edition_id: str | None) -> bool:
    """``True`` wenn die Edition die Stufe 'Aus (0)' technisch zulaesst."""
    if not edition_id:
        return False
    low = edition_id.lower()
    return any(marker in low for marker in _TELEMETRY_ZERO_MARKERS)


def _banner(edition_id: str | None, product: str | None, supported: bool) -> str:
    """Baut die Laien-taugliche Edition-Klartext-Aussage."""
    label = product or edition_id
    if edition_id is None:
        return (
            "Windows-Edition konnte nicht ermittelt werden. Vorsichtshalber wird "
            "'Telemetrie aus (0)' NICHT als erreichbar angenommen."
        )
    if supported:
        return (
            f"Ihre Edition ({label}) erlaubt die strengste Telemetrie-Stufe "
            "'Aus (0)'."
        )
    return (
        f"Sie nutzen {label}. Die strengste von Microsoft erlaubte Telemetrie-"
        "Stufe ist hier 'Erforderlich (1)' — 'Aus (0)' verlangt Enterprise/"
        "Education. Tools, die auf Ihrer Edition 'telemetriefrei' versprechen, "
        "sagen die Unwahrheit."
    )


class EditionGate:
    """Erkennt die Windows-Edition und leitet die Telemetrie-Ehrlichkeit ab."""

    def __init__(self, probe: IHardeningProbe) -> None:
        self._probe = probe

    def detect(self) -> EditionInfo:
        """Liest EditionID/ProductName (read-only) und baut:class:`EditionInfo`."""
        if not self._probe.is_available():
            return EditionInfo(
                edition_id=None,
                product_name=None,
                telemetry_zero_supported=False,
                banner_de=_banner(None, None, False),
            )
        edition_id = self._probe.read_registry_value(HIVE_HKLM, _CV_KEY, "EditionID")
        raw_product = self._probe.read_registry_value(HIVE_HKLM, _CV_KEY, "ProductName")
        current_build = self._probe.read_registry_value(
            HIVE_HKLM, _CV_KEY, "CurrentBuild"
        )
        product = _normalize_product(raw_product, current_build)
        supported = _telemetry_zero_supported(edition_id)
        return EditionInfo(
            edition_id=edition_id,
            product_name=product,
            telemetry_zero_supported=supported,
            banner_de=_banner(edition_id, product, supported),
        )
