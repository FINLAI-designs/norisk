"""
sovereignty_scanner — Auto-Detection von Cloud-Providern fuer den
Datensouveraenitaets-Audit.

Drei Quellen werden kombiniert:

1. **DNS-MX-Lookup** der eingegebenen Kanzlei-Domain via ``dnspython``.
   Wir mappen die MX-Hostnames auf den Provider-Catalog.
2. **SPF/TXT-Lookup** — der ``v=spf1``-Record listet typischerweise
   ``include:spf.protection.outlook.com`` etc.; jedes ``include`` wird
   gegen den Catalog gematcht.
3. **Installed-Software-Scan** ueber Windows-Registry-Uninstall-Keys
   (analog ``BackupDetector``). Sucht nach Cloud-Clients (OneDrive,
   Google Drive, Dropbox, Teams, Zoom, Slack-Desktop, GitHub-Desktop).

Patrick-Direktive 2026-05-15: nur DNS + MX + Software. Keine
Browser-History, kein Outlook-Profil-Scan (das gehoert in spaetere
Iter falls noetig).

Schichtzugehoerigkeit: application/ — darf domain + core + dnspython.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass

from core.feed_settings import OFFLINE_HINT, external_fetches_allowed
from core.logger import get_logger
from core.tech_stack.resolver import get_own_tech_stack_names
from tools.customer_audit.application.provider_catalog import (
    CloudProvider,
    find_by_keyword,
)
from tools.customer_audit.domain.entities import DetectedProvider

_log = get_logger(__name__)

#: Software-Display-Name-Marker (lowercase) fuer den Installed-Apps-
#: Scan. Werden gegen ``DisplayName`` aus den Uninstall-Registry-Keys
#: gematcht und an ``provider_catalog.find_by_keyword`` weitergereicht.
_SOFTWARE_MARKERS: tuple[str, ...] = (
    "onedrive",
    "microsoft teams",
    "outlook",
    "office 365",
    "google drive",
    "google chrome",  # nur als Indiz fuer Google-Bindung
    "dropbox",
    "icloud",
    "zoom",
    "slack",
    "github desktop",
    "adobe creative cloud",
    "atlassian",
)

_SPF_INCLUDE_RE = re.compile(r"include:([^\s\"]+)", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)

# DoS-Hard-Caps gegen feindliche/fehlkonfigurierte DNS-Server.
# Legitime SPF/MX-Setups passen in diese Grenzen.
_MAX_MX_RECORDS = 20
_MAX_TXT_RECORDS = 20
_MAX_TXT_BYTES = 4096
_MAX_INCLUDES = 20
_MAX_HOSTNAME_LEN = 253


@dataclass
class ScanReport:
    """Sammel-Ergebnis des Scanners."""

    detected: list[DetectedProvider]
    errors: list[str]


def _provider_to_detected(p: CloudProvider, via: str, evidence: str) -> DetectedProvider:
    return DetectedProvider(
        name=p.name,
        status=p.status,
        category=p.category,
        via=via,
        evidence=evidence,
        legal_entity_country=p.legal_entity_country,
        parent_country=p.parent_country,
        residual_risk_note=p.residual_risk_note,
    )


def is_valid_domain(s: str) -> bool:
    """True wenn der String wie eine Domain aussieht (RFC-konform-ish)."""
    return bool(_DOMAIN_RE.match(s.strip()))


class SovereigntyScanner:
    """Hauptklasse fuer den Datensouveraenitaets-Scan."""

    def scan(
        self,
        *,
        enabled: bool,
        domain: str = "",
        timeout_seconds: float = 5.0,
    ) -> ScanReport:
        """Fuehrt alle drei Sub-Scans (DNS, SPF, Software) aus.

        Args:
            enabled: User-Flag — bei ``False`` wird gar nichts
                gescannt, leeres Result. Patrick-Direktive: optional.
            domain: Kanzlei-Domain (mit oder ohne Subdomain).
                Wenn leer, werden DNS+SPF uebersprungen.
            timeout_seconds: DNS-Timeout je Lookup.

        Returns:
:class:`ScanReport` mit deduplizierten Providern.
        """
        if not enabled:
            return ScanReport(detected=[], errors=[])

        if not external_fetches_allowed():
            return ScanReport(detected=[], errors=[OFFLINE_HINT])

        detected_by_name: dict[str, DetectedProvider] = {}
        errors: list[str] = []

        if domain:
            d = domain.strip()
            if not is_valid_domain(d):
                errors.append(
                    f"'{d}' sieht nicht wie eine Domain aus — DNS/SPF "
                    "uebersprungen."
                )
            else:
                self._scan_dns_mx(d, detected_by_name, errors, timeout_seconds)
                self._scan_spf(d, detected_by_name, errors, timeout_seconds)

        self._scan_software(detected_by_name, errors)
        self._scan_tech_stack(detected_by_name, errors)

        return ScanReport(
            detected=list(detected_by_name.values()),
            errors=errors,
        )

    # ------------------------------------------------------------------

    def _scan_dns_mx(
        self,
        domain: str,
        out: dict[str, DetectedProvider],
        errors: list[str],
        timeout: float,
    ) -> None:
        try:
            import dns.resolver  # noqa: PLC0415

            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            answers = resolver.resolve(domain, "MX")
        except Exception as exc:  # noqa: BLE001 -- dnspython kann diverse Fehler werfen
            errors.append(
                f"DNS-MX-Lookup fuer '{domain}' fehlgeschlagen: "
                f"{type(exc).__name__}"
            )
            return

        # DoS-Hard-Cap: maliziöse oder fehlkonfigurierte DNS-Server koennen
        # 100+ MX-Eintraege liefern. 20 reicht fuer jedes legitime Setup.
        for rdata in list(answers)[:_MAX_MX_RECORDS]:
            mx_host = str(getattr(rdata, "exchange", "")).rstrip(".")
            if not mx_host or len(mx_host) > _MAX_HOSTNAME_LEN:
                continue
            provider = find_by_keyword(mx_host)
            if provider is None:
                continue
            out.setdefault(
                provider.name,
                _provider_to_detected(provider, via="dns_mx", evidence=mx_host),
            )

    def _scan_spf(
        self,
        domain: str,
        out: dict[str, DetectedProvider],
        errors: list[str],
        timeout: float,
    ) -> None:
        try:
            import dns.resolver  # noqa: PLC0415

            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            answers = resolver.resolve(domain, "TXT")
        except Exception as exc:  # noqa: BLE001
            errors.append(
                f"DNS-TXT-Lookup fuer '{domain}' fehlgeschlagen: "
                f"{type(exc).__name__}"
            )
            return

        for rdata in list(answers)[:_MAX_TXT_RECORDS]:
            try:
                raw = b"".join(rdata.strings)
            except Exception:  # noqa: BLE001
                continue
            # Hard-Cap: legitimes SPF passt in <2 KB; alles darueber ist
            # entweder Mis-Config oder DoS-Versuch.
            if len(raw) > _MAX_TXT_BYTES:
                errors.append(
                    f"DNS-TXT-Record fuer '{domain}' uebersprungen "
                    f"(>{_MAX_TXT_BYTES} Bytes)."
                )
                continue
            txt = raw.decode("utf-8", errors="ignore")
            if "v=spf1" not in txt.lower():
                continue
            for include_host in _SPF_INCLUDE_RE.findall(txt)[:_MAX_INCLUDES]:
                if len(include_host) > _MAX_HOSTNAME_LEN:
                    continue
                provider = find_by_keyword(include_host)
                if provider is None:
                    continue
                out.setdefault(
                    provider.name,
                    _provider_to_detected(
                        provider, via="spf", evidence=include_host
                    ),
                )

    def _scan_software(
        self,
        out: dict[str, DetectedProvider],
        errors: list[str],
    ) -> None:
        if platform.system().lower() != "windows":
            return
        try:
            self._scan_windows_uninstall(out)
        except Exception as exc:  # noqa: BLE001 -- Registry-Scan darf nie crashen
            errors.append(f"Software-Scan fehlgeschlagen: {type(exc).__name__}")

    def _scan_tech_stack(
        self,
        out: dict[str, DetectedProvider],
        errors: list[str],
    ) -> None:
        """Gleicht den erfassten eigenen Tech-Stack gegen den Provider-Catalog.

        Der User erwartet, dass die im ``security_scoring`` erfassten eigenen
        Dienste (z. B. Dropbox, Mullvad) auch in der Souveraenitaets-Auto-
        Erkennung auftauchen — der Registry-Scan allein erfasst sie nicht. Cross-
        Tool LAZY ueber den core-Resolver, kein tool->tool-Import).
        ``out.setdefault`` -> ein bereits per DNS/SPF/Software erkannter Provider
        wird nicht ueberschrieben (jene Quellen sind spezifischer).
        """
        try:
            names = get_own_tech_stack_names()
        except Exception as exc:  # noqa: BLE001 -- Cross-Tool-Lesen darf nie crashen
            errors.append(f"Tech-Stack-Abgleich fehlgeschlagen: {type(exc).__name__}")
            return
        for raw in names:
            provider = find_by_keyword(raw.lower())
            if provider is None:
                continue
            out.setdefault(
                provider.name,
                _provider_to_detected(provider, via="tech_stack", evidence=raw),
            )

    def _scan_windows_uninstall(
        self, out: dict[str, DetectedProvider]
    ) -> None:
        import winreg  # noqa: PLC0415

        roots = (
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
        )
        for hive, subkey in roots:
            try:
                key = winreg.OpenKey(hive, subkey)
            except FileNotFoundError:
                continue
            with key:
                count = winreg.QueryInfoKey(key)[0]
                for i in range(count):
                    try:
                        sub_name = winreg.EnumKey(key, i)
                    except OSError:
                        continue
                    try:
                        with winreg.OpenKey(key, sub_name) as sub_h:
                            try:
                                display_name = winreg.QueryValueEx(
                                    sub_h, "DisplayName"
                                )[0]
                            except FileNotFoundError:
                                continue
                    except OSError:
                        continue
                    name_lower = str(display_name).lower()
                    matched_marker = next(
                        (m for m in _SOFTWARE_MARKERS if m in name_lower), None
                    )
                    if matched_marker is None:
                        continue
                    provider = find_by_keyword(name_lower)
                    if provider is None:
                        continue
                    out.setdefault(
                        provider.name,
                        _provider_to_detected(
                            provider, via="software", evidence=str(display_name)
                        ),
                    )


def build_rechtshinweise(
    branche: str, detected_or_declared: list[DetectedProvider]
) -> list[str]:
    """Generiert Berufsrechts-/Compliance-Warnungen fuer den Report.

    Args:
        branche: ``CustomerData.branche`` (z. B. ``"Sonstige"`` oder
            ``"Finanzen"``). Bei Kanzlei-typischen Werten greifen
            §43e BRAO / §9 RAO-Warnungen.
        detected_or_declared: Aggregierte Provider-Liste.

    Returns:
        Liste von User-orientierten Warntexten (Deutsch).
    """
    is_kanzlei_keyword = any(
        w in branche.lower() for w in ("kanzlei", "rechtsanwalt", "anwalt", "steuer")
    )
    hints: list[str] = []
    for p in detected_or_declared:
        if p.status == "cloud_act":
            text = (
                f"{p.name}: faellt unter US Cloud Act. DSGVO Art. 44ff "
                "verlangt zusaetzliche technische Massnahmen (E2EE / "
                "BYOK / DataDiode); Transfer-Impact-Assessment (TIA) "
                "ist dokumentationspflichtig."
            )
            if is_kanzlei_keyword:
                text += " §43e BRAO / §9 RAO: pruefen ob Verschwiegenheit gewahrt."
            hints.append(text)
        elif p.status == "eu_boundary":
            hints.append(
                f"{p.name}: EU-Boundary-Variante verfuegbar — "
                "Restrisiko durch Mutterkonzern. " + p.residual_risk_note
            )
    return hints
