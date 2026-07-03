"""
catalog_seeder — Initial-Befuellung des Vendor-Catalogs.

Iteration 2b: Stellt eine kuratierte Startliste von
~30 Vendoren bereit, die in deutsch-/oesterreichischen Kanzleien typisch
sind. Beim ersten Tool-Start (Catalog leer) wird die Liste eingespielt.
Der User kann die Eintraege spaeter editieren, ergaenzen oder loeschen.

Wartung: Die Liste lebt absichtlich im Code (nicht in JSON-Resource).
Aenderungen sind versionierbar, reviewbar und werden via Git-PR getrackt.

Schichtzugehoerigkeit: application/ — darf domain + data + core
importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass

from core.logger import get_logger
from tools.supply_chain_monitor.data.vendor_catalog_repository import (
    VendorCatalogRepository,
)
from tools.supply_chain_monitor.domain.models import (
    VendorCatalogEntry,
    VendorCategory,
)

_log = get_logger(__name__)


@dataclass(frozen=True)
class _SeedEntry:
    """Compact Seed-Definition — wird in:class:`VendorCatalogEntry` umgesetzt."""

    canonical_name: str
    category: VendorCategory
    aliases: tuple[str, ...] = ()
    apps: tuple[str, ...] = ()
    mx: tuple[str, ...] = ()
    cert: tuple[str, ...] = ()
    notes: str = ""


# Initial-Catalog — ~30 Eintraege. Wir sortieren nach Kategorie, damit
# das Code-Review die Vollstaendigkeit pro Kategorie pruefen kann.
_SEED: tuple[_SeedEntry, ...] = (
    # ── KANZLEISOFTWARE (DE/AT) ───────────────────────────────────────
    _SeedEntry(
        canonical_name="DATEV",
        category=VendorCategory.KANZLEISOFTWARE,
        aliases=("datev eg",),
        apps=("datev",),
        mx=("datev.de",),
        cert=("datev",),
        notes="Steuer- und Kanzleisoftware (DE-Genossenschaft).",
    ),
    _SeedEntry(
        canonical_name="RA-MICRO",
        category=VendorCategory.KANZLEISOFTWARE,
        aliases=("ramicro",),
        apps=("ra-micro", "ramicro"),
        notes="Anwalts-Kanzleisoftware.",
    ),
    _SeedEntry(
        canonical_name="AnNoText",
        category=VendorCategory.KANZLEISOFTWARE,
        apps=("annotext",),
        notes="Anwaltssoftware (Wolters Kluwer).",
    ),
    _SeedEntry(
        canonical_name="Advoware",
        category=VendorCategory.KANZLEISOFTWARE,
        apps=("advoware",),
        notes="Anwalts-Verwaltungssoftware.",
    ),
    _SeedEntry(
        canonical_name="Lexware",
        category=VendorCategory.KANZLEISOFTWARE,
        apps=("lexware",),
        cert=("lexware", "haufe-lexware"),
        notes="Buchhaltungs-/Lohn-Software (Haufe-Lexware).",
    ),
    _SeedEntry(
        canonical_name="BMD",
        category=VendorCategory.KANZLEISOFTWARE,
        apps=("bmd",),
        mx=("bmd.com",),
        notes="Steuerberater-Software (AT).",
    ),
    # ── CLOUD ─────────────────────────────────────────────────────────
    _SeedEntry(
        canonical_name="Microsoft",
        category=VendorCategory.CLOUD,
        aliases=("microsoft 365", "office 365", "ms365", "azure"),
        apps=(
            "microsoft 365",
            "microsoft office",
            "office 365",
            "onedrive",
            "sharepoint",
            "microsoft azure",
            "windows defender",
        ),
        mx=("protection.outlook.com", "mail.protection.outlook.com"),
        cert=("microsoft", "azure tls", "microsoft rsa tls"),
        notes="Office/Cloud-Suite (US, EU Data Boundary verfuegbar).",
    ),
    _SeedEntry(
        canonical_name="Google",
        category=VendorCategory.CLOUD,
        aliases=("google workspace", "google cloud", "gmail", "gcp"),
        apps=("google workspace", "google drive", "google chrome"),
        mx=("aspmx.l.google.com", "googlemail.com"),
        cert=("google trust services", "google internet authority"),
        notes="Workspace/Cloud-Suite (US).",
    ),
    _SeedEntry(
        canonical_name="Amazon Web Services",
        category=VendorCategory.CLOUD,
        aliases=("aws",),
        apps=("aws cli", "amazon corretto"),
        mx=("amazonses.com",),
        cert=("amazon", "amazon rsa", "amazon trust services"),
        notes="Cloud-Infrastruktur (US).",
    ),
    _SeedEntry(
        canonical_name="Apple",
        category=VendorCategory.CLOUD,
        aliases=("icloud", "apple business"),
        apps=("icloud",),
        mx=("icloud.com",),
        cert=("apple",),
        notes="iCloud / Apple Business (US).",
    ),
    _SeedEntry(
        canonical_name="Dropbox",
        category=VendorCategory.CLOUD,
        apps=("dropbox",),
        cert=("dropbox",),
        notes="File-Sync (US).",
    ),
    _SeedEntry(
        canonical_name="Adobe",
        category=VendorCategory.CLOUD,
        aliases=("adobe creative cloud", "adobe acrobat"),
        apps=("adobe creative cloud", "adobe acrobat", "adobe reader"),
        cert=("adobe",),
        notes="Creative Cloud + Acrobat (US).",
    ),
    _SeedEntry(
        canonical_name="Nextcloud",
        category=VendorCategory.CLOUD,
        apps=("nextcloud",),
        cert=("nextcloud",),
        notes="Self-hosted File-Sync (DE-Mutter).",
    ),
    # ── MSP / Hosting ─────────────────────────────────────────────────
    _SeedEntry(
        canonical_name="Hetzner",
        category=VendorCategory.MSP,
        apps=("hetzner",),
        mx=("hetzner.com", "your-server.de"),
        cert=("hetzner",),
        notes="Hoster (DE).",
    ),
    _SeedEntry(
        canonical_name="IONOS",
        category=VendorCategory.MSP,
        aliases=("1&1 ionos",),
        apps=("ionos",),
        mx=("ionos.de", "kundenserver.de", "online.de", "1und1.de"),
        cert=("ionos", "thawte"),
        notes="Hoster (DE).",
    ),
    _SeedEntry(
        canonical_name="STRATO",
        category=VendorCategory.MSP,
        mx=("strato.de", "strato-hosting.de"),
        cert=("strato",),
        notes="Hoster (DE).",
    ),
    _SeedEntry(
        canonical_name="OVHcloud",
        category=VendorCategory.MSP,
        mx=("ovh.com", "ovh.net"),
        cert=("ovh",),
        notes="Hoster (FR).",
    ),
    _SeedEntry(
        canonical_name="Cloudflare",
        category=VendorCategory.MSP,
        mx=("mx.cloudflare.net",),
        cert=("cloudflare",),
        notes="CDN + DNS + WAF (US).",
    ),
    # ── Kommunikation ─────────────────────────────────────────────────
    _SeedEntry(
        canonical_name="Microsoft Teams",
        category=VendorCategory.KOMMUNIKATION,
        apps=("microsoft teams",),
        notes="Video/Chat — Teil von Microsoft 365 (kann separat erfasst werden).",
    ),
    _SeedEntry(
        canonical_name="Zoom",
        category=VendorCategory.KOMMUNIKATION,
        apps=("zoom",),
        mx=("zoom.us",),
        cert=("zoom",),
        notes="Video-Conferencing (US).",
    ),
    _SeedEntry(
        canonical_name="Slack",
        category=VendorCategory.KOMMUNIKATION,
        apps=("slack",),
        cert=("slack",),
        notes="Messaging (Salesforce, US).",
    ),
    _SeedEntry(
        canonical_name="WebEx",
        category=VendorCategory.KOMMUNIKATION,
        apps=("webex", "cisco webex"),
        cert=("cisco",),
        notes="Cisco Webex Meetings.",
    ),
    _SeedEntry(
        canonical_name="beA",
        category=VendorCategory.KOMMUNIKATION,
        aliases=(
            "besonderes elektronisches anwaltspostfach",
            "bea client security",
        ),
        apps=("bea client security",),
        notes="Bundesweite elektronische Anwaltsakte (BRAK).",
    ),
    _SeedEntry(
        canonical_name="Deutsche Telekom",
        category=VendorCategory.KOMMUNIKATION,
        aliases=("telekom", "t-systems"),
        mx=("t-online.de", "telekom.de"),
        notes="Telefonie + Glasfaser (DE).",
    ),
    _SeedEntry(
        canonical_name="Mailbox.org",
        category=VendorCategory.KOMMUNIKATION,
        mx=("mailbox.org", "mxext.mailbox.org"),
        cert=("mailbox.org",),
        notes="E-Mail-Provider (DE, EU-souveraen).",
    ),
    _SeedEntry(
        canonical_name="Posteo",
        category=VendorCategory.KOMMUNIKATION,
        mx=("posteo.de",),
        cert=("posteo",),
        notes="E-Mail-Provider (DE, EU-souveraen).",
    ),
    _SeedEntry(
        canonical_name="ProtonMail",
        category=VendorCategory.KOMMUNIKATION,
        aliases=("proton", "proton mail"),
        mx=("proton.me", "protonmail.ch"),
        cert=("proton",),
        notes="E-Mail-Provider (CH).",
    ),
    # ── Spezial ───────────────────────────────────────────────────────
    _SeedEntry(
        canonical_name="DocuSign",
        category=VendorCategory.SPEZIAL,
        apps=("docusign",),
        cert=("docusign",),
        notes="E-Signatur (US).",
    ),
    _SeedEntry(
        canonical_name="GitHub",
        category=VendorCategory.SPEZIAL,
        apps=("github desktop",),
        cert=("github",),
        notes="Code-Hosting (Microsoft-Tochter, US).",
    ),
    _SeedEntry(
        canonical_name="Bitdefender",
        category=VendorCategory.SPEZIAL,
        apps=("bitdefender",),
        cert=("bitdefender",),
        notes="AV/EDR (RO).",
    ),
    _SeedEntry(
        canonical_name="ESET",
        category=VendorCategory.SPEZIAL,
        apps=("eset",),
        cert=("eset",),
        notes="AV/EDR (SK).",
    ),
    _SeedEntry(
        canonical_name="LastPass",
        category=VendorCategory.SPEZIAL,
        apps=("lastpass",),
        cert=("lastpass",),
        notes="Password-Manager (US).",
    ),
    _SeedEntry(
        canonical_name="Bitwarden",
        category=VendorCategory.SPEZIAL,
        apps=("bitwarden",),
        cert=("bitwarden",),
        notes="Password-Manager (US, open-source).",
    ),
)


class CatalogSeeder:
    """Befuellt einen leeren Catalog mit den Initial-Eintraegen."""

    def __init__(self, repository: VendorCatalogRepository | None = None) -> None:
        self._repo = repository or VendorCatalogRepository()

    def seed_if_empty(self) -> int:
        """Spielt die Seed-Liste ein, **wenn** der Catalog leer ist.

        Returns:
            Anzahl neu eingefuegter Eintraege. ``0`` wenn der Catalog
            bereits Eintraege enthielt oder der Seed leer ist.
        """
        if self._repo.count() > 0:
            return 0
        return self._insert_seed()

    def force_reseed(self) -> int:
        """Spielt fehlende Eintraege nach (idempotent fuer ``canonical_name``).

        Existierende Eintraege werden NICHT veraendert (User-Edits bleiben).
        Nur Seed-Eintraege mit unbekanntem ``canonical_name`` werden
        ergaenzt — nuetzlich nach Catalog-Erweiterung in einem Patch.

        Returns:
            Anzahl neu eingefuegter Eintraege.
        """
        return self._insert_seed()

    def _insert_seed(self) -> int:
        inserted = 0
        for seed in _SEED:
            existing = self._repo.get_by_canonical_name(seed.canonical_name)
            if existing is not None:
                continue
            entry = VendorCatalogEntry(
                id=None,
                canonical_name=seed.canonical_name,
                default_category=seed.category,
                aliases=seed.aliases,
                app_name_patterns=seed.apps,
                mx_hostname_patterns=seed.mx,
                cert_issuer_patterns=seed.cert,
                notes=seed.notes,
            )
            self._repo.add(entry)
            inserted += 1
        if inserted > 0:
            _log.info("catalog_seeded count=%s", inserted)
        return inserted

    @staticmethod
    def seed_size() -> int:
        """Anzahl Eintraege in der Seed-Liste — fuer Tests + Smoke."""
        return len(_SEED)
