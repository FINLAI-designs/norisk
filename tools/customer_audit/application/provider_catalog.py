"""
provider_catalog — Kurierte Datenbank von Cloud-Providern mit
CLOUD-Act-Bewertung fuer den Datensouveraenitaets-Audit.

Quelle: Sub-Agent-Recherche 2026-05-15 (
ein internes Konzept (§4.2)
und das Datensouveraenitaets-Recherche-Resultat).

Wartung: Cloud-Provider-Landschaft veraendert sich. Updates direkt in
diesem Modul; eine offline-Catalog-Update-Pipeline (signiertes FINLAI-
Cache-File) ist Iter 4-Backlog.

Schichtzugehoerigkeit: application/ — darf domain importieren, kein
GUI/Data.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ProviderCategory = Literal[
    "email",
    "file_sync",
    "messaging",
    "videoconf",
    "vpn",
    "office_suite",
    "kanzlei_software",
    "backup_cloud",
    "code_hosting",
    "saas_other",
]


@dataclass(frozen=True)
class CloudProvider:
    """Eintrag in der Provider-DB.

    Attributes:
        name: Display-Name (z. B. ``"Microsoft 365"``).
        legal_entity_country: Sitz der vertraglichen Entity (ISO-Code).
        parent_country: Sitz des Mutterkonzerns.
        cloud_act_exposed: True wenn US-Mutter/Tochter mit operativer
            Kontrolle vorhanden ist.
        eu_boundary_available: True wenn ein EU-Boundary-Tier angeboten
            wird (z. B. Microsoft EU Data Boundary).
        residual_risk_note: Wo die EU-Boundary-Variante leckt
            (Support-Daten, Metadaten, Mutterkonzern-Pflicht).
        category: Use-Case-Kategorie.
        detection_keywords: Strings die in Software-Display-Namen,
            MX-Hostnames oder SPF-Records nach diesem Provider
            riechen. Lowercase. Wird vom Scanner zum Matching genutzt.
    """

    name: str
    legal_entity_country: str
    parent_country: str
    cloud_act_exposed: bool
    eu_boundary_available: bool
    residual_risk_note: str
    category: ProviderCategory
    detection_keywords: tuple[str, ...]

    @property
    def status(self) -> str:
        """Aggregierter Status — fuer Score und UI-Badge."""
        if not self.cloud_act_exposed:
            return "eu_sovereign"
        if self.eu_boundary_available:
            return "eu_boundary"
        return "cloud_act"


# ---------------------------------------------------------------------------
# Statischer Catalog — Stand 2026-05-15
# ---------------------------------------------------------------------------

_CATALOG: list[CloudProvider] = [
    # === Microsoft ====================================================
    CloudProvider(
        name="Microsoft 365",
        legal_entity_country="IE",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note=(
            "EU Data Boundary Phase 3 (Feb 2025) deckt Kerndaten ab. "
            "Metadaten + Support-Daten partiell ausserhalb EU. "
            "Mutterkonzern bleibt CLOUD-Act-pflichtig."
        ),
        category="office_suite",
        detection_keywords=(
            "microsoft 365", "microsoft office 365", "office 365",
            "onedrive", "microsoft teams", "outlook",
            "outlook.com", "office.com", "sharepoint",
            "protection.outlook.com", "spf.protection.outlook.com",
        ),
    ),
    CloudProvider(
        name="Azure",
        legal_entity_country="IE",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note="Wie Microsoft 365 (Microsoft Corp.).",
        category="saas_other",
        detection_keywords=("azure", "windows.net", "azurewebsites.net"),
    ),
    # === Google =======================================================
    CloudProvider(
        name="Google Workspace",
        legal_entity_country="IE",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note=(
            "Sovereign Controls + T-Systems-Partnerschaft reduzieren, "
            "eliminieren aber CLOUD-Act-Pflicht des Mutterkonzerns nicht."
        ),
        category="office_suite",
        detection_keywords=(
            "google workspace", "google drive", "gmail",
            "google.com", "googlemail.com", "aspmx.l.google.com",
            "_spf.google.com",
        ),
    ),
    CloudProvider(
        name="Google Cloud",
        legal_entity_country="IE",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note="Wie Google Workspace.",
        category="saas_other",
        detection_keywords=("gcp", "googleapis.com", "appspot.com"),
    ),
    # === Amazon =======================================================
    CloudProvider(
        name="AWS",
        legal_entity_country="LU",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note=(
            "European Sovereign Cloud (Brandenburg, GA 2025): eigene "
            "Legal-Entity, aber US-Mutter behaelt rechtlichen Zugriff."
        ),
        category="saas_other",
        detection_keywords=("aws", "amazonaws.com", "s3.amazonaws.com", "amazonses.com"),
    ),
    CloudProvider(
        name="Dropbox",
        legal_entity_country="IE",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note=(
            "Dropbox EU-Regionen verfuegbar, Mutterkonzern bleibt "
            "CLOUD-Act-pflichtig."
        ),
        category="file_sync",
        detection_keywords=("dropbox",),
    ),
    CloudProvider(
        name="Apple iCloud",
        legal_entity_country="IE",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=False,
        residual_risk_note=(
            "Advanced Data Protection E2EE optional fuer Backups/Notes, "
            "nicht fuer Mail/Kalender."
        ),
        category="file_sync",
        detection_keywords=("icloud", "icloud.com", "apple business"),
    ),
    # === Zoom / Slack / GitHub ========================================
    CloudProvider(
        name="Zoom",
        legal_entity_country="NL",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note="EU-Region verfuegbar; US-Mutterkonzern bleibt.",
        category="videoconf",
        detection_keywords=("zoom.us", "zoom"),
    ),
    CloudProvider(
        name="Slack",
        legal_entity_country="IE",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note="Salesforce-Mutter, EU Data Residency. CLOUD Act bleibt.",
        category="messaging",
        detection_keywords=("slack.com", "slack"),
    ),
    CloudProvider(
        name="GitHub",
        legal_entity_country="US",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=False,
        residual_risk_note="Microsoft-Tochter, keine echte EU-Option.",
        category="code_hosting",
        detection_keywords=("github.com", "github desktop"),
    ),
    CloudProvider(
        name="Adobe Creative Cloud",
        legal_entity_country="IE",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note="EU-Region fuer Creative-Cloud-Storage; Mutterkonzern bleibt.",
        category="saas_other",
        detection_keywords=("adobe creative cloud", "adobe acrobat"),
    ),
    CloudProvider(
        name="Atlassian",
        legal_entity_country="AU",
        parent_country="AU",
        cloud_act_exposed=True,  # US-Tochter
        eu_boundary_available=True,
        residual_risk_note=(
            "Atlassian US Inc. ist CLOUD-Act-pflichtig — EU Data "
            "Residency reduziert Exposure auf Datenebene, nicht auf "
            "Tochter-Ebene."
        ),
        category="saas_other",
        detection_keywords=("atlassian", "jira", "confluence"),
    ),
    CloudProvider(
        name="HubSpot",
        legal_entity_country="IE",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note="EU-Region, US-Mutter.",
        category="saas_other",
        detection_keywords=("hubspot",),
    ),
    CloudProvider(
        name="Salesforce",
        legal_entity_country="IE",
        parent_country="US",
        cloud_act_exposed=True,
        eu_boundary_available=True,
        residual_risk_note="EU-Region, US-Mutter.",
        category="saas_other",
        detection_keywords=("salesforce", "force.com", "my.salesforce.com"),
    ),
    # === EU-souveraen =================================================
    CloudProvider(
        name="Open-Xchange (OX App Suite)",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="email",
        detection_keywords=("open-xchange", "ox app suite", "appsuite"),
    ),
    CloudProvider(
        name="mailbox.org",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="email",
        detection_keywords=("mailbox.org", "mxext", "mxext1.mailbox.org"),
    ),
    CloudProvider(
        name="Posteo",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="email",
        detection_keywords=("posteo.de", "posteo"),
    ),
    CloudProvider(
        name="Tutanota",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="email",
        detection_keywords=("tutanota", "tuta.io", "tuta.com"),
    ),
    CloudProvider(
        name="Hetzner",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="saas_other",
        detection_keywords=("hetzner", "hetzner.com", "your-server.de"),
    ),
    CloudProvider(
        name="IONOS",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="saas_other",
        detection_keywords=("ionos", "1und1.de", "kundenserver.de"),
    ),
    CloudProvider(
        name="STACKIT",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="saas_other",
        detection_keywords=("stackit",),
    ),
    CloudProvider(
        name="OVHcloud",
        legal_entity_country="FR",
        parent_country="FR",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="saas_other",
        detection_keywords=("ovh.com", "ovhcloud", "ovh.net"),
    ),
    CloudProvider(
        name="Scaleway",
        legal_entity_country="FR",
        parent_country="FR",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="saas_other",
        detection_keywords=("scaleway",),
    ),
    CloudProvider(
        name="Infomaniak",
        legal_entity_country="CH",
        parent_country="CH",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note=(
            "Schweizer Surveillance-VO geplant (2025) — Status "
            "regelmaessig pruefen."
        ),
        category="saas_other",
        detection_keywords=("infomaniak",),
    ),
    CloudProvider(
        name="Nextcloud (Self-hosted)",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note=(
            "Status haengt vom Hosting ab — auf AWS/Azure waere "
            "Nextcloud trotz EU-Mutterprojekt wieder CLOUD-Act-exposed."
        ),
        category="file_sync",
        detection_keywords=("nextcloud",),
    ),
    CloudProvider(
        name="ProtonMail / Proton Drive",
        legal_entity_country="CH",
        parent_country="CH",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note=(
            "Schweizer Surveillance-VO geplant (2025) — beobachten."
        ),
        category="email",
        detection_keywords=("proton.me", "protonmail.com", "protonmail.ch"),
    ),
    CloudProvider(
        name="ProtonVPN",
        legal_entity_country="CH",
        parent_country="CH",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note=(
            "Schweizer Surveillance-VO geplant (2025) — beobachten."
        ),
        category="vpn",
        detection_keywords=("protonvpn",),
    ),
    CloudProvider(
        name="Mullvad VPN",
        legal_entity_country="SE",
        parent_country="SE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note=(
            "Schweden ist Fourteen-Eyes, Mullvad ist No-Logs + "
            "RAM-only — kein praktischer Daten-Zugriff moeglich."
        ),
        category="vpn",
        detection_keywords=("mullvad",),
    ),
    CloudProvider(
        name="NordVPN",
        legal_entity_country="PA",
        parent_country="LT",
        cloud_act_exposed=True,  # US-Investor + NL-Tochter
        eu_boundary_available=False,
        residual_risk_note=(
            "Nord Security in NL, Eigentuemer Tesonet (LT), US-Investor "
            "Warburg Pincus (Minderheit). Yellow-Flag."
        ),
        category="vpn",
        detection_keywords=("nordvpn",),
    ),
    # === Kanzlei-Software (DACH-souveraen) ============================
    CloudProvider(
        name="DATEV",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="kanzlei_software",
        detection_keywords=("datev",),
    ),
    CloudProvider(
        name="BMD",
        legal_entity_country="AT",
        parent_country="AT",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="kanzlei_software",
        detection_keywords=("bmd ntcs", "bmd com", "bmdcom"),
    ),
    CloudProvider(
        name="RA-MICRO",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="kanzlei_software",
        detection_keywords=("ra-micro", "ramicro"),
    ),
    CloudProvider(
        name="advoware",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="kanzlei_software",
        detection_keywords=("advoware",),
    ),
    CloudProvider(
        name="AnNoText",
        legal_entity_country="DE",
        parent_country="DE",
        cloud_act_exposed=False,
        eu_boundary_available=False,
        residual_risk_note="",
        category="kanzlei_software",
        detection_keywords=("annotext",),
    ),
]


def all_providers() -> list[CloudProvider]:
    """Liefert eine Kopie aller Catalog-Eintraege."""
    return list(_CATALOG)


def by_category(category: ProviderCategory) -> list[CloudProvider]:
    """Filter nach Kategorie."""
    return [p for p in _CATALOG if p.category == category]


def find_by_keyword(text: str) -> CloudProvider | None:
    """Sucht den ersten Provider dessen Keyword im (lowercased) ``text``
    auftaucht.

    Args:
        text: Beliebiger Lookup-String — DNS-Hostname, Software-Display-
            Name, MX-Record-Value, SPF-Include.

    Returns:
        Der erste Treffer oder ``None``. Die Reihenfolge im Catalog
        bestimmt die Praezedenz (Microsoft 365 vor Azure vor allgemeinem
        Outlook etc.).
    """
    needle = text.lower()
    for provider in _CATALOG:
        for kw in provider.detection_keywords:
            if kw in needle:
                return provider
    return None
